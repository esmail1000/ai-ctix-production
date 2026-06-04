"""Hybrid Cyber NLP inference.

This module combines:
1. A trained Hugging Face token-classification model when available and trusted.
2. A deterministic cybersecurity regex/rule extractor as fallback and enrichment.

Production protections:
- Model quality gate based on saved eval_f1.
- Token-level confidence threshold.
- Optional regex enrichment for true model-only evaluation.
- Contextual rule enrichment for remediation, impact, assets, components, and attack vectors.
- In auto mode, weak models are ignored instead of polluting the output.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from labels import ID2LABEL, LABEL2ID, output_key_for_entity
from regex_extractor import extract_all_structured
from utils import merge_dict_lists, normalize_report_text, write_json

try:
    import torch  # type: ignore
except ImportError:
    torch = None  # type: ignore

try:
    from transformers import AutoModelForTokenClassification  # type: ignore
    from transformers import (AutoTokenizer,  # type: ignore
                              PreTrainedTokenizerBase)
except ImportError:
    AutoModelForTokenClassification = None  # type: ignore
    AutoTokenizer = None  # type: ignore
    PreTrainedTokenizerBase = Any  # type: ignore


OUTPUT_KEYS: Tuple[str, ...] = (
    "cve_ids",
    "cwe_ids",
    "cvss_scores",
    "cvss_vectors",
    "cpes",
    "vulnerability_types",
    "severity",
    "risk_levels",
    "impacts",
    "remediations",
    "mitigations",
    "patches",
    "products",
    "vendors",
    "versions",
    "affected_components",
    "assets",
    "endpoints",
    "services",
    "ips",
    "ip_ranges",
    "urls",
    "domains",
    "emails",
    "ports",
    "file_paths",
    "file_names",
    "md5_hashes",
    "sha1_hashes",
    "sha256_hashes",
    "hashes",
    "malware",
    "attack_vectors",
    "attack_techniques",
    "mitre_techniques",
    "threat_actors",
    "exploits",
    "exploit_available",
    "exploitability",
    "confidentiality_impacts",
    "integrity_impacts",
    "availability_impacts",
)

MODEL_REQUIRED_FILES: Tuple[str, ...] = ("config.json",)

MIN_MODEL_F1_DEFAULT = 0.30
MIN_ENTITY_CONFIDENCE_DEFAULT = 0.75

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,6}\b", re.IGNORECASE)
CVSS_SCORE_RE = re.compile(r"^(10(?:\.0)?|[0-9](?:\.[0-9])?)$")
CVSS_VECTOR_RE = re.compile(r"^CVSS:\d\.\d/[A-Z]{1,3}:[A-Z]/.*$", re.IGNORECASE)
CPE_RE = re.compile(r"^cpe:2\.3:[aho]:[^\s]+$", re.IGNORECASE)
PORT_RE = re.compile(r"^\d{1,5}$")
DOMAIN_RE = re.compile(
    r"^(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

VALID_SEVERITIES: Dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "informational": "Low",
    "info": "Low",
}

GENERIC_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "com",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "url",
    "was",
    "with",
    "www",
    "cve",
    "cwe",
    "cvss",
    "port",
}

NOISE_VALUES = {
    "apply",
    "score",
    "version",
    "corp",
    "https",
    "http",
    "login",
    "vendor",
    "patch",
    "critical",
    "high",
    "medium",
    "low",
}

VULN_TYPE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bno\s*sql\s+injection\b|\bnosql\s+injection\b", "NoSQL Injection"),
    (r"\bsql\s+injection\b|\bsqli\b", "SQL Injection"),
    (r"\bcommand\s+injection\b|\bos\s+command\s+injection\b", "Command Injection"),
    (r"\bxml\s+external\s+entity\b|\bxxe\b", "XML External Entity"),
    (r"\bcross[-\s]*site\s+scripting\b|\bxss\b", "Cross-Site Scripting"),
    (r"\bserver[-\s]*side\s+request\s+forgery\b|\bssrf\b", "Server-Side Request Forgery"),
    (r"\bcross[-\s]*site\s+request\s+forgery\b|\bcsrf\b", "Cross-Site Request Forgery"),
    (r"\bremote\s+code\s+execution\b|\brce\b", "Remote Code Execution"),
    (r"\bpath\s+traversal\b|\bdirectory\s+traversal\b", "Path Traversal"),
    (r"\bauthentication\s+bypass\b|\bauth\s+bypass\b", "Authentication Bypass"),
    (r"\bauthorization\s+bypass\b", "Authorization Bypass"),
    (r"\binsecure\s+deserialization\b", "Insecure Deserialization"),
    (r"\bopen\s+redirect\b", "Open Redirect"),
    (r"\blocal\s+file\s+inclusion\b|\blfi\b", "Local File Inclusion"),
    (r"\bremote\s+file\s+inclusion\b|\brfi\b", "Remote File Inclusion"),
    (r"\bprivilege\s+escalation\b", "Privilege Escalation"),
    (r"\bbuffer\s+overflow\b", "Buffer Overflow"),
    (r"\bdenial\s+of\s+service\b|\bdos\b|\bddos\b", "Denial of Service"),
    (r"\bbroken\s+access\s+control\b", "Broken Access Control"),
    (r"\bsecurity\s+misconfiguration\b|\bmisconfiguration\b", "Security Misconfiguration"),
    (r"\bsensitive\s+data\s+exposure\b", "Sensitive Data Exposure"),
    (r"\binformation\s+disclosure\b|\bdata\s+leak(?:age)?\b", "Information Disclosure"),
    (r"\bunrestricted\s+file\s+upload\b|\bfile\s+upload\s+vulnerab", "File Upload Vulnerability"),
)

VULN_KEYWORDS = (
    "injection",
    "scripting",
    "execution",
    "bypass",
    "traversal",
    "deserialization",
    "redirect",
    "overflow",
    "disclosure",
    "escalation",
    "forgery",
    "misconfiguration",
    "exposure",
    "inclusion",
    "upload",
)


def empty_structured_output() -> Dict[str, List[str]]:
    return {key: [] for key in OUTPUT_KEYS}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _read_json_file(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    return data if isinstance(data, dict) else None


def _read_model_quality(model_dir: Optional[Path]) -> Dict[str, Any]:
    """Read saved model metrics and decide whether the model is trustworthy."""
    quality: Dict[str, Any] = {
        "metrics_found": False,
        "eval_f1": None,
        "eval_precision": None,
        "eval_recall": None,
        "eval_accuracy": None,
        "source": None,
    }

    if model_dir is None:
        return quality

    candidates = [
        model_dir / "test_metrics.json",
        model_dir / "training_config.json",
    ]

    for path in candidates:
        data = _read_json_file(path)

        if data is None:
            continue

        if path.name == "test_metrics.json":
            metrics = data
        else:
            metrics = data.get("final_metrics", {})

        if not isinstance(metrics, dict):
            continue

        quality.update(
            {
                "metrics_found": True,
                "eval_f1": _safe_float(metrics.get("eval_f1")),
                "eval_precision": _safe_float(metrics.get("eval_precision")),
                "eval_recall": _safe_float(metrics.get("eval_recall")),
                "eval_accuracy": _safe_float(metrics.get("eval_accuracy")),
                "source": str(path),
            }
        )
        return quality

    return quality


def _model_passes_quality_gate(
    quality: Dict[str, Any],
    *,
    min_model_f1: float,
) -> bool:
    if not quality.get("metrics_found"):
        return False

    return _safe_float(quality.get("eval_f1")) >= min_model_f1


def _normalize_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _strip_entity_value(value: str) -> str:
    return _normalize_spaces(value.strip().strip(" \t\r\n\"'`“”‘’.,;:()[]{}<>"))


def _dedupe_ci_preserve_order(items: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []

    for item in items:
        cleaned = _strip_entity_value(str(item))
        key = cleaned.casefold()

        if not cleaned:
            continue

        if key not in seen:
            seen.add(key)
            out.append(cleaned)

    return out


def _clean_cves(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        out.extend(match.upper() for match in CVE_RE.findall(str(item)))

    return _dedupe_ci_preserve_order(out)


def _clean_cwes(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        out.extend(match.upper() for match in CWE_RE.findall(str(item)))

    return _dedupe_ci_preserve_order(out)


def _clean_cvss_scores(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))

        if not CVSS_SCORE_RE.fullmatch(candidate):
            continue

        score = float(candidate)
        if 0 <= score <= 10:
            out.append(f"{score:.1f}".rstrip("0").rstrip("."))

    return _dedupe_ci_preserve_order(out)


def _clean_cvss_vectors(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).upper()
        if CVSS_VECTOR_RE.fullmatch(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_cpes(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))
        if CPE_RE.fullmatch(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_severities(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        words = re.findall(r"[a-z]+", str(item).casefold())

        for word in words:
            canonical = VALID_SEVERITIES.get(word)
            if canonical:
                out.append(canonical)
                break

    return _dedupe_ci_preserve_order(out)


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _clean_ips(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))
        if _is_valid_ip(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_urls(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = str(item).strip().strip(" \t\r\n\"'`“”‘’<>").rstrip(".,;:)])}")

        if not candidate.casefold().startswith(("http://", "https://")):
            continue

        if "." not in candidate or " " in candidate:
            continue

        out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_domains(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).casefold()
        candidate = re.sub(r"^https?://", "", candidate)
        candidate = candidate.split("/")[0].split(":")[0]

        if not candidate:
            continue

        if _is_valid_ip(candidate):
            continue

        if DOMAIN_RE.fullmatch(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_ports(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))

        if not PORT_RE.fullmatch(candidate):
            continue

        port = int(candidate)
        if 1 <= port <= 65535:
            out.append(str(port))

    return _dedupe_ci_preserve_order(out)


def _clean_hashes(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).lower()
        if HASH_RE.fullmatch(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_mitre(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).upper()
        if MITRE_RE.fullmatch(candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _canonicalize_vulnerability_type(value: str) -> Optional[str]:
    candidate = _strip_entity_value(value)
    candidate = candidate.replace("_", " ").replace("/", " ")
    candidate = _normalize_spaces(candidate)

    if not candidate:
        return None

    lowered = candidate.casefold()

    if lowered in GENERIC_STOPWORDS or lowered in NOISE_VALUES:
        return None

    if lowered.isdigit() or len(lowered) < 3:
        return None

    for pattern, canonical in VULN_TYPE_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            return canonical

    word_count = len(re.findall(r"[a-z0-9]+", lowered))
    has_vuln_keyword = any(keyword in lowered for keyword in VULN_KEYWORDS)

    if word_count >= 2 and has_vuln_keyword:
        return " ".join(part.capitalize() for part in candidate.split())

    return None


def _clean_vulnerability_types(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        canonical = _canonicalize_vulnerability_type(str(item))
        if canonical:
            out.append(canonical)

    return _dedupe_ci_preserve_order(out)


def _looks_like_url_or_ip_or_domain_fragment(value: str) -> bool:
    candidate = _strip_entity_value(value)
    lowered = candidate.casefold()

    if lowered.startswith(("http://", "https://")):
        return True

    if _is_valid_ip(candidate):
        return True

    if DOMAIN_RE.fullmatch(lowered):
        return True

    return False


def _clean_free_text(items: Sequence[str], *, min_chars: int = 2, min_words: int = 1) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))
        lowered = candidate.casefold()

        if not candidate:
            continue

        if lowered in GENERIC_STOPWORDS or lowered in NOISE_VALUES:
            continue

        if len(candidate) < min_chars:
            continue

        if CVE_RE.search(candidate):
            continue

        if _looks_like_url_or_ip_or_domain_fragment(candidate):
            continue

        if PORT_RE.fullmatch(candidate):
            continue

        word_count = len(re.findall(r"[a-z0-9]+", lowered))
        if word_count < min_words:
            continue

        out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_file_names(items: Sequence[str]) -> List[str]:
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item))
        if re.fullmatch(r"[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,10}", candidate):
            out.append(candidate)

    return _dedupe_ci_preserve_order(out)


def _clean_attack_vectors(items: Sequence[str]) -> List[str]:
    allowed = {
        "network": "Network",
        "adjacent network": "Adjacent Network",
        "local": "Local",
        "physical": "Physical",
    }
    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).casefold()
        if candidate in allowed:
            out.append(allowed[candidate])
        elif re.fullmatch(r"AV:[NALP]", candidate.upper()):
            out.append(candidate.upper())

    return _dedupe_ci_preserve_order(out)


def _clean_booleanish(items: Sequence[str]) -> List[str]:
    if not items:
        return []

    truthy = {
        "true",
        "yes",
        "available",
        "exploit available",
        "public exploit",
        "known exploited",
        "weaponized",
    }
    falsy = {"false", "no", "none", "not available", "no public exploit observed"}

    out: List[str] = []

    for item in items:
        candidate = _strip_entity_value(str(item)).casefold()

        if candidate in truthy or "exploit available" in candidate or "public exploit" in candidate:
            out.append("true")
        elif candidate in falsy or "no public exploit" in candidate:
            out.append("false")

    return _dedupe_ci_preserve_order(out)


def _clean_structured_output(raw: Dict[str, List[str]]) -> Dict[str, List[str]]:
    cleaned = empty_structured_output()

    cleaned["cve_ids"] = _clean_cves(raw.get("cve_ids", []))
    cleaned["cwe_ids"] = _clean_cwes(raw.get("cwe_ids", []))
    cleaned["cvss_scores"] = _clean_cvss_scores(raw.get("cvss_scores", []))
    cleaned["cvss_vectors"] = _clean_cvss_vectors(raw.get("cvss_vectors", []))
    cleaned["cpes"] = _clean_cpes(raw.get("cpes", []))

    cleaned["vulnerability_types"] = _clean_vulnerability_types(raw.get("vulnerability_types", []))
    cleaned["severity"] = _clean_severities(raw.get("severity", []))
    cleaned["risk_levels"] = _clean_severities(raw.get("risk_levels", []))
    cleaned["impacts"] = _clean_free_text(raw.get("impacts", []), min_chars=6, min_words=2)

    cleaned["remediations"] = _clean_free_text(raw.get("remediations", []), min_chars=5, min_words=2)
    cleaned["mitigations"] = _clean_free_text(raw.get("mitigations", []), min_chars=5, min_words=2)
    cleaned["patches"] = _clean_free_text(raw.get("patches", []), min_chars=5, min_words=2)

    cleaned["products"] = _clean_free_text(raw.get("products", []), min_chars=2, min_words=1)
    cleaned["vendors"] = _clean_free_text(raw.get("vendors", []), min_chars=2, min_words=1)
    cleaned["versions"] = _dedupe_ci_preserve_order(raw.get("versions", []))
    cleaned["affected_components"] = _clean_free_text(raw.get("affected_components", []), min_chars=2, min_words=1)
    cleaned["assets"] = _clean_free_text(raw.get("assets", []), min_chars=2, min_words=1)
    cleaned["endpoints"] = _clean_free_text(raw.get("endpoints", []), min_chars=2, min_words=1)
    cleaned["services"] = _clean_free_text(raw.get("services", []), min_chars=2, min_words=1)

    cleaned["ips"] = _clean_ips(raw.get("ips", []))
    cleaned["ip_ranges"] = _dedupe_ci_preserve_order(raw.get("ip_ranges", []))
    cleaned["urls"] = _clean_urls(raw.get("urls", []))
    cleaned["domains"] = _clean_domains(raw.get("domains", []))
    cleaned["emails"] = _dedupe_ci_preserve_order(raw.get("emails", []))
    cleaned["ports"] = _clean_ports(raw.get("ports", []))

    cleaned["file_paths"] = _dedupe_ci_preserve_order(raw.get("file_paths", []))
    cleaned["file_names"] = _clean_file_names(raw.get("file_names", []))
    cleaned["md5_hashes"] = _clean_hashes(raw.get("md5_hashes", []))
    cleaned["sha1_hashes"] = _clean_hashes(raw.get("sha1_hashes", []))
    cleaned["sha256_hashes"] = _clean_hashes(raw.get("sha256_hashes", []))
    cleaned["hashes"] = _clean_hashes(
        raw.get("hashes", [])
        + cleaned["md5_hashes"]
        + cleaned["sha1_hashes"]
        + cleaned["sha256_hashes"]
    )
    cleaned["malware"] = _clean_free_text(raw.get("malware", []), min_chars=2, min_words=1)

    cleaned["attack_vectors"] = _clean_attack_vectors(raw.get("attack_vectors", []))
    cleaned["attack_techniques"] = _clean_free_text(raw.get("attack_techniques", []), min_chars=2, min_words=1)
    cleaned["mitre_techniques"] = _clean_mitre(raw.get("mitre_techniques", []))
    cleaned["threat_actors"] = _clean_free_text(raw.get("threat_actors", []), min_chars=2, min_words=1)
    cleaned["exploits"] = _clean_free_text(raw.get("exploits", []), min_chars=2, min_words=1)
    cleaned["exploit_available"] = _clean_booleanish(raw.get("exploit_available", []))

    cleaned["exploitability"] = _clean_free_text(raw.get("exploitability", []), min_chars=2, min_words=1)
    cleaned["confidentiality_impacts"] = _clean_free_text(raw.get("confidentiality_impacts", []), min_chars=2, min_words=1)
    cleaned["integrity_impacts"] = _clean_free_text(raw.get("integrity_impacts", []), min_chars=2, min_words=1)
    cleaned["availability_impacts"] = _clean_free_text(raw.get("availability_impacts", []), min_chars=2, min_words=1)

    return cleaned


def _decode_spans_from_labels(
    text: str,
    offsets: Sequence[Tuple[int, int]],
    label_ids: Sequence[int],
) -> Dict[str, List[Tuple[int, int, str]]]:
    active: Optional[Tuple[str, int, int]] = None
    spans_by_type: Dict[str, List[Tuple[int, int, str]]] = {}

    def flush() -> None:
        nonlocal active

        if active is None:
            return

        entity_type, start, end = active
        surface = text[start:end].strip()

        if entity_type and surface:
            spans_by_type.setdefault(entity_type, []).append((start, end, surface))

        active = None

    for label_id, offset in zip(label_ids, offsets):
        start, end = offset

        if start is None or end is None:
            continue

        if start == end or start >= len(text):
            continue

        name = ID2LABEL.get(int(label_id), "O")

        if name == "O":
            flush()
            continue

        if name.startswith("B-"):
            flush()
            entity_type = name[2:]
            active = (entity_type, start, end)
            continue

        if name.startswith("I-"):
            entity_type = name[2:]

            if active is None or active[0] != entity_type:
                flush()
                active = (entity_type, start, end)
            else:
                _, old_start, _ = active
                active = (entity_type, old_start, end)
            continue

        flush()

    flush()
    return spans_by_type


def _sliding_windows(
    tokenizer: PreTrainedTokenizerBase,
    text: str,
    max_length: int,
    stride: int,
) -> Tuple[Dict[str, Any], Any]:
    enc = tokenizer(
        text,
        truncation=True,
        max_length=max_length,
        stride=stride,
        return_overflowing_tokens=True,
        return_offsets_mapping=True,
        padding=True,
        return_tensors="pt",
    )

    offsets_batches = enc.pop("offset_mapping")
    enc.pop("overflow_to_sample_mapping", None)

    return enc, offsets_batches


def predict_entities(
    model: Any,
    tokenizer: PreTrainedTokenizerBase,
    text: str,
    max_length: int = 512,
    stride: int = 64,
    device: Optional[Any] = None,
    min_entity_confidence: float = MIN_ENTITY_CONFIDENCE_DEFAULT,
) -> Dict[str, List[Tuple[int, int, str]]]:
    if torch is None:
        raise RuntimeError("PyTorch is not installed. Install requirements.txt or use --mode regex/auto.")

    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model.to(device)
    model.eval()

    text = normalize_report_text(text)
    enc, offsets_batches = _sliding_windows(tokenizer, text, max_length, stride)

    merged: Dict[str, List[Tuple[int, int, str]]] = {}

    input_ids = enc["input_ids"]
    attention_mask = enc["attention_mask"]
    o_id = LABEL2ID.get("O", 0)

    for row in range(input_ids.shape[0]):
        batch = {
            "input_ids": input_ids[row: row + 1].to(device),
            "attention_mask": attention_mask[row: row + 1].to(device),
        }

        token_type_ids = enc.get("token_type_ids")
        if token_type_ids is not None:
            batch["token_type_ids"] = token_type_ids[row: row + 1].to(device)

        with torch.no_grad():
            logits = model(**batch).logits

        probs = torch.softmax(logits, dim=-1)
        conf_values, pred_tensor = torch.max(probs, dim=-1)

        pred_ids_raw = pred_tensor[0].tolist()
        conf_list = conf_values[0].tolist()

        pred_ids = [
            int(label_id) if float(conf) >= min_entity_confidence else o_id
            for label_id, conf in zip(pred_ids_raw, conf_list)
        ]

        offsets = [tuple(int(x) for x in o) for o in offsets_batches[row].tolist()]
        decoded = _decode_spans_from_labels(text, offsets, pred_ids)

        for entity_type, values in decoded.items():
            merged.setdefault(entity_type, []).extend(values)

    deduped: Dict[str, List[Tuple[int, int, str]]] = {}

    for entity_type, items in merged.items():
        seen: set[Tuple[int, int, str]] = set()
        out: List[Tuple[int, int, str]] = []

        for item in sorted(items, key=lambda x: (x[0], x[1], x[2].casefold())):
            key = (item[0], item[1], item[2].casefold())

            if key not in seen:
                seen.add(key)
                out.append(item)

        deduped[entity_type] = out

    return deduped


def structured_hybrid_output(
    ner_spans: Dict[str, List[Tuple[int, int, str]]],
    regex_hits: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    raw = empty_structured_output()

    for entity_type, spans in ner_spans.items():
        output_key = output_key_for_entity(entity_type)

        if output_key not in raw:
            raw[output_key] = []

        for _, _, surface in spans:
            raw[output_key].append(surface.strip())

    merge_dict_lists(raw, regex_hits)

    return _clean_structured_output(raw)


def _model_dir_has_local_model(model_dir: Path) -> bool:
    if not model_dir.is_dir():
        return False

    if not all((model_dir / name).is_file() for name in MODEL_REQUIRED_FILES):
        return False

    has_weights = any(
        (model_dir / name).is_file()
        for name in ("model.safetensors", "pytorch_model.bin", "tf_model.h5", "flax_model.msgpack")
    )

    has_tokenizer = any(
        (model_dir / name).is_file()
        for name in ("tokenizer.json", "vocab.txt", "merges.txt", "spiece.model")
    )

    return has_weights and has_tokenizer


_MODEL_CACHE: Dict[str, Tuple[Any, Any]] = {}


def _load_model(model_dir: Path) -> Tuple[Any, Any]:
    if AutoTokenizer is None or AutoModelForTokenClassification is None or torch is None:
        raise RuntimeError(
            "ML dependencies are missing. Run: pip install -r requirements.txt, or use --mode regex/auto."
        )

    if not _model_dir_has_local_model(model_dir):
        raise FileNotFoundError(
            f"Model directory is missing or incomplete: {model_dir}. Train first or pass --mode regex/auto."
        )

    cache_key = str(model_dir.resolve())

    if cache_key in _MODEL_CACHE:
        return _MODEL_CACHE[cache_key]

    tokenizer = AutoTokenizer.from_pretrained(str(model_dir), use_fast=True)
    model = AutoModelForTokenClassification.from_pretrained(str(model_dir))

    _MODEL_CACHE[cache_key] = (model, tokenizer)
    return model, tokenizer


def build_findings(structured: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create lightweight finding objects for dashboard/API usage.

    This is heuristic grouping. A later relation model can replace it.
    """
    finding: Dict[str, Any] = {}

    first_map = {
        "vulnerability_type": "vulnerability_types",
        "severity": "severity",
        "risk_level": "risk_levels",
        "impact": "impacts",
        "remediation": "remediations",
        "product": "products",
        "version": "versions",
        "affected_component": "affected_components",
        "asset": "assets",
        "endpoint": "endpoints",
        "attack_vector": "attack_vectors",
    }

    for output_field, source_key in first_map.items():
        values = structured.get(source_key, [])
        if values:
            finding[output_field] = values[0]

    list_map = {
        "cve_ids": "cve_ids",
        "cwe_ids": "cwe_ids",
        "cvss_scores": "cvss_scores",
        "cvss_vectors": "cvss_vectors",
        "urls": "urls",
        "domains": "domains",
        "ips": "ips",
        "ports": "ports",
        "mitre_techniques": "mitre_techniques",
        "exploits": "exploits",
    }

    for output_field, source_key in list_map.items():
        values = structured.get(source_key, [])
        if values:
            finding[output_field] = values

    if not finding:
        return []

    return [finding]


def _contextual_rule_enrichment(text: str) -> Dict[str, List[str]]:
    """Extract contextual CTI fields that are hard for simple regex."""
    hits = empty_structured_output()

    patterns: Dict[str, List[str]] = {
        "remediations": [
            r"\b(?:remediation|recommended remediation|required remediation)\s*:\s*([^.;\n]+)",
            r"\b(?:recommended remediation|remediation)\s+is\s+to\s+([^.;\n]+)",
            r"\brecommended remediation\s*:\s*([^.;\n]+)",
            r"\bapply\s+(?:the\s+)?vendor\s+patch\b",
            r"\binstall\s+(?:the\s+)?vendor\s+patch\b",
            r"\buse\s+parameterized\s+queries\b",
            r"\bencode\s+output\s+and\s+sanitize\s+user\s+input\b",
            r"\bblock\s+internal\s+metadata\s+endpoints\b",
            r"\bdisable\s+external\s+entity\s+processing\b",
            r"\bfix\s+authentication\s+flow\s+validation\b",
            r"\bcanonicalize\s+paths\s+and\s+enforce\s+safe\s+directories\b",
            r"\bavoid\s+shell\s+execution\s+and\s+validate\s+command\s+arguments\b",
            r"\bvalidate\s+file\s+type\s+and\s+store\s+uploads\s+outside\s+the\s+web\s+root\b",
        ],
        "mitigations": [
            r"\b(?:mitigation|recommended mitigation)\s*:\s*([^.;\n]+)",
            r"\buse\s+parameterized\s+queries\b",
            r"\bencode\s+output\s+and\s+sanitize\s+user\s+input\b",
            r"\bblock\s+internal\s+metadata\s+endpoints\b",
            r"\bdisable\s+external\s+entity\s+processing\b",
            r"\bfix\s+authentication\s+flow\s+validation\b",
            r"\bcanonicalize\s+paths\s+and\s+enforce\s+safe\s+directories\b",
            r"\bavoid\s+shell\s+execution\s+and\s+validate\s+command\s+arguments\b",
            r"\bvalidate\s+file\s+type\s+and\s+store\s+uploads\s+outside\s+the\s+web\s+root\b",
        ],
        "patches": [
            r"\b(?:patch|required patch)\s*:\s*([^.;\n]+)",
            r"\bapply\s+vendor\s+patch\b",
            r"\bupgrade\s+[A-Za-z0-9 ._-]+?\s+to\s+a\s+fixed\s+version\b",
        ],
        "impacts": [
            r"\bimpact\s*:\s*([^.;\n]+)",
            r"\bimpact\s+is\s+to\s+([^.;\n]+)",
            r"\ballows?\s+attackers?\s+to\s+([^.;\n]+)",
            r"\bmay\s+([^.;\n]+)",
            r"\ballowed\s+a\s+([^.;\n]+)",
        ],
        "affected_components": [
            r"\baffected\s+component\s+(?:is\s+)?([^.;,\n]+)",
            r"\baffected\s+component\s*:\s*([^.;,\n]+)",
            r"\bin\s+the\s+([A-Za-z0-9 _/-]+?\s+(?:endpoint|parser|feature|parameter|api|panel|console))\b",
            r"\bdetected\s+in\s+the\s+([A-Za-z0-9 _/-]+?\s+(?:parser|endpoint|feature|api|panel|console))\b",
        ],
        "assets": [
            r"\bon\s+asset\s+([A-Za-z0-9_.:-]+)",
            r"\basset\s+([A-Za-z0-9_.:-]+)",
            r"\bhost\s+([A-Za-z0-9_.:-]+)",
            r"\bserver\s+([A-Za-z0-9_.:-]+)",
        ],
        "attack_vectors": [
            r"\battack\s+vector\s*:\s*(Network|Adjacent Network|Local|Physical)\b",
            r"\battack\s+vector\s+(Network|Adjacent Network|Local|Physical)\b",
            r"\bvector\s+(Network|Adjacent Network|Local|Physical)\b",
        ],
    }

    for key, regexes in patterns.items():
        for pattern in regexes:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)
                value = _strip_entity_value(value)

                if value:
                    hits[key].append(value)

    return _clean_structured_output(hits)


def run_inference_text(
    text: str,
    *,
    model_dir: Optional[Path] = None,
    max_length: int = 512,
    stride: int = 64,
    mode: str = "auto",
    include_meta: bool = True,
    include_findings: bool = True,
    min_model_f1: float = MIN_MODEL_F1_DEFAULT,
    min_entity_confidence: float = MIN_ENTITY_CONFIDENCE_DEFAULT,
    use_regex_enrichment: bool = True,
) -> Dict[str, Any]:
    text = normalize_report_text(text)

    if use_regex_enrichment:
        regex_hits = extract_all_structured(text, filter_domain_fp=True, strict_ports=True)
        contextual_hits = _contextual_rule_enrichment(text)
        merge_dict_lists(regex_hits, contextual_hits)
    else:
        regex_hits = empty_structured_output()

    warnings: List[str] = []
    ner: Dict[str, List[Tuple[int, int, str]]] = {}
    model_loaded = False

    if mode not in {"auto", "model", "regex"}:
        raise ValueError("mode must be one of: auto, model, regex")

    model_quality = _read_model_quality(model_dir)
    model_allowed_by_quality = _model_passes_quality_gate(
        model_quality,
        min_model_f1=min_model_f1,
    )

    if mode != "regex":
        try:
            if model_dir is None:
                raise FileNotFoundError("No model_dir provided.")

            if mode == "auto" and not model_allowed_by_quality:
                warnings.append(
                    "Model quality gate failed; ignored model predictions and used regex-only fallback. "
                    f"Required eval_f1 >= {min_model_f1}, found eval_f1={model_quality.get('eval_f1')}."
                )
            else:
                model, tokenizer = _load_model(model_dir)
                ner = predict_entities(
                    model,
                    tokenizer,
                    text,
                    max_length=max_length,
                    stride=stride,
                    min_entity_confidence=min_entity_confidence,
                )
                model_loaded = True

        except Exception as exc:
            if mode == "model":
                raise

            warnings.append(f"Model unavailable; used regex-only fallback: {exc}")

    structured: Dict[str, Any] = structured_hybrid_output(ner, regex_hits)

    if include_findings:
        structured["findings"] = build_findings(structured)

    if include_meta:
        structured["meta"] = {
            "engine": "nlp-hybrid-cti",
            "schema_version": "2.0",
            "mode": mode,
            "model_loaded": model_loaded,
            "model_dir": str(model_dir) if model_dir is not None else None,
            "fallback_used": not model_loaded,
            "regex_enrichment_used": use_regex_enrichment,
            "contextual_rule_enrichment_used": use_regex_enrichment,
            "safety_filter_used": True,
            "model_quality": model_quality,
            "model_quality_gate_passed": model_allowed_by_quality,
            "min_model_f1": min_model_f1,
            "min_entity_confidence": min_entity_confidence,
            "warnings": warnings,
        }

    return structured


def run_inference_file(
    model_dir: Optional[Path],
    input_path: Path,
    output_path: Path,
    max_length: int,
    stride: int,
    mode: str = "auto",
    include_meta: bool = True,
    include_findings: bool = True,
    min_model_f1: float = MIN_MODEL_F1_DEFAULT,
    min_entity_confidence: float = MIN_ENTITY_CONFIDENCE_DEFAULT,
    use_regex_enrichment: bool = True,
) -> Dict[str, Any]:
    if not input_path.is_file():
        raise FileNotFoundError(f"Report text file not found: {input_path}")

    text = input_path.read_text(encoding="utf-8", errors="replace")

    structured = run_inference_text(
        text,
        model_dir=model_dir,
        max_length=max_length,
        stride=stride,
        mode=mode,
        include_meta=include_meta,
        include_findings=include_findings,
        min_model_f1=min_model_f1,
        min_entity_confidence=min_entity_confidence,
        use_regex_enrichment=use_regex_enrichment,
    )

    write_json(output_path, structured)
    return structured


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Hybrid cyber CTI entity extraction inference.")

    p.add_argument("--model_dir", type=Path, default=Path("models/cyberbert-ner"))
    p.add_argument("--report_text_file", type=Path, required=True)
    p.add_argument("--output_json", type=Path, default=Path("outputs/prediction.json"))
    p.add_argument("--max_length", type=int, default=512)
    p.add_argument("--stride", type=int, default=64)

    p.add_argument(
        "--mode",
        choices=("auto", "model", "regex"),
        default="auto",
        help="auto=use model only if quality gate passes, model=strict ML inference, regex=no ML dependency.",
    )

    p.add_argument("--min_model_f1", type=float, default=MIN_MODEL_F1_DEFAULT)
    p.add_argument("--min_entity_confidence", type=float, default=MIN_ENTITY_CONFIDENCE_DEFAULT)
    p.add_argument("--no_regex_enrichment", action="store_true", help="Disable regex/contextual enrichment.")
    p.add_argument("--no_meta", action="store_true", help="Keep output without the meta object.")
    p.add_argument("--no_findings", action="store_true", help="Disable heuristic findings array.")

    return p.parse_args()


def main() -> None:
    args = parse_args()
    args.output_json.parent.mkdir(parents=True, exist_ok=True)

    result = run_inference_file(
        args.model_dir,
        args.report_text_file,
        args.output_json,
        args.max_length,
        args.stride,
        mode=args.mode,
        include_meta=not args.no_meta,
        include_findings=not args.no_findings,
        min_model_f1=args.min_model_f1,
        min_entity_confidence=args.min_entity_confidence,
        use_regex_enrichment=not args.no_regex_enrichment,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
