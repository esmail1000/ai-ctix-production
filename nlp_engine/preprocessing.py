"""Dataset construction: span alignment, BIO tagging, and Hugging Face datasets.

This version is built for a Cyber Threat Intelligence / Pentest Report NER model.
It supports two supervision sources:
1. Structured fields from processed_reports.json.
2. High-precision cybersecurity regex extractors for entities like CVE, CWE, IP,
   URL, hashes, ports, CVSS vectors, and MITRE ATT&CK technique IDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import (TYPE_CHECKING, Any, Dict, Iterable, List, MutableMapping,
                    Optional, Pattern, Sequence, Tuple)

if TYPE_CHECKING:
    from transformers import PreTrainedTokenizerBase
else:
    PreTrainedTokenizerBase = Any

from labels import IGNORE_INDEX, LABEL2ID, LABELS
from span_matching import find_cve_spans, find_phrase_spans
from text_loader import resolve_report_text
from utils import ensure_list_str, normalize_report_text, read_json, write_json

_TYPE_PRIORITY: Dict[str, int] = {
    "SHA256": 120,
    "SHA1": 119,
    "MD5": 118,
    "HASH": 117,
    "CVE_ID": 115,
    "CWE_ID": 114,
    "CVSS_VECTOR": 113,
    "CPE": 112,
    "URL": 110,
    "EMAIL": 108,
    "IP_RANGE": 106,
    "IP_ADDRESS": 105,
    "MITRE_TECHNIQUE": 102,
    "DOMAIN": 95,
    "PORT": 90,
    "CVSS_SCORE": 88,
    "VERSION": 70,
    "SEVERITY": 65,
    "RISK_LEVEL": 64,
    "PRODUCT": 60,
    "VENDOR": 59,
    "AFFECTED_COMPONENT": 58,
    "ASSET": 55,
    "ENDPOINT": 54,
    "SERVICE": 53,
    "VULN_TYPE": 50,
    "ATTACK_VECTOR": 45,
    "ATTACK_TECHNIQUE": 44,
    "THREAT_ACTOR": 43,
    "EXPLOIT": 42,
    "EXPLOIT_AVAILABLE": 41,
    "IMPACT": 30,
    "REMEDIATION": 25,
    "MITIGATION": 24,
    "PATCH": 23,
}


_FIELD_TO_ENTITY_TYPE: Dict[str, str] = {
    "vulnerabilities": "VULN_TYPE",
    "vulnerability": "VULN_TYPE",
    "vulnerability_type": "VULN_TYPE",
    "vulnerability_types": "VULN_TYPE",

    "cves": "CVE_ID",
    "cve": "CVE_ID",
    "cve_id": "CVE_ID",
    "cve_ids": "CVE_ID",

    "impact": "IMPACT",
    "impacts": "IMPACT",

    "severity": "SEVERITY",
    "risk_level": "SEVERITY",
    "risk_levels": "RISK_LEVEL",

    "cwe": "CWE_ID",
    "cwes": "CWE_ID",
    "cwe_id": "CWE_ID",
    "cwe_ids": "CWE_ID",

    "cvss": "CVSS_SCORE",
    "cvss_score": "CVSS_SCORE",
    "cvss_scores": "CVSS_SCORE",
    "cvss_vector": "CVSS_VECTOR",
    "cvss_vectors": "CVSS_VECTOR",

    "cpe": "CPE",
    "cpes": "CPE",

    "remediation": "REMEDIATION",
    "remediations": "REMEDIATION",
    "recommendation": "REMEDIATION",
    "recommendations": "REMEDIATION",

    "mitigation": "MITIGATION",
    "mitigations": "MITIGATION",
    "patch": "PATCH",
    "patches": "PATCH",

    "product": "PRODUCT",
    "products": "PRODUCT",
    "vendor": "VENDOR",
    "vendors": "VENDOR",
    "version": "VERSION",
    "versions": "VERSION",

    "affected_component": "AFFECTED_COMPONENT",
    "affected_components": "AFFECTED_COMPONENT",
    "component": "AFFECTED_COMPONENT",
    "components": "AFFECTED_COMPONENT",

    "asset": "ASSET",
    "assets": "ASSET",
    "endpoint": "ENDPOINT",
    "endpoints": "ENDPOINT",
    "service": "SERVICE",
    "services": "SERVICE",

    "ip": "IP_ADDRESS",
    "ips": "IP_ADDRESS",
    "ip_address": "IP_ADDRESS",
    "ip_addresses": "IP_ADDRESS",
    "ip_range": "IP_RANGE",
    "ip_ranges": "IP_RANGE",

    "url": "URL",
    "urls": "URL",
    "domain": "DOMAIN",
    "domains": "DOMAIN",
    "email": "EMAIL",
    "emails": "EMAIL",
    "port": "PORT",
    "ports": "PORT",

    "file_path": "FILE_PATH",
    "file_paths": "FILE_PATH",
    "file_name": "FILE_NAME",
    "file_names": "FILE_NAME",

    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "hash": "HASH",
    "hashes": "HASH",

    "malware": "MALWARE",

    "attack_vector": "ATTACK_VECTOR",
    "attack_vectors": "ATTACK_VECTOR",
    "attack_technique": "ATTACK_TECHNIQUE",
    "attack_techniques": "ATTACK_TECHNIQUE",
    "mitre_technique": "MITRE_TECHNIQUE",
    "mitre_techniques": "MITRE_TECHNIQUE",

    "threat_actor": "THREAT_ACTOR",
    "threat_actors": "THREAT_ACTOR",

    "exploit": "EXPLOIT",
    "exploits": "EXPLOIT",
    "exploit_available": "EXPLOIT_AVAILABLE",
    "exploitability": "EXPLOITABILITY",
}


@dataclass(frozen=True)
class Span:
    """Character span with entity type."""

    start: int
    end: int
    entity_type: str

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("Invalid span bounds")


@dataclass(frozen=True)
class RegexRule:
    """A high-precision regex rule for weak cybersecurity labels."""

    entity_type: str
    pattern: Pattern[str]
    group: int = 0


_REGEX_RULES: Tuple[RegexRule, ...] = (
    RegexRule("CVE_ID", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    RegexRule("CWE_ID", re.compile(r"\bCWE-\d{1,6}\b", re.IGNORECASE)),
    RegexRule("CVSS_VECTOR", re.compile(r"\bCVSS:[0-9]\.[0-9]/[A-Z]{1,3}:[A-Z0-9]+(?:/[A-Z]{1,3}:[A-Z0-9]+)+\b")),
    RegexRule("CPE", re.compile(r"\bcpe:2\.3:[aho]:[^\s,;\]\)\"']+", re.IGNORECASE)),

    RegexRule(
        "CVSS_SCORE",
        re.compile(
            r"\b(?:CVSS(?:\s*v?[0-9](?:\.[0-9])?)?|base)\s*(?:score|severity)?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
            re.IGNORECASE,
        ),
        group=1,
    ),

    RegexRule("URL", re.compile(r"\bhttps?://[^\s<>\]\)\"']+", re.IGNORECASE)),
    RegexRule("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),

    RegexRule("IP_RANGE", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-9]|[12]\d|3[0-2])\b")),
    RegexRule("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),

    RegexRule("SHA256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    RegexRule("SHA1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    RegexRule("MD5", re.compile(r"\b[a-fA-F0-9]{32}\b")),

    RegexRule("MITRE_TECHNIQUE", re.compile(r"\bT\d{4}(?:\.\d{3})?\b")),
    RegexRule("PORT", re.compile(r"\b(?:port|tcp|udp)\s*[:/#-]?\s*(\d{1,5})\b", re.IGNORECASE), group=1),
    RegexRule("VERSION", re.compile(r"\b(?:v(?:ersion)?\.?\s*)\d+(?:\.\d+){1,4}[A-Za-z0-9._-]*\b", re.IGNORECASE)),

    RegexRule("SEVERITY", re.compile(r"\b(?:critical|high|medium|moderate|low|informational|info)\b", re.IGNORECASE)),
    RegexRule("EXPLOIT_AVAILABLE", re.compile(r"\b(?:public\s+exploit|exploit\s+available|known\s+exploited|weaponized)\b", re.IGNORECASE)),
)


_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")

_FALSE_DOMAIN_SUFFIXES = {
    "json",
    "yaml",
    "yml",
    "xml",
    "txt",
    "pdf",
    "doc",
    "docx",
    "log",
    "conf",
    "config",
    "local",
}


def _dedupe_spans(spans: List[Span]) -> List[Span]:
    seen: set[Tuple[int, int, str]] = set()
    out: List[Span] = []

    for sp in spans:
        key = (sp.start, sp.end, sp.entity_type)
        if key not in seen:
            seen.add(key)
            out.append(sp)

    return out


def _resolve_overlaps(spans: List[Span]) -> List[Span]:
    if not spans:
        return []

    chosen: List[Span] = []

    ordered = sorted(
        spans,
        key=lambda s: (
            -_TYPE_PRIORITY.get(s.entity_type, 1),
            -(s.end - s.start),
            s.start,
        ),
    )

    for sp in ordered:
        conflict = False

        for existing in chosen:
            if not (sp.end <= existing.start or sp.start >= existing.end):
                conflict = True
                break

        if not conflict:
            chosen.append(sp)

    chosen.sort(key=lambda s: (s.start, s.end))
    return chosen


def _count_spans_by_type(spans: Iterable[Span]) -> Dict[str, int]:
    counts: Dict[str, int] = {}

    for sp in spans:
        counts[sp.entity_type] = counts.get(sp.entity_type, 0) + 1

    return dict(sorted(counts.items()))


def _extract_match_span(match: re.Match[str], group: int = 0) -> Tuple[int, int]:
    try:
        return match.start(group), match.end(group)
    except IndexError:
        return match.start(), match.end()


def _valid_port(text: str) -> bool:
    try:
        n = int(text)
    except ValueError:
        return False

    return 1 <= n <= 65535


def _looks_like_domain(value: str) -> bool:
    lower = value.lower().strip(". ")

    if ".." in lower:
        return False

    suffix = lower.rsplit(".", 1)[-1]

    if suffix in _FALSE_DOMAIN_SUFFIXES:
        return False

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", lower):
        return False

    return True


def _inside_url_or_email(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 12):start].lower()
    after = text[end:min(len(text), end + 3)]

    if "http://" in before or "https://" in before:
        return True

    if "@" in text[max(0, start - 1):min(len(text), end + 1)]:
        return True

    if after.startswith("/"):
        return True

    return False


def extract_regex_spans(text: str) -> List[Span]:
    spans: List[Span] = []

    for rule in _REGEX_RULES:
        for match in rule.pattern.finditer(text):
            start, end = _extract_match_span(match, rule.group)

            if start < 0 or end <= start:
                continue

            value = text[start:end]

            if rule.entity_type == "PORT" and not _valid_port(value):
                continue

            spans.append(Span(start, end, rule.entity_type))

    for match in _DOMAIN_RE.finditer(text):
        start, end = match.start(), match.end()
        value = text[start:end]

        if _inside_url_or_email(text, start, end):
            continue

        if not _looks_like_domain(value):
            continue

        spans.append(Span(start, end, "DOMAIN"))

    return _dedupe_spans(spans)


def spans_to_char_label_ids(text: str, spans: Sequence[Span]) -> List[int]:
    n = len(text)
    char_ids = [LABEL2ID["O"]] * n
    resolved = _resolve_overlaps(list(spans))

    for sp in resolved:
        if sp.start >= n or sp.end > n:
            continue

        entity_type = sp.entity_type
        b_label = f"B-{entity_type}"
        i_label = f"I-{entity_type}"

        if b_label not in LABEL2ID or i_label not in LABEL2ID:
            continue

        char_ids[sp.start] = LABEL2ID[b_label]

        for i in range(sp.start + 1, sp.end):
            if i < n:
                char_ids[i] = LABEL2ID[i_label]

    return char_ids


def _add_phrase_spans(
    spans: List[Span],
    text: str,
    values: Iterable[str],
    entity_type: str,
    *,
    fuzzy_threshold: float,
) -> None:
    for value in values:
        if not value or len(value.strip()) < 2:
            continue

        if entity_type == "CVE_ID":
            matches = find_cve_spans(text, value)
        else:
            matches = find_phrase_spans(
                text,
                value,
                fuzzy_threshold=fuzzy_threshold,
                severity=entity_type in {"SEVERITY", "RISK_LEVEL"},
            )

        for start, end in matches:
            spans.append(Span(start, end, entity_type))


def extract_spans_from_record(
    record: Dict[str, Any],
    *,
    fuzzy_threshold: float = 0.88,
    use_regex: bool = True,
) -> List[Span]:
    text = record.get("_working_text", "")
    spans: List[Span] = []

    for field_name, entity_type in _FIELD_TO_ENTITY_TYPE.items():
        values = ensure_list_str(record.get(field_name))

        if not values:
            continue

        _add_phrase_spans(
            spans,
            text,
            values,
            entity_type,
            fuzzy_threshold=fuzzy_threshold,
        )

    if use_regex:
        spans.extend(extract_regex_spans(text))

    return _resolve_overlaps(_dedupe_spans(spans))


def count_structured_labels(record: Dict[str, Any]) -> int:
    total = 0

    for field_name in _FIELD_TO_ENTITY_TYPE:
        total += len(ensure_list_str(record.get(field_name)))

    return total


def align_token_labels(
    offsets: List[Optional[Tuple[int, int]]],
    char_label_ids: List[int],
    text_len: int,
) -> List[int]:
    labels: List[int] = []
    previous_word_end: Optional[int] = None

    for offset in offsets:
        if offset is None:
            labels.append(IGNORE_INDEX)
            continue

        start, end = offset

        if start is None or end is None:
            labels.append(IGNORE_INDEX)
            continue

        if start == end:
            labels.append(IGNORE_INDEX)
            continue

        if start >= text_len:
            labels.append(IGNORE_INDEX)
            continue

        if previous_word_end is not None and start == previous_word_end:
            labels.append(IGNORE_INDEX)
            previous_word_end = end
            continue

        label_id = char_label_ids[start] if start < len(char_label_ids) else LABEL2ID["O"]
        labels.append(label_id)
        previous_word_end = end

    previous_non_ignore = IGNORE_INDEX

    for i, label_id in enumerate(labels):
        if label_id == IGNORE_INDEX:
            continue

        label_name = LABELS[label_id] if 0 <= label_id < len(LABELS) else "O"

        if label_name.startswith("I-"):
            ok = False

            if previous_non_ignore != IGNORE_INDEX:
                previous_name = LABELS[previous_non_ignore] if 0 <= previous_non_ignore < len(LABELS) else "O"

                if previous_name == f"B-{label_name[2:]}" or previous_name == label_name:
                    ok = True

            if not ok:
                begin_name = f"B-{label_name[2:]}"

                if begin_name in LABEL2ID:
                    labels[i] = LABEL2ID[begin_name]
                    label_id = labels[i]

        previous_non_ignore = label_id

    return labels


def expand_examples_to_token_rows(
    examples: List[Dict[str, Any]],
    tokenizer: PreTrainedTokenizerBase,
    max_length: int,
    stride: int,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for example in examples:
        text = example["tokens_text"]
        char_ids = example["char_label_ids"]
        text_len = example["text_length"]

        encoded = tokenizer(
            text,
            truncation=True,
            max_length=max_length,
            stride=stride,
            return_overflowing_tokens=True,
            return_offsets_mapping=True,
            padding=False,
        )

        n_parts = len(encoded["input_ids"])

        for window_index in range(n_parts):
            offsets = encoded["offset_mapping"][window_index]
            labels = align_token_labels(list(offsets), char_ids, text_len)

            rows.append(
                {
                    "input_ids": encoded["input_ids"][window_index],
                    "attention_mask": encoded["attention_mask"][window_index],
                    "labels": labels,
                    "id": f"{example['id']}::win{window_index}",
                }
            )

    return rows


def build_examples_from_processed_json(
    records: Sequence[MutableMapping[str, Any]],
    raw_text_dir: Optional[Path] = None,
    raw_pdf_dir: Optional[Path] = None,
    allow_synthetic_fallback: bool = False,
    fuzzy_threshold: float = 0.88,
    min_labels_matched: int = 1,
    use_regex: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    examples: List[Dict[str, Any]] = []

    stats: Dict[str, Any] = {
        "total_records": len(records),
        "used": 0,
        "skipped_no_text": [],
        "skipped_low_alignment": [],
        "by_source": {},
        "unmatched_labels": [],
        "span_counts_by_type": {},
        "use_regex": use_regex,
    }

    for rec in records:
        if not isinstance(rec, dict):
            continue

        text, source = resolve_report_text(
            rec,
            raw_text_dir=raw_text_dir,
            raw_pdf_dir=raw_pdf_dir,
            allow_synthetic_fallback=allow_synthetic_fallback,
        )

        text = normalize_report_text(text)
        rec_id = f"{rec.get('company', 'unknown')}::{rec.get('file', 'unknown')}"

        if not text:
            stats["skipped_no_text"].append(rec_id)
            continue

        stats["by_source"][source] = stats["by_source"].get(source, 0) + 1

        working = dict(rec)
        working["_working_text"] = text

        spans = extract_spans_from_record(
            working,
            fuzzy_threshold=fuzzy_threshold,
            use_regex=use_regex,
        )

        char_ids = spans_to_char_label_ids(text, spans)

        structured_label_count = count_structured_labels(rec)

        if structured_label_count > 0 and len(spans) < min_labels_matched:
            stats["skipped_low_alignment"].append(rec_id)
            stats["unmatched_labels"].append(
                {
                    "id": rec_id,
                    "source": source,
                    "spans_found": len(spans),
                    "labels_in_json": structured_label_count,
                }
            )
            continue

        for entity_type, count in _count_spans_by_type(spans).items():
            stats["span_counts_by_type"][entity_type] = stats["span_counts_by_type"].get(entity_type, 0) + count

        examples.append(
            {
                "tokens_text": text,
                "char_label_ids": char_ids,
                "text_length": len(text),
                "id": rec_id,
                "text_source": source,
                "span_count": len(spans),
                "span_counts_by_type": _count_spans_by_type(spans),
            }
        )

        stats["used"] += 1

    stats["examples_built"] = len(examples)
    stats["span_counts_by_type"] = dict(sorted(stats["span_counts_by_type"].items()))

    return examples, stats


def train_val_test_split(
    examples: List[Dict[str, Any]],
    seed: int,
    ratios: Tuple[float, float, float] = (0.8, 0.1, 0.1),
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    if abs(sum(ratios) - 1.0) > 1e-6:
        raise ValueError("Split ratios must sum to 1.0")

    rng = __import__("random").Random(seed)
    indexes = list(range(len(examples)))
    rng.shuffle(indexes)

    n = len(indexes)
    n_train = int(n * ratios[0])
    n_val = int(n * ratios[1])

    train_indexes = indexes[:n_train]
    val_indexes = indexes[n_train:n_train + n_val]
    test_indexes = indexes[n_train + n_val:]

    def pick(selected_indexes: List[int]) -> List[Dict[str, Any]]:
        return [examples[i] for i in selected_indexes]

    return pick(train_indexes), pick(val_indexes), pick(test_indexes)


def build_dataset_dict(
    train: List[Dict[str, Any]],
    val: List[Dict[str, Any]],
    test: List[Dict[str, Any]],
    tokenizer: PreTrainedTokenizerBase,
    max_length: int,
    stride: int = 64,
) -> Any:
    try:
        from datasets import Dataset, DatasetDict
    except ImportError as exc:
        raise ImportError(
            "Dataset building requires Hugging Face datasets. Install with: pip install -r requirements.txt"
        ) from exc

    train_rows = expand_examples_to_token_rows(train, tokenizer, max_length, stride)
    val_rows = expand_examples_to_token_rows(val, tokenizer, max_length, stride)
    test_rows = expand_examples_to_token_rows(test, tokenizer, max_length, stride)

    return DatasetDict(
        {
            "train": Dataset.from_list(train_rows),
            "validation": Dataset.from_list(val_rows),
            "test": Dataset.from_list(test_rows),
        }
    )


def load_processed_reports(
    json_path: Path,
    raw_text_dir: Optional[Path] = None,
    raw_pdf_dir: Optional[Path] = None,
    allow_synthetic_fallback: bool = False,
    fuzzy_threshold: float = 0.88,
    coverage_report_path: Optional[Path] = None,
    use_regex: bool = True,
) -> List[Dict[str, Any]]:
    data = read_json(json_path)

    if not isinstance(data, list):
        raise ValueError("processed_reports.json must contain a JSON array")

    examples, stats = build_examples_from_processed_json(
        data,
        raw_text_dir=raw_text_dir,
        raw_pdf_dir=raw_pdf_dir,
        allow_synthetic_fallback=allow_synthetic_fallback,
        fuzzy_threshold=fuzzy_threshold,
        use_regex=use_regex,
    )

    if coverage_report_path is not None:
        write_json(coverage_report_path, stats)

    return examples