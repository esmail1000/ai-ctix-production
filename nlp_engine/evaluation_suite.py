"""Evaluate CTI extraction quality across regex-only / auto-hybrid / model-only modes.

This script runs a deterministic evaluation suite against inference.py
and writes a JSON report with per-field and global precision/recall/F1.

Important:
- regex_only  = deterministic regex/rule extraction only.
- auto_hybrid = model predictions when quality gate passes + regex enrichment.
- model_only  = trained model predictions only, without regex enrichment.

Example:
    python evaluation_suite.py --model_dir models/cyberbert-ner-v3-aug
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple

from inference import run_inference_text

EVALUATED_FIELDS: Tuple[str, ...] = (
    "cve_ids",
    "cwe_ids",
    "cvss_scores",
    "cvss_vectors",
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
    "urls",
    "domains",
    "ips",
    "ip_ranges",
    "emails",
    "ports",
    "attack_vectors",
    "attack_techniques",
    "mitre_techniques",
    "exploits",
    "exploit_available",
)


EVALUATION_PLANS: Tuple[Dict[str, Any], ...] = (
    {
        "name": "regex_only",
        "mode": "regex",
        "use_regex_enrichment": True,
        "description": "Regex/rule extraction only.",
    },
    {
        "name": "auto_hybrid",
        "mode": "auto",
        "use_regex_enrichment": True,
        "description": "Model if quality gate passes plus regex enrichment.",
    },
    {
        "name": "model_only",
        "mode": "model",
        "use_regex_enrichment": False,
        "description": "Model predictions only without regex enrichment.",
    },
)


CASES: List[Dict[str, Any]] = ( 
    {
        "id": "rce_struts_basic",
        "text": (
            "Critical RCE in Apache Struts version 2.5.10 CVE-2023-12345 CWE-94 "
            "CVSS score: 9.8 at https://app.testcorp.com:8443/login. "
            "Apply vendor patch."
        ),
        "expected": {
            "cve_ids": ["CVE-2023-12345"],
            "cwe_ids": ["CWE-94"],
            "cvss_scores": ["9.8"],
            "vulnerability_types": ["Remote Code Execution"],
            "severity": ["Critical"],
            "impacts": ["Remote Code Execution"],
            "remediations": ["Apply vendor patch"],
            "mitigations": ["Apply vendor patch"],
            "patches": ["Apply vendor patch"],
            "products": ["Apache Struts"],
            "versions": ["2.5.10"],
            "urls": ["https://app.testcorp.com:8443/login"],
            "domains": ["app.testcorp.com"],
            "ports": ["8443"],
        },
    },
    {
        "id": "sql_injection_gitlab",
        "text": (
            "High severity SQL Injection in GitLab CE 16.1 affects "
            "https://api.northwind.example:8080/api/v1/search. "
            "CVE-2025-12001 CWE-89 CVSS score: 8.1. "
            "Use parameterized queries."
        ),
        "expected": {
            "cve_ids": ["CVE-2025-12001"],
            "cwe_ids": ["CWE-89"],
            "cvss_scores": ["8.1"],
            "vulnerability_types": ["SQL Injection"],
            "severity": ["High"],
            "remediations": ["Use parameterized queries"],
            "mitigations": ["Use parameterized queries"],
            "products": ["GitLab"],
            "versions": ["16.1"],
            "urls": ["https://api.northwind.example:8080/api/v1/search"],
            "domains": ["api.northwind.example"],
            "ports": ["8080"],
        },
    },
    {
        "id": "xss_portal",
        "text": (
            "The customer portal contains High Cross-Site Scripting on "
            "https://portal.bluebank.example/profile. CVE-2024-22001 CWE-79 "
            "CVSS score: 8.1. The issue may steal user session cookies. "
            "Encode output and sanitize user input."
        ),
        "expected": {
            "cve_ids": ["CVE-2024-22001"],
            "cwe_ids": ["CWE-79"],
            "cvss_scores": ["8.1"],
            "vulnerability_types": ["Cross-Site Scripting"],
            "severity": ["High"],
            "impacts": ["steal user session cookies"],
            "remediations": ["Encode output and sanitize user input"],
            "mitigations": ["Encode output and sanitize user input"],
            "urls": ["https://portal.bluebank.example/profile"],
            "domains": ["portal.bluebank.example"],
        },
    },
    {
        "id": "ssrf_internal",
        "text": (
            "High Server-Side Request Forgery was found in the image import feature. "
            "CVE-2025-13009 CWE-918 CVSS score: 8.1. "
            "The vulnerable endpoint is https://app.acme-corp.com/api/v1/import "
            "on IP 10.0.0.5 port 443. Block internal metadata endpoints."
        ),
        "expected": {
            "cve_ids": ["CVE-2025-13009"],
            "cwe_ids": ["CWE-918"],
            "cvss_scores": ["8.1"],
            "vulnerability_types": ["Server-Side Request Forgery"],
            "severity": ["High"],
            "remediations": ["Block internal metadata endpoints"],
            "mitigations": ["Block internal metadata endpoints"],
            "urls": ["https://app.acme-corp.com/api/v1/import"],
            "domains": ["app.acme-corp.com"],
            "ips": ["10.0.0.5"],
            "ports": ["443"],
        },
    },
    {
        "id": "xxe_xml",
        "text": (
            "Medium XML External Entity vulnerability in Oracle WebLogic Server 12.2.1 "
            "was detected in the XML parser. CVE-2022-18888 CWE-611 CVSS score: 6.5. "
            "Disable external entity processing."
        ),
        "expected": {
            "cve_ids": ["CVE-2022-18888"],
            "cwe_ids": ["CWE-611"],
            "cvss_scores": ["6.5"],
            "vulnerability_types": ["XML External Entity"],
            "severity": ["Medium"],
            "remediations": ["Disable external entity processing"],
            "mitigations": ["Disable external entity processing"],
            "products": ["Oracle WebLogic Server"],
            "versions": ["12.2.1"],
            "affected_components": ["XML parser"],
        },
    },
    {
        "id": "auth_bypass_vpn",
        "text": (
            "Critical Authentication Bypass affects Ivanti Connect Secure version 22.3 "
            "at https://vpn.contoso.example:10443/admin. CVE-2025-19999 CWE-287 "
            "CVSS score: 9.8. Exploit Available. Fix authentication flow validation."
        ),
        "expected": {
            "cve_ids": ["CVE-2025-19999"],
            "cwe_ids": ["CWE-287"],
            "cvss_scores": ["9.8"],
            "vulnerability_types": ["Authentication Bypass"],
            "severity": ["Critical"],
            "remediations": ["Fix authentication flow validation"],
            "mitigations": ["Fix authentication flow validation"],
            "products": ["Ivanti Connect Secure"],
            "versions": ["22.3"],
            "urls": ["https://vpn.contoso.example:10443/admin"],
            "domains": ["vpn.contoso.example"],
            "ports": ["10443"],
            "exploits": ["Exploit Available"],
            "exploit_available": ["true"],
        },
    },
    {
        "id": "path_traversal",
        "text": (
            "High Path Traversal in the download endpoint allows attackers to read arbitrary files. "
            "CVE-2023-17777 CWE-22 CVSS score: 8.1. "
            "Affected URL https://api.northwind.example:8080/download. "
            "Canonicalize paths and enforce safe directories."
        ),
        "expected": {
            "cve_ids": ["CVE-2023-17777"],
            "cwe_ids": ["CWE-22"],
            "cvss_scores": ["8.1"],
            "vulnerability_types": ["Path Traversal"],
            "severity": ["High"],
            "impacts": ["read arbitrary files"],
            "remediations": ["Canonicalize paths and enforce safe directories"],
            "mitigations": ["Canonicalize paths and enforce safe directories"],
            "affected_components": ["download endpoint"],
            "urls": ["https://api.northwind.example:8080/download"],
            "domains": ["api.northwind.example"],
            "ports": ["8080"],
        },
    },
    {
        "id": "mitre_email",
        "text": (
            "Critical Command Injection in Jenkins 2.401 on asset ci-server-01. "
            "CVE-2024-15555 CWE-78 CVSS score: 9.8. "
            "Attack vector Network. MITRE technique T1059. "
            "Contact security@acme-corp.com. Avoid shell execution and validate command arguments."
        ),
        "expected": {
            "cve_ids": ["CVE-2024-15555"],
            "cwe_ids": ["CWE-78"],
            "cvss_scores": ["9.8"],
            "vulnerability_types": ["Command Injection"],
            "severity": ["Critical"],
            "remediations": ["Avoid shell execution and validate command arguments"],
            "mitigations": ["Avoid shell execution and validate command arguments"],
            "products": ["Jenkins"],
            "versions": ["2.401"],
            "assets": ["ci-server-01"],
            "emails": ["security@acme-corp.com"],
            "attack_vectors": ["Network"],
            "mitre_techniques": ["T1059"],
        },
    },
    {
        "id": "cpe_cvss_vector_full",
        "text": (
            "Critical Remote Code Execution affects Apache Struts 2.5.10. "
            "CVE-2025-30001 CWE-94 CVSS score: 9.8 "
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "
            "CPE cpe:2.3:a:apache:apache_struts:2.5.10:*:*:*:*:*:*:*. "
            "Apply vendor patch."
        ),
        "expected": {
            "cve_ids": ["CVE-2025-30001"],
            "cwe_ids": ["CWE-94"],
            "cvss_scores": ["9.8"],
            "cvss_vectors": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            "vulnerability_types": ["Remote Code Execution"],
            "severity": ["Critical"],
            "products": ["Apache Struts"],
            "versions": ["2.5.10"],
            "remediations": ["Apply vendor patch"],
            "mitigations": ["Apply vendor patch"],
        },
    },
    {
        "id": "file_hashes_malware",
        "text": (
            "High File Upload Vulnerability in the upload endpoint allowed a web shell. "
            "CVE-2024-44001 CWE-434 CVSS score: 8.1. "
            "Evidence file path /var/www/html/shell.php and file name shell.php. "
            "MD5 d41d8cd98f00b204e9800998ecf8427e "
            "SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
            "SHA256 e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855. "
            "Malware Cobalt Strike was observed. Validate file type and store uploads outside the web root."
        ),
        "expected": {
            "cve_ids": ["CVE-2024-44001"],
            "cwe_ids": ["CWE-434"],
            "cvss_scores": ["8.1"],
            "vulnerability_types": ["File Upload Vulnerability"],
            "severity": ["High"],
            "remediations": ["Validate file type and store uploads outside the web root"],
            "mitigations": ["Validate file type and store uploads outside the web root"],
        },
    },
)


def normalize_value(value: Any) -> str:
    return str(value).strip().casefold()


def to_set(values: Sequence[Any]) -> Set[str]:
    return {normalize_value(v) for v in values if str(v).strip()}


def score_field(expected: Sequence[Any], predicted: Sequence[Any]) -> Dict[str, Any]:
    exp = to_set(expected)
    pred = to_set(predicted)

    tp = len(exp & pred)
    fp = len(pred - exp)
    fn = len(exp - pred)

    precision = tp / (tp + fp) if tp + fp else 1.0 if not exp else 0.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "expected": sorted(exp),
        "predicted": sorted(pred),
        "missing": sorted(exp - pred),
        "extra": sorted(pred - exp),
    }


def aggregate_scores(field_scores: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    tp = sum(int(s["tp"]) for s in field_scores)
    fp = sum(int(s["fp"]) for s in field_scores)
    fn = sum(int(s["fn"]) for s in field_scores)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def score_case(expected: Dict[str, Any], prediction: Dict[str, Any]) -> Dict[str, Any]:
    field_scores: Dict[str, Any] = {}

    for field in EVALUATED_FIELDS:
        exp_values = expected.get(field, [])
        pred_values = prediction.get(field, []) if isinstance(prediction, dict) else []
        field_scores[field] = score_field(exp_values, pred_values)

    return {
        "global": aggregate_scores(list(field_scores.values())),
        "fields": field_scores,
    }


def evaluate_plan(
    cases: Sequence[Dict[str, Any]],
    *,
    plan: Dict[str, Any],
    model_dir: Path,
    min_model_f1: float,
    min_entity_confidence: float,
    include_predictions: bool,
) -> Dict[str, Any]:
    case_results: List[Dict[str, Any]] = []
    all_field_scores: List[Dict[str, Any]] = []
    per_field_bucket: Dict[str, List[Dict[str, Any]]] = {field: [] for field in EVALUATED_FIELDS}

    for case in cases:
        try:
            result = run_inference_text(
                case["text"],
                model_dir=model_dir,
                mode=plan["mode"],
                min_model_f1=min_model_f1,
                min_entity_confidence=min_entity_confidence,
                use_regex_enrichment=bool(plan["use_regex_enrichment"]),
            )
            error = None
        except Exception as exc:
            result = {}
            error = str(exc)

        expected = case.get("expected", {})
        scored = score_case(expected, result)

        for field_score in scored["fields"].values():
            all_field_scores.append(field_score)

        for field in EVALUATED_FIELDS:
            per_field_bucket[field].append(scored["fields"][field])

        case_result: Dict[str, Any] = {
            "id": case["id"],
            "error": error,
            "meta": result.get("meta", {}) if isinstance(result, dict) else {},
            "global": scored["global"],
            "fields": scored["fields"],
        }

        if include_predictions:
            case_result["expected"] = {
                field: expected.get(field, [])
                for field in EVALUATED_FIELDS
                if expected.get(field, [])
            }
            case_result["prediction"] = {
                field: result.get(field, [])
                for field in EVALUATED_FIELDS
                if isinstance(result, dict) and result.get(field, [])
            }

        case_results.append(case_result)

    per_field = {
        field: aggregate_scores(scores)
        for field, scores in per_field_bucket.items()
    }

    return {
        "name": plan["name"],
        "mode": plan["mode"],
        "use_regex_enrichment": bool(plan["use_regex_enrichment"]),
        "description": plan["description"],
        "global": aggregate_scores(all_field_scores),
        "per_field": per_field,
        "cases": case_results,
    }


def evaluate_all(
    model_dir: Path,
    output_json: Path,
    min_model_f1: float,
    min_entity_confidence: float,
    include_predictions: bool,
    skip_model_only: bool,
) -> Dict[str, Any]:
    plans = [
        plan
        for plan in EVALUATION_PLANS
        if not (skip_model_only and plan["name"] == "model_only")
    ]

    report: Dict[str, Any] = {
        "model_dir": str(model_dir),
        "case_count": len(CASES),
        "fields": list(EVALUATED_FIELDS),
        "min_model_f1": min_model_f1,
        "min_entity_confidence": min_entity_confidence,
        "plans": plans,
        "results": {},
    }

    for plan in plans:
        report["results"][plan["name"]] = evaluate_plan(
            CASES,
            plan=plan,
            model_dir=model_dir,
            min_model_f1=min_model_f1,
            min_entity_confidence=min_entity_confidence,
            include_predictions=include_predictions,
        )

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return report


def best_mode_name(report: Dict[str, Any]) -> str:
    results = report.get("results", {})
    if not results:
        return "none"

    return max(
        results.keys(),
        key=lambda name: float(results[name]["global"].get("f1", 0.0)),
    )


def print_summary(report: Dict[str, Any]) -> None:
    print("Evaluation complete.")
    print(f"Model: {report['model_dir']}")
    print(f"Cases: {report['case_count']}")
    print(f"Fields: {len(report['fields'])}")
    print()

    for name, result in report["results"].items():
        g = result["global"]
        print(
            f"{name:>11} | "
            f"P={g['precision']:.3f} "
            f"R={g['recall']:.3f} "
            f"F1={g['f1']:.3f} "
            f"TP={int(g['tp'])} FP={int(g['fp'])} FN={int(g['fn'])}"
        )

    print()
    print(f"Best mode: {best_mode_name(report)}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate CTI extraction outputs.")

    p.add_argument("--model_dir", type=Path, default=Path("models/cyberbert-ner-v3-aug"))
    p.add_argument("--output_json", type=Path, default=Path("outputs/evaluation_report.json"))
    p.add_argument("--min_model_f1", type=float, default=0.30)
    p.add_argument("--min_entity_confidence", type=float, default=0.75)

    p.add_argument(
        "--no_predictions",
        action="store_true",
        help="Do not include expected/predicted values in the JSON report.",
    )
    p.add_argument(
        "--skip_model_only",
        action="store_true",
        help="Skip strict model-only evaluation.",
    )

    return p.parse_args()


def main() -> None:
    args = parse_args()

    report = evaluate_all(
        model_dir=args.model_dir,
        output_json=args.output_json,
        min_model_f1=args.min_model_f1,
        min_entity_confidence=args.min_entity_confidence,
        include_predictions=not args.no_predictions,
        skip_model_only=args.skip_model_only,
    )

    print_summary(report)
    print(f"\nReport saved to: {args.output_json}")


if __name__ == "__main__":
    main()