"""Build an augmented CTI / pentest NER dataset.

This script expands the small demo processed_reports.json into a larger,
deterministic cybersecurity training dataset compatible with preprocessing.py
and train.py.

Output example:
    data/processed/processed_reports_augmented.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

SEVERITY_TO_CVSS = {
    "Critical": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "High": ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Medium": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L"),
    "Low": ("3.1", "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
}

VULNERABILITY_PROFILES: List[Dict[str, Any]] = [
    {
        "vuln": "SQL Injection",
        "cwe": "CWE-89",
        "severity": "Critical",
        "impact": "dump database records",
        "remediation": "Use parameterized queries",
        "mitigation": "Add input validation and web application firewall rules",
        "attack_technique": "Exploit Public-Facing Application",
        "mitre": "T1190",
        "attack_vector": "Network",
        "component": "login endpoint",
    },
    {
        "vuln": "NoSQL Injection",
        "cwe": "CWE-943",
        "severity": "High",
        "impact": "bypass authentication controls",
        "remediation": "Validate JSON query operators",
        "mitigation": "Restrict unsafe database operators",
        "attack_technique": "Exploit Public-Facing Application",
        "mitre": "T1190",
        "attack_vector": "Network",
        "component": "search API",
    },
    {
        "vuln": "Cross-Site Scripting",
        "cwe": "CWE-79",
        "severity": "High",
        "impact": "steal user session cookies",
        "remediation": "Encode output and sanitize user input",
        "mitigation": "Enable Content Security Policy",
        "attack_technique": "User Execution",
        "mitre": "T1204",
        "attack_vector": "Adjacent Network",
        "component": "customer portal",
    },
    {
        "vuln": "Remote Code Execution",
        "cwe": "CWE-94",
        "severity": "Critical",
        "impact": "execute arbitrary commands",
        "remediation": "Apply vendor patch",
        "mitigation": "Restrict external access to the vulnerable service",
        "attack_technique": "Exploit Public-Facing Application",
        "mitre": "T1190",
        "attack_vector": "Network",
        "component": "API service",
    },
    {
        "vuln": "Command Injection",
        "cwe": "CWE-78",
        "severity": "Critical",
        "impact": "execute system commands",
        "remediation": "Avoid shell execution and validate command arguments",
        "mitigation": "Run the service with least privilege",
        "attack_technique": "Command and Scripting Interpreter",
        "mitre": "T1059",
        "attack_vector": "Network",
        "component": "diagnostics endpoint",
    },
    {
        "vuln": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "High",
        "impact": "access internal services",
        "remediation": "Block internal metadata endpoints",
        "mitigation": "Enforce outbound allowlists",
        "attack_technique": "Exploit Public-Facing Application",
        "mitre": "T1190",
        "attack_vector": "Network",
        "component": "image import feature",
    },
    {
        "vuln": "XML External Entity",
        "cwe": "CWE-611",
        "severity": "Medium",
        "impact": "read local files",
        "remediation": "Disable external entity processing",
        "mitigation": "Use a hardened XML parser configuration",
        "attack_technique": "Exfiltration Over Web Service",
        "mitre": "T1567",
        "attack_vector": "Network",
        "component": "XML parser",
    },
    {
        "vuln": "Path Traversal",
        "cwe": "CWE-22",
        "severity": "High",
        "impact": "read arbitrary files",
        "remediation": "Canonicalize paths and enforce safe directories",
        "mitigation": "Deny path traversal sequences at the gateway",
        "attack_technique": "Exfiltration Over Web Service",
        "mitre": "T1567",
        "attack_vector": "Network",
        "component": "download endpoint",
    },
    {
        "vuln": "Authentication Bypass",
        "cwe": "CWE-287",
        "severity": "Critical",
        "impact": "gain unauthorized access",
        "remediation": "Fix authentication flow validation",
        "mitigation": "Require multi-factor authentication for privileged users",
        "attack_technique": "Valid Accounts",
        "mitre": "T1078",
        "attack_vector": "Network",
        "component": "admin panel",
    },
    {
        "vuln": "Broken Access Control",
        "cwe": "CWE-284",
        "severity": "High",
        "impact": "modify another user's records",
        "remediation": "Enforce object-level authorization checks",
        "mitigation": "Audit access control decisions",
        "attack_technique": "Valid Accounts",
        "mitre": "T1078",
        "attack_vector": "Network",
        "component": "account management API",
    },
    {
        "vuln": "Insecure Deserialization",
        "cwe": "CWE-502",
        "severity": "Critical",
        "impact": "perform remote code execution",
        "remediation": "Avoid unsafe object deserialization",
        "mitigation": "Sign serialized objects and restrict accepted classes",
        "attack_technique": "Exploitation for Client Execution",
        "mitre": "T1203",
        "attack_vector": "Network",
        "component": "session handler",
    },
    {
        "vuln": "Open Redirect",
        "cwe": "CWE-601",
        "severity": "Low",
        "impact": "conduct phishing attacks",
        "remediation": "Validate redirect destinations",
        "mitigation": "Use a server-side redirect allowlist",
        "attack_technique": "Phishing",
        "mitre": "T1566",
        "attack_vector": "Network",
        "component": "redirect parameter",
    },
    {
        "vuln": "File Upload Vulnerability",
        "cwe": "CWE-434",
        "severity": "High",
        "impact": "upload a web shell",
        "remediation": "Validate file type and store uploads outside the web root",
        "mitigation": "Scan uploads and disable script execution",
        "attack_technique": "Ingress Tool Transfer",
        "mitre": "T1105",
        "attack_vector": "Network",
        "component": "upload endpoint",
    },
    {
        "vuln": "Privilege Escalation",
        "cwe": "CWE-269",
        "severity": "High",
        "impact": "gain administrative privileges",
        "remediation": "Correct insecure permission checks",
        "mitigation": "Run services with least privilege",
        "attack_technique": "Exploitation for Privilege Escalation",
        "mitre": "T1068",
        "attack_vector": "Local",
        "component": "worker process",
    },
    {
        "vuln": "Sensitive Data Exposure",
        "cwe": "CWE-200",
        "severity": "Medium",
        "impact": "expose sensitive customer data",
        "remediation": "Encrypt sensitive data at rest and in transit",
        "mitigation": "Mask sensitive fields in responses",
        "attack_technique": "Data from Information Repositories",
        "mitre": "T1213",
        "attack_vector": "Network",
        "component": "profile API",
    },
    {
        "vuln": "Security Misconfiguration",
        "cwe": "CWE-16",
        "severity": "Medium",
        "impact": "expose administrative interfaces",
        "remediation": "Disable debug mode and remove default credentials",
        "mitigation": "Harden deployment configuration",
        "attack_technique": "Exploit Public-Facing Application",
        "mitre": "T1190",
        "attack_vector": "Network",
        "component": "management console",
    },
]

PRODUCTS: List[Dict[str, str]] = [
    {"vendor": "Apache", "product": "Apache Struts", "version": "2.5.10", "service": "Tomcat"},
    {"vendor": "Microsoft", "product": "Exchange Server", "version": "2019", "service": "IIS"},
    {"vendor": "Atlassian", "product": "Confluence", "version": "7.13.0", "service": "Confluence"},
    {"vendor": "VMware", "product": "vCenter Server", "version": "7.0.3", "service": "vCenter"},
    {"vendor": "Cisco", "product": "Cisco ASA", "version": "9.16", "service": "VPN Gateway"},
    {"vendor": "Fortinet", "product": "FortiGate", "version": "7.2.1", "service": "SSL VPN"},
    {"vendor": "Ivanti", "product": "Ivanti Connect Secure", "version": "22.3", "service": "VPN Portal"},
    {"vendor": "Oracle", "product": "WebLogic Server", "version": "12.2.1", "service": "WebLogic"},
    {"vendor": "Jenkins", "product": "Jenkins", "version": "2.401", "service": "CI Server"},
    {"vendor": "GitLab", "product": "GitLab CE", "version": "16.1", "service": "Git Repository"},
]

TARGETS: List[Dict[str, str]] = [
    {
        "company": "AcmeCorp",
        "domain": "app.acme-corp.com",
        "ip": "10.0.0.5",
        "ip_range": "10.0.0.0/24",
        "email": "security@acme-corp.com",
        "asset": "web-prod-01",
        "port": "443",
    },
    {
        "company": "BlueBank",
        "domain": "portal.bluebank.example",
        "ip": "10.12.4.18",
        "ip_range": "10.12.4.0/24",
        "email": "soc@bluebank.example",
        "asset": "customer-portal-02",
        "port": "8443",
    },
    {
        "company": "Northwind",
        "domain": "api.northwind.example",
        "ip": "172.16.8.20",
        "ip_range": "172.16.8.0/24",
        "email": "security@northwind.example",
        "asset": "api-gateway-01",
        "port": "8080",
    },
    {
        "company": "Contoso",
        "domain": "vpn.contoso.example",
        "ip": "192.168.56.12",
        "ip_range": "192.168.56.0/24",
        "email": "incident@contoso.example",
        "asset": "vpn-edge-01",
        "port": "10443",
    },
]

PATHS = [
    "/login",
    "/api/v1/search",
    "/api/v1/upload",
    "/admin",
    "/download",
    "/redirect",
    "/oauth/callback",
    "/xml/import",
    "/debug/console",
    "/profile",
]

MALWARE_NAMES = ["TrickBot", "Emotet", "Cobalt Strike", "QakBot", "LockBit"]
FILE_PATHS = [
    "/var/log/app/error.log",
    "/opt/app/config.yaml",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\Windows\\Temp\\payload.exe",
    "/tmp/suspicious.sh",
]


def read_json(path: Path) -> Any:
    if not path.is_file():
        return []

    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def as_list(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]

    text = str(value).strip()
    return [text] if text else []


def normalize_original_record(row: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Keep original examples but normalize common fields."""
    report_text = str(row.get("report_text") or row.get("text") or "").strip()

    out = dict(row)
    out["company"] = str(out.get("company") or "OriginalDataset")
    out["file"] = str(out.get("file") or f"original_{index:04d}.txt")
    out["report_text"] = report_text

    out["severity"] = as_list(out.get("severity"))
    out["vulnerabilities"] = as_list(
        out.get("vulnerabilities")
        or out.get("vulnerability_types")
        or out.get("vulnerability")
    )
    out["cves"] = as_list(out.get("cves") or out.get("cve_ids") or out.get("cve"))
    out["impact"] = as_list(out.get("impact") or out.get("impacts"))

    return out


def stable_hash(text: str, length: int) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest[:length]


def cve_for(index: int) -> str:
    year = 2021 + (index % 5)
    number = 10000 + index
    return f"CVE-{year}-{number}"


def cpe_for(vendor: str, product: str, version: str) -> str:
    vendor_slug = re.sub(r"[^a-z0-9]+", "_", vendor.lower()).strip("_")
    product_slug = re.sub(r"[^a-z0-9]+", "_", product.lower()).strip("_")
    version_slug = re.sub(r"[^A-Za-z0-9._-]+", "_", version).strip("_")
    return f"cpe:2.3:a:{vendor_slug}:{product_slug}:{version_slug}:*:*:*:*:*:*:*"


def build_url(domain: str, port: str, path: str) -> str:
    if port in {"80", "443"}:
        return f"https://{domain}{path}"
    return f"https://{domain}:{port}{path}"


def choose_template(rng: random.Random) -> str:
    templates = [
        (
            "Finding {finding_id}: {severity} {vuln} was identified in {product} "
            "version {version} by vendor {vendor}. The affected component is {component} "
            "on asset {asset}, service {service}, endpoint {endpoint}. "
            "{cve} and {cwe} were observed. CVSS score: {cvss_score} {cvss_vector}. "
            "CPE {cpe}. The vulnerable URL is {url} on domain {domain}, IP {ip}, "
            "network {ip_range}, port {port}. Contact {email}. "
            "Attack vector {attack_vector}; attack technique {attack_technique} {mitre}. "
            "{exploit_status}. Impact: {impact}. Remediation: {remediation}. "
            "Mitigation: {mitigation}. Patch: {patch}. Evidence file {file_path}, "
            "file name {file_name}, MD5 {md5}, SHA1 {sha1}, SHA256 {sha256}."
        ),
        (
            "During penetration testing of {company}, the team found {severity} risk from "
            "{vuln} in {component}. Product {product} version {version} from vendor {vendor} "
            "runs as {service} on {asset}. Evidence maps to {cwe} and {cve}. "
            "The issue is reachable through {url}; domain {domain}; IP {ip}; port {port}; "
            "subnet {ip_range}. CVSS score: {cvss_score} {cvss_vector}. "
            "The observed attack vector is {attack_vector} and MITRE technique {mitre} "
            "for {attack_technique}. {exploit_status}. The impact is to {impact}. "
            "Recommended remediation: {remediation}. Recommended mitigation: {mitigation}. "
            "Required patch: {patch}. Notification mailbox {email}. "
            "Related file path {file_path} and file name {file_name}. Hashes: MD5 {md5}, "
            "SHA1 {sha1}, SHA256 {sha256}. CPE {cpe}."
        ),
        (
            "{company} report section {finding_id} confirms {vuln} affecting {product} "
            "version {version}. Severity {severity}. CVE reference {cve}; CWE reference {cwe}; "
            "CVSS score: {cvss_score}; vector {cvss_vector}. The affected component is "
            "{component}, endpoint {endpoint}, service {service}, asset {asset}. "
            "The application is hosted at {url}, domain {domain}, IP address {ip}, "
            "IP range {ip_range}, port {port}. Security contact {email}. "
            "Attack vector {attack_vector}. Attack technique {attack_technique}. "
            "MITRE technique {mitre}. {exploit_status}. Impact: {impact}. "
            "Remediation: {remediation}. Mitigation: {mitigation}. Patch: {patch}. "
            "Vendor {vendor}. CPE {cpe}. Evidence file path {file_path}; file name {file_name}; "
            "MD5 {md5}; SHA1 {sha1}; SHA256 {sha256}."
        ),
    ]
    return rng.choice(templates)


def build_record(index: int, rng: random.Random) -> Dict[str, Any]:
    profile = rng.choice(VULNERABILITY_PROFILES)
    product_row = rng.choice(PRODUCTS)
    target = rng.choice(TARGETS)

    path = rng.choice(PATHS)
    url = build_url(target["domain"], target["port"], path)
    endpoint = path
    cve = cve_for(index)
    cvss_score, cvss_vector = SEVERITY_TO_CVSS[profile["severity"]]
    cpe = cpe_for(product_row["vendor"], product_row["product"], product_row["version"])

    exploit_status = "Exploit Available" if profile["severity"] in {"Critical", "High"} else "No public exploit observed"
    exploit_values = ["Exploit Available"] if exploit_status == "Exploit Available" else []

    patch = f"Upgrade {product_row['product']} to a fixed version"
    file_path = rng.choice(FILE_PATHS)
    file_name = file_path.replace("\\", "/").split("/")[-1]

    hash_seed = f"{index}-{profile['vuln']}-{product_row['product']}-{target['domain']}"
    md5 = stable_hash(hash_seed + "-md5", 32)
    sha1 = stable_hash(hash_seed + "-sha1", 40)
    sha256 = stable_hash(hash_seed + "-sha256", 64)

    maybe_malware = rng.choice(MALWARE_NAMES) if rng.random() < 0.25 else ""
    malware_sentence = f" Malware {maybe_malware} was also observed." if maybe_malware else ""

    values = {
        "finding_id": f"CTI-{index:05d}",
        "company": target["company"],
        "severity": profile["severity"],
        "vuln": profile["vuln"],
        "product": product_row["product"],
        "version": product_row["version"],
        "vendor": product_row["vendor"],
        "component": profile["component"],
        "asset": target["asset"],
        "service": product_row["service"],
        "endpoint": endpoint,
        "cve": cve,
        "cwe": profile["cwe"],
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cpe": cpe,
        "url": url,
        "domain": target["domain"],
        "ip": target["ip"],
        "ip_range": target["ip_range"],
        "port": target["port"],
        "email": target["email"],
        "attack_vector": profile["attack_vector"],
        "attack_technique": profile["attack_technique"],
        "mitre": profile["mitre"],
        "exploit_status": exploit_status,
        "impact": profile["impact"],
        "remediation": profile["remediation"],
        "mitigation": profile["mitigation"],
        "patch": patch,
        "file_path": file_path,
        "file_name": file_name,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }

    text = choose_template(rng).format(**values) + malware_sentence

    record: Dict[str, Any] = {
        "company": target["company"],
        "file": f"augmented_report_{index:05d}.txt",
        "report_text": text,

        # Original project fields
        "severity": [profile["severity"]],
        "vulnerabilities": [profile["vuln"]],
        "cves": [cve],
        "impact": [profile["impact"]],

        # Expanded CTI fields supported by preprocessing.py
        "cwe_ids": [profile["cwe"]],
        "cvss_scores": [cvss_score],
        "cvss_vectors": [cvss_vector],
        "cpes": [cpe],

        "remediations": [profile["remediation"]],
        "mitigations": [profile["mitigation"]],
        "patches": [patch],

        "products": [product_row["product"]],
        "vendors": [product_row["vendor"]],
        "versions": [product_row["version"]],
        "affected_components": [profile["component"]],
        "assets": [target["asset"]],
        "endpoints": [endpoint],
        "services": [product_row["service"]],

        "ips": [target["ip"]],
        "ip_ranges": [target["ip_range"]],
        "urls": [url],
        "domains": [target["domain"]],
        "emails": [target["email"]],
        "ports": [target["port"]],

        "file_paths": [file_path],
        "file_names": [file_name],
        "md5": [md5],
        "sha1": [sha1],
        "sha256": [sha256],
        "hashes": [md5, sha1, sha256],

        "attack_vectors": [profile["attack_vector"]],
        "attack_techniques": [profile["attack_technique"]],
        "mitre_techniques": [profile["mitre"]],
        "exploits": exploit_values,
        "exploit_available": exploit_values,

        "exploitability": [profile["severity"]],
        "confidentiality_impacts": ["High" if profile["severity"] in {"Critical", "High"} else "Low"],
        "integrity_impacts": ["High" if profile["severity"] in {"Critical", "High"} else "Low"],
        "availability_impacts": ["High" if profile["vuln"] in {"Remote Code Execution", "Command Injection"} else "Low"],
    }

    if maybe_malware:
        record["malware"] = [maybe_malware]

    return record


def validate_record(record: Dict[str, Any]) -> List[str]:
    """Check that each labeled value exists in report_text."""
    text = record.get("report_text", "")
    problems: List[str] = []

    fields_to_check = [
        "severity",
        "vulnerabilities",
        "cves",
        "impact",
        "cwe_ids",
        "cvss_scores",
        "cvss_vectors",
        "cpes",
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
        "md5",
        "sha1",
        "sha256",
        "attack_vectors",
        "attack_techniques",
        "mitre_techniques",
        "exploits",
        "exploit_available",
        "malware",
    ]

    for field in fields_to_check:
        for value in as_list(record.get(field)):
            if value and value not in text:
                problems.append(f"{field}: {value}")

    return problems


def build_augmented_dataset(
    input_json: Path,
    output_json: Path,
    count: int,
    seed: int,
    include_original: bool,
    validate: bool,
) -> Dict[str, Any]:
    rng = random.Random(seed)
    output: List[Dict[str, Any]] = []

    if include_original:
        original = read_json(input_json)
        if isinstance(original, list):
            for i, row in enumerate(original, start=1):
                if isinstance(row, dict):
                    normalized = normalize_original_record(row, i)
                    if normalized.get("report_text"):
                        output.append(normalized)

    start_index = len(output) + 1
    for i in range(start_index, start_index + count):
        output.append(build_record(i, rng))

    random.Random(seed).shuffle(output)

    validation_errors: Dict[str, List[str]] = {}
    if validate:
        for idx, row in enumerate(output, start=1):
            errors = validate_record(row)
            if errors:
                validation_errors[str(idx)] = errors[:20]

    write_json(output_json, output)

    stats = build_stats(output)
    stats["input_json"] = str(input_json)
    stats["output_json"] = str(output_json)
    stats["seed"] = seed
    stats["requested_augmented_count"] = count
    stats["included_original"] = include_original
    stats["validation_error_records"] = len(validation_errors)

    stats_path = output_json.with_name(output_json.stem + "_stats.json")
    write_json(stats_path, stats)

    if validation_errors:
        errors_path = output_json.with_name(output_json.stem + "_validation_errors.json")
        write_json(errors_path, validation_errors)

    return stats


def build_stats(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counter: Counter[str] = Counter()
    vuln_counter: Counter[str] = Counter()
    field_presence: Counter[str] = Counter()

    for row in records:
        for sev in as_list(row.get("severity")):
            severity_counter[sev] += 1

        for vuln in as_list(row.get("vulnerabilities")):
            vuln_counter[vuln] += 1

        for key, value in row.items():
            if key in {"report_text", "file", "company"}:
                continue
            if as_list(value):
                field_presence[key] += 1

    return {
        "records": len(records),
        "severity_distribution": dict(sorted(severity_counter.items())),
        "vulnerability_distribution": dict(sorted(vuln_counter.items())),
        "field_presence": dict(sorted(field_presence.items())),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build augmented CTI processed_reports JSON.")

    p.add_argument(
        "--input_json",
        type=Path,
        default=Path("data/processed/processed_reports.json"),
    )
    p.add_argument(
        "--output_json",
        type=Path,
        default=Path("data/processed/processed_reports_augmented.json"),
    )
    p.add_argument("--count", type=int, default=300)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no_original", action="store_true")
    p.add_argument("--no_validate", action="store_true")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    stats = build_augmented_dataset(
        input_json=args.input_json,
        output_json=args.output_json,
        count=args.count,
        seed=args.seed,
        include_original=not args.no_original,
        validate=not args.no_validate,
    )

    print("Augmented dataset built.")
    print(f"Output: {args.output_json}")
    print(f"Records: {stats['records']}")
    print(f"Validation error records: {stats['validation_error_records']}")
    print(f"Stats: {args.output_json.with_name(args.output_json.stem + '_stats.json')}")


if __name__ == "__main__":
    main()  