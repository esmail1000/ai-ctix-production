#!/usr/bin/env python3
"""Build processed_reports_real_gold_v1.json from reviewed/gold CTIX reports.

Use this after you copy only approved reports into data/gold_reports_v1.
The output is compatible with the current nlp_engine/preprocessing.py and train.py:
- report_text: finding-scoped real text
- severity: labels present in text
- vulnerabilities: finding title / vuln phrase present in text
- cves: CVE IDs found in section
- impact: extracted impact phrase when available

Default behavior is strict: files with unexpected finding counts are excluded from
training output and listed in the stats JSON.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

GOLD_EXPECTED: Dict[str, int] = {
    "HLM-01-report.pdf": 1,
    "NCC_Group_Zcash_NU5_PublicReportFinal.pdf": 3,
    "Cure53-1PW17-report.pdf": 6,
    "Cure53-1PW18-report.pdf": 6,
    "pentest-report-amneziavpn.pdf": 16,
    "RedSiege-SampleReport.pdf": 10,
    "Doyensec_Gravitational_Teleport_Testing_Q42020.pdf": 18,
}

# Optional later, after manual review. Not included unless --include-silver is passed.
SILVER_EXPECTED: Dict[str, int] = {
    "NCC_Group_ProtocolLabs_PRLB007_Report_2020-10-20_v1.0.pdf": 8,
    "NCC_Group_WhatsAppLLC_OPAQUE_Report_2021-12-10_v1.3.pdf": 8,
    "Jackson-Report-Shared.pdf": 12,
    "GosseDeFi-hackenAudit.pdf": 3,
    "03042021_Kalmar_SC_Audit_Report.pdf": 5,
}

HOLD_FILES = {
    "realvnc-penetration-test.pdf",
    "KudelskiBulletproofsFinal.pdf",
    "FTI-Report-into-Jeff-Bezos-Phone-Hack.pdf",
    "Fraunhofer_-_TrueCrypt.pdf",
    "[OSTIF] Bref - Report v1.2.pdf",
}

SEVERITY_CANON = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "informational": "Low",
    "info": "Low",
    "none": "Low",
    "note": "Low",
}
SEVERITY_WORDS = r"Critical|High|Medium|Moderate|Low|Informational|Info|None|Note"

AUDIT_ID_RE = re.compile(
    r"\b(?:"
    r"HLM-\d{2}-\d{3}|1PW-\d{2}-\d{3}|AVP-\d{2}-\d{3}|TEL-Q420-\d{1,3}|Finding-\d{1,3}|"
    r"NCC-[A-Z0-9-]+|[A-Z]{2,12}-[A-Za-z0-9]+-\d{1,4}|[A-Z]{2,12}-\d{1,4}-\d{1,4}|"
    r"[A-Z]{2,12}-\d{3,}|\d+PW-\d{2}-\d{3}"
    r")\b",
    re.I,
)

STOP_RE = re.compile(
    r"^\s*(?:Appendix|References|Glossary|About|Conclusions?|Conclusion\s*&\s*Verdict|Methodology|"
    r"Test\s+Methodology|Executive\s+Summary|Table\s+of\s+Contents|Contents|Index|Scope|Revision\s+History|"
    r"Contacts|Hardening\s+Recommendations|Strategic\s+Recommendations)\b",
    re.I | re.M,
)

SECURITY_KEYWORDS = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,6}|CVSS|RCE|XSS|CSRF|SSRF|XXE|SQL\s+Injection|NoSQL|"
    r"Injection|Overflow|DoS|Denial\s+of\s+Service|Bypass|Leak|Disclosure|Exposure|Authentication|"
    r"Authorization|Privilege|Password|Credential|Token|Secret|Key|MAC|HMAC|Cipher|PBKDF2|Salt|Random|"
    r"Entropy|Validation|Traversal|Misconfiguration|Weak|Insecure|Vulnerab|Finding|Issue|Risk|Impact|"
    r"Remediation|Recommendation|Permission|Backdoor|Malware|Spoof|Signing|Storage|Session|Upload|"
    r"Policy|Indexing|HSTS|Unpatched|Poisoning|SMB|PowerShell|Pretext)\b",
    re.I,
)

VULN_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"remote\s+code\s+execution|\brce\b", re.I), "Remote Code Execution"),
    (re.compile(r"sql\s+injection|\bsqli\b", re.I), "SQL Injection"),
    (re.compile(r"cross[-\s]*site\s+scripting|\bxss\b", re.I), "Cross-Site Scripting"),
    (re.compile(r"cross[-\s]*site\s+request\s+forgery|\bcsrf\b", re.I), "Cross-Site Request Forgery"),
    (re.compile(r"server[-\s]*side\s+request\s+forgery|\bssrf\b", re.I), "Server-Side Request Forgery"),
    (re.compile(r"path\s+traversal|directory\s+traversal", re.I), "Path Traversal"),
    (re.compile(r"authentication\s+bypass|auth\s+bypass", re.I), "Authentication Bypass"),
    (re.compile(r"authorization\s+bypass|access\s+control", re.I), "Authorization Bypass"),
    (re.compile(r"information\s+disclosure|information\s+exposure|data\s+leak", re.I), "Information Disclosure"),
    (re.compile(r"denial[-\s]of[-\s]service|\bdos\b|oom", re.I), "Denial of Service"),
    (re.compile(r"weak\s+password|password\s+policy|credential", re.I), "Weak Authentication"),
    (re.compile(r"cryptograph|encryption|cipher|hmac|mac|pbkdf|salt|random|entropy|signature", re.I), "Cryptographic Weakness"),
    (re.compile(r"input\s+validation|validation", re.I), "Input Validation"),
    (re.compile(r"open\s+redirect", re.I), "Open Redirect"),
    (re.compile(r"content\s+spoof", re.I), "Content Spoofing"),
    (re.compile(r"privilege\s+escalation|privesc", re.I), "Privilege Escalation"),
    (re.compile(r"file\s+upload|uploaded\s+file", re.I), "File Upload Weakness"),
    (re.compile(r"session|cookie|token", re.I), "Session Management Weakness"),
    (re.compile(r"malware|backdoor|exfiltration|apt|forensic", re.I), "Threat Intelligence Finding"),
]

DETAIL_LABELS = [
    "Severity", "Risk", "Risk Level", "Status", "Description", "Summary", "Impact", "Business Impact",
    "Technical Impact", "Recommendation", "Recommendations", "Remediation", "Mitigation", "Fix", "Solution",
    "Evidence", "Observation", "Proof of Concept", "PoC", "Steps to Reproduce", "Component", "Affected Component",
    "Affected File", "Affected Code", "Location", "References", "Exploitability", "Security Impact",
]

@dataclass
class Finding:
    title: str
    severity: str
    source_file: str
    section_text: str
    finding_id: Optional[str] = None
    vulnerability_type: str = "Security Weakness"
    impact: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    cve_ids: List[str] = None  # type: ignore[assignment]
    cwe_ids: List[str] = None  # type: ignore[assignment]
    urls: List[str] = None  # type: ignore[assignment]
    domains: List[str] = None  # type: ignore[assignment]
    affected_components: List[str] = None  # type: ignore[assignment]
    confidence: int = 90
    extraction_method: str = "real-gold-parser-v1"

    def __post_init__(self) -> None:
        for name in ["cve_ids", "cwe_ids", "urls", "domains", "affected_components"]:
            if getattr(self, name) is None:
                setattr(self, name, [])


def normalize_text(text: str) -> str:
    text = text.replace("\r", "\n").replace("\x00", "").replace("\u00a0", " ")
    text = text.replace("ﬁ", "fi").replace("ﬂ", "fl")
    text = re.sub(r"([A-Za-z])-\n([a-z])", r"\1\2", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def clean_title(title: str) -> str:
    value = one_line(title)
    value = re.sub(r"^#+\s*", "", value)
    value = re.sub(r"^[-*•.]\s*", "", value)
    value = re.sub(r"^(?:Finding|Issue|Vulnerability|Observation|Risk|Weakness)\s*(?:#|No\.)?\s*\d*[\s:.)-]*", "", value, flags=re.I)
    value = re.sub(AUDIT_ID_RE, "", value, count=1).strip(" :.-–—|")
    value = re.sub(r"\.{2,}\s*\d+\s*$", "", value)
    value = re.sub(rf"\b(?:{SEVERITY_WORDS})\s*(?:Risk|Severity)?\s*$", "", value, flags=re.I)
    value = re.sub(r"^WP\d+(?:/\d+)?\s*[:.)-]*\s*", "", value, flags=re.I)
    value = re.sub(r"\s+", " ", value).strip(" :.-–—|")
    return value or "Security Finding"


def normalize_severity(value: Optional[str], text: str = "") -> str:
    raw = one_line(value or "")
    if not raw and text:
        m = re.search(rf"\b(?:Severity|Risk|Rating|Priority)\s*[:=]?\s*({SEVERITY_WORDS})\b", text[:1600], re.I)
        if m:
            raw = m.group(1)
        else:
            m = re.search(rf"\b({SEVERITY_WORDS})\s+(?:Risk|Severity)\b|\(({SEVERITY_WORDS})\s*(?:risk)?\)", text[:1000], re.I)
            if m:
                raw = next(g for g in m.groups() if g)
    return SEVERITY_CANON.get(raw.lower(), "Medium") if raw else "Medium"


def detect_vuln_type(text: str) -> str:
    for pat, label in VULN_PATTERNS:
        if pat.search(text):
            return label
    return "Security Weakness"


def extract_label_block(text: str, labels: Sequence[str], max_chars: int = 900) -> Optional[str]:
    lines = [ln.strip() for ln in text.splitlines()]
    label_alt = "|".join(re.escape(label) for label in labels)
    detail_alt = "|".join(re.escape(x) for x in DETAIL_LABELS)
    next_label_re = re.compile(rf"^(?:{detail_alt})\s*[:=]?\s*$", re.I)
    for i, line in enumerate(lines):
        m = re.match(rf"^(?:{label_alt})\s*[:=]\s*(.*)$", line, re.I)
        if m:
            buf = [m.group(1).strip()] if m.group(1).strip() else []
        elif re.match(rf"^(?:{label_alt})\s*:?\s*$", line, re.I):
            buf = []
        else:
            continue
        for nxt in lines[i + 1 : i + 14]:
            if not nxt:
                if buf:
                    break
                continue
            if next_label_re.match(nxt) and buf:
                break
            if AUDIT_ID_RE.match(nxt) and buf:
                break
            if STOP_RE.match(nxt) and buf:
                break
            buf.append(nxt)
            if len(" ".join(buf)) > max_chars:
                break
        val = one_line(" ".join(buf))[:max_chars]
        if val:
            return val
    return None


def extract_iocs(text: str) -> Dict[str, List[str]]:
    return {
        "cve_ids": sorted(set(m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I))),
        "cwe_ids": sorted(set(m.upper() for m in re.findall(r"\bCWE-\d{1,6}\b", text, re.I))),
        "urls": sorted(set(u.rstrip(".,;:)]}") for u in re.findall(r"https?://[^\s<>'\")]+", text, re.I)))[:25],
        "domains": sorted(set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text, re.I)))[:25],
    }


def extract_components(text: str) -> List[str]:
    vals: List[str] = []
    for label in ["Component", "Affected Component", "Affected File", "Affected Code", "Location", "Path"]:
        v = extract_label_block(text, [label], 300)
        if v:
            vals.append(v)
    vals.extend(re.findall(r"\b[A-Za-z0-9_./+-]+\.(?:go|rs|py|js|ts|tsx|java|sol|c|cpp|h|hpp|php|yaml|yml|json|xml|conf|cfg)\b", text))
    out: List[str] = []
    seen = set()
    for v in vals:
        key = one_line(v).lower()
        if key and key not in seen and len(key) < 240:
            seen.add(key)
            out.append(one_line(v))
    return out[:20]


def make_finding(section: str, source_file: str, title: str, fid: Optional[str] = None, severity: Optional[str] = None, confidence: int = 90) -> Finding:
    section = normalize_text(section)
    clean = clean_title(title)
    if not fid:
        m = AUDIT_ID_RE.search(section[:500])
        fid = m.group(0).upper() if m else None
    sev = normalize_severity(severity, section)
    impact = extract_label_block(section, ["Impact", "Business Impact", "Technical Impact", "Security Impact", "Consequence", "Consequences"], 700)
    remediation = extract_label_block(section, ["Recommendation", "Recommendations", "Remediation", "Mitigation", "Suggested Remediation", "Fix", "Solution"], 800)
    evidence = extract_label_block(section, ["Description", "Observation", "Evidence", "Details", "Proof of Concept", "PoC"], 1000)
    lines = [one_line(x) for x in section.splitlines() if one_line(x)]
    if not evidence:
        evidence = one_line(" ".join(lines[1:8] if len(lines) > 1 else lines))[:1000]
    iocs = extract_iocs(section)
    return Finding(
        title=clean,
        severity=sev,
        source_file=source_file,
        section_text=section,
        finding_id=fid,
        vulnerability_type=detect_vuln_type(section + " " + clean),
        impact=impact,
        remediation=remediation,
        evidence=evidence,
        cve_ids=iocs["cve_ids"],
        cwe_ids=iocs["cwe_ids"],
        urls=iocs["urls"],
        domains=iocs["domains"],
        affected_components=extract_components(section),
        confidence=confidence,
    )


def section_score(section: str) -> int:
    score = 0
    text = one_line(section[:3000])
    if len(text) > 500:
        score += 20
    if re.search(r"\b(?:Impact|Description|Recommendation|Remediation|PoC|Affected File|Component|Location|Status|Risk)\b", section, re.I):
        score += 50
    if SECURITY_KEYWORDS.search(section):
        score += 30
    if re.search(r"\b(Index|Table of Contents|Contents)\b", section[:600], re.I):
        score -= 60
    return score


def split_by_markers(text: str, marker_re: re.Pattern[str], source_file: str, start_at: int = 0, stop_re: Optional[re.Pattern[str]] = None) -> List[Finding]:
    sub = text[start_at:]
    matches = list(marker_re.finditer(sub))
    out: List[Finding] = []
    for idx, m in enumerate(matches):
        start = start_at + m.start()
        end = start_at + (matches[idx + 1].start() if idx + 1 < len(matches) else len(sub))
        if stop_re:
            stop = stop_re.search(text[start:end])
            if stop and stop.start() > 220:
                end = start + stop.start()
        section = text[start:end]
        if len(one_line(section)) < 80:
            continue
        gd = m.groupdict()
        out.append(make_finding(section, source_file, title=gd.get("title") or m.group(0), fid=gd.get("id"), severity=gd.get("sev"), confidence=92 if gd.get("id") else 84))
    return dedupe_findings(out)


def dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    order: List[str] = []
    for f in findings:
        key = (f.finding_id or re.sub(r"[^a-z0-9]+", " ", f.title.lower()).strip()).lower()
        if not key:
            continue
        if key not in seen:
            seen[key] = f
            order.append(key)
        else:
            old = seen[key]
            if section_score(f.section_text) > section_score(old.section_text):
                seen[key] = f
            elif section_score(f.section_text) == section_score(old.section_text) and len(f.section_text) > len(old.section_text):
                seen[key] = f
    return [seen[k] for k in order]


def body_start_for_findings(text: str, headings: Sequence[str]) -> int:
    # Skip index / table-of-contents entries by choosing the first matching
    # findings heading after the first page or introduction area.
    pattern = r"^\s*(?:" + "|".join(re.escape(h) for h in headings) + r")\s*$"
    starts = [m.start() for m in re.finditer(pattern, text, re.I | re.M) if m.start() > 1000]
    return min(starts) if starts else 0


def parse_cure53(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(
        rf"^\s*(?P<id>(?:HLM-\d{{2}}-\d{{3}}|1PW-\d{{2}}-\d{{3}}|\d+PW-\d{{2}}-\d{{3}}))\s+(?P<title>[^\n]{{5,190}}?)\s*\((?P<sev>{SEVERITY_WORDS})\)\s*$",
        re.I | re.M,
    )
    start = body_start_for_findings(text, ["Identified Vulnerabilities", "Miscellaneous Issues"])
    return split_by_markers(text, marker, source_file, start_at=start, stop_re=re.compile(r"^\s*Conclusions?\b", re.I | re.M))


def parse_amnezia(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(
        rf"^\s*(?P<id>AVP-\d{{2}}-\d{{3}})\s+(?P<title>[^\n]{{5,200}}?)\s*\((?P<sev>{SEVERITY_WORDS})\)\s*$",
        re.I | re.M,
    )
    start = body_start_for_findings(text, ["Identified Vulnerabilities", "Hardening Recommendations"])
    return split_by_markers(text, marker, source_file, start_at=start, stop_re=re.compile(r"^\s*Conclusion\b", re.I | re.M))


def parse_ncc_zcash(text: str, source_file: str) -> List[Finding]:
    start = text.lower().find("finding details")
    if start < 0:
        start = 0
    marker = re.compile(r"^\s*Finding\s+(?P<title>[A-Z][^\n]{6,180})\s*$", re.I | re.M)
    out = split_by_markers(text, marker, source_file, start_at=start, stop_re=re.compile(r"^\s*Appendix\b", re.I | re.M))
    return [f for f in out if not re.search(r"field definitions|table of findings", f.title, re.I)]


def parse_doyensec(text: str, source_file: str) -> List[Finding]:
    start = text.find("TEL-Q420-1")
    marker = re.compile(r"^\s*(?P<id>TEL-Q420-\d{1,3})\s+(?P<title>[^\n]{4,180})\s*$", re.I | re.M)
    return split_by_markers(text, marker, source_file, start_at=max(0, start), stop_re=re.compile(r"^\s*Appendix\b", re.I | re.M))


def parse_redsiege(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(r"^\s*(?P<id>Finding-\d{1,3})\s+(?P<title>[^\n.]{4,180})\s*$", re.I | re.M)
    findings = split_by_markers(text, marker, source_file, stop_re=re.compile(r"^\s*(?:External|Internal|Web Application|Assumed Breach|Social Engineering).*Methodology\b", re.I | re.M))
    detailed = [f for f in findings if section_score(f.section_text) >= 30]
    return detailed or findings


# Silver parsers are available but not enabled unless --include-silver.
def parse_ncc_generic(text: str, source_file: str) -> List[Finding]:
    start = text.lower().find("finding details")
    marker = re.compile(r"^\s*Finding\s+(?P<title>[A-Z][^\n]{6,190})\s*$", re.I | re.M)
    return split_by_markers(text, marker, source_file, start_at=max(0, start), stop_re=re.compile(r"^\s*Appendix\b", re.I | re.M))


def parse_hacken(text: str, source_file: str) -> List[Finding]:
    # Hacken audit reports often have HACKEN-[LEVEL] before title.
    marker = re.compile(rf"^\s*(?P<id>HACKEN-(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL))\s*[-–—:]?\s*(?P<title>[^\n]{{5,180}})\s*$", re.I | re.M)
    return split_by_markers(text, marker, source_file)


def parse_generic_numbered_issues(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(
        r"^\s*(?P<id>\d+(?:\.\d+){1,3})\.??\s+(?P<title>(?!Overview|Methodology|Recommendations|Summary|Scope|Version|Contacts|Classification|About)[A-Z][^\n]{5,180})\s*$",
        re.I | re.M,
    )
    candidates = split_by_markers(text, marker, source_file)
    return [f for f in candidates if SECURITY_KEYWORDS.search((f.title or "") + " " + (f.evidence or ""))]


def parse_findings(text: str, source_file: str, include_silver: bool = False) -> List[Finding]:
    name = source_file.lower()
    text = normalize_text(text)
    parsers: List[Callable[[str, str], List[Finding]]] = []
    if "hlm-01" in name or "1pw" in name or "cure53" in name:
        parsers.append(parse_cure53)
    if "amnezia" in name or "AVP-01-001" in text:
        parsers.append(parse_amnezia)
    if "zcash" in name:
        parsers.append(parse_ncc_zcash)
    if "doyensec" in name or "TEL-Q420" in text:
        parsers.append(parse_doyensec)
    if "redsiege" in name or "Finding-01 Weak Password Policy" in text:
        parsers.append(parse_redsiege)
    if include_silver:
        if "protocol" in name or "opaque" in name:
            parsers.append(parse_ncc_generic)
        if "hacken" in name or "kalmar" in name or "gosse" in name:
            parsers.append(parse_hacken)
        if "jackson" in name:
            parsers.append(parse_generic_numbered_issues)

    results: List[Finding] = []
    for parser in parsers:
        try:
            results.extend(parser(text, source_file))
        except Exception as exc:
            print(f"[warn] parser {parser.__name__} failed for {source_file}: {exc}", file=sys.stderr)
    if not results and include_silver:
        results = parse_generic_numbered_issues(text, source_file)
    return dedupe_findings(results)


def try_pdfminer(path: Path) -> str:
    try:
        from pdfminer.high_level import extract_text  # type: ignore
        return extract_text(str(path)) or ""
    except Exception:
        return ""


def try_pymupdf(path: Path) -> str:
    try:
        import fitz  # type: ignore
        doc = fitz.open(str(path))
        return "\n".join(page.get_text("text") for page in doc)
    except Exception:
        return ""


def try_pdftotext(path: Path) -> str:
    try:
        result = subprocess.run(["pdftotext", "-layout", str(path), "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if result.returncode == 0:
            return result.stdout.decode("utf-8", "ignore")
    except Exception:
        return ""
    return ""


def extract_text(path: Path) -> Tuple[str, str, List[str]]:
    warnings: List[str] = []
    ext = path.suffix.lower()
    if ext in {".txt", ".md", ".log"}:
        return normalize_text(path.read_text("utf-8", errors="ignore")), "text", warnings
    if ext == ".pdf":
        best = ""
        best_method = "none"
        for method, func in [("pdftotext", try_pdftotext), ("pymupdf", try_pymupdf), ("pdfminer", try_pdfminer)]:
            text = normalize_text(func(path))
            if len(text) > len(best):
                best, best_method = text, method
            if len(text) >= 200:
                return text, method, warnings
        if len(best) < 200:
            warnings.append("low_text_extraction")
        return best, best_method, warnings
    warnings.append(f"unsupported extension: {ext}")
    return "", "unsupported", warnings


def build_training_text(f: Finding) -> str:
    # Preserve real section text, but prepend normalized labels so all training labels align reliably.
    header = [
        f"Finding: {f.title}",
        f"Severity: {f.severity}",
        f"Vulnerability: {f.vulnerability_type}",
    ]
    if f.finding_id:
        header.append(f"Identifier: {f.finding_id}")
    if f.impact:
        header.append(f"Impact: {f.impact}")
    if f.remediation:
        header.append(f"Remediation: {f.remediation}")
    return normalize_text("\n".join(header) + "\n\nOriginal Finding Section:\n" + f.section_text)


def to_processed_records(path: Path, findings: Sequence[Finding], decision: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for i, f in enumerate(findings, 1):
        report_text = build_training_text(f)
        vuln_labels = [f.title]
        if f.vulnerability_type and f.vulnerability_type.lower() not in f.title.lower():
            vuln_labels.append(f.vulnerability_type)
        impact_labels = [x for x in [f.impact] if x]
        rec = {
            "company": "real_gold_v1",
            "file": f"{path.stem}__finding_{i:03d}.txt",
            "source_file": path.name,
            "finding_id": f.finding_id or f"{path.stem}-{i:03d}",
            "finding_title": f.title,
            "report_text": report_text,
            "severity": [f.severity],
            "risk_level": [f.severity],
            "vulnerabilities": vuln_labels,
            "cves": f.cve_ids,
            "cwes": f.cwe_ids,
            "impact": impact_labels,
            "remediation": [f.remediation] if f.remediation else [],
            "affected_components": f.affected_components,
            "urls": f.urls,
            "domains": f.domains,
            "extraction_method": f.extraction_method,
            "confidence": f.confidence,
            "review_status": decision,
            "dataset_version": "processed_reports_real_gold_v1",
        }
        records.append(rec)
    return records


def collect_paths(input_dir: Path, expected: Dict[str, int]) -> List[Path]:
    paths: List[Path] = []
    lower_map = {p.name.lower(): p for p in input_dir.rglob("*") if p.is_file()}
    for fname in expected:
        p = lower_map.get(fname.lower())
        if p:
            paths.append(p)
    return paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build clean CTIX real gold training JSON.")
    ap.add_argument("input_dir", nargs="?", default="data/gold_reports_v1")
    ap.add_argument("--output", default="data/processed/processed_reports_real_gold_v1.json")
    ap.add_argument("--stats", default="data/processed/processed_reports_real_gold_v1_stats.json")
    ap.add_argument("--include-silver", action="store_true", help="Also include reviewed silver files if their counts match.")
    ap.add_argument("--allow-count-mismatch", action="store_true", help="Write records even when count differs. Not recommended.")
    ap.add_argument("--allow-missing", action="store_true", help="Do not fail when some whitelist files are missing.")
    args = ap.parse_args(argv)

    input_dir = Path(args.input_dir)
    expected = dict(GOLD_EXPECTED)
    if args.include_silver:
        expected.update(SILVER_EXPECTED)

    if not input_dir.exists():
        print(f"[error] input folder not found: {input_dir}", file=sys.stderr)
        return 2

    paths = collect_paths(input_dir, expected)
    found_names = {p.name for p in paths}
    missing = [name for name in expected if name not in found_names]
    if missing and not args.allow_missing:
        print("[error] missing whitelist files:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print("Use --allow-missing if you intentionally want to build from available files only.", file=sys.stderr)
        return 2

    records: List[Dict[str, Any]] = []
    stats: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    for path in paths:
        if path.name in HOLD_FILES:
            excluded.append({"file": path.name, "reason": "hold_file"})
            continue
        text, method, warnings = extract_text(path)
        findings = parse_findings(text, path.name, include_silver=args.include_silver)
        exp = expected[path.name]
        count_ok = len(findings) == exp
        decision = "gold" if path.name in GOLD_EXPECTED else "silver_reviewed"
        row = {
            "file": path.name,
            "expected_findings": exp,
            "actual_findings": len(findings),
            "count_ok": count_ok,
            "text_len": len(text),
            "method": method,
            "warnings": warnings,
            "titles": [f.title for f in findings],
            "decision": decision if count_ok else "exclude_count_mismatch",
        }
        stats.append(row)
        print(f"{path.name}: expected={exp} actual={len(findings)} method={method} {'OK' if count_ok else 'MISMATCH'}")
        if count_ok or args.allow_count_mismatch:
            records.extend(to_processed_records(path, findings, decision=decision))
        else:
            excluded.append({"file": path.name, "reason": "count_mismatch", "expected": exp, "actual": len(findings)})

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")

    stats_obj = {
        "dataset_version": "processed_reports_real_gold_v1",
        "input_dir": str(input_dir),
        "records_written": len(records),
        "files_used": sorted(set(r["source_file"] for r in records)),
        "missing_files": missing,
        "excluded": excluded,
        "per_file": stats,
    }
    st = Path(args.stats)
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps(stats_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nSaved JSON: {out}")
    print(f"Saved stats: {st}")
    print(f"Training records written: {len(records)}")
    if excluded:
        print("Excluded files:")
        for item in excluded:
            print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
