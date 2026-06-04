#!/usr/bin/env python3
"""CTIX real report extractor/training-data builder v12.

Purpose:
- Read PDF/TXT/DOCX security reports.
- Use robust text extraction with OCR fallback for scanned PDFs.
- Split real audit reports into findings across common report styles.
- Export model-training JSON compatible with processed_reports style.

No external network access required.
Optional OCR requires: PyMuPDF (fitz), pytesseract, and Tesseract installed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

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

SECURITY_KEYWORDS = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,6}|CVSS|RCE|XSS|CSRF|SSRF|XXE|SQL\s+Injection|NoSQL|"
    r"Injection|Overflow|Over\s*flow|DoS|Denial\s+of\s+Service|Bypass|Leak|Disclosure|Exposure|"
    r"Authentication|Authorization|Privilege|Password|Credential|Token|Secret|Key|MAC|HMAC|Cipher|"
    r"PBKDF2|Salt|Random|Entropy|Validation|Sanitization|Traversal|Misconfiguration|Weak|Insecure|"
    r"Vulnerab|Finding|Issue|Risk|Impact|Remediation|Recommendation)\b",
    re.I,
)

VULN_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"remote\s+code\s+execution|\brce\b", re.I), "Remote Code Execution"),
    (re.compile(r"sql\s+injection|\bsqli\b", re.I), "SQL Injection"),
    (re.compile(r"no\s*sql\s+injection|nosql", re.I), "NoSQL Injection"),
    (re.compile(r"command\s+injection|parameter\s+injection|shell\s+injection", re.I), "Command Injection"),
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
    (re.compile(r"malware|backdoor|exfiltration|apt|forensic", re.I), "Threat Intelligence Finding"),
]

DETAIL_LABELS = [
    "Severity", "Risk", "Risk Level", "Status", "Description", "Summary", "Impact", "Business Impact",
    "Recommendation", "Recommendations", "Remediation", "Mitigation", "Fix", "Solution",
    "Evidence", "Observation", "Proof of Concept", "PoC", "Steps to Reproduce", "Component", "Affected Component",
    "Affected File", "Location", "References", "Exploitability", "Security Impact",
]

STOP_HEADINGS = re.compile(
    r"^(?:Appendix|References|Glossary|About|Conclusion|Conclusions|Methodology|Executive\s+Summary|"
    r"Table\s+of\s+Contents|Contents|Scope|Revision\s+History|Contacts|Recommendations|Hardening\s+Recommendations)\b",
    re.I,
)

AUDIT_ID_RE = re.compile(
    r"\b(?:TEL-Q420-\d{1,3}|Finding-\d{1,3}|BP-[FO]-(?:\d{1,4})?|[A-Z]{2,12}-[A-Za-z0-9]+-\d{1,4}|"
    r"[A-Z]{2,12}-\d{1,4}-\d{1,4}|[A-Z]{2,12}-\d{3,}|\d+PW-\d+-\d{3})\b",
    re.I,
)

@dataclass
class Finding:
    title: str
    severity: str
    source_file: str
    finding_id: Optional[str] = None
    vulnerability_type: Optional[str] = None
    asset: Optional[str] = None
    status: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[str] = None
    cve_ids: List[str] = None  # type: ignore[assignment]
    cwe_ids: List[str] = None  # type: ignore[assignment]
    urls: List[str] = None  # type: ignore[assignment]
    domains: List[str] = None  # type: ignore[assignment]
    affected_components: List[str] = None  # type: ignore[assignment]
    confidence: int = 82
    extraction_method: str = "real-report-parser-v12"

    def __post_init__(self) -> None:
        for name in ["cve_ids", "cwe_ids", "urls", "domains", "affected_components"]:
            if getattr(self, name) is None:
                setattr(self, name, [])


def normalize_text(text: str) -> str:
    text = text.replace("\r", "\n")
    text = text.replace("\x00", "")
    text = text.replace("\u00a0", " ")
    text = text.replace("ﬁ", "fi").replace("ﬂ", "fl")
    text = re.sub(r"([A-Za-z])-\n([a-z])", r"\1\2", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def one_line(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def clean_title(title: str) -> str:
    value = one_line(title)
    value = re.sub(r"^#+\s*", "", value)
    value = re.sub(r"^[-*•.]\s*", "", value)
    value = re.sub(r"^(?:Finding|Issue|Vulnerability|Observation|Risk|Weakness)\s*(?:#|No\.)?\s*\d*[\s:.)-]*", "", value, flags=re.I)
    value = re.sub(AUDIT_ID_RE, "", value, count=1).strip(" :.-–—|")
    value = re.sub(r"\.{2,}\s*\d+\s*$", "", value)
    value = re.sub(r"\b(?:Critical|High|Medium|Moderate|Low|Informational|Info)\s*(?:Risk|Severity)?\s*$", "", value, flags=re.I)
    value = re.sub(r"\s+", " ", value).strip(" :.-–—|")
    return value or "Security Finding Requiring Review"


def normalize_severity(value: Optional[str], text: str = "") -> str:
    raw = one_line(value or "")
    if not raw and text:
        m = re.search(rf"\b(?:Severity|Risk|Rating|Priority)\s*[:=]?\s*({SEVERITY_WORDS})\b", text, re.I)
        if m:
            raw = m.group(1)
        else:
            m = re.search(rf"\b({SEVERITY_WORDS})\s+(?:Risk|Severity)\b|\(({SEVERITY_WORDS})\s+risk\)", text[:1000], re.I)
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
    next_label_re = re.compile(rf"^(?:{'|'.join(re.escape(x) for x in DETAIL_LABELS)})\s*[:=]?\s*$", re.I)
    for i, line in enumerate(lines):
        m = re.match(rf"^(?:{label_alt})\s*[:=]\s*(.*)$", line, re.I)
        if m:
            buf = [m.group(1).strip()] if m.group(1).strip() else []
            for nxt in lines[i+1:i+12]:
                if not nxt:
                    if buf:
                        break
                    continue
                if next_label_re.match(nxt) and buf:
                    break
                if AUDIT_ID_RE.match(nxt) and buf:
                    break
                if STOP_HEADINGS.match(nxt) and buf:
                    break
                buf.append(nxt)
                if len(" ".join(buf)) > max_chars:
                    break
            val = one_line(" ".join(buf))[:max_chars]
            if val:
                return val
        elif re.match(rf"^(?:{label_alt})\s*:?\s*$", line, re.I):
            buf = []
            for nxt in lines[i+1:i+14]:
                if not nxt:
                    if buf:
                        break
                    continue
                if next_label_re.match(nxt) and buf:
                    break
                if AUDIT_ID_RE.match(nxt) and buf:
                    break
                if STOP_HEADINGS.match(nxt) and buf:
                    break
                buf.append(nxt)
                if len(" ".join(buf)) > max_chars:
                    break
            val = one_line(" ".join(buf))[:max_chars]
            if val:
                return val
    return None


def extract_iocs(text: str) -> Dict[str, List[str]]:
    cves = sorted(set(m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I)))
    cwes = sorted(set(m.upper() for m in re.findall(r"\bCWE-\d{1,6}\b", text, re.I)))
    urls = sorted(set(u.rstrip(".,;:)]}") for u in re.findall(r"https?://[^\s<>'\")]+", text, re.I)))
    domains = sorted(set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text, re.I)))
    return {"cve_ids": cves, "cwe_ids": cwes, "urls": urls, "domains": domains}


def guess_asset(text: str) -> Optional[str]:
    label = extract_label_block(text, ["Affected Asset", "Asset", "Host", "Target", "Component", "Affected Component"], 180)
    if label:
        return label
    m = re.search(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", text, re.I)
    if m:
        return m.group(0)
    m = re.search(r"\b(?:[A-Za-z0-9_.-]+\.(?:go|js|ts|php|py|java|cc|cpp|h|sol|rs))\b", text)
    if m:
        return m.group(0)
    return None


def finding_from_section(section: str, source_file: str, title: Optional[str] = None, fid: Optional[str] = None, severity: Optional[str] = None, confidence: int = 82) -> Finding:
    section = normalize_text(section)
    lines = [one_line(x) for x in section.splitlines() if one_line(x)]
    heading = title or (lines[0] if lines else "Security Finding")
    id_match = AUDIT_ID_RE.search(section[:300])
    if not fid and id_match:
        fid = id_match.group(0).upper()
    clean = clean_title(heading)
    sev = normalize_severity(severity, section)
    status = extract_label_block(section, ["Status", "Finding Status"], 180)
    impact = extract_label_block(section, ["Impact", "Business Impact", "Technical Impact", "Security Impact", "Consequence", "Consequences"], 700)
    remediation = extract_label_block(section, ["Recommendation", "Recommendations", "Remediation", "Mitigation", "Suggested Remediation", "Fix", "Solution"], 800)
    evidence = extract_label_block(section, ["Description", "Observation", "Evidence", "Details", "Proof of Concept", "PoC"], 1000)
    if not evidence:
        evidence = one_line(" ".join(lines[1:8] if len(lines) > 1 else lines))[:1000]
    iocs = extract_iocs(section)
    return Finding(
        title=clean,
        severity=sev,
        source_file=source_file,
        finding_id=fid,
        vulnerability_type=detect_vuln_type(section + " " + clean),
        asset=guess_asset(section),
        status=status,
        impact=impact,
        remediation=remediation,
        evidence=evidence,
        cve_ids=iocs["cve_ids"],
        cwe_ids=iocs["cwe_ids"],
        urls=iocs["urls"][:10],
        domains=iocs["domains"][:10],
        confidence=confidence,
    )


def split_by_markers(text: str, marker_re: re.Pattern[str], source_file: str, start_at: int = 0, stop_re: Optional[re.Pattern[str]] = None) -> List[Finding]:
    sub = text[start_at:]
    matches = list(marker_re.finditer(sub))
    out: List[Finding] = []
    for idx, m in enumerate(matches):
        start = start_at + m.start()
        end = start_at + (matches[idx + 1].start() if idx + 1 < len(matches) else len(sub))
        if stop_re:
            stop = stop_re.search(text[start:end])
            if stop and stop.start() > 250:
                end = start + stop.start()
        section = text[start:end]
        title = m.groupdict().get("title") if m.groupdict() else None
        fid = m.groupdict().get("id") if m.groupdict() else None
        sev = m.groupdict().get("sev") if m.groupdict() else None
        if len(one_line(section)) < 70:
            continue
        out.append(finding_from_section(section, source_file, title=title, fid=fid, severity=sev, confidence=90 if fid else 82))
    return dedupe_findings(out)


def dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    order: List[str] = []
    for f in findings:
        key = (f.finding_id or re.sub(r"[^a-z0-9]+", " ", f.title.lower()).strip())
        if not key or key in {"security finding requiring review", "security finding"}:
            key = re.sub(r"[^a-z0-9]+", " ", (f.title + " " + (f.asset or "")).lower()).strip()
        if key not in seen:
            seen[key] = f
            order.append(key)
        else:
            old = seen[key]
            # Prefer richer evidence and explicit severity.
            old_len = len(old.evidence or "") + len(old.remediation or "") + len(old.impact or "")
            new_len = len(f.evidence or "") + len(f.remediation or "") + len(f.impact or "")
            if new_len > old_len:
                seen[key] = f
    return [seen[k] for k in order]


def parse_realvnc(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(rf"^\s*(?P<title>[A-Z][A-Za-z0-9 ,/'’\-]+?)\s*\((?P<sev>{SEVERITY_WORDS})\s+risk\)\s*$", re.I | re.M)
    return split_by_markers(text, marker, source_file)


def parse_doyensec(text: str, source_file: str) -> List[Finding]:
    start = text.find("TEL-Q420-1")
    marker = re.compile(r"^\s*(?P<id>TEL-Q420-\d{1,3})\s+(?P<title>[^\n]{4,180})\s*$", re.I | re.M)
    return split_by_markers(text, marker, source_file, start_at=max(0, start), stop_re=re.compile(r"^\s*Appendix\b", re.I | re.M))


def parse_redsiege(text: str, source_file: str) -> List[Finding]:
    # Body headings appear again after table-of-contents; choose rich body sections via dedupe.
    marker = re.compile(r"^\s*(?P<id>Finding-\d{1,3})\s+(?P<title>[^\n.]{4,180})\s*$", re.I | re.M)
    findings = split_by_markers(text, marker, source_file, stop_re=re.compile(r"^\s*(?:External|Internal|Web Application|Assumed Breach|Social Engineering).*Methodology\b", re.I | re.M))
    # If TOC duplicates were kept, prefer detailed sections only.
    detailed = [f for f in findings if (f.evidence and len(f.evidence) > 120) or f.impact or f.remediation]
    return detailed or findings


def parse_bref(text: str, source_file: str) -> List[Finding]:
    start = text.lower().find("4. findings details")
    if start < 0:
        start = text.lower().find("findings details")
    marker = re.compile(r"^\s*(?P<id>4\.\d+)\.\s+(?P<title>[A-Z][^\n]{6,180})\s*$", re.I | re.M)
    findings = split_by_markers(text, marker, source_file, start_at=max(0, start), stop_re=re.compile(r"^\s*(?:5\.|Appendix|References)\b", re.I | re.M))
    return [f for f in findings if not re.search(r"classification|summary|methodology|overview", f.title, re.I)]


def parse_defuse_hash0(text: str, source_file: str) -> List[Finding]:
    start = text.find("3. Issues")
    end = text.find("4. Recommendations")
    body = text[max(0, start): end if end > start else len(text)]
    marker = re.compile(r"^\s*(?P<id>3\.\d{1,2})\s+(?P<title>[A-Z][^\n]{5,160})\s*$", re.I | re.M)
    return split_by_markers(body, marker, source_file)


def parse_defuse_encfs(text: str, source_file: str) -> List[Finding]:
    start = text.find("2. Issues")
    body = text[max(0, start):]
    marker = re.compile(r"^\s*(?P<id>[23]\.\d{1,2})\.\s+(?P<title>[A-Z][^\n]{5,180})\s*$", re.I | re.M)
    findings = split_by_markers(body, marker, source_file)
    return [f for f in findings if not re.search(r"audit results summary|what is encfs", f.title, re.I)]


def parse_kudelski(text: str, source_file: str) -> List[Finding]:
    # pdf text loses BP numbers, but body markers are still stable: `. BP-F-: Title`.
    start = max(0, text.find("\nFindings"))
    body = text[start:]
    marker = re.compile(r"^\s*\.\s*(?P<id>BP-[FO]-(?:\d{1,4})?)\s*:\s*(?P<title>[^\n]{5,180})\s*$", re.I | re.M)
    matches = list(marker.finditer(body))
    out: List[Finding] = []
    for idx, m in enumerate(matches):
        section_start = start + m.start()
        section_end = start + (matches[idx + 1].start() if idx + 1 < len(matches) else len(body))
        about = re.search(r"^\s*About\b", text[section_start:section_end], re.I | re.M)
        if about and about.start() > 200:
            section_end = section_start + about.start()
        title = m.group("title")
        raw_id = (m.group("id") or "").upper()
        prefix = "BP-O" if raw_id.startswith("BP-O") else "BP-F"
        # Generate stable unique IDs when the numeric glyphs were lost by PDF extraction.
        fid = raw_id if re.search(r"\d", raw_id) else f"{prefix}-{idx + 1:03d}"
        section = text[section_start:section_end]
        if len(one_line(section)) < 60:
            continue
        out.append(finding_from_section(section, source_file, title=title, fid=fid, severity=None, confidence=86))
    return dedupe_findings(out)


def parse_generic_numbered_issues(text: str, source_file: str) -> List[Finding]:
    marker = re.compile(
        r"^\s*(?P<id>\d+(?:\.\d+){1,3})\.??\s+(?P<title>(?!Overview|Methodology|Recommendations|Summary|Scope|Version|Contacts|Classification|About)[A-Z][^\n]{5,180})\s*$",
        re.I | re.M,
    )
    candidates = split_by_markers(text, marker, source_file)
    return [f for f in candidates if SECURITY_KEYWORDS.search((f.title or "") + " " + (f.evidence or ""))]



def parse_truecrypt(text: str, source_file: str) -> List[Finding]:
    titles = [
        ("Unfixed TrueCrypt Security Issues Warning", "High", "The report notes that the official TrueCrypt website warned that using TrueCrypt is not secure as it may contain unfixed security issues."),
        ("Security-Relevant Version Differences Require Review", "Medium", "The analysis evaluates differences between TrueCrypt 7.0a and 7.1a for security relevance and downstream Trusted Disk impact."),
        ("Automated Code Analysis Warnings Require Remediation", "Medium", "The report summarizes static analysis results from Clang, Coverity, and Cppcheck and their security implications."),
        ("Code Quality and Maintainability Weaknesses", "Low", "The report identifies programming guideline violations, complexity, duplicate code, and maintainability issues."),
        ("Architecture and Attack Strategy Risks", "Medium", "The report discusses attack strategies including brute force, forensic analysis, password/key detection, side-channel attacks, and indirect attacks."),
    ]
    out: List[Finding] = []
    for title, sev, evidence in titles:
        f = finding_from_section(text[:6000] + "\n" + evidence, source_file, title=title, severity=sev, confidence=68)
        f.evidence = evidence
        f.vulnerability_type = detect_vuln_type(title + " " + evidence)
        f.extraction_method = "truecrypt-summary-v12"
        out.append(f)
    return out

def parse_threat_intel(text: str, source_file: str) -> List[Finding]:
    if not re.search(r"\b(?:APT|forensic|exfiltration|malware|spy|compromise|unauthorized)\b", text, re.I):
        return []
    if not re.search(r"\b(?:phone|device|iPhone|WhatsApp|downloader|attachment)\b", text, re.I):
        return []
    title = "Possible Mobile Device Compromise and Data Exfiltration"
    finding = finding_from_section(text[:5000], source_file, title=title, severity="High", confidence=72)
    finding.vulnerability_type = "Threat Intelligence Finding"
    finding.extraction_method = "threat-intel-summary-v12"
    return [finding]


def parse_findings(text: str, source_file: str) -> List[Finding]:
    text = normalize_text(text)
    lower_name = source_file.lower()
    parsers = []
    if "realvnc" in lower_name or "web application password policy" in text.lower():
        parsers.append(parse_realvnc)
    if "doyensec" in lower_name or "TEL-Q420" in text:
        parsers.append(parse_doyensec)
    if "redsiege" in lower_name or "Finding-01 Weak Password Policy" in text:
        parsers.append(parse_redsiege)
    if "bref" in lower_name or "Technical Report – Bref" in text or "Technical Report - Bref" in text:
        parsers.append(parse_bref)
    if "hash0" in lower_name:
        parsers.append(parse_defuse_hash0)
    if "encfs" in lower_name:
        parsers.append(parse_defuse_encfs)
    if "truecrypt" in lower_name or "Security Analysis of TrueCrypt" in text:
        parsers.append(parse_truecrypt)
    if "bulletproof" in lower_name or "BP-F-" in text:
        parsers.append(parse_kudelski)

    results: List[Finding] = []
    for parser in parsers:
        try:
            results.extend(parser(text, source_file))
        except Exception as exc:
            print(f"[warn] parser {parser.__name__} failed for {source_file}: {exc}", file=sys.stderr)

    if not results:
        results = parse_generic_numbered_issues(text, source_file)
    if not results:
        results = parse_threat_intel(text, source_file)

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


def try_ocr_pdf(path: Path, max_pages: int = 3, dpi_scale: float = 1.2) -> str:
    try:
        import fitz  # type: ignore
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
        import io
    except Exception:
        return ""
    try:
        doc = fitz.open(str(path))
        pages = min(len(doc), max_pages)
        out: List[str] = []
        matrix = fitz.Matrix(dpi_scale, dpi_scale)
        for i in range(pages):
            pix = doc[i].get_pixmap(matrix=matrix, alpha=False)
            img = Image.open(io.BytesIO(pix.tobytes("png")))
            txt = pytesseract.image_to_string(img)
            if txt.strip():
                out.append(txt)
        return "\n\n".join(out)
    except Exception:
        return ""


def extract_text_from_file(path: Path, ocr: bool = True) -> Tuple[str, Dict[str, Any]]:
    suffix = path.suffix.lower()
    meta: Dict[str, Any] = {"file": str(path), "method": None, "ocr_used": False, "warnings": []}
    if suffix in {".txt", ".md", ".log", ".csv"}:
        meta["method"] = "text"
        return normalize_text(path.read_text("utf-8", errors="ignore")), meta
    if suffix == ".docx":
        try:
            from docx import Document  # type: ignore
            doc = Document(str(path))
            parts = [p.text for p in doc.paragraphs if p.text.strip()]
            meta["method"] = "docx"
            return normalize_text("\n".join(parts)), meta
        except Exception as exc:
            meta["warnings"].append(f"docx extraction failed: {exc}")
            return "", meta
    if suffix == ".pdf":
        best_method = "none"
        best_text = ""

        # Fast path: most pentest PDFs have an embedded text layer. Return early
        # instead of running every extractor, because some PDFs can make pdftotext slow.
        for method_name, extractor in (("pdfminer", try_pdfminer), ("pymupdf", try_pymupdf), ("pdftotext", try_pdftotext)):
            candidate = normalize_text(extractor(path))
            if len(candidate) > len(best_text):
                best_method, best_text = method_name, candidate
            if len(candidate) >= 200:
                meta["method"] = method_name
                return candidate, meta

        if ocr:
            ocr_text = normalize_text(try_ocr_pdf(path))
            if len(ocr_text) > len(best_text):
                meta["method"] = "ocr-pymupdf-tesseract"
                meta["ocr_used"] = True
                return ocr_text, meta

        meta["method"] = best_method
        if len(best_text) < 200:
            meta["warnings"].append("Text extraction returned little/no text. Enable/install OCR for scanned PDFs.")
        return best_text, meta
    # fallback
    meta["method"] = "raw-text-fallback"
    return normalize_text(path.read_text("utf-8", errors="ignore")), meta


def to_processed_record(path: Path, text: str, findings: Sequence[Finding], meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "report_id": path.stem,
        "source_file": path.name,
        "text": text,
        "findings": [asdict(f) for f in findings],
        "meta": {
            **meta,
            "finding_count": len(findings),
            "parser_version": "ctix-real-report-training-builder-v12",
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="PDF/TXT/DOCX files or directories")
    ap.add_argument("--output", default="data/processed/processed_reports_real_v12.json")
    ap.add_argument("--stats", default="data/processed/processed_reports_real_v12_stats.json")
    ap.add_argument("--no-ocr", action="store_true")
    ap.add_argument("--glob", default="*.pdf,*.txt,*.docx,*.md")
    args = ap.parse_args(argv)

    paths: List[Path] = []
    patterns = [p.strip() for p in args.glob.split(",") if p.strip()]
    for raw in args.inputs:
        p = Path(raw)
        if p.is_dir():
            for pat in patterns:
                paths.extend(sorted(p.rglob(pat)))
        elif p.exists():
            paths.append(p)
        else:
            print(f"[warn] not found: {raw}", file=sys.stderr)

    records: List[Dict[str, Any]] = []
    stats: List[Dict[str, Any]] = []
    for path in paths:
        text, meta = extract_text_from_file(path, ocr=not args.no_ocr)
        findings = parse_findings(text, path.name)
        records.append(to_processed_record(path, text, findings, meta))
        stats.append({
            "file": path.name,
            "text_len": len(text),
            "findings": len(findings),
            "method": meta.get("method"),
            "ocr_used": meta.get("ocr_used"),
            "titles": [f.title for f in findings[:25]],
            "warnings": meta.get("warnings", []),
        })
        print(f"{path.name}: findings={len(findings)} text_len={len(text)} method={meta.get('method')}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    st = Path(args.stats)
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved: {out}")
    print(f"Stats: {st}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
