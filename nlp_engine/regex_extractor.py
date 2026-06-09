"""Regex/rule extraction for cybersecurity indicators and CTI fields.

This is the deterministic fallback layer used by inference when the trained NER
model is missing or has low coverage. It preserves the old dashboard keys and
adds the expanded CTI schema keys used by the upgraded NLP pipeline.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set, Tuple
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\b(?i:cve)[\s_-]?(?P<year>\d{4})[\s_-]?(?P<seq>\d{4,7})\b")
_CWE_RE = re.compile(r"\bCWE-(?P<num>\d{1,6})\b", re.IGNORECASE)

_CVSS_VECTOR_RE = re.compile(
    r"\bCVSS:[0-9]\.[0-9]/[A-Z]{1,3}:[A-Z0-9]+(?:/[A-Z]{1,3}:[A-Z0-9]+)+\b",
    re.IGNORECASE,
)

_CVSS_SCORE_RE = re.compile(
    r"\b(?:CVSS(?:\s*v?[0-9](?:\.[0-9])?)?|base)\s*(?:score|severity)?\s*[:=]?\s*"
    r"(?P<score>10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
    re.IGNORECASE,
)

_CPE_RE = re.compile(r"\bcpe:2\.3:[aho]:[^\s,;\]\)\"']+", re.IGNORECASE)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

_IP_RANGE_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-9]|[12]\d|3[0-2])\b"
)

_URL_RE = re.compile(r"\bhttps?://[^\s\]\)\"'>,]+", re.IGNORECASE)

_DOMAIN_RE = re.compile(
    r"\b(?=[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63})\b",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

_PORT_AFTER_HOST_RE = re.compile(
    r"(?:\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"|[a-z0-9][-a-z0-9.]*\.[a-z]{2,}):(\d{1,5})\b",
    re.IGNORECASE,
)

_PORT_WORD_RE = re.compile(r"\b(?:port|tcp|udp)\s*[:/#-]?\s*(\d{1,5})\b", re.IGNORECASE)

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")

_UNIX_PATH_RE = re.compile(
    r"(?<!https:)\b/(?:etc|var|tmp|usr|home|opt|srv|bin|sbin|root)/[^\s\]\)\"'<>]+"
)

_FILE_NAME_RE = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|sh|py|jar|war|php|jsp|aspx|conf|config|log|pem|key|zip|tar|gz)\b",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(
    r"\b(?:v(?:ersion)?\.?\s*)?(?P<version>\d+(?:\.\d+){1,4}[A-Za-z0-9._-]*)\b",
    re.IGNORECASE,
)


_SEVERITY_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Critical", r"\bcritical\b|\bp1\b"),
    ("High", r"\bhigh\b|\bp2\b"),
    ("Medium", r"\bmedium\b|\bmoderate\b|\bp3\b"),
    ("Low", r"\blow\b|\binformational\b|\binfo\b|\bp4\b"),
)

_VULN_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("NoSQL Injection", r"\bno\s*sql\s+injection\b|\bnosql\s+injection\b"),
    ("SQL Injection", r"\bsql\s+injection\b|\bsqli\b"),
    ("Cross-Site Scripting", r"\bcross[-\s]?site\s+scripting\b|\bxss\b"),
    ("Remote Code Execution", r"\bremote\s+code\s+execution\b|\brce\b"),
    ("Command Injection", r"\bcommand\s+injection\b|\bos\s+command\s+injection\b"),
    ("Server-Side Request Forgery", r"\bserver[-\s]?side\s+request\s+forgery\b|\bssrf\b"),
    ("Cross-Site Request Forgery", r"\bcross[-\s]?site\s+request\s+forgery\b|\bcsrf\b"),
    ("XML External Entity", r"\bxml\s+external\s+entity\b|\bxxe\b"),
    ("Path Traversal", r"\bpath\s+traversal\b|\bdirectory\s+traversal\b"),
    ("Authentication Bypass", r"\bauthentication\s+bypass\b|\bauth\s+bypass\b"),
    ("Authorization Bypass", r"\bauthorization\s+bypass\b"),
    ("Broken Access Control", r"\bbroken\s+access\s+control\b"),
    ("Insecure Direct Object Reference", r"\binsecure\s+direct\s+object\s+reference\b|\bidor\b"),
    ("Insecure Deserialization", r"\binsecure\s+deserialization\b"),
    ("Open Redirect", r"\bopen\s+redirect\b"),
    ("File Inclusion", r"\blocal\s+file\s+inclusion\b|\bremote\s+file\s+inclusion\b|\blfi\b|\brfi\b"),
    ("File Upload Vulnerability", r"\bunrestricted\s+file\s+upload\b|\bfile\s+upload\s+vulnerab"),
    ("Buffer Overflow", r"\bbuffer\s+overflow\b"),
    ("Memory Corruption", r"\bmemory\s+corruption\b"),
    ("Privilege Escalation", r"\bprivilege\s+escalation\b"),
    ("Denial of Service", r"\bdenial\s+of\s+service\b|\bdos\b|\bddos\b"),
    ("Sensitive Data Exposure", r"\bsensitive\s+data\s+exposure\b"),
    ("Information Disclosure", r"\binformation\s+disclosure\b|\bdata\s+leak(?:age)?\b"),
    ("Security Misconfiguration", r"\bsecurity\s+misconfiguration\b|\bmisconfiguration\b"),
)

_IMPACT_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Data Breach", r"\bdata\s+breach\b|\bdata\s+theft\b"),
    ("Remote Code Execution", r"\bremote\s+code\s+execution\b|\brce\b"),
    ("Unauthorized Access", r"\bunauthori[sz]ed\s+access\b"),
    ("Privilege Escalation", r"\bprivilege\s+escalation\b"),
    ("Information Disclosure", r"\binformation\s+disclosure\b|\bdata\s+leak(?:age)?\b"),
    ("Full System Compromise", r"\bfull\s+system\s+compromise\b|\bsystem\s+compromise\b"),
    ("Service Disruption", r"\bservice\s+disruption\b|\bdenial\s+of\s+service\b"),
    ("Account Takeover", r"\baccount\s+takeover\b|\bato\b"),
    ("Credential Theft", r"\bcredential\s+theft\b|\bcredential\s+exposure\b"),
    ("Data Loss", r"\bdata\s+loss\b"),
    ("Lateral Movement", r"\blateral\s+movement\b"),
)

_ATTACK_VECTOR_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Remote Unauthenticated", r"\bremote\s+unauthenticated\b|\bunauthenticated\s+remote\b"),
    ("Remote Authenticated", r"\bremote\s+authenticated\b|\bauthenticated\s+remote\b"),
    ("Network", r"\bnetwork\s+attack\b|\bnetwork\s+vector\b|\bAV:N\b"),
    ("Adjacent Network", r"\badjacent\s+network\b|\bAV:A\b"),
    ("Local", r"\blocal\s+attack\b|\blocal\s+access\b|\bAV:L\b"),
    ("Physical", r"\bphysical\s+access\b|\bAV:P\b"),
)

_EXPLOIT_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Exploit Available", r"\bpublic\s+exploit\b|\bexploit\s+available\b|\bknown\s+exploited\b|\bweaponized\b"),
    ("Proof of Concept", r"\bproof\s+of\s+concept\b|\bpoc\b"),
    ("Metasploit Module", r"\bmetasploit\b"),
)

_REMEDIATION_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Apply vendor patch", r"\bapply\s+(?:the\s+)?(?:vendor\s+)?patch\b|\binstall\s+(?:the\s+)?(?:latest\s+)?patch\b"),
    ("Upgrade to a fixed version", r"\bupgrade\s+to\s+(?:a\s+)?(?:fixed|patched|latest)\s+version\b|\bupdate\s+to\s+(?:the\s+)?latest\s+version\b"),
    ("Disable vulnerable component", r"\bdisable\s+(?:the\s+)?vulnerable\s+component\b"),
    ("Restrict network access", r"\brestrict\s+network\s+access\b|\blimit\s+access\s+to\s+trusted\s+hosts\b"),
    ("Sanitize user input", r"\bsanitize\s+user\s+input\b|\bvalidate\s+user\s+input\b"),
    ("Use parameterized queries", r"\bparameteri[sz]ed\s+quer(?:y|ies)\b|\bprepared\s+statements\b"),
    ("Enable multi-factor authentication", r"\benable\s+(?:mfa|multi[-\s]?factor\s+authentication)\b"),
    ("Rotate credentials", r"\brotate\s+credentials\b|\breset\s+passwords\b"),
)

_PRODUCT_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("Apache Struts", r"\bApache\s+Struts\b|\bStruts\b"),
    ("Apache Tomcat", r"\bApache\s+Tomcat\b|\bTomcat\b"),
    ("Apache HTTP Server", r"\bApache\s+HTTP\s+Server\b|\bhttpd\b"),
    ("Log4j", r"\bLog4j\b"),
    ("OpenSSL", r"\bOpenSSL\b"),
    ("OpenSSH", r"\bOpenSSH\b"),
    ("Nginx", r"\bNginx\b"),
    ("Microsoft Exchange", r"\bMicrosoft\s+Exchange\b|\bExchange\s+Server\b"),
    ("Windows", r"\bMicrosoft\s+Windows\b|\bWindows\s+Server\b|\bWindows\b"),
    ("Linux", r"\bLinux\b"),
    ("WordPress", r"\bWordPress\b"),
    ("Drupal", r"\bDrupal\b"),
    ("Joomla", r"\bJoomla\b"),
    ("PHP", r"\bPHP\b"),
    ("MySQL", r"\bMySQL\b"),
    ("PostgreSQL", r"\bPostgreSQL\b|\bPostgres\b"),
    ("MongoDB", r"\bMongoDB\b"),
    ("Redis", r"\bRedis\b"),
    ("Elasticsearch", r"\bElasticsearch\b|\bElastic\s+Search\b"),
    ("Kubernetes", r"\bKubernetes\b|\bk8s\b"),
    ("Docker", r"\bDocker\b"),
    ("Jenkins", r"\bJenkins\b"),
    ("GitLab", r"\bGitLab\b"),
    ("Jira", r"\bJira\b"),
    ("Confluence", r"\bConfluence\b"),
    ("Spring Framework", r"\bSpring\s+Framework\b|\bSpring4Shell\b"),
)

_DOMAIN_BLOCKLIST: Set[str] = {
    "example.com", "example.org", "example.net", "localhost", "127.0.0.1",
    "schemas.microsoft.com", "www.w3.org", "github.com", "google.com", "mozilla.org",
}

_FAKE_TLD_SUFFIXES = (
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".doc", ".docx", ".xml", ".json",
    ".yaml", ".yml", ".html", ".css", ".js", ".log", ".conf", ".config",
)


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []

    for item in items:
        value = str(item).strip()
        if not value:
            continue

        key = value.casefold()
        if key not in seen:
            seen.add(key)
            out.append(value)

    return out


def _extract_named_patterns(text: str, patterns: Tuple[Tuple[str, str], ...]) -> List[str]:
    return _dedupe_preserve_order(
        canonical
        for canonical, pattern in patterns
        if re.search(pattern, text or "", re.IGNORECASE)
    )


def _range_spans(pattern: re.Pattern[str], text: str) -> List[Tuple[int, int]]:
    return [(m.start(), m.end()) for m in pattern.finditer(text or "")]


def _overlaps_any(start: int, end: int, spans: List[Tuple[int, int]]) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _valid_port(value: str) -> bool:
    try:
        port = int(value)
    except ValueError:
        return False

    return 1 <= port <= 65535


def _clean_url(value: str) -> str:
    return value.strip().strip(" \t\r\n\"'`“”‘’<>").rstrip(".,;:)]}")


def _hostname_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip(". ").lower()
    except ValueError:
        return ""


def _is_blocked_domain(domain: str) -> bool:
    d = domain.strip(". ").lower()

    if not d or d in _DOMAIN_BLOCKLIST or d.count(".") < 1:
        return True

    if any(d.endswith(suffix) for suffix in _FAKE_TLD_SUFFIXES):
        return True

    labels = d.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return True

    return len(labels[-1]) > 24


def extract_cves(text: str) -> List[str]:
    return _dedupe_preserve_order(
        f"CVE-{m.group('year')}-{m.group('seq')}"
        for m in _CVE_RE.finditer(text or "")
    )


def extract_cwes(text: str) -> List[str]:
    return _dedupe_preserve_order(
        f"CWE-{m.group('num')}"
        for m in _CWE_RE.finditer(text or "")
    )


def extract_cvss_vectors(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0).upper()
        for m in _CVSS_VECTOR_RE.finditer(text or "")
    )


def extract_cvss_scores(text: str) -> List[str]:
    scores: List[str] = []
    text = text or ""

    for m in _CVSS_SCORE_RE.finditer(text):
        if m.end() < len(text) and text[m.end():m.end() + 1] == "/":
            continue

        try:
            score = float(m.group("score"))
        except ValueError:
            continue

        if 0 <= score <= 10:
            scores.append(f"{score:.1f}".rstrip("0").rstrip("."))

    return _dedupe_preserve_order(scores)


def extract_cpes(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0).rstrip(".,;)]}")
        for m in _CPE_RE.finditer(text or "")
    )


def extract_ip_ranges(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0)
        for m in _IP_RANGE_RE.finditer(text or "")
    )


def extract_ips(text: str) -> List[str]:
    text = text or ""
    range_spans = _range_spans(_IP_RANGE_RE, text)
    ips: List[str] = []

    for m in _IPV4_RE.finditer(text):
        if _overlaps_any(m.start(), m.end(), range_spans):
            continue

        ip = m.group(0)
        if not ip.startswith("0.") and ip != "255.255.255.255":
            ips.append(ip)

    return _dedupe_preserve_order(ips)


def extract_urls(text: str) -> List[str]:
    return _dedupe_preserve_order(
        _clean_url(m.group(0))
        for m in _URL_RE.finditer(text or "")
    )


def extract_emails(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0).lower()
        for m in _EMAIL_RE.finditer(text or "")
    )


def extract_domains(text: str, *, filter_fp: bool = True, include_url_hosts: bool = True) -> List[str]:
    text = text or ""
    domains: List[str] = []
    url_spans = _range_spans(_URL_RE, text)
    email_spans = _range_spans(_EMAIL_RE, text)

    if include_url_hosts:
        for url in extract_urls(text):
            host = _hostname_from_url(url)
            if host and not (filter_fp and _is_blocked_domain(host)):
                domains.append(host)

    for m in _DOMAIN_RE.finditer(text):
        domain = m.group(0).strip(". ").lower()

        if filter_fp:
            if _is_blocked_domain(domain):
                continue

            if _overlaps_any(m.start(), m.end(), url_spans + email_spans):
                continue

        domains.append(domain)

    return _dedupe_preserve_order(domains)


def extract_ports(text: str, *, strict: bool = True) -> List[str]:
    text = text or ""
    ports: List[str] = []

    for pattern in (_PORT_AFTER_HOST_RE, _PORT_WORD_RE):
        for m in pattern.finditer(text):
            p = m.group(1)
            if _valid_port(p):
                ports.append(str(int(p)))

    if not strict:
        for m in re.finditer(r":(\d{1,5})\b", text):
            p = m.group(1)
            if _valid_port(p):
                ports.append(str(int(p)))

    return _dedupe_preserve_order(ports)


def extract_hashes(text: str) -> Dict[str, List[str]]:
    text = text or ""
    sha256_spans = _range_spans(_SHA256_RE, text)
    sha1_spans = _range_spans(_SHA1_RE, text)

    sha256 = [m.group(0).lower() for m in _SHA256_RE.finditer(text)]

    sha1 = [
        m.group(0).lower()
        for m in _SHA1_RE.finditer(text)
        if not _overlaps_any(m.start(), m.end(), sha256_spans)
    ]

    md5 = [
        m.group(0).lower()
        for m in _MD5_RE.finditer(text)
        if not _overlaps_any(m.start(), m.end(), sha256_spans + sha1_spans)
    ]

    result = {
        "md5_hashes": _dedupe_preserve_order(md5),
        "sha1_hashes": _dedupe_preserve_order(sha1),
        "sha256_hashes": _dedupe_preserve_order(sha256),
    }

    result["hashes"] = _dedupe_preserve_order(
        result["md5_hashes"] + result["sha1_hashes"] + result["sha256_hashes"]
    )

    return result


def extract_file_paths(text: str) -> List[str]:
    text = text or ""

    found = [
        m.group(0).rstrip(".,;:)]}")
        for m in _WINDOWS_PATH_RE.finditer(text)
    ]

    found += [
        m.group(0).rstrip(".,;:)]}")
        for m in _UNIX_PATH_RE.finditer(text)
    ]

    return _dedupe_preserve_order(x for x in found if len(x) > 2)


def extract_file_names(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0).rstrip(".,;:)]}")
        for m in _FILE_NAME_RE.finditer(text or "")
    )


def extract_versions(text: str) -> List[str]:
    text = text or ""

    blocked = (
        _range_spans(_CVE_RE, text)
        + _range_spans(_IPV4_RE, text)
        + _range_spans(_IP_RANGE_RE, text)
        + _range_spans(_CVSS_VECTOR_RE, text)
        + _range_spans(_CVSS_SCORE_RE, text)
    )

    values: List[str] = []

    for m in _VERSION_RE.finditer(text):
        if _overlaps_any(m.start(), m.end(), blocked):
            continue

        values.append(m.group("version"))

    return _dedupe_preserve_order(values)


def extract_severities(text: str) -> List[str]:
    return _extract_named_patterns(text, _SEVERITY_PATTERNS)


def extract_vulnerability_types(text: str) -> List[str]:
    return _extract_named_patterns(text, _VULN_PATTERNS)


def extract_impacts(text: str) -> List[str]:
    return _extract_named_patterns(text, _IMPACT_PATTERNS)


def extract_attack_vectors(text: str) -> List[str]:
    return _extract_named_patterns(text, _ATTACK_VECTOR_PATTERNS)


def extract_exploits(text: str) -> List[str]:
    return _extract_named_patterns(text, _EXPLOIT_PATTERNS)


def extract_remediations(text: str) -> List[str]:
    return _extract_named_patterns(text, _REMEDIATION_PATTERNS)


def extract_exploitation_steps(text: str) -> List[str]:
    """Extract concise reproduction/exploitation steps from pentest prose."""
    text = text or ""
    blocks: List[str] = []

    label_re = re.compile(
        r"\b(?:exploitation\s+steps|steps\s+to\s+reproduce|reproduction\s+steps|proof\s+of\s+concept|poc|attack\s+scenario)\s*:\s*"
        r"(?P<body>.*?)(?=\n\s*(?:Impact|Remediation|Recommendation|Severity|Finding|Vulnerability|References?)\s*:|\Z)",
        re.IGNORECASE | re.DOTALL,
    )

    for match in label_re.finditer(text):
        blocks.append(match.group("body"))

    search_text = "\n".join(blocks) if blocks else text
    steps: List[str] = []

    for line in search_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = re.match(r"^(?:step\s*)?\d+[.)-]\s+(.{8,260})$", line, flags=re.IGNORECASE)
        if m:
            steps.append(m.group(1))
            continue

        m = re.match(r"^[-*•]\s+(.{8,260})$", line)
        if m:
            steps.append(m.group(1))

    if not steps and blocks:
        for sentence in re.split(r"(?<=[.!?])\s+", " ".join(blocks)):
            cleaned = sentence.strip()
            if 8 <= len(cleaned) <= 260:
                steps.append(cleaned)

    return _dedupe_preserve_order(steps)[:12]


def extract_products(text: str) -> List[str]:
    return _extract_named_patterns(text, _PRODUCT_PATTERNS)


def extract_mitre_techniques(text: str) -> List[str]:
    return _dedupe_preserve_order(
        m.group(0).upper()
        for m in _MITRE_TECHNIQUE_RE.finditer(text or "")
    )


def extract_all_structured(
    text: str,
    *,
    filter_domain_fp: bool = True,
    strict_ports: bool = True,
) -> Dict[str, List[str]]:
    text = text or ""
    hashes = extract_hashes(text)
    exploits = extract_exploits(text)
    remediations = extract_remediations(text)

    result: Dict[str, List[str]] = {
        "cve_ids": extract_cves(text),
        "vulnerability_types": extract_vulnerability_types(text),
        "severity": extract_severities(text),
        "impacts": extract_impacts(text),
        "ips": extract_ips(text),
        "urls": extract_urls(text),
        "domains": extract_domains(text, filter_fp=filter_domain_fp),
        "ports": extract_ports(text, strict=strict_ports),

        "cwe_ids": extract_cwes(text),
        "cvss_scores": extract_cvss_scores(text),
        "cvss_vectors": extract_cvss_vectors(text),
        "cpes": extract_cpes(text),
        "ip_ranges": extract_ip_ranges(text),
        "emails": extract_emails(text),
        "file_paths": extract_file_paths(text),
        "file_names": extract_file_names(text),
        "mitre_techniques": extract_mitre_techniques(text),
        "attack_vectors": extract_attack_vectors(text),
        "exploitation_steps": extract_exploitation_steps(text),
        "exploits": exploits,
        "exploit_available": ["true"] if exploits else [],
        "remediations": remediations,
        "mitigations": remediations,
        "patches": [
            x for x in remediations
            if "patch" in x.casefold() or "upgrade" in x.casefold()
        ],
        "products": extract_products(text),
        "versions": extract_versions(text),
    }

    result.update(hashes)
    return result