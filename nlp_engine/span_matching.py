"""Flexible phrase and CVE span matching for weak supervision alignment."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Set, Tuple

# Severity / risk aliases commonly seen across pentest vendors.
_SEVERITY_ALIASES: Dict[str, List[str]] = {
    "critical": ["critical", "crit", "severe", "p1"],
    "high": ["high", "p2"],
    "medium": ["medium", "moderate", "p3"],
    "low": ["low", "informational", "info", "p4"],
}


def _dedupe_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    seen: Set[Tuple[int, int]] = set()
    out: List[Tuple[int, int]] = []
    for s, e in sorted(spans, key=lambda x: (x[0], x[1])):
        if (s, e) not in seen:
            seen.add((s, e))
            out.append((s, e))
    return out


def expand_phrase_variants(phrase: str) -> List[str]:
    """Return search variants for a label phrase (literal + abbreviations)."""
    phrase = phrase.strip()
    if not phrase:
        return []

    variants: List[str] = [phrase]
    m = re.match(r"^(?P<full>.+?)\s*\((?P<abbr>[^)]+)\)\s*$", phrase)
    if m:
        full = m.group("full").strip()
        abbr = m.group("abbr").strip()
        if full:
            variants.append(full)
        if abbr:
            variants.append(abbr)

    # Drop trailing punctuation-only duplicates
    cleaned: List[str] = []
    seen: Set[str] = set()
    for v in variants:
        key = v.casefold()
        if key and key not in seen and len(v) >= 2:
            seen.add(key)
            cleaned.append(v)
    return cleaned


def expand_severity_variants(severity: str) -> List[str]:
    """Expand severity label with common vendor aliases."""
    base = expand_phrase_variants(severity)
    key = severity.strip().casefold()
    for canon, aliases in _SEVERITY_ALIASES.items():
        if key == canon or key in aliases:
            base.extend(aliases)
            base.append(canon.title())
            break
    seen: Set[str] = set()
    out: List[str] = []
    for v in base:
        k = v.casefold()
        if k not in seen:
            seen.add(k)
            out.append(v)
    return out


def _flexible_phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Build regex allowing flexible whitespace between words."""
    tokens = [re.escape(t) for t in phrase.split() if t]
    if not tokens:
        return re.compile(r"a^")
    if len(tokens) == 1:
        body = tokens[0]
    else:
        body = r"\s+".join(tokens)
    return re.compile(rf"(?<!\w){body}(?!\w)", re.IGNORECASE)


def find_literal_spans(text: str, phrase: str) -> List[Tuple[int, int]]:
    """Find all literal occurrences (case-insensitive)."""
    if not phrase or not text:
        return []
    pattern = re.compile(re.escape(phrase), re.IGNORECASE)
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def find_flexible_spans(text: str, phrase: str) -> List[Tuple[int, int]]:
    """Find spans allowing flexible whitespace between words."""
    if not phrase or not text:
        return []
    pattern = _flexible_phrase_pattern(phrase)
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def normalize_cve_token(cve: str) -> str:
    """Normalize CVE to ``CVE-YYYY-NNNN`` when possible.

    Supported examples:
    - CVE-2021-44228
    - CVE 2021 44228
    - CVE_2021_44228
    - cve-2021-44228
    """
    s = cve.strip()
    m = re.match(r"^cve[\s_-]?(\d{4})[\s_-]?(\d{4,7})\s*$", s, re.IGNORECASE)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return s


def cve_flexible_pattern(cve_value: str) -> re.Pattern[str]:
    """Build regex for CVE with optional separators/spaces/underscores."""
    norm = normalize_cve_token(cve_value)
    m = re.match(r"^CVE-(\d{4})-(\d{4,7})$", norm, re.IGNORECASE)

    if not m:
        return re.compile(re.escape(cve_value), re.IGNORECASE)

    year, seq = m.group(1), m.group(2)

    return re.compile(
        rf"\b(?i:cve)[\s_-]?{year}[\s_-]?{seq}\b",
        re.IGNORECASE,
    )

def cve_flexible_pattern(cve_value: str) -> re.Pattern[str]:
    """Build regex for CVE with optional separators/spaces."""
    norm = normalize_cve_token(cve_value)
    m = re.match(r"^CVE-(\d{4})-(\d+)$", norm, re.IGNORECASE)
    if not m:
        return re.compile(re.escape(cve_value), re.IGNORECASE)
    year, seq = m.group(1), m.group(2)
    return re.compile(
        rf"\b(?i:cve)[\s-]?{year}[\s-]?{seq}\b",
        re.IGNORECASE,
    )


def find_cve_spans(text: str, cve_value: str) -> List[Tuple[int, int]]:
    """Locate CVE mentions with flexible formatting."""
    if not text or not cve_value:
        return []
    spans: List[Tuple[int, int]] = []
    for variant in {normalize_cve_token(cve_value), cve_value.strip()}:
        spans.extend(find_literal_spans(text, variant))
    pat = cve_flexible_pattern(cve_value)
    spans.extend((m.start(), m.end()) for m in pat.finditer(text))
    return _dedupe_spans(spans)


def _fuzzy_window_match(text: str, phrase: str, threshold: float) -> List[Tuple[int, int]]:
    """Sliding-window fuzzy match for long phrases (stdlib, no extra deps)."""
    if len(phrase) < 12 or threshold <= 0:
        return []

    words = text.split()
    phrase_words = phrase.split()
    if len(phrase_words) < 2:
        return []

    win = len(phrase_words)
    max_win = win + 3
    matches: List[Tuple[int, int]] = []

    for wsize in range(win, min(max_win, len(words)) + 1):
        for i in range(0, len(words) - wsize + 1):
            window = " ".join(words[i : i + wsize])
            ratio = SequenceMatcher(None, phrase.casefold(), window.casefold()).ratio()
            if ratio >= threshold:
                start = text.find(window)
                if start >= 0:
                    matches.append((start, start + len(window)))
    return _dedupe_spans(matches)


def find_phrase_spans(
    text: str,
    phrase: str,
    *,
    fuzzy_threshold: float = 0.0,
    severity: bool = False,
) -> List[Tuple[int, int]]:
    """Find spans using variants, flexible whitespace, and optional fuzzy match."""
    variants = expand_severity_variants(phrase) if severity else expand_phrase_variants(phrase)
    spans: List[Tuple[int, int]] = []

    for variant in variants:
        spans.extend(find_literal_spans(text, variant))
        if " " in variant:
            spans.extend(find_flexible_spans(text, variant))

    if not spans and fuzzy_threshold > 0:
        spans.extend(_fuzzy_window_match(text, phrase, fuzzy_threshold))

    return _dedupe_spans(spans)
