"""Resolve raw report text from JSON fields, TXT/PDF files, or structured fallback."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils import ensure_list_str, normalize_report_text, safe_stem

logger = logging.getLogger(__name__)

_TEXT_FIELD_KEYS: Tuple[str, ...] = (
    "report_text",
    "raw_report",
    "text",
    "content",
    "body",
)


def extract_pdf_text(pdf_path: Path) -> str:
    """Extract plain text from a PDF file."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError(
            "PDF extraction requires ``pypdf``. Install with: pip install pypdf"
        ) from exc

    reader = PdfReader(str(pdf_path))
    pages: List[str] = []
    for page in reader.pages:
        page_text = page.extract_text() or ""
        if page_text.strip():
            pages.append(page_text)
    return normalize_report_text("\n".join(pages))


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _cache_extracted_text(cache_dir: Path, stem: str, text: str) -> None:
    if not text.strip():
        return
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{stem}.txt"
    if not cache_path.exists():
        cache_path.write_text(text, encoding="utf-8")


def build_synthetic_report_text(record: Dict[str, Any]) -> str:
    """Build minimal text from structured labels so alignment can still run.

    Used only when no raw report file exists. Each label string is included
    verbatim so automatic BIO span detection can succeed.
    """
    chunks: List[str] = []
    for key in ("severity", "risk_level", "vulnerabilities", "cves", "impact", "attack_vectors"):
        chunks.extend(ensure_list_str(record.get(key)))
    steps: List[str] = []
    steps = ensure_list_str(record.get("exploitation_steps"))
    for step in steps:
        if len(step) >= 12:
            chunks.append(step)
    return normalize_report_text(" ".join(chunks))


def resolve_report_text(
    record: Dict[str, Any],
    raw_text_dir: Optional[Path] = None,
    raw_pdf_dir: Optional[Path] = None,
    cache_extracted: bool = True,
    allow_synthetic_fallback: bool = False,
) -> Tuple[str, str]:
    """Resolve report text and return ``(text, source)``.

    ``source`` is one of: ``json_field``, ``txt_file``, ``pdf_file``,
    ``pdf_cached``, ``synthetic``, or ``missing``.
    """
    for key in _TEXT_FIELD_KEYS:
        val = record.get(key)
        if isinstance(val, str) and val.strip():
            return normalize_report_text(val), "json_field"

    fname = record.get("file")
    if not isinstance(fname, str) or not fname.strip():
        if allow_synthetic_fallback:
            synthetic = build_synthetic_report_text(record)
            if synthetic:
                return synthetic, "synthetic"
        return "", "missing"

    stem = safe_stem(fname)

    if raw_text_dir is not None:
        txt_path = raw_text_dir / f"{stem}.txt"
        if txt_path.is_file():
            return normalize_report_text(_read_text_file(txt_path)), "txt_file"

    if raw_pdf_dir is not None:
        pdf_path = raw_pdf_dir / f"{stem}.pdf"
        if not pdf_path.is_file():
            pdf_path = raw_pdf_dir / fname
        if pdf_path.is_file():
            extracted = extract_pdf_text(pdf_path)
            if extracted and cache_extracted and raw_text_dir is not None:
                _cache_extracted_text(raw_text_dir, stem, extracted)
                return extracted, "pdf_cached"
            if extracted:
                return extracted, "pdf_file"

    if allow_synthetic_fallback:
        synthetic = build_synthetic_report_text(record)
        if synthetic:
            logger.warning(
                "Using synthetic fallback text for %s (%s). Prefer real report files.",
                stem,
                record.get("company", "unknown"),
            )
            return synthetic, "synthetic"

    return "", "missing"


def batch_extract_pdfs(
    processed_json_path: Path,
    raw_pdf_dir: Path,
    raw_text_dir: Path,
) -> Dict[str, Any]:
    """Extract all PDFs referenced in JSON and write ``data/raw/{stem}.txt``."""
    from utils import read_json

    records = read_json(processed_json_path)
    if not isinstance(records, list):
        raise ValueError("processed_reports.json must contain a JSON array")

    raw_text_dir.mkdir(parents=True, exist_ok=True)
    stats: Dict[str, Any] = {
        "total_records": len(records),
        "extracted": [],
        "already_cached": [],
        "pdf_missing": [],
        "empty_extraction": [],
    }

    for rec in records:
        if not isinstance(rec, dict):
            continue
        fname = rec.get("file")
        if not isinstance(fname, str) or not fname.strip():
            continue
        stem = safe_stem(fname)
        out_txt = raw_text_dir / f"{stem}.txt"
        if out_txt.is_file() and out_txt.read_text(encoding="utf-8", errors="replace").strip():
            stats["already_cached"].append(stem)
            continue

        pdf_path = raw_pdf_dir / f"{stem}.pdf"
        if not pdf_path.is_file():
            pdf_path = raw_pdf_dir / fname
        if not pdf_path.is_file():
            stats["pdf_missing"].append(stem)
            continue

        text = extract_pdf_text(pdf_path)
        if not text.strip():
            stats["empty_extraction"].append(stem)
            continue

        out_txt.write_text(text, encoding="utf-8")
        stats["extracted"].append(stem)

    stats["summary"] = {
        "extracted_count": len(stats["extracted"]),
        "cached_count": len(stats["already_cached"]),
        "pdf_missing_count": len(stats["pdf_missing"]),
        "empty_count": len(stats["empty_extraction"]),
    }
    return stats
