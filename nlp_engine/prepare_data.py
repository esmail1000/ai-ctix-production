"""Prepare raw report text from PDFs and report coverage statistics."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from text_loader import batch_extract_pdfs
from utils import write_json

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract PDF reports to data/raw/*.txt")
    p.add_argument("--processed_json", type=Path, required=True)
    p.add_argument("--raw_pdf_dir", type=Path, required=True, help="Folder with pentest PDF files")
    p.add_argument("--raw_text_dir", type=Path, default=Path("data/raw"))
    p.add_argument("--report_json", type=Path, default=Path("data/processed/extraction_report.json"))
    return p.parse_args()


def main() -> None:
    args = parse_args()
    stats = batch_extract_pdfs(args.processed_json, args.raw_pdf_dir, args.raw_text_dir)
    write_json(args.report_json, stats)
    s = stats["summary"]
    logger.info(
        "Done: extracted=%s already_cached=%s pdf_missing=%s empty=%s",
        s["extracted_count"],
        s["cached_count"],
        s["pdf_missing_count"],
        s["empty_count"],
    )
    logger.info("Report written to %s", args.report_json)


if __name__ == "__main__":
    main()
