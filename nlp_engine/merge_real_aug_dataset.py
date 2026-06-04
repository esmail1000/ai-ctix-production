#!/usr/bin/env python3
"""Merge reviewed real CTIX training data with augmented synthetic CTIX data.

Default output is intended for the next stronger NER training round:
  data/processed/processed_reports_real_aug_v1.json

Why this exists:
- real_gold_v1 is high-quality but small, so recall stays weak.
- augmented data is larger and teaches the model more label patterns.
- oversampling real records keeps the model grounded in real reports.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

Record = Dict[str, Any]


def load_json_list(path: Path) -> List[Record]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON list in {path}, got {type(data).__name__}")
    return [x for x in data if isinstance(x, dict)]


def normalize_text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def record_key(record: Record) -> str:
    # Stable dedupe key. Keep different findings from the same PDF separate.
    source_file = normalize_text(record.get("source_file") or record.get("file") or "").lower()
    finding_id = normalize_text(record.get("finding_id") or "").lower()
    title = normalize_text(record.get("finding_title") or " ".join(record.get("vulnerabilities") or [])).lower()
    text = normalize_text(record.get("report_text") or "").lower()[:500]
    if source_file and finding_id:
        return f"srcid::{source_file}::{finding_id}"
    if source_file and title:
        return f"srctitle::{source_file}::{title}"
    return f"text::{text}"


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def clean_record(record: Record, dataset_name: str, copy_index: int = 1) -> Record:
    item: Record = copy.deepcopy(record)
    item["source_dataset"] = dataset_name
    item["dataset_version"] = "processed_reports_real_aug_v1"

    # Keep train/preprocessing-compatible fields present.
    item["report_text"] = normalize_text(item.get("report_text"))
    for key in [
        "severity",
        "risk_level",
        "vulnerabilities",
        "cves",
        "cwes",
        "impact",
        "remediation",
        "affected_components",
        "urls",
        "domains",
        "ips",
        "ports",
        "products",
        "versions",
    ]:
        if key in item:
            item[key] = [str(x).strip() for x in ensure_list(item.get(key)) if str(x).strip()]

    # Make duplicated/oversampled rows unique in metadata only.
    if copy_index > 1:
        base_file = normalize_text(item.get("file") or item.get("source_file") or f"{dataset_name}_record")
        if "." in base_file:
            stem, ext = base_file.rsplit(".", 1)
            item["file"] = f"{stem}__sample_{copy_index:02d}.{ext}"
        else:
            item["file"] = f"{base_file}__sample_{copy_index:02d}"
        if item.get("finding_id"):
            item["finding_id"] = f"{item['finding_id']}__sample_{copy_index:02d}"

    return item


def weighted_records(records: Sequence[Record], weight: int, dataset_name: str) -> List[Record]:
    out: List[Record] = []
    for copy_index in range(1, max(1, weight) + 1):
        for record in records:
            cleaned = clean_record(record, dataset_name=dataset_name, copy_index=copy_index)
            if cleaned.get("report_text"):
                out.append(cleaned)
    return out


def dedupe(records: Iterable[Record]) -> List[Record]:
    seen = set()
    out: List[Record] = []
    for record in records:
        key = record_key(record)
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge real gold CTIX dataset with augmented synthetic dataset.")
    parser.add_argument("--real", default="data/processed/processed_reports_real_gold_v1.json")
    parser.add_argument("--aug", default="data/processed/processed_reports_augmented.json")
    parser.add_argument("--output", default="data/processed/processed_reports_real_aug_v1.json")
    parser.add_argument("--stats", default="data/processed/processed_reports_real_aug_v1_stats.json")
    parser.add_argument("--real-weight", type=int, default=3, help="Oversample real gold records this many times. Default: 3")
    parser.add_argument("--aug-weight", type=int, default=1, help="Oversample augmented records this many times. Default: 1")
    parser.add_argument("--no-dedupe", action="store_true", help="Do not dedupe before weighting. Usually not needed.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    real_path = Path(args.real)
    aug_path = Path(args.aug)
    out_path = Path(args.output)
    stats_path = Path(args.stats)

    try:
        real_records = load_json_list(real_path)
        aug_records = load_json_list(aug_path)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    real_clean = [clean_record(r, "real_gold_v1") for r in real_records if normalize_text(r.get("report_text"))]
    aug_clean = [clean_record(r, "augmented_v1") for r in aug_records if normalize_text(r.get("report_text"))]

    if not args.no_dedupe:
        real_clean = dedupe(real_clean)
        aug_clean = dedupe(aug_clean)

    merged = weighted_records(real_clean, args.real_weight, "real_gold_v1") + weighted_records(aug_clean, args.aug_weight, "augmented_v1")
    random.Random(args.seed).shuffle(merged)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")

    source_files = sorted({str(r.get("source_file") or "") for r in real_clean if r.get("source_file")})
    stats = {
        "dataset_version": "processed_reports_real_aug_v1",
        "real_input": str(real_path),
        "aug_input": str(aug_path),
        "output": str(out_path),
        "real_records_input": len(real_records),
        "real_records_after_clean_dedupe": len(real_clean),
        "aug_records_input": len(aug_records),
        "aug_records_after_clean_dedupe": len(aug_clean),
        "real_weight": args.real_weight,
        "aug_weight": args.aug_weight,
        "merged_records_written": len(merged),
        "real_gold_source_files": source_files,
    }
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    print("Merge complete.")
    print(f"Real records: {len(real_clean)} x {args.real_weight} = {len(real_clean) * max(1, args.real_weight)}")
    print(f"Aug records:  {len(aug_clean)} x {args.aug_weight} = {len(aug_clean) * max(1, args.aug_weight)}")
    print(f"Total written: {len(merged)}")
    print(f"Saved JSON: {out_path}")
    print(f"Saved stats: {stats_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
