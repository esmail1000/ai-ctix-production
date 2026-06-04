"""Shared utilities: I/O, normalization, and reproducibility."""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any, Dict, List, MutableMapping, Union

_WS_RE = re.compile(r"\s+")


def set_seed(seed: int) -> None:
    """Fix random seeds for reproducibility when optional ML deps are installed."""
    random.seed(seed)
    try:
        import numpy as np  # type: ignore

        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch  # type: ignore

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def normalize_report_text(text: str) -> str:
    """Normalize whitespace and strip control noise from report text.

    Collapses consecutive whitespace to single spaces and strips ends.
    Does not lower-case, to preserve case-sensitive indicators (e.g. CVE).
    """
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = _WS_RE.sub(" ", t)
    return t.strip()


def read_json(path: Union[str, Path]) -> Any:
    """Load JSON from a file path."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Union[str, Path], obj: Any, indent: int = 2) -> None:
    """Write JSON object to disk with UTF-8 encoding."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=indent)


def ensure_list_str(value: Any) -> List[str]:
    """Coerce optional string or list field into a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        s = value.strip()
        return [s] if s else []
    if isinstance(value, list):
        out: List[str] = []
        for v in value:
            if v is None:
                continue
            s = str(v).strip()
            if s:
                out.append(s)
        return out
    s = str(value).strip()
    return [s] if s else []


def merge_dict_lists(
    base: MutableMapping[str, List[str]],
    extra: MutableMapping[str, List[str]],
) -> None:
    """Append unique items from ``extra`` into list values of ``base``."""
    for k, vals in extra.items():
        if k not in base:
            base[k] = []
        seen = set(base[k])
        for v in vals:
            if v not in seen:
                base[k].append(v)
                seen.add(v)


def safe_stem(filename: str) -> str:
    """Return file stem for a filename that may include paths or extensions."""
    return Path(filename).stem
