from __future__ import annotations

import re
from pathlib import Path


DISABLED_MARKER_RE = re.compile(r"\s*\[disabled\]\s*", re.IGNORECASE)


def strip_disabled_marker(name: str) -> tuple[str, bool]:
    cleaned, count = DISABLED_MARKER_RE.subn(" ", name or "")
    return " ".join(cleaned.split()).strip(), count > 0


def split_multi_value(value: object) -> list[str]:
    if value is None:
        return []
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "any"}:
        return [] if text.lower() != "any" else ["any"]
    parts = re.split(r"[;,|\n]+", text)
    return [part.strip() for part in parts if part.strip()]


def normalize_layer_name(filename: str) -> str:
    stem = Path(filename).stem.strip()
    for suffix in ("-layer", "_layer", " layer"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-._")
    return normalized.lower() or "new-layer"


def safe_target_name(name: str) -> str:
    return " ".join((name or "").split()).strip()


def timestamp_for_filename(timestamp: str) -> str:
    return re.sub(r"[^0-9A-Za-z_-]+", "-", timestamp).strip("-")
