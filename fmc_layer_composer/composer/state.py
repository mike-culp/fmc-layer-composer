from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def get_config_path() -> Path:
    return Path.home() / ".fmc_layer_composer" / "config.json"


def load_user_config() -> dict[str, Any]:
    path = get_config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {key: data[key] for key in ("fmc_host", "verify_tls", "last_domain_uuid", "last_domain_name") if key in data}


def save_user_config(config: dict[str, Any]) -> None:
    allowed = {key: config[key] for key in ("fmc_host", "verify_tls", "last_domain_uuid", "last_domain_name") if key in config}
    path = get_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(allowed, indent=2, sort_keys=True), encoding="utf-8")


def build_plan_signature(
    fmc_host: str,
    domain_uuid: str,
    selected_source_acps: list[dict],
    csv_filename: str,
    csv_sha256: str,
    target_acp_name: str,
    match_options: dict[str, Any],
) -> str:
    payload = {
        "fmc_host": (fmc_host or "").strip(),
        "domain_uuid": domain_uuid or "",
        "selected_source_acp_ids": [str(acp.get("id", "")) for acp in selected_source_acps],
        "selected_source_acp_priority": [
            {"id": str(acp.get("id", "")), "name": str(acp.get("name", "")), "priority": index}
            for index, acp in enumerate(selected_source_acps, start=1)
        ],
        "csv_filename": csv_filename or "",
        "csv_sha256": csv_sha256 or "",
        "target_acp_name": target_acp_name or "",
        "match_options": match_options,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def make_rule_key(csv_order: int, csv_rule_name: str) -> str:
    return f"{csv_order}:{csv_rule_name}"
