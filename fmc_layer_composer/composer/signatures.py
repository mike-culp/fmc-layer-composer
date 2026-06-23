from __future__ import annotations

import json
from typing import Any


SIGNATURE_FIELDS = (
    "sourceZones",
    "destinationZones",
    "sourceNetworks",
    "destinationNetworks",
    "sourcePorts",
    "destinationPorts",
    "applications",
    "urls",
    "users",
    "sourceSecurityGroupTags",
    "destinationSecurityGroupTags",
    "vlanTags",
    "filePolicy",
    "ipsPolicy",
    "variableSet",
    "timeRangeObjects",
    "sourceDynamicObjects",
    "destinationDynamicObjects",
    "originalSourceNetworks",
    "advancedLogging",
)

LOGGING_FIELDS = (
    "logBegin",
    "logEnd",
    "logFiles",
    "sendEventsToFMC",
    "enableSyslog",
    "syslogSeverity",
    "safeSearch",
    "youTube",
)


def build_rule_signature(rule: dict[str, Any]) -> dict[str, Any]:
    signature: dict[str, Any] = {
        "action": rule.get("action"),
        "enabled": rule.get("enabled"),
    }
    for field in SIGNATURE_FIELDS:
        signature[field] = _extract_value(rule.get(field))
    for field in LOGGING_FIELDS:
        signature[field] = rule.get(field)
    return signature


def normalized_signature_json(signature: dict[str, Any]) -> str:
    return json.dumps(signature, sort_keys=True, separators=(",", ":"), default=str)


def signatures_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return normalized_signature_json(left) == normalized_signature_json(right)


def signature_delta(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for key in sorted(set(left) | set(right)):
        if normalized_signature_json({"value": left.get(key)}) != normalized_signature_json({"value": right.get(key)}):
            delta[key] = {"left": left.get(key), "right": right.get(key)}
    return delta


def _extract_value(value: Any) -> Any:
    if isinstance(value, dict):
        if "objects" in value or "literals" in value:
            return {
                "objects": [_extract_object(item) for item in value.get("objects", [])],
                "literals": [_extract_object(item) for item in value.get("literals", [])],
            }
        return _extract_object(value)
    if isinstance(value, list):
        return [_extract_object(item) for item in value]
    return value


def _extract_object(item: Any) -> Any:
    if isinstance(item, dict):
        extracted = {key: item.get(key) for key in ("name", "id", "type", "value", "literal") if key in item}
        return extracted or {key: _extract_value(value) for key, value in sorted(item.items())}
    return item
