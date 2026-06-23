from __future__ import annotations

import json
from typing import Any

from .models import CandidateFieldDelta, SourceRuleCandidate


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

BLOCKING_LOGGING_FIELDS = (
    "logBegin",
    "logEnd",
    "logFiles",
    "sendEventsToFMC",
    "enableSyslog",
    "syslogSeverity",
    "advancedLogging",
)

OBJECT_FIELD_MESSAGES = {
    "sourceZones": ("sourceZones.objects.names", "ZONE_NAME_MISMATCH", "Source zone object names differ across source ACP candidates."),
    "destinationZones": ("destinationZones.objects.names", "ZONE_NAME_MISMATCH", "Destination zone object names differ across source ACP candidates."),
    "sourceNetworks": ("sourceNetworks.objects.names", "OBJECT_NAME_MISMATCH", "Source network object names differ across source ACP candidates."),
    "destinationNetworks": ("destinationNetworks.objects.names", "OBJECT_NAME_MISMATCH", "Destination network object names differ across source ACP candidates."),
    "sourcePorts": ("sourcePorts.objects.names", "PORT_SERVICE_MISMATCH", "Source port/service object names differ across source ACP candidates."),
    "destinationPorts": ("destinationPorts.objects.names", "PORT_SERVICE_MISMATCH", "Destination port/service object names differ across source ACP candidates."),
    "applications": ("applications.objects.names", "APPLICATION_MISMATCH", "Application names differ across source ACP candidates."),
    "urls": ("urls.objects.names", "URL_MISMATCH", "URL object/category/literal values differ across source ACP candidates."),
    "users": ("users.objects.names", "USER_MISMATCH", "User names differ across source ACP candidates."),
    "sourceSecurityGroupTags": ("sourceSecurityGroupTags.objects.names", "SGT_MISMATCH", "Source SGT names differ across source ACP candidates."),
    "destinationSecurityGroupTags": ("destinationSecurityGroupTags.objects.names", "SGT_MISMATCH", "Destination SGT names differ across source ACP candidates."),
    "vlanTags": ("vlanTags.objects.names", "VLAN_TAG_MISMATCH", "VLAN tag values differ across source ACP candidates."),
    "sourceDynamicObjects": ("sourceDynamicObjects.objects.names", "OBJECT_NAME_MISMATCH", "Source dynamic object names differ across source ACP candidates."),
    "destinationDynamicObjects": ("destinationDynamicObjects.objects.names", "OBJECT_NAME_MISMATCH", "Destination dynamic object names differ across source ACP candidates."),
    "originalSourceNetworks": ("originalSourceNetworks.objects.names", "OBJECT_NAME_MISMATCH", "Original source network names differ across source ACP candidates."),
    "timeRangeObjects": ("timeRangeObjects.objects.names", "OBJECT_NAME_MISMATCH", "Time range object names differ across source ACP candidates."),
}

POLICY_FIELD_MESSAGES = {
    "filePolicy": ("filePolicy.name", "FILE_POLICY_MISMATCH", "File policy names differ across source ACP candidates."),
    "ipsPolicy": ("ipsPolicy.name", "IPS_POLICY_MISMATCH", "IPS policy names differ across source ACP candidates."),
}

SCALAR_FIELD_MESSAGES = {
    "action": ("action", "ACTION_MISMATCH", "Rule actions differ across source ACP candidates."),
    "enabled": ("enabled", "ENABLED_MISMATCH", "Rule enabled states differ across source ACP candidates."),
}

LOGGING_FIELD_MESSAGES = {
    field: (field, "LOGGING_BEHAVIOR_MISMATCH", f"Logging field {field} differs across source ACP candidates.")
    for field in BLOCKING_LOGGING_FIELDS
}

VARIABLE_SET_CONTEXT_MESSAGE = (
    "Variable set differs between source ACPs. "
    "This is treated as informational and does not block rule copy."
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


def compare_candidate_signatures(candidates: list[SourceRuleCandidate]) -> list[CandidateFieldDelta]:
    if len(candidates) < 2:
        return []

    deltas: list[CandidateFieldDelta] = []
    deltas.extend(_compare_scalar_fields(candidates, SCALAR_FIELD_MESSAGES, severity="warning"))
    deltas.extend(_compare_object_fields(candidates))
    deltas.extend(_compare_policy_fields(candidates))
    deltas.extend(_compare_variable_set_context(candidates))
    deltas.extend(_compare_scalar_fields(candidates, LOGGING_FIELD_MESSAGES, severity="warning"))
    return deltas


def has_blocking_candidate_delta(deltas: list[CandidateFieldDelta]) -> bool:
    return any(delta.severity == "warning" for delta in deltas)


def blocking_candidate_delta_count(deltas: list[CandidateFieldDelta]) -> int:
    return sum(1 for delta in deltas if delta.severity == "warning")


def id_only_delta_count(deltas: list[CandidateFieldDelta]) -> int:
    return sum(1 for delta in deltas if delta.delta_type == "ID_ONLY_DIFFERENCE")


def informational_candidate_delta_count(deltas: list[CandidateFieldDelta]) -> int:
    return sum(1 for delta in deltas if delta.severity == "info")


def semantic_candidate_delta_count(deltas: list[CandidateFieldDelta]) -> int:
    return sum(1 for delta in deltas if delta.severity == "warning")


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


def _compare_scalar_fields(
    candidates: list[SourceRuleCandidate],
    field_messages: dict[str, tuple[str, str, str]],
    severity: str,
) -> list[CandidateFieldDelta]:
    deltas: list[CandidateFieldDelta] = []
    for field, (field_path, delta_type, message) in field_messages.items():
        values = {candidate.source_acp_name: _normalize_empty(candidate.signature.get(field)) for candidate in candidates}
        if _values_differ(values):
            deltas.append(
                CandidateFieldDelta(
                    field_path=field_path,
                    severity=severity,
                    delta_type=delta_type,
                    values_by_candidate=values,
                    message=message,
                )
            )
    return deltas


def _compare_policy_fields(candidates: list[SourceRuleCandidate]) -> list[CandidateFieldDelta]:
    deltas: list[CandidateFieldDelta] = []
    for field, (field_path, delta_type, message) in POLICY_FIELD_MESSAGES.items():
        values = {candidate.source_acp_name: _policy_name(candidate.signature.get(field)) for candidate in candidates}
        if _values_differ(values):
            deltas.append(
                CandidateFieldDelta(
                    field_path=field_path,
                    severity="warning",
                    delta_type=delta_type,
                    values_by_candidate=values,
                    message=message,
                )
            )
    return deltas


def _compare_variable_set_context(candidates: list[SourceRuleCandidate]) -> list[CandidateFieldDelta]:
    deltas: list[CandidateFieldDelta] = []
    for attribute in ("name", "id", "type"):
        values = {
            candidate.source_acp_name: _context_attribute(candidate.signature.get("variableSet"), attribute)
            for candidate in candidates
        }
        if _values_differ(values):
            deltas.append(
                CandidateFieldDelta(
                    field_path=f"variableSet.{attribute}",
                    severity="info",
                    delta_type="CONTEXT_ONLY_DIFFERENCE",
                    values_by_candidate=values,
                    message=VARIABLE_SET_CONTEXT_MESSAGE,
                )
            )
    return deltas


def _compare_object_fields(candidates: list[SourceRuleCandidate]) -> list[CandidateFieldDelta]:
    deltas: list[CandidateFieldDelta] = []
    for field, (field_path, delta_type, message) in OBJECT_FIELD_MESSAGES.items():
        containers = {candidate.source_acp_name: _container_parts(candidate.signature.get(field)) for candidate in candidates}
        semantic_values = {
            acp_name: _sorted_unique(parts["names"] + parts["literals"])
            for acp_name, parts in containers.items()
        }
        if _values_differ(semantic_values):
            deltas.append(
                CandidateFieldDelta(
                    field_path=field_path,
                    severity="warning",
                    delta_type=_literal_delta_type(containers, delta_type),
                    values_by_candidate=semantic_values,
                    message=message,
                )
            )
            continue

        ids_by_candidate = {acp_name: _sorted_unique(parts["ids"]) for acp_name, parts in containers.items()}
        if any(ids_by_candidate.values()) and _values_differ(ids_by_candidate):
            deltas.append(
                CandidateFieldDelta(
                    field_path=f"{field}.objects.ids",
                    severity="info",
                    delta_type="ID_ONLY_DIFFERENCE",
                    values_by_candidate=ids_by_candidate,
                    message=f"{field} object IDs differ, but names/literals match.",
                )
            )

        order_by_candidate = {
            acp_name: parts["raw_values"]
            for acp_name, parts in containers.items()
            if len(parts["raw_values"]) > 1
        }
        if order_by_candidate and _sequence_values_differ(order_by_candidate):
            deltas.append(
                CandidateFieldDelta(
                    field_path=field_path,
                    severity="info",
                    delta_type="ORDERING_ONLY_DIFFERENCE",
                    values_by_candidate=order_by_candidate,
                    message=f"{field} values have different order, but normalized values match.",
                )
            )
    return deltas


def _container_parts(value: Any) -> dict[str, list[str]]:
    names: list[str] = []
    ids: list[str] = []
    literals: list[str] = []
    raw_values: list[str] = []

    objects = _object_list(value)
    for item in objects:
        if isinstance(item, dict):
            name = item.get("name")
            object_id = item.get("id")
            literal = item.get("value", item.get("literal"))
            if name not in (None, ""):
                names.append(str(name))
                raw_values.append(str(name))
            if object_id not in (None, ""):
                ids.append(str(object_id))
            if literal not in (None, ""):
                literals.append(str(literal))
                raw_values.append(str(literal))
        elif item not in (None, ""):
            literals.append(str(item))
            raw_values.append(str(item))

    return {
        "names": _sorted_unique(names),
        "ids": _sorted_unique(ids),
        "literals": _sorted_unique(literals),
        "raw_values": raw_values,
    }


def _object_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, dict):
        items: list[Any] = []
        items.extend(value.get("objects") or [])
        items.extend(value.get("literals") or [])
        if not items and any(key in value for key in ("name", "id", "value", "literal")):
            items.append(value)
        return items
    if isinstance(value, list):
        return value
    return [value]


def _policy_name(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, dict):
        return value.get("name") or value.get("value") or value.get("id")
    return str(value)


def _context_attribute(value: Any, attribute: str) -> Any:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, dict):
        return value.get(attribute)
    return str(value) if attribute == "name" else None


def _literal_delta_type(containers: dict[str, dict[str, list[str]]], default: str) -> str:
    literal_sets = [parts["literals"] for parts in containers.values()]
    if any(literal_sets) and _values_differ({str(index): values for index, values in enumerate(literal_sets)}):
        return "LITERAL_VALUE_MISMATCH"
    return default


def _normalize_empty(value: Any) -> Any:
    if value in (None, "", [], {}):
        return None
    return value


def _values_differ(values_by_candidate: dict[str, Any]) -> bool:
    normalized = {json.dumps(_canonical(value), sort_keys=True, default=str) for value in values_by_candidate.values()}
    return len(normalized) > 1


def _sequence_values_differ(values_by_candidate: dict[str, list[str]]) -> bool:
    normalized = {json.dumps(value, default=str) for value in values_by_candidate.values()}
    return len(normalized) > 1


def _canonical(value: Any) -> Any:
    if isinstance(value, list):
        return sorted((_canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, dict):
        return {key: _canonical(value[key]) for key in sorted(value)}
    return value


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value) != ""}, key=str.casefold)
