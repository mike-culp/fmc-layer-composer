from __future__ import annotations

import re
from typing import Any

from .models import LayerCsvEntry, SanityDelta


def compare_csv_to_rule_signature(csv_entry: LayerCsvEntry, signature: dict[str, Any]) -> list[SanityDelta]:
    deltas: list[SanityDelta] = []
    _compare_scalar(deltas, csv_entry.csv_enabled, signature.get("enabled"), "enabled", "ENABLED_STATE_DELTA")
    _compare_scalar(deltas, _upper(csv_entry.csv_action), _upper(signature.get("action")), "action", "ACTION_DELTA")
    _compare_name_field(deltas, csv_entry.csv_source_zones, signature.get("sourceZones"), "sourceZones", "SOURCE_ZONE_DELTA", extract_zone_names)
    _compare_name_field(deltas, csv_entry.csv_destination_zones, signature.get("destinationZones"), "destinationZones", "DESTINATION_ZONE_DELTA", extract_zone_names)
    _compare_name_field(deltas, csv_entry.csv_source_objects, signature.get("sourceNetworks"), "sourceNetworks", "SOURCE_OBJECT_DELTA", extract_network_names)
    _compare_name_field(deltas, csv_entry.csv_destination_objects, signature.get("destinationNetworks"), "destinationNetworks", "DESTINATION_OBJECT_DELTA", extract_network_names)
    _compare_name_field(deltas, csv_entry.csv_services, signature.get("destinationPorts"), "destinationPorts", "PORT_DELTA", extract_port_names)
    _compare_name_field(deltas, csv_entry.csv_applications, signature.get("applications"), "applications", "APPLICATION_MAPPING_OR_EXPANSION_DELTA", extract_application_names)
    _compare_name_field(deltas, csv_entry.csv_urls, signature.get("urls"), "urls", "URL_DELTA", extract_url_names)
    return deltas


def extract_object_names(container: Any) -> list[str]:
    return _dedupe_sorted(
        detail["name"]
        for detail in extract_object_details(container)
        if detail.get("name")
    )


def extract_object_details(container: Any) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for item in _iter_condition_items(container):
        if isinstance(item, dict):
            detail = {key: item.get(key) for key in ("name", "id", "type", "value", "literal") if item.get(key) not in (None, "")}
            if detail:
                details.append(detail)
        elif item not in (None, ""):
            details.append({"value": str(item)})
    return _dedupe_details(details)


def extract_network_names(rule_field: Any) -> list[str]:
    return _dedupe_sorted(_detail_compare_value(detail) for detail in extract_object_details(rule_field))


def extract_port_names(rule_field: Any) -> list[str]:
    return _dedupe_sorted(_detail_compare_value(detail) for detail in extract_object_details(rule_field))


def extract_zone_names(rule_field: Any) -> list[str]:
    return extract_object_names(rule_field)


def extract_url_names(rule_field: Any) -> list[str]:
    return _dedupe_sorted(_detail_compare_value(detail) for detail in extract_object_details(rule_field))


def extract_application_names(rule_field: Any) -> list[str]:
    return extract_object_names(rule_field)


def normalize_object_name_for_compare(name: str) -> str:
    return " ".join(str(name).strip().split()).casefold()


def looks_like_migration_artifact(expected: str, actual: str) -> bool:
    expected_norm = expected.strip().casefold()
    actual_norm = actual.strip().casefold()
    if not expected_norm or expected_norm == actual_norm:
        return False
    patterns = (
        rf"^{re.escape(expected_norm)}(?:_\d+)+$",
        rf"^{re.escape(expected_norm)}-\d+$",
        rf"^{re.escape(expected_norm)}-copy$",
    )
    return any(re.match(pattern, actual_norm) for pattern in patterns)


def _compare_scalar(deltas: list[SanityDelta], csv_value: Any, fmc_value: Any, field: str, code: str) -> None:
    if csv_value is None or fmc_value is None:
        return
    if csv_value != fmc_value:
        deltas.append(
            SanityDelta(
                code=code,
                severity="warning",
                field=field,
                csv_value=csv_value,
                fmc_value=fmc_value,
                message=f"CSV {field} differs from selected FMC rule.",
            )
        )


def _compare_name_field(
    deltas: list[SanityDelta],
    csv_values: list[str],
    fmc_value: Any,
    field: str,
    code: str,
    extractor: Any,
) -> None:
    if not csv_values:
        return
    fmc_names = extractor(fmc_value)
    if not fmc_names:
        return
    fmc_details = extract_object_details(fmc_value)
    csv_compare = _normalized_set(csv_values)
    fmc_compare = _normalized_set(fmc_names)
    if csv_compare == fmc_compare:
        return
    if _case_only_difference(csv_values, fmc_names):
        deltas.append(
            SanityDelta(
                code="CASE_ONLY_OBJECT_NAME_DIFFERENCE",
                severity="info",
                field=field,
                csv_value=csv_values,
                fmc_value=fmc_names,
                fmc_details=fmc_details,
                message=f"CSV {field} values differ only by case from selected FMC rule.",
            )
        )
        return
    if _possible_group_collapse(csv_values, fmc_names, fmc_details, field):
        group_name = fmc_names[0] if fmc_names else "unknown"
        deltas.append(
            SanityDelta(
                code="POSSIBLE_GROUP_COLLAPSE_OR_EXPANSION_DELTA",
                severity="warning",
                field=field,
                csv_value=csv_values,
                fmc_value=fmc_names,
                fmc_details=fmc_details,
                message=(
                    f"CSV has {len(csv_values)} destination objects; FMC has NetworkGroup {group_name}. "
                    "Group membership was not expanded, so equivalence is unknown."
                ),
            )
        )
        return
    if field == "applications":
        deltas.append(
            SanityDelta(
                code="APPLICATION_MAPPING_OR_EXPANSION_DELTA",
                severity="warning",
                field=field,
                csv_value=csv_values,
                fmc_value=fmc_names,
                fmc_details=fmc_details,
                message=(
                    "CSV application values appear to be PAN application/app-group names, while FMC contains "
                    "Cisco/FMC application names. Exact name comparison may not indicate an error."
                ),
            )
        )
        return
    artifact_pairs = [
        {"expected": expected, "actual": actual}
        for expected in csv_values
        for actual in fmc_names
        if looks_like_migration_artifact(expected, actual)
    ]
    if artifact_pairs:
        deltas.append(
            SanityDelta(
                code="OBJECT_NAME_ARTIFACT_DELTA",
                severity="warning",
                field=field,
                csv_value=csv_values,
                fmc_value=fmc_names,
                fmc_details=fmc_details,
                message="FMC object names look like migration artifacts for CSV values.",
            )
        )
        return
    deltas.append(
        SanityDelta(
            code=code,
            severity="warning",
            field=field,
            csv_value=csv_values,
            fmc_value=fmc_names,
            fmc_details=fmc_details,
            message=f"CSV {field} values differ from selected FMC rule.",
        )
    )


def _iter_condition_items(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, dict):
        items: list[Any] = []
        items.extend(value.get("objects") or [])
        items.extend(value.get("literals") or [])
        if not items and any(key in value for key in ("name", "id", "type", "value", "literal")):
            items.append(value)
        return items
    if isinstance(value, list):
        return value
    return [value]


def _detail_compare_value(detail: dict[str, Any]) -> str:
    value = detail.get("name", detail.get("value", detail.get("literal", "")))
    return str(value) if value not in (None, "") else ""


def _dedupe_sorted(values: Any) -> list[str]:
    unique = {str(value).strip() for value in values if str(value).strip()}
    return sorted(unique, key=str.casefold)


def _dedupe_details(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    deduped: list[dict[str, Any]] = []
    for detail in details:
        key = tuple(sorted((str(k), str(v)) for k, v in detail.items()))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(detail)
    return deduped


def _normalized_set(values: list[str]) -> set[str]:
    return {normalize_object_name_for_compare(value) for value in values}


def _case_only_difference(csv_values: list[str], fmc_names: list[str]) -> bool:
    return _normalized_set(csv_values) == _normalized_set(fmc_names) and set(csv_values) != set(fmc_names)


def _possible_group_collapse(csv_values: list[str], fmc_names: list[str], fmc_details: list[dict[str, Any]], field: str) -> bool:
    if field != "destinationNetworks":
        return False
    if len(csv_values) <= 1 or len(fmc_names) != 1:
        return False
    return any(detail.get("type") == "NetworkGroup" for detail in fmc_details)


def _upper(value: Any) -> Any:
    return value.upper() if isinstance(value, str) else value
