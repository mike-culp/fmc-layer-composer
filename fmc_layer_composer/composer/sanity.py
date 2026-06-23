from __future__ import annotations

import re
from typing import Any

from .models import LayerCsvEntry, SanityDelta


def compare_csv_to_rule_signature(csv_entry: LayerCsvEntry, signature: dict[str, Any]) -> list[SanityDelta]:
    deltas: list[SanityDelta] = []
    _compare_scalar(deltas, csv_entry.csv_enabled, signature.get("enabled"), "enabled", "ENABLED_STATE_DELTA")
    _compare_scalar(deltas, _upper(csv_entry.csv_action), _upper(signature.get("action")), "action", "ACTION_DELTA")
    _compare_names(deltas, csv_entry.csv_source_zones, signature.get("sourceZones"), "sourceZones", "SOURCE_ZONE_DELTA")
    _compare_names(deltas, csv_entry.csv_destination_zones, signature.get("destinationZones"), "destinationZones", "DESTINATION_ZONE_DELTA")
    _compare_names(deltas, csv_entry.csv_source_objects, signature.get("sourceNetworks"), "sourceNetworks", "SOURCE_OBJECT_DELTA")
    _compare_names(deltas, csv_entry.csv_destination_objects, signature.get("destinationNetworks"), "destinationNetworks", "DESTINATION_OBJECT_DELTA")
    _compare_names(deltas, csv_entry.csv_services, signature.get("destinationPorts"), "destinationPorts", "PORT_DELTA")
    _compare_names(deltas, csv_entry.csv_applications, signature.get("applications"), "applications", "APPLICATION_DELTA")
    _compare_names(deltas, csv_entry.csv_urls, signature.get("urls"), "urls", "URL_DELTA")
    return deltas


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


def _compare_names(
    deltas: list[SanityDelta],
    csv_values: list[str],
    fmc_value: Any,
    field: str,
    code: str,
) -> None:
    if not csv_values:
        return
    fmc_names = _flatten_names(fmc_value)
    if not fmc_names:
        return
    csv_set = {_norm(value) for value in csv_values}
    fmc_set = {_norm(value) for value in fmc_names}
    if csv_set == fmc_set:
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
            message=f"CSV {field} values differ from selected FMC rule.",
        )
    )


def _flatten_names(value: Any) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        if "name" in value:
            names.append(str(value["name"]))
        for child in value.values():
            names.extend(_flatten_names(child))
    elif isinstance(value, list):
        for item in value:
            names.extend(_flatten_names(item))
    elif value not in (None, ""):
        names.append(str(value))
    return names


def _norm(value: str) -> str:
    return " ".join(str(value).split()).casefold()


def _upper(value: Any) -> Any:
    return value.upper() if isinstance(value, str) else value
