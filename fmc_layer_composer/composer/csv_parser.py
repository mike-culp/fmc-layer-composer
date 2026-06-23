from __future__ import annotations

import csv
import io
from collections import Counter
from typing import Any

from .models import CsvParseResult, LayerCsvEntry
from .utils import split_multi_value, strip_disabled_marker


RULE_NAME_COLUMNS = ("name", "rule name", "rule", "rulebase")
ACTION_COLUMNS = ("action",)
SOURCE_ZONE_COLUMNS = ("source zone", "source zones")
DESTINATION_ZONE_COLUMNS = ("destination zone", "destination zones")
SOURCE_OBJECT_COLUMNS = ("source address", "source addresses", "source object", "source objects", "source")
DESTINATION_OBJECT_COLUMNS = (
    "destination address",
    "destination addresses",
    "destination object",
    "destination objects",
    "destination",
)
SERVICE_COLUMNS = ("service", "services", "port", "ports")
APPLICATION_COLUMNS = ("application", "applications")
URL_COLUMNS = ("url", "urls", "url category", "url categories")
DESCRIPTION_COLUMNS = ("description", "comments", "comment")
ENABLED_COLUMNS = ("enabled", "disabled", "state", "status")


class CsvValidationError(ValueError):
    """Raised when the layer CSV cannot be parsed deterministically."""


def parse_layer_csv(content: str | bytes) -> CsvParseResult:
    text = content.decode("utf-8-sig") if isinstance(content, bytes) else content
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise CsvValidationError("CSV has no header row.")

    headers = [header or "" for header in reader.fieldnames]
    lookup = {_normalize_header(header): header for header in headers}
    rule_name_column = _find_column(lookup, RULE_NAME_COLUMNS)
    if not rule_name_column:
        raise CsvValidationError("CSV must include a rule name column such as Name, Rule Name, Rule, or Rulebase.")

    entries: list[LayerCsvEntry] = []
    for index, row in enumerate(reader, start=1):
        raw_name = _cell(row, rule_name_column)
        if not raw_name:
            continue
        rule_name, marker_disabled = strip_disabled_marker(raw_name)
        csv_enabled = _parse_enabled(row, lookup)
        if marker_disabled:
            csv_enabled = False

        entries.append(
            LayerCsvEntry(
                order=index,
                raw_name=raw_name,
                rule_name=rule_name,
                csv_enabled=csv_enabled,
                csv_action=_optional_scalar(row, lookup, ACTION_COLUMNS),
                csv_source_zones=_optional_list(row, lookup, SOURCE_ZONE_COLUMNS),
                csv_destination_zones=_optional_list(row, lookup, DESTINATION_ZONE_COLUMNS),
                csv_source_objects=_optional_list(row, lookup, SOURCE_OBJECT_COLUMNS),
                csv_destination_objects=_optional_list(row, lookup, DESTINATION_OBJECT_COLUMNS),
                csv_services=_optional_list(row, lookup, SERVICE_COLUMNS),
                csv_applications=_optional_list(row, lookup, APPLICATION_COLUMNS),
                csv_urls=_optional_list(row, lookup, URL_COLUMNS),
                csv_description=_optional_scalar(row, lookup, DESCRIPTION_COLUMNS),
                raw_row=dict(row),
            )
        )

    counts = Counter(entry.rule_name for entry in entries)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    return CsvParseResult(entries=entries, rule_name_column=rule_name_column, duplicate_rule_names=duplicates)


def _normalize_header(header: str) -> str:
    return " ".join(str(header).strip().lower().replace("_", " ").replace("-", " ").split())


def _find_column(lookup: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if candidate in lookup:
            return lookup[candidate]
    return None


def _cell(row: dict[str, Any], column: str | None) -> str:
    if not column:
        return ""
    value = row.get(column)
    return "" if value is None else str(value).strip()


def _optional_scalar(row: dict[str, Any], lookup: dict[str, str], columns: tuple[str, ...]) -> str | None:
    value = _cell(row, _find_column(lookup, columns))
    return value or None


def _optional_list(row: dict[str, Any], lookup: dict[str, str], columns: tuple[str, ...]) -> list[str]:
    return split_multi_value(_cell(row, _find_column(lookup, columns)))


def _parse_enabled(row: dict[str, Any], lookup: dict[str, str]) -> bool | None:
    column = _find_column(lookup, ENABLED_COLUMNS)
    if not column:
        return None
    value = _cell(row, column).lower()
    if not value:
        return None
    if _normalize_header(column) == "disabled":
        if value in {"true", "yes", "y", "1", "disabled"}:
            return False
        if value in {"false", "no", "n", "0", "enabled"}:
            return True
    if value in {"true", "yes", "y", "1", "enabled", "enable"}:
        return True
    if value in {"false", "no", "n", "0", "disabled", "disable"}:
        return False
    return None
