from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .matcher import build_source_rule_index, normalize_rule_name
from .models import (
    LayerComposerOptions,
    LayerComposerPlan,
    LayerCsvEntry,
    LayerRuleMatch,
    RuleMatchStatus,
    SourceAcpRef,
    SourceRuleCandidate,
)
from .sanity import compare_csv_to_rule_signature
from .signatures import (
    blocking_candidate_delta_count,
    compare_candidate_signatures,
    id_only_delta_count,
    semantic_candidate_delta_count,
)
from .utils import safe_target_name


def build_plan(
    *,
    csv_filename: str,
    entries: list[LayerCsvEntry],
    duplicate_rule_names: list[str],
    source_acps: list[SourceAcpRef],
    source_rules_by_acp: dict[str, list[dict[str, Any]]],
    options: LayerComposerOptions,
    target_exists: bool = False,
) -> LayerComposerPlan:
    timestamp = datetime.now(timezone.utc).isoformat()
    index = build_source_rule_index(source_rules_by_acp, source_acps, options.match_mode) if source_acps else {}
    duplicate_set = set(duplicate_rule_names)
    matches: list[LayerRuleMatch] = []

    for entry in entries:
        candidates = index.get(normalize_rule_name(entry.rule_name, options.match_mode), [])
        if entry.rule_name in duplicate_set:
            matches.append(_duplicate_match(entry, candidates))
            continue
        if not candidates:
            matches.append(_missing_match(entry, options.skip_missing))
            continue
        matches.append(_candidate_match(entry, candidates, options))

    summary = _build_summary(matches)
    blockers, warnings = _build_readiness(
        entries=entries,
        source_acps=source_acps,
        matches=matches,
        options=options,
        target_exists=target_exists,
        duplicate_rule_names=duplicate_rule_names,
    )
    return LayerComposerPlan(
        timestamp=timestamp,
        csv_filename=csv_filename,
        target_acp_name=options.target_acp_name,
        source_acps=source_acps,
        options=options,
        entries=entries,
        matches=matches,
        summary=summary,
        commit_allowed=not blockers,
        blockers=blockers,
        warnings=warnings,
    )


def _duplicate_match(entry: LayerCsvEntry, candidates: list[SourceRuleCandidate]) -> LayerRuleMatch:
    return LayerRuleMatch(
        csv_entry=entry,
        status=RuleMatchStatus.CSV_DUPLICATE_RULE_NAME.value,
        candidates=candidates,
        selected_candidate=None,
        candidate_deltas=[],
        candidate_field_deltas=[],
        semantic_candidate_delta_count=0,
        id_only_delta_count=0,
        blocking_candidate_delta_count=0,
        sanity_deltas=[],
        warnings=["Duplicate CSV rule name after normalization."],
        skip_reason="Duplicate CSV rule names block deterministic copy order.",
    )


def _missing_match(entry: LayerCsvEntry, skip_missing: bool) -> LayerRuleMatch:
    status = RuleMatchStatus.SKIPPED if skip_missing else RuleMatchStatus.MISSING
    return LayerRuleMatch(
        csv_entry=entry,
        status=status.value,
        candidates=[],
        selected_candidate=None,
        candidate_deltas=[],
        candidate_field_deltas=[],
        semantic_candidate_delta_count=0,
        id_only_delta_count=0,
        blocking_candidate_delta_count=0,
        sanity_deltas=[],
        warnings=[],
        skip_reason="Missing rule skipped by option." if skip_missing else "No matching source rule found.",
    )


def _candidate_match(
    entry: LayerCsvEntry,
    candidates: list[SourceRuleCandidate],
    options: LayerComposerOptions,
) -> LayerRuleMatch:
    selected = candidates[0]
    candidate_field_deltas = compare_candidate_signatures(candidates)
    blocking_count = blocking_candidate_delta_count(candidate_field_deltas)
    semantic_count = semantic_candidate_delta_count(candidate_field_deltas)
    id_only_count = id_only_delta_count(candidate_field_deltas)
    candidate_deltas = [
        asdict(delta)
        for delta in candidate_field_deltas
        if delta.severity == "warning"
    ]
    if len(candidates) == 1:
        status = RuleMatchStatus.MATCHED_ONE
    elif blocking_count:
        status = RuleMatchStatus.MATCHED_MULTIPLE_WITH_DELTA
    else:
        status = RuleMatchStatus.MATCHED_IDENTICAL_MULTIPLE

    sanity_deltas = compare_csv_to_rule_signature(entry, selected.signature)
    warnings = [delta.message for delta in sanity_deltas]
    if blocking_count:
        field_preview = ", ".join(delta.field_path for delta in candidate_field_deltas if delta.severity == "warning")
        warnings.append(f"{blocking_count} blocking candidate field delta(s): {field_preview}.")
    elif candidate_field_deltas:
        info_count = len(candidate_field_deltas)
        warnings.append(f"{info_count} informational candidate field delta(s); no semantic copy blocker.")

    return LayerRuleMatch(
        csv_entry=entry,
        status=status.value,
        candidates=candidates,
        selected_candidate=selected,
        candidate_deltas=candidate_deltas,
        candidate_field_deltas=candidate_field_deltas,
        semantic_candidate_delta_count=semantic_count,
        id_only_delta_count=id_only_count,
        blocking_candidate_delta_count=blocking_count,
        sanity_deltas=sanity_deltas,
        warnings=warnings,
        skip_reason=None,
    )


def _build_summary(matches: list[LayerRuleMatch]) -> dict[str, Any]:
    counts = Counter(match.status for match in matches)
    ready = sum(1 for match in matches if match.selected_candidate and match.status != RuleMatchStatus.CSV_DUPLICATE_RULE_NAME.value)
    warnings = sum(len(match.warnings) for match in matches)
    field_delta_types = Counter(
        delta.delta_type
        for match in matches
        for delta in match.candidate_field_deltas
    )
    return {
        "total_csv_rules": len(matches),
        "matched_one": counts[RuleMatchStatus.MATCHED_ONE.value],
        "matched_identical_multiple": counts[RuleMatchStatus.MATCHED_IDENTICAL_MULTIPLE.value],
        "matched_with_candidate_deltas": counts[RuleMatchStatus.MATCHED_MULTIPLE_WITH_DELTA.value],
        "missing": counts[RuleMatchStatus.MISSING.value],
        "csv_duplicates": counts[RuleMatchStatus.CSV_DUPLICATE_RULE_NAME.value],
        "ready_to_copy": ready,
        "skipped": counts[RuleMatchStatus.SKIPPED.value],
        "created": counts[RuleMatchStatus.CREATED.value],
        "failed": counts[RuleMatchStatus.CREATE_FAILED.value],
        "warnings": warnings,
        "blockers": 0,
        "semantic_candidate_deltas": sum(match.semantic_candidate_delta_count for match in matches),
        "id_only_candidate_deltas": field_delta_types["ID_ONLY_DIFFERENCE"],
        "ordering_only_deltas": field_delta_types["ORDERING_ONLY_DIFFERENCE"],
        "empty_missing_normalization_deltas": field_delta_types["EMPTY_MISSING_NORMALIZATION"],
    }


def _build_readiness(
    *,
    entries: list[LayerCsvEntry],
    source_acps: list[SourceAcpRef],
    matches: list[LayerRuleMatch],
    options: LayerComposerOptions,
    target_exists: bool,
    duplicate_rule_names: list[str],
) -> tuple[list[str], list[str]]:
    blockers: list[str] = []
    warnings: list[str] = []
    if target_exists:
        blockers.append(f"Target ACP '{options.target_acp_name}' already exists.")
    if not safe_target_name(options.target_acp_name):
        blockers.append("Target ACP name is required.")
    if not source_acps:
        blockers.append("At least one source ACP must be selected.")
    if not entries:
        blockers.append("CSV has no rules.")
    if duplicate_rule_names:
        blockers.append("CSV has duplicate normalized rule names: " + ", ".join(duplicate_rule_names))

    missing = [match for match in matches if match.status == RuleMatchStatus.MISSING.value]
    skipped = [match for match in matches if match.status == RuleMatchStatus.SKIPPED.value]
    candidate_deltas = [match for match in matches if match.blocking_candidate_delta_count]
    selected = [match for match in matches if match.selected_candidate]
    if entries and not selected:
        blockers.append("All CSV rules are missing from selected source ACPs.")
    if missing and not options.skip_missing:
        blockers.append(f"{len(missing)} CSV rule(s) are missing and skip missing is disabled.")
    if candidate_deltas and not options.use_priority_despite_candidate_deltas:
        blockers.append(f"{len(candidate_deltas)} rule(s) have source candidate signature deltas.")
    if skipped:
        warnings.append(f"{len(skipped)} missing rule(s) will be skipped.")
    sanity_warnings = sum(len(match.sanity_deltas) for match in matches)
    if sanity_warnings:
        warnings.append(f"{sanity_warnings} CSV-to-FMC sanity warning(s) found.")
    return blockers, warnings


def plan_to_dict(plan: LayerComposerPlan) -> dict[str, Any]:
    return asdict(plan)
