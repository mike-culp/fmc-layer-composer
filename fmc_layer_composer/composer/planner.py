from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .fuzzy import find_fuzzy_rule_candidates, find_split_rule_candidates, group_split_rule_candidates
from .matcher import build_source_rule_index, normalize_rule_name
from .models import (
    LayerComposerOptions,
    LayerComposerPlan,
    LayerCsvEntry,
    LayerRuleMatch,
    RuleSkipReason,
    RuleMatchStatus,
    SourceAcpRef,
    FuzzyRuleCandidate,
    SourceRuleCandidate,
)
from .sanity import compare_csv_to_rule_signature
from .signatures import (
    blocking_candidate_delta_count,
    compare_candidate_signatures,
    id_only_delta_count,
    informational_candidate_delta_count,
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
    diagnostics_logger: Any | None = None,
) -> LayerComposerPlan:
    timestamp = datetime.now(timezone.utc).isoformat()
    index = build_source_rule_index(source_rules_by_acp, source_acps, options.match_mode) if source_acps else {}
    source_rule_candidates = [candidate for candidates in index.values() for candidate in candidates]
    duplicate_set = set(duplicate_rule_names)
    matches: list[LayerRuleMatch] = []

    for entry in entries:
        candidates = index.get(normalize_rule_name(entry.rule_name, options.match_mode), [])
        if entry.rule_name in duplicate_set:
            matches.append(_duplicate_match(entry, candidates))
            continue
        if not candidates:
            match = _missing_match(entry, options, source_rule_candidates, source_acps)
            _record_fuzzy_diagnostic(diagnostics_logger, entry, match, source_rule_candidates, source_acps, options)
            matches.append(match)
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
        fuzzy_candidates=[],
        split_candidate_groups=[],
        selected_candidate=None,
        selected_fuzzy_candidate=None,
        candidate_deltas=[],
        candidate_field_deltas=[],
        semantic_candidate_delta_count=0,
        id_only_delta_count=0,
        blocking_candidate_delta_count=0,
        sanity_deltas=[],
        warnings=["Duplicate CSV rule name after normalization."],
        skip_reason="Duplicate CSV rule names block deterministic copy order.",
        primary_reason_code="CSV_DUPLICATE_RULE_NAME",
        human_reason="Duplicate CSV rule names block deterministic copy order.",
        user_decision="BLOCKED",
        commit_impact="Rule was not copied.",
        skip_reason_detail=_skip_reason_detail(
            entry=entry,
            status="SKIPPED",
            reason_code="CSV_DUPLICATE_RULE_NAME",
            human_reason="Duplicate CSV rule names block deterministic copy order.",
            source_acps=[],
            exact_candidates=candidates,
            fuzzy_candidates=[],
            selected_candidate=None,
            user_decision="BLOCKED",
            commit_impact="Rule was not copied.",
            warnings=["Duplicate CSV rule name after normalization."],
        ),
    )


def _missing_match(
    entry: LayerCsvEntry,
    options: LayerComposerOptions,
    source_rules: list[SourceRuleCandidate],
    source_acps: list[SourceAcpRef],
) -> LayerRuleMatch:
    fuzzy_candidates = find_fuzzy_rule_candidates(entry.rule_name, source_rules, options.fuzzy)
    split_candidates = find_split_rule_candidates(entry.rule_name, source_rules, options.fuzzy)
    split_groups = group_split_rule_candidates(entry.order, entry.rule_name, split_candidates)
    selected_fuzzy = _selected_fuzzy(entry, fuzzy_candidates, options)
    selected_source = _source_candidate_for_fuzzy(selected_fuzzy, source_rules) if selected_fuzzy else None
    if selected_fuzzy and selected_source:
        status = RuleMatchStatus.FUZZY_SELECTED_RENAMED_TO_CSV if options.target_rule_name_mode == "csv" else RuleMatchStatus.FUZZY_SELECTED
        return LayerRuleMatch(
            csv_entry=entry,
            status=status.value,
            candidates=[],
            fuzzy_candidates=fuzzy_candidates,
            split_candidate_groups=split_groups,
            selected_candidate=selected_source,
            selected_fuzzy_candidate=selected_fuzzy,
            candidate_deltas=[],
            candidate_field_deltas=[],
            semantic_candidate_delta_count=0,
            id_only_delta_count=0,
            blocking_candidate_delta_count=0,
            sanity_deltas=compare_csv_to_rule_signature(entry, selected_source.signature),
            warnings=[],
            skip_reason=None,
            primary_reason_code="FUZZY_SELECTED_BY_USER" if entry.order in options.fuzzy_selections else "FUZZY_AUTO_SELECTED_SINGLE_ARTIFACT",
            human_reason="Fuzzy source candidate selected for copy.",
            user_decision="FUZZY_SELECTED_BY_USER" if entry.order in options.fuzzy_selections else "FUZZY_AUTO_SELECTED_SINGLE_ARTIFACT",
            commit_impact="Rule will be copied from the selected fuzzy source candidate.",
            target_rule_name=entry.rule_name if options.target_rule_name_mode == "csv" else selected_source.rule_name,
            rename_to_csv_rule_name=options.target_rule_name_mode == "csv" and selected_source.rule_name != entry.rule_name,
        )

    if entry.order in options.fuzzy_skips:
        status = RuleMatchStatus.SKIPPED_BY_USER
        reason_code = "SKIPPED_BY_USER"
        human_reason = "User selected skip for this rule."
        user_decision = "SKIPPED_BY_USER"
    elif fuzzy_candidates:
        status = RuleMatchStatus.SKIPPED_NO_CANDIDATE_SELECTED if options.skip_missing else RuleMatchStatus.FUZZY_CANDIDATES_FOUND
        reason_code = "NO_EXACT_MATCH"
        human_reason = "No exact rule-name match was found in selected source ACPs. Fuzzy candidates were found but none were selected."
        user_decision = "SKIPPED_NO_CANDIDATE_SELECTED" if options.skip_missing else "NEEDS_USER_RESOLUTION"
    else:
        status = RuleMatchStatus.SKIPPED_BY_OPTION if options.skip_missing else RuleMatchStatus.NO_FUZZY_CANDIDATES
        reason_code = "NO_FUZZY_CANDIDATES"
        human_reason = "No exact or fuzzy rule-name match was found in selected source ACPs."
        user_decision = "SKIPPED_BY_OPTION" if options.skip_missing else "NEEDS_SOURCE_RULE"

    return LayerRuleMatch(
        csv_entry=entry,
        status=status.value,
        candidates=[],
        fuzzy_candidates=fuzzy_candidates,
        split_candidate_groups=split_groups,
        selected_candidate=None,
        selected_fuzzy_candidate=None,
        candidate_deltas=[],
        candidate_field_deltas=[],
        semantic_candidate_delta_count=0,
        id_only_delta_count=0,
        blocking_candidate_delta_count=0,
        sanity_deltas=[],
        warnings=[],
        skip_reason=human_reason if status.value.startswith("SKIPPED") else "No exact matching source rule found.",
        primary_reason_code=reason_code,
        human_reason=human_reason,
        user_decision=user_decision,
        commit_impact="Rule was not copied." if status.value.startswith("SKIPPED") else "Commit is blocked until this rule is resolved or skipped.",
        skip_reason_detail=_skip_reason_detail(
            entry=entry,
            status="SKIPPED" if status.value.startswith("SKIPPED") else status.value,
            reason_code=reason_code,
            human_reason=human_reason,
            source_acps=source_acps,
            exact_candidates=[],
            fuzzy_candidates=fuzzy_candidates,
            selected_candidate=None,
            user_decision=user_decision,
            commit_impact="Rule was not copied." if status.value.startswith("SKIPPED") else "Commit is blocked until this rule is resolved or skipped.",
            warnings=[],
        ),
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
    informational_count = informational_candidate_delta_count(candidate_field_deltas)
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
        warnings.append(f"{informational_count} informational candidate field delta(s); no semantic copy blocker.")

    return LayerRuleMatch(
        csv_entry=entry,
        status=status.value,
        candidates=candidates,
        fuzzy_candidates=[],
        split_candidate_groups=[],
        selected_candidate=selected,
        selected_fuzzy_candidate=None,
        candidate_deltas=candidate_deltas,
        candidate_field_deltas=candidate_field_deltas,
        semantic_candidate_delta_count=semantic_count,
        id_only_delta_count=id_only_count,
        blocking_candidate_delta_count=blocking_count,
        sanity_deltas=sanity_deltas,
        warnings=warnings,
        skip_reason=None,
        primary_reason_code="EXACT_MATCH_FOUND",
        human_reason="Exact rule-name match found in selected source ACPs.",
        user_decision="EXACT_MATCH_SELECTED",
        commit_impact="Rule will be copied.",
        target_rule_name=entry.rule_name if options.target_rule_name_mode == "csv" else selected.rule_name,
        rename_to_csv_rule_name=options.target_rule_name_mode == "csv" and selected.rule_name != entry.rule_name,
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
        "missing": counts[RuleMatchStatus.MISSING.value] + counts[RuleMatchStatus.NO_FUZZY_CANDIDATES.value],
        "exact_matched": counts[RuleMatchStatus.MATCHED_ONE.value] + counts[RuleMatchStatus.MATCHED_IDENTICAL_MULTIPLE.value] + counts[RuleMatchStatus.MATCHED_MULTIPLE_WITH_DELTA.value],
        "exact_missing": counts[RuleMatchStatus.FUZZY_CANDIDATES_FOUND.value] + counts[RuleMatchStatus.NO_FUZZY_CANDIDATES.value] + counts[RuleMatchStatus.SKIPPED_NO_CANDIDATE_SELECTED.value] + counts[RuleMatchStatus.SKIPPED_BY_OPTION.value] + counts[RuleMatchStatus.SKIPPED_BY_USER.value],
        "fuzzy_candidates_found": sum(1 for match in matches if match.fuzzy_candidates),
        "fuzzy_selected": counts[RuleMatchStatus.FUZZY_SELECTED.value] + counts[RuleMatchStatus.FUZZY_SELECTED_RENAMED_TO_CSV.value],
        "csv_duplicates": counts[RuleMatchStatus.CSV_DUPLICATE_RULE_NAME.value],
        "ready_to_copy": ready,
        "skipped": counts[RuleMatchStatus.SKIPPED.value] + counts[RuleMatchStatus.SKIPPED_NO_CANDIDATE_SELECTED.value] + counts[RuleMatchStatus.SKIPPED_BY_OPTION.value] + counts[RuleMatchStatus.SKIPPED_BY_USER.value],
        "unresolved": counts[RuleMatchStatus.FUZZY_CANDIDATES_FOUND.value] + counts[RuleMatchStatus.NO_FUZZY_CANDIDATES.value],
        "created": counts[RuleMatchStatus.CREATED.value],
        "failed": counts[RuleMatchStatus.CREATE_FAILED.value],
        "warnings": warnings,
        "blockers": 0,
        "semantic_candidate_deltas": sum(match.semantic_candidate_delta_count for match in matches),
        "informational_candidate_deltas": sum(
            informational_candidate_delta_count(match.candidate_field_deltas)
            for match in matches
        ),
        "id_only_candidate_deltas": field_delta_types["ID_ONLY_DIFFERENCE"],
        "context_only_candidate_deltas": field_delta_types["CONTEXT_ONLY_DIFFERENCE"],
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

    missing = [match for match in matches if match.status in {RuleMatchStatus.MISSING.value, RuleMatchStatus.NO_FUZZY_CANDIDATES.value, RuleMatchStatus.FUZZY_CANDIDATES_FOUND.value}]
    skipped = [match for match in matches if match.status.startswith("SKIPPED")]
    candidate_deltas = [match for match in matches if match.blocking_candidate_delta_count]
    selected = [match for match in matches if match.selected_candidate]
    if entries and not selected and not options.skip_missing:
        blockers.append("All CSV rules are missing from selected source ACPs.")
    if missing and not options.skip_missing:
        blockers.append(f"{len(missing)} CSV rule(s) are missing or fuzzy-unresolved and skip missing is disabled.")
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


def _selected_fuzzy(
    entry: LayerCsvEntry,
    fuzzy_candidates: list[FuzzyRuleCandidate],
    options: LayerComposerOptions,
) -> FuzzyRuleCandidate | None:
    selected_key = options.fuzzy_selections.get(entry.order)
    if selected_key:
        return next((candidate for candidate in fuzzy_candidates if _fuzzy_key(candidate) == selected_key), None)
    if (
        options.fuzzy.auto_accept_single_deterministic_artifact
        or options.fuzzy.auto_select_single_artifact_match
        and len(fuzzy_candidates) == 1
        and fuzzy_candidates[0].match_tier == "ARTIFACT_SUFFIX"
        and not fuzzy_candidates[0].blocking_candidate_deltas
    ):
        return fuzzy_candidates[0]
    return None


def _source_candidate_for_fuzzy(
    fuzzy: FuzzyRuleCandidate | None,
    source_rules: list[SourceRuleCandidate],
) -> SourceRuleCandidate | None:
    if not fuzzy:
        return None
    return next(
        (
            source
            for source in source_rules
            if source.source_acp_id == fuzzy.source_acp_id and source.rule_id == fuzzy.source_rule_id
        ),
        None,
    )


def _fuzzy_key(candidate: FuzzyRuleCandidate) -> str:
    return f"{candidate.source_acp_id}:{candidate.source_rule_id}"


def _record_fuzzy_diagnostic(
    diagnostics_logger: Any | None,
    entry: LayerCsvEntry,
    match: LayerRuleMatch,
    source_rules: list[SourceRuleCandidate],
    source_acps: list[SourceAcpRef],
    options: LayerComposerOptions,
) -> None:
    if not diagnostics_logger:
        return
    diagnostics_logger.event(
        stage="match_rules",
        severity="info" if match.selected_candidate or match.status.startswith("SKIPPED") else "warning",
        csv_order=entry.order,
        rule_name=entry.rule_name,
        status=match.status,
        decision=match.user_decision,
        reason_code=match.primary_reason_code,
        details={
            "exact_name_searched": entry.rule_name,
            "normalized_names_searched": [normalize_rule_name(entry.rule_name, options.match_mode)],
            "source_acps_searched": [acp.name for acp in source_acps],
            "rules_scanned": len(source_rules),
            "fuzzy_candidates_found": len(match.fuzzy_candidates),
            "candidate_ranking_details": [asdict(candidate) for candidate in match.fuzzy_candidates],
            "final_decision": match.user_decision,
        },
    )


def _skip_reason_detail(
    *,
    entry: LayerCsvEntry,
    status: str,
    reason_code: str,
    human_reason: str,
    source_acps: list[SourceAcpRef],
    exact_candidates: list[SourceRuleCandidate],
    fuzzy_candidates: list[FuzzyRuleCandidate],
    selected_candidate: dict[str, Any] | None,
    user_decision: str,
    commit_impact: str,
    warnings: list[str],
) -> RuleSkipReason:
    return RuleSkipReason(
        csv_order=entry.order,
        csv_rule_name=entry.rule_name,
        final_status=status,
        primary_reason_code=reason_code,
        human_reason=human_reason,
        match_mode_used="exact + artifact_fuzzy",
        source_acps_searched=[acp.name for acp in source_acps],
        exact_candidates_found=[
            {"rule_name": candidate.rule_name, "source_acp_name": candidate.source_acp_name, "source_rule_id": candidate.rule_id}
            for candidate in exact_candidates
        ],
        fuzzy_candidates_found=[
            {
                "rule_name": candidate.candidate_rule_name,
                "source_acp_name": candidate.source_acp_name,
                "source_rule_id": candidate.source_rule_id,
                "score": candidate.score,
                "match_tier": candidate.match_tier,
                "match_reasons": candidate.match_reasons,
            }
            for candidate in fuzzy_candidates
        ],
        selected_candidate=selected_candidate,
        user_decision=user_decision,
        commit_impact=commit_impact,
        blockers_or_warnings=warnings,
    )
