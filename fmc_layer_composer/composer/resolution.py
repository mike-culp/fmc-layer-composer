from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Any

from .models import (
    FuzzyRuleCandidate,
    LayerComposerPlan,
    ResolvedLayerComposerPlan,
    RuleSkipReason,
    RuleMatchStatus,
    SourceRuleCandidate,
)
from .state import make_rule_key


def initialize_resolution_state(plan: LayerComposerPlan, existing: dict[str, dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    state = dict(existing or {})
    valid_keys = set()
    for match in plan.matches:
        if not _needs_resolution(match):
            continue
        key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
        valid_keys.add(key)
        state.setdefault(
            key,
            {
                "csv_order": match.csv_entry.order,
                "csv_rule_name": match.csv_entry.rule_name,
                "decision": "UNRESOLVED",
                "selected_candidate_key": None,
                "selected_source_acp_id": None,
                "selected_source_acp_name": None,
                "selected_source_rule_id": None,
                "selected_source_rule_name": None,
                "use_priority_override": False,
                "skip": False,
                "rename_to_csv_rule_name": True,
                "selection_method": None,
                "notes": "",
            },
        )
    return {key: value for key, value in state.items() if key in valid_keys}


def apply_resolution_state_to_plan(
    plan: LayerComposerPlan,
    resolution_state: dict[str, dict[str, Any]],
) -> ResolvedLayerComposerPlan:
    resolved = copy.deepcopy(plan)
    for match in resolved.matches:
        key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
        decision = resolution_state.get(key)
        if not decision:
            continue
        if decision.get("skip") or decision.get("decision") in {"SKIP", "MARK_NOT_FOUND"}:
            match.status = RuleMatchStatus.SKIPPED_BY_USER.value
            match.selected_candidate = None
            match.selected_fuzzy_candidate = None
            match.skip_reason = "User selected skip for this rule."
            match.primary_reason_code = "SKIPPED_BY_USER"
            match.human_reason = "User selected skip for this rule."
            match.user_decision = decision.get("decision") or "SKIP"
            match.commit_impact = "Rule was not copied."
            match.skip_reason_detail = _skip_reason_detail(match, decision)
            continue
        if decision.get("decision") == "USE_SELECTED_FUZZY_CANDIDATE":
            selected_fuzzy = _find_fuzzy(match.fuzzy_candidates, decision.get("selected_candidate_key"))
            if selected_fuzzy:
                match.selected_fuzzy_candidate = selected_fuzzy
                match.selected_candidate = _source_from_fuzzy(selected_fuzzy)
                rename = bool(decision.get("rename_to_csv_rule_name", True))
                match.rename_to_csv_rule_name = rename and selected_fuzzy.candidate_rule_name != match.csv_entry.rule_name
                match.target_rule_name = match.csv_entry.rule_name if rename else selected_fuzzy.candidate_rule_name
                match.status = RuleMatchStatus.FUZZY_SELECTED_RENAMED_TO_CSV.value if match.rename_to_csv_rule_name else RuleMatchStatus.FUZZY_SELECTED.value
                match.primary_reason_code = "FUZZY_SELECTED_BY_USER"
                match.human_reason = "Fuzzy source candidate selected for copy."
                match.user_decision = "FUZZY_SELECTED_BY_USER"
                match.commit_impact = "Rule will be copied from the selected fuzzy source candidate."
        elif decision.get("decision") == "USE_PRIORITY_OVERRIDE" and match.candidates:
            selected = match.candidates[0]
            match.selected_candidate = selected
            match.status = RuleMatchStatus.MATCHED_IDENTICAL_MULTIPLE.value
            match.primary_reason_code = "PRIORITY_OVERRIDE_SELECTED_BY_USER"
            match.user_decision = "PRIORITY_OVERRIDE_SELECTED_BY_USER"
            match.commit_impact = "Rule will be copied using source ACP priority override."

    summary = _summary(resolved)
    blockers = _blockers(resolved, summary)
    resolved.summary.update(summary)
    resolved.commit_allowed = not blockers
    resolved.blockers = blockers
    return ResolvedLayerComposerPlan(plan=resolved, summary=summary, commit_allowed=not blockers, blockers=blockers, warnings=resolved.warnings)


def candidate_key(candidate: FuzzyRuleCandidate) -> str:
    return f"{candidate.source_acp_id}:{candidate.source_rule_id}"


def _needs_resolution(match: Any) -> bool:
    return bool(match.fuzzy_candidates) or match.status in {RuleMatchStatus.MATCHED_MULTIPLE_WITH_DELTA.value, RuleMatchStatus.NO_FUZZY_CANDIDATES.value}


def _find_fuzzy(candidates: list[FuzzyRuleCandidate], key: str | None) -> FuzzyRuleCandidate | None:
    return next((candidate for candidate in candidates if candidate_key(candidate) == key), None)


def _source_from_fuzzy(fuzzy: FuzzyRuleCandidate) -> SourceRuleCandidate:
    return SourceRuleCandidate(
        source_acp_id=fuzzy.source_acp_id,
        source_acp_name=fuzzy.source_acp_name,
        source_priority=0,
        rule_id=fuzzy.source_rule_id,
        rule_name=fuzzy.candidate_rule_name,
        rule={"id": fuzzy.source_rule_id, "name": fuzzy.candidate_rule_name},
        signature=fuzzy.semantic_summary,
    )


def _summary(plan: LayerComposerPlan) -> dict[str, int]:
    exact_ready = sum(1 for match in plan.matches if match.selected_candidate and not match.selected_fuzzy_candidate)
    fuzzy_selected = sum(1 for match in plan.matches if match.selected_fuzzy_candidate)
    priority_overrides = sum(1 for match in plan.matches if match.user_decision == "PRIORITY_OVERRIDE_SELECTED_BY_USER")
    skipped = sum(1 for match in plan.matches if str(match.status).startswith("SKIPPED"))
    unresolved = sum(1 for match in plan.matches if not match.selected_candidate and not str(match.status).startswith("SKIPPED"))
    expected_creates = exact_ready + fuzzy_selected
    return {
        "total_csv_rules": len(plan.matches),
        "exact_ready": exact_ready,
        "fuzzy_selected": fuzzy_selected,
        "priority_overrides_selected": priority_overrides,
        "skipped_by_user": sum(1 for match in plan.matches if match.status == RuleMatchStatus.SKIPPED_BY_USER.value),
        "skipped_by_option": sum(1 for match in plan.matches if match.status == RuleMatchStatus.SKIPPED_BY_OPTION.value or match.status == RuleMatchStatus.SKIPPED_NO_CANDIDATE_SELECTED.value),
        "skipped": skipped,
        "unresolved": unresolved,
        "blocked": 0,
        "expected_creates": expected_creates,
        "ready_to_copy": expected_creates,
    }


def _blockers(plan: LayerComposerPlan, summary: dict[str, int]) -> list[str]:
    blockers = [
        blocker
        for blocker in plan.blockers
        if "missing or fuzzy-unresolved" not in blocker and "All CSV rules are missing" not in blocker
    ]
    if summary["unresolved"] and not plan.options.skip_missing:
        blockers.append(f"{summary['unresolved']} unresolved rule(s) require selection or skip.")
    if not summary["expected_creates"]:
        blockers.append("No rules are ready to copy.")
    return blockers


def _skip_reason_detail(match: Any, decision: dict[str, Any]) -> RuleSkipReason:
    return RuleSkipReason(
        csv_order=match.csv_entry.order,
        csv_rule_name=match.csv_entry.rule_name,
        final_status="SKIPPED",
        primary_reason_code="SKIPPED_BY_USER" if decision.get("decision") == "SKIP" else "NO_FUZZY_CANDIDATES",
        human_reason=match.human_reason or match.skip_reason or "Rule was skipped by user decision.",
        match_mode_used="exact + artifact_fuzzy",
        source_acps_searched=sorted({candidate.source_acp_name for candidate in match.candidates} | {candidate.source_acp_name for candidate in match.fuzzy_candidates}),
        exact_candidates_found=[
            {"rule_name": candidate.rule_name, "source_acp_name": candidate.source_acp_name, "source_rule_id": candidate.rule_id}
            for candidate in match.candidates
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
            for candidate in match.fuzzy_candidates
        ],
        selected_candidate=None,
        user_decision=decision.get("decision") or "SKIP",
        commit_impact="Rule was not copied.",
        blockers_or_warnings=list(match.warnings),
    )


def resolution_state_to_jsonable(state: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {key: dict(value) for key, value in state.items()}
