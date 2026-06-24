from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Any

from .models import (
    FuzzyRuleCandidate,
    LayerComposerPlan,
    ResolvedLayerComposerPlan,
    RuleCreateTask,
    RuleSkipReason,
    RuleMatchStatus,
    SourceRuleCandidate,
)
from .naming import FMC_ACCESS_RULE_NAME_MAX_LENGTH, get_rule_name_length_warning, is_valid_fmc_rule_name, rule_name_length
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
                "selected_candidate_keys": [],
                "selected_source_rules": [],
                "selected_source_acp_id": None,
                "selected_source_acp_name": None,
                "selected_source_rule_id": None,
                "selected_source_rule_name": None,
                "use_priority_override": False,
                "multi_rule_override": False,
                "skip": False,
                "target_naming_mode": "AUTO",
                "rename_to_csv_rule_name": True,
                "custom_target_rule_names": {},
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
        selected_keys = list(decision.get("selected_candidate_keys") or [])
        if not selected_keys and decision.get("selected_candidate_key"):
            selected_keys = [decision["selected_candidate_key"]]
        if decision.get("decision") in {"USE_SELECTED_FUZZY_CANDIDATE", "USE_MULTI_RULE_OVERRIDE"} and selected_keys:
            selected_fuzzies = [candidate for key in selected_keys if (candidate := _find_fuzzy(match.fuzzy_candidates, key))]
            if len(selected_fuzzies) > 1:
                _apply_multi_rule_override(match, selected_fuzzies, decision)
                continue
            selected_fuzzy = _find_fuzzy(match.fuzzy_candidates, decision.get("selected_candidate_key"))
            if selected_fuzzy:
                match.selected_fuzzy_candidate = selected_fuzzy
                match.selected_candidate = _source_from_fuzzy(selected_fuzzy)
                target_mode = decision.get("target_naming_mode") or "AUTO"
                custom_name = _custom_target_name_for_selected(decision, selected_fuzzy.source_acp_id, selected_fuzzy.source_rule_id)
                match.target_rule_name = custom_name or _target_rule_name(
                    match.csv_entry.rule_name,
                    selected_fuzzy.candidate_rule_name,
                    target_mode,
                    1,
                    1,
                )
                match.rename_to_csv_rule_name = match.target_rule_name == match.csv_entry.rule_name and selected_fuzzy.candidate_rule_name != match.csv_entry.rule_name
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
    create_tasks, validation_blockers = build_create_tasks(resolved, resolution_state)
    blockers = _blockers(resolved, summary)
    blockers.extend(validation_blockers)
    summary["expected_create_operations"] = len(create_tasks)
    summary["multi_rule_overrides"] = sum(1 for match in resolved.matches if match.status in {RuleMatchStatus.MULTI_RULE_OVERRIDE_READY.value, RuleMatchStatus.MULTI_RULE_OVERRIDE_RENAMED.value, RuleMatchStatus.MULTI_RULE_OVERRIDE_PRESERVE_SOURCE_NAMES.value})
    summary["create_tasks"] = [asdict(task) for task in create_tasks]
    summary["target_rule_name_validation"] = [_target_name_validation_record(task) for task in create_tasks]
    summary["invalid_target_rule_names"] = sum(1 for task in create_tasks if task.target_rule_name_validation_status != "VALID")
    resolved.summary.update(summary)
    resolved.resolved_plan_summary = summary
    resolved.commit_allowed = not blockers
    resolved.blockers = blockers
    return ResolvedLayerComposerPlan(plan=resolved, summary=summary, commit_allowed=not blockers, blockers=blockers, warnings=resolved.warnings)


def build_create_tasks(
    plan: LayerComposerPlan,
    resolution_state: dict[str, dict[str, Any]] | None = None,
    diagnostics_logger: Any | None = None,
) -> tuple[list[RuleCreateTask], list[str]]:
    tasks: list[RuleCreateTask] = []
    blockers: list[str] = []
    task_order = 1
    target_names: dict[str, RuleCreateTask] = {}
    state = resolution_state or {}
    for match in sorted(plan.matches, key=lambda item: item.csv_entry.order):
        rule_key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
        decision = state.get(rule_key, {})
        selected_rules = _selected_rules_from_decision(match, decision)
        if not selected_rules and match.selected_candidate:
            selected_rules = [
                {
                    "source_acp_id": match.selected_candidate.source_acp_id,
                    "source_acp_name": match.selected_candidate.source_acp_name,
                    "source_rule_id": match.selected_candidate.rule_id,
                    "source_rule_name": match.selected_candidate.rule_name,
                    "source_rule_index": _rule_index(match.selected_candidate.rule),
                    "selection_order": 1,
                    "selection_method": match.user_decision or "EXACT_MATCH_SELECTED",
                }
            ]
        if not selected_rules:
            continue
        target_naming_mode = decision.get("target_naming_mode") or "AUTO"
        if len(selected_rules) > 1 and target_naming_mode == "CSV_NAME":
            blockers.append(f"CSV_NAME target naming cannot be used for multi-rule override at CSV order {match.csv_entry.order}.")
            _record_name_diagnostic(
                diagnostics_logger,
                "TARGET_NAME_VALIDATION_FAILED",
                {"csv_order": match.csv_entry.order, "problem": "CSV_NAME cannot be used for multi-rule override."},
            )
            continue
        for part_number, selected in enumerate(sorted(selected_rules, key=lambda item: int(item.get("selection_order", 1))), start=1):
            candidate_key_value = selected.get("candidate_key") or f"{selected.get('source_acp_id')}:{selected.get('source_rule_id')}"
            custom_target_name = _custom_target_name_for_key(decision, candidate_key_value, str(selected.get("source_rule_id", "")))
            target_name = custom_target_name or _target_rule_name(match.csv_entry.rule_name, selected["source_rule_name"], target_naming_mode, len(selected_rules), part_number)
            if custom_target_name:
                _record_name_diagnostic(
                    diagnostics_logger,
                    "CUSTOM_TARGET_NAME_SET",
                    {"csv_order": match.csv_entry.order, "source_rule_name": selected["source_rule_name"], "target_rule_name": custom_target_name},
                )
            elif target_naming_mode == "AUTO" and target_name == selected["source_rule_name"] and match.csv_entry.rule_name != selected["source_rule_name"]:
                _record_name_diagnostic(
                    diagnostics_logger,
                    "TARGET_NAME_MODE_AUTO_PRESERVE_SOURCE",
                    {"csv_order": match.csv_entry.order, "csv_rule_name": match.csv_entry.rule_name, "source_rule_name": selected["source_rule_name"]},
                )
            task = RuleCreateTask(
                csv_order=match.csv_entry.order,
                csv_rule_name=match.csv_entry.rule_name,
                task_order=task_order,
                source_acp_id=selected["source_acp_id"],
                source_acp_name=selected["source_acp_name"],
                source_rule_id=selected["source_rule_id"],
                source_rule_name=selected["source_rule_name"],
                target_rule_name=target_name,
                selection_method=selected.get("selection_method") or "USER_SELECTED",
                is_multi_rule_override=len(selected_rules) > 1,
                multi_rule_part_number=part_number if len(selected_rules) > 1 else None,
                multi_rule_part_total=len(selected_rules) if len(selected_rules) > 1 else None,
                target_naming_mode=target_naming_mode,
                custom_target_rule_name=custom_target_name,
            )
            _validate_task_target_name(task, blockers, diagnostics_logger)
            if target_name in target_names:
                task.target_rule_name_validation_status = "ERROR"
                task.target_rule_name_warning = f"Duplicate target rule name '{target_name}' in create queue."
                task.target_rule_name_recommended_action = "Choose a unique custom target rule name."
                blockers.append(f"Duplicate target rule name '{target_name}' from CSV order {match.csv_entry.order}.")
                _record_name_diagnostic(
                    diagnostics_logger,
                    "TARGET_NAME_VALIDATION_FAILED",
                    {"csv_order": match.csv_entry.order, "target_rule_name": target_name, "problem": task.target_rule_name_warning},
                )
            target_names[target_name] = task
            tasks.append(task)
            task_order += 1
    return tasks, blockers


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


def _apply_multi_rule_override(match: Any, selected_fuzzies: list[FuzzyRuleCandidate], decision: dict[str, Any]) -> None:
    match.selected_candidate = _source_from_fuzzy(selected_fuzzies[0])
    match.selected_fuzzy_candidate = selected_fuzzies[0]
    target_mode = decision.get("target_naming_mode") or "AUTO"
    if target_mode == "CSV_NAME_WITH_PART_SUFFIX":
        match.status = RuleMatchStatus.MULTI_RULE_OVERRIDE_RENAMED.value
    elif target_mode in {"AUTO", "PRESERVE_SOURCE_NAMES"}:
        match.status = RuleMatchStatus.MULTI_RULE_OVERRIDE_PRESERVE_SOURCE_NAMES.value
    else:
        match.status = RuleMatchStatus.MULTI_RULE_OVERRIDE_READY.value
    match.primary_reason_code = "MULTI_RULE_OVERRIDE_SELECTED"
    match.human_reason = "Multiple source rules selected for one CSV rule."
    match.user_decision = "USE_MULTI_RULE_OVERRIDE"
    match.commit_impact = f"{len(selected_fuzzies)} source rules will be copied contiguously at this CSV rule position."


def _summary(plan: LayerComposerPlan) -> dict[str, int]:
    exact_ready = sum(1 for match in plan.matches if match.selected_candidate and not match.selected_fuzzy_candidate)
    fuzzy_selected = sum(1 for match in plan.matches if match.selected_fuzzy_candidate)
    priority_overrides = sum(1 for match in plan.matches if match.user_decision == "PRIORITY_OVERRIDE_SELECTED_BY_USER")
    skipped = sum(1 for match in plan.matches if str(match.status).startswith("SKIPPED"))
    unresolved = sum(1 for match in plan.matches if not match.selected_candidate and not str(match.status).startswith("SKIPPED"))
    create_tasks, _ = build_create_tasks(plan, {})
    expected_creates = len(create_tasks)
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


def _selected_rules_from_decision(match: Any, decision: dict[str, Any]) -> list[dict[str, Any]]:
    if decision.get("selected_source_rules"):
        return list(decision["selected_source_rules"])
    keys = list(decision.get("selected_candidate_keys") or [])
    if not keys and decision.get("selected_candidate_key"):
        keys = [decision["selected_candidate_key"]]
    selected: list[dict[str, Any]] = []
    for order, key in enumerate(keys, start=1):
        fuzzy = _find_fuzzy(match.fuzzy_candidates, key)
        if not fuzzy:
            continue
        selected.append(
            {
                "candidate_key": key,
                "source_acp_id": fuzzy.source_acp_id,
                "source_acp_name": fuzzy.source_acp_name,
                "source_rule_id": fuzzy.source_rule_id,
                "source_rule_name": fuzzy.candidate_rule_name,
                "source_rule_index": 999999,
                "selection_order": order,
                "selection_method": decision.get("selection_method") or ("USER_SELECTED_MULTI_RULE_OVERRIDE" if len(keys) > 1 else "USER_SELECTED"),
            }
        )
    return selected


def _target_rule_name(csv_rule_name: str, source_rule_name: str, mode: str, total: int, part_number: int) -> str:
    if mode == "CSV_NAME":
        return csv_rule_name
    if mode == "CSV_NAME_WITH_PART_SUFFIX":
        return f"{csv_rule_name} - part {part_number}"
    if mode in {"AUTO", "PRESERVE_SOURCE_NAMES"} and total > 1:
        return source_rule_name
    if mode == "PRESERVE_SOURCE_NAMES":
        return source_rule_name
    if mode == "AUTO" and not is_valid_fmc_rule_name(csv_rule_name):
        return source_rule_name
    return csv_rule_name


def default_target_naming_mode(csv_rule_name: str, selected_rule_count: int) -> str:
    if selected_rule_count > 1:
        return "PRESERVE_SOURCE_NAMES"
    return "CSV_NAME" if is_valid_fmc_rule_name(csv_rule_name) else "PRESERVE_SOURCE_NAMES"


def csv_name_mode_disabled_reason(csv_rule_name: str, selected_rule_count: int) -> str | None:
    if selected_rule_count > 1:
        return "Use CSV rule name is not valid for multi-rule overrides."
    warning = get_rule_name_length_warning(csv_rule_name)
    if warning:
        return warning
    return None


def _validate_task_target_name(task: RuleCreateTask, blockers: list[str], diagnostics_logger: Any | None) -> None:
    task.target_rule_name_length = rule_name_length(task.target_rule_name)
    warning = get_rule_name_length_warning(task.target_rule_name)
    if not warning:
        task.target_rule_name_validation_status = "VALID"
        task.target_rule_name_warning = None
        task.target_rule_name_recommended_action = None
        return
    task.target_rule_name_validation_status = "ERROR"
    if not task.target_rule_name:
        task.target_rule_name_warning = "Target rule name is empty."
    else:
        task.target_rule_name_warning = f"Target rule name is {task.target_rule_name_length} characters; FMC maximum is {FMC_ACCESS_RULE_NAME_MAX_LENGTH}."
    task.target_rule_name_recommended_action = "Use Preserve source rule name or choose a shorter custom target name."
    blockers.append(f"CSV order {task.csv_order}: {task.target_rule_name_warning}")
    _record_name_diagnostic(
        diagnostics_logger,
        "TARGET_NAME_TOO_LONG" if task.target_rule_name else "TARGET_NAME_VALIDATION_FAILED",
        {
            "csv_order": task.csv_order,
            "csv_rule_name": task.csv_rule_name,
            "source_rule_name": task.source_rule_name,
            "target_rule_name": task.target_rule_name,
            "target_rule_name_length": task.target_rule_name_length,
            "problem": task.target_rule_name_warning,
        },
    )


def _custom_target_name_for_selected(decision: dict[str, Any], source_acp_id: str, source_rule_id: str) -> str | None:
    return _custom_target_name_for_key(decision, f"{source_acp_id}:{source_rule_id}", source_rule_id)


def _custom_target_name_for_key(decision: dict[str, Any], candidate_key_value: str, source_rule_id: str) -> str | None:
    custom_names = decision.get("custom_target_rule_names") or {}
    value = custom_names.get(candidate_key_value) or custom_names.get(source_rule_id) or decision.get("custom_target_rule_name")
    value = str(value).strip() if value is not None else ""
    return value or None


def _record_name_diagnostic(diagnostics_logger: Any | None, event_type: str, payload: dict[str, Any]) -> None:
    if not diagnostics_logger:
        return
    diagnostics_logger.event(event_type, payload)


def _target_name_validation_record(task: RuleCreateTask) -> dict[str, Any]:
    return {
        "csv_order": task.csv_order,
        "csv_rule_name": task.csv_rule_name,
        "csv_rule_name_length": rule_name_length(task.csv_rule_name),
        "source_rule_name": task.source_rule_name,
        "target_rule_name": task.target_rule_name,
        "target_rule_name_length": task.target_rule_name_length,
        "naming_mode": task.target_naming_mode,
        "custom_target_rule_name": task.custom_target_rule_name or "",
        "validation_status": task.target_rule_name_validation_status,
        "problem": task.target_rule_name_warning or "",
        "recommended_action": task.target_rule_name_recommended_action or "",
    }


def _rule_index(rule: dict[str, Any]) -> int:
    metadata = rule.get("metadata") or {}
    return int(metadata.get("ruleIndex") or 999999)


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
