from __future__ import annotations

import copy
from dataclasses import asdict
from typing import Any

from .models import CreatedRuleResult, LayerComposerPlan, LayerComposerResult, RuleMatchStatus


SERVER_MANAGED_RULE_FIELDS = {
    "id",
    "links",
    "metadata",
    "version",
    "commentHistoryList",
}

VERIFIED = "VERIFIED"
VERIFY_MISMATCH = "VERIFY_MISMATCH"
VERIFY_FAILED = "VERIFY_FAILED"


def sanitize_access_rule_for_create(
    source_rule: dict[str, Any],
    provenance: dict[str, Any],
    csv_entry: Any,
    honor_csv_disabled: bool = True,
    target_rule_name: str | None = None,
) -> dict[str, Any]:
    payload = copy.deepcopy(source_rule)
    for field in SERVER_MANAGED_RULE_FIELDS:
        payload.pop(field, None)
    payload["type"] = "AccessRule"
    if "action" not in payload:
        raise ValueError("Source access rule payload is missing required action.")
    if target_rule_name:
        payload["name"] = target_rule_name
    if honor_csv_disabled and csv_entry.csv_enabled is False:
        payload["enabled"] = False
    comment = (
        "Copied by FMC Layer Composer from source ACP "
        f"'{provenance.get('source_acp_name')}', source rule '{provenance.get('rule_name')}', "
        f"source rule ID '{provenance.get('source_rule_id')}', CSV rule '{csv_entry.rule_name}', CSV '{provenance.get('csv_filename')}', "
        f"CSV order '{csv_entry.order}'."
    )
    if target_rule_name and target_rule_name != provenance.get("rule_name"):
        comment += " Source rule was renamed to the CSV rule name during copy."
    payload["newComments"] = [comment]
    return payload


def execute_plan(
    *,
    plan: LayerComposerPlan,
    client: Any,
    domain_uuid: str,
    policies_module: Any,
    rules_module: Any,
    reports_module: Any | None = None,
    diagnostics_logger: Any | None = None,
) -> LayerComposerResult:
    if not plan.commit_allowed:
        raise ValueError("Plan is not commit allowed.")

    existing = policies_module.get_access_policy_by_name(client, domain_uuid, plan.target_acp_name)
    if existing:
        raise ValueError(f"Target ACP '{plan.target_acp_name}' already exists.")

    target = policies_module.create_access_policy(
        client,
        domain_uuid,
        plan.target_acp_name,
        default_action=plan.options.default_action,
    )
    target_id = str(target.get("id", ""))
    created: list[CreatedRuleResult] = []
    skipped: list[dict[str, Any]] = []
    failed: CreatedRuleResult | None = None
    errors: list[dict[str, Any]] = []

    for match in plan.matches:
        if not match.selected_candidate:
            skipped.append(_skipped_rule_record(match))
            continue
        candidate = match.selected_candidate
        try:
            fresh_rule = rules_module.get_access_rule(client, domain_uuid, candidate.source_acp_id, candidate.rule_id)
            payload = sanitize_access_rule_for_create(
                fresh_rule,
                provenance={
                    "source_acp_name": candidate.source_acp_name,
                    "rule_name": candidate.rule_name,
                    "source_rule_id": candidate.rule_id,
                    "csv_filename": plan.csv_filename,
                },
                csv_entry=match.csv_entry,
                honor_csv_disabled=plan.options.honor_csv_disabled,
                target_rule_name=match.target_rule_name or match.csv_entry.rule_name,
            )
            response = rules_module.create_access_rule_from_payload(
                client,
                domain_uuid,
                target_id,
                payload,
                section=plan.options.rule_section,
                diagnostics_logger=diagnostics_logger,
            )
            created.append(
                CreatedRuleResult(
                    csv_order=match.csv_entry.order,
                    rule_name=match.csv_entry.rule_name,
                    source_acp_name=candidate.source_acp_name,
                    source_rule_id=candidate.rule_id,
                    target_rule_id=response.get("id"),
                    status=RuleMatchStatus.CREATED.value,
                    error=None,
                    response=response,
                    placement_strategy=response.get("_placement_strategy"),
                )
            )
        except Exception as exc:  # noqa: BLE001 - report FMC/API failures without rollback in v1.
            failed = CreatedRuleResult(
                csv_order=match.csv_entry.order,
                rule_name=match.csv_entry.rule_name,
                source_acp_name=candidate.source_acp_name,
                source_rule_id=candidate.rule_id,
                target_rule_id=None,
                status=RuleMatchStatus.CREATE_FAILED.value,
                error=str(exc),
                response=getattr(exc, "response_body", None),
                placement_strategy=None,
            )
            created.append(failed)
            errors.append({"csv_order": match.csv_entry.order, "rule_name": match.csv_entry.rule_name, "error": str(exc)})
            if plan.options.stop_on_first_failure:
                break

    result = LayerComposerResult(
        plan=plan,
        target_acp_id=target_id,
        target_acp_name=plan.target_acp_name,
        created_rules=created,
        skipped_rules=skipped,
        failed_rule=failed,
        errors=errors,
        report_paths={},
    )
    _verify_commit_result(
        result=result,
        client=client,
        domain_uuid=domain_uuid,
        rules_module=rules_module,
        diagnostics_logger=diagnostics_logger,
    )
    if reports_module:
        result.report_paths = reports_module.write_commit_report(result)
    return result


def result_to_dict(result: LayerComposerResult) -> dict[str, Any]:
    return asdict(result)


def _verify_commit_result(
    *,
    result: LayerComposerResult,
    client: Any,
    domain_uuid: str,
    rules_module: Any,
    diagnostics_logger: Any | None = None,
) -> None:
    expected_names = [
        item.rule_name
        for item in result.created_rules
        if item.status == RuleMatchStatus.CREATED.value and item.target_rule_id
    ]
    result.expected_create_count = sum(1 for match in result.plan.matches if match.selected_candidate)
    result.api_created_count = len(expected_names)
    if not result.target_acp_id:
        result.verification_status = VERIFY_FAILED
        return
    try:
        target_rules = rules_module.list_access_rules(
            client,
            domain_uuid,
            result.target_acp_id,
            expanded=True,
            diagnostics_logger=diagnostics_logger,
        )
        actual_names = [str(rule.get("name", "")).strip() for rule in target_rules if str(rule.get("name", "")).strip()]
        result.verified_target_rule_count = len(actual_names)
        result.missing_after_commit = _missing_names(expected_names, actual_names)
        result.extra_after_commit = _extra_names(expected_names, actual_names)
        if result.api_created_count == result.expected_create_count and not result.missing_after_commit:
            result.verification_status = VERIFIED
        else:
            result.verification_status = VERIFY_MISMATCH
            matching_expected_count = max(result.api_created_count - len(result.missing_after_commit), 0)
            result.errors.append(
                {
                    "type": VERIFY_MISMATCH,
                    "message": (
                        f"FMC API returned created IDs for {result.api_created_count} rules, but post-commit "
                        f"verification found only {matching_expected_count} matching rules in the target ACP."
                    ),
                    "missing_after_commit": result.missing_after_commit,
                    "extra_after_commit": result.extra_after_commit,
                }
            )
    except Exception as exc:  # noqa: BLE001 - verification failure must not hide commit results.
        result.verification_status = VERIFY_FAILED
        result.errors.append({"type": VERIFY_FAILED, "message": str(exc)})


def _missing_names(expected_names: list[str], actual_names: list[str]) -> list[str]:
    actual_counts = _counts(actual_names)
    missing: list[str] = []
    for name in expected_names:
        if actual_counts.get(name, 0):
            actual_counts[name] -= 1
        else:
            missing.append(name)
    return missing


def _extra_names(expected_names: list[str], actual_names: list[str]) -> list[str]:
    expected_counts = _counts(expected_names)
    extra: list[str] = []
    for name in actual_names:
        if expected_counts.get(name, 0):
            expected_counts[name] -= 1
        else:
            extra.append(name)
    return extra


def _counts(names: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return counts


def _skipped_rule_record(match: Any) -> dict[str, Any]:
    return {
        "csv_order": match.csv_entry.order,
        "rule_name": match.csv_entry.rule_name,
        "csv_rule_name": match.csv_entry.rule_name,
        "final_status": "SKIPPED",
        "status": match.status,
        "primary_reason_code": match.primary_reason_code,
        "human_reason": match.human_reason or match.skip_reason,
        "match_mode_used": "exact",
        "source_acps_searched": sorted({candidate.source_acp_name for candidate in match.candidates} | {candidate.source_acp_name for candidate in match.fuzzy_candidates}),
        "exact_candidates_found": [
            {"rule_name": candidate.rule_name, "source_acp_name": candidate.source_acp_name, "source_rule_id": candidate.rule_id}
            for candidate in match.candidates
        ],
        "fuzzy_candidates_found": [
            {
                "rule_name": candidate.candidate_rule_name,
                "source_acp_name": candidate.source_acp_name,
                "source_rule_id": candidate.source_rule_id,
                "score": candidate.score,
                "match_tier": candidate.match_tier,
                "match_reason": ", ".join(candidate.match_reasons),
            }
            for candidate in match.fuzzy_candidates
        ],
        "selected_candidate": None,
        "user_decision": match.user_decision,
        "commit_impact": match.commit_impact or "Rule was not copied.",
        "skip_reason": match.skip_reason or "No selected source candidate.",
        "source_candidate_summary": [
            {
                "source_acp_name": candidate.source_acp_name,
                "rule_id": candidate.rule_id,
                "rule_name": candidate.rule_name,
            }
            for candidate in match.candidates
        ],
        "blockers_or_warnings": list(match.warnings) + ([match.skip_reason] if match.skip_reason else []),
    }
