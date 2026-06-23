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


def sanitize_access_rule_for_create(
    source_rule: dict[str, Any],
    provenance: dict[str, Any],
    csv_entry: Any,
    honor_csv_disabled: bool = True,
) -> dict[str, Any]:
    payload = copy.deepcopy(source_rule)
    for field in SERVER_MANAGED_RULE_FIELDS:
        payload.pop(field, None)
    payload["type"] = "AccessRule"
    if "action" not in payload:
        raise ValueError("Source access rule payload is missing required action.")
    if honor_csv_disabled and csv_entry.csv_enabled is False:
        payload["enabled"] = False
    comment = (
        "Copied by FMC Layer Composer from source ACP "
        f"'{provenance.get('source_acp_name')}', source rule '{provenance.get('rule_name')}', "
        f"source rule ID '{provenance.get('source_rule_id')}', CSV '{provenance.get('csv_filename')}', "
        f"CSV order '{csv_entry.order}'."
    )
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
            skipped.append({"csv_order": match.csv_entry.order, "rule_name": match.csv_entry.rule_name, "reason": match.skip_reason})
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
            )
            response = rules_module.create_access_rule_from_payload(
                client,
                domain_uuid,
                target_id,
                payload,
                category=plan.options.rule_category,
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
    if reports_module:
        result.report_paths = reports_module.write_commit_report(result)
    return result


def result_to_dict(result: LayerComposerResult) -> dict[str, Any]:
    return asdict(result)
