from __future__ import annotations

from typing import Any

from .client import FmcApiError, FmcClient


PLACEMENT_SECTION_MANDATORY = "section_mandatory"
PLACEMENT_NO_PARAMS = "no_placement_params"


def list_access_rules(
    client: FmcClient,
    domain_uuid: str,
    acp_id: str,
    expanded: bool = True,
) -> list[dict]:
    params = {"expanded": "true"} if expanded else None
    return client.get_paginated(
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{acp_id}/accessrules",
        params=params,
    )


def get_access_rule(
    client: FmcClient,
    domain_uuid: str,
    acp_id: str,
    rule_id: str,
) -> dict:
    return client.get(f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{acp_id}/accessrules/{rule_id}")


def create_access_rule_from_payload(
    client: FmcClient,
    domain_uuid: str,
    target_acp_id: str,
    payload: dict,
    section: str = "mandatory",
    diagnostics_logger: Any | None = None,
) -> dict:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{target_acp_id}/accessrules"
    first_params = {"section": section} if section else None
    try:
        response = client.post(path, payload, params=first_params)
        _record_create_diagnostic(
            diagnostics_logger,
            placement_strategy=PLACEMENT_SECTION_MANDATORY if section == "mandatory" else "section",
            params=first_params,
            response=response,
            path=path,
        )
        return _with_placement_strategy(response, PLACEMENT_SECTION_MANDATORY if section == "mandatory" else "section")
    except FmcApiError as exc:
        _record_create_diagnostic(
            diagnostics_logger,
            placement_strategy=PLACEMENT_SECTION_MANDATORY if section == "mandatory" else "section",
            params=first_params,
            response=exc.response_body,
            status=exc.status_code,
            severity="warning",
            path=path,
        )
        if not _is_placement_error(exc):
            raise
    response = client.post(path, payload, params=None)
    _record_create_diagnostic(
        diagnostics_logger,
        placement_strategy=PLACEMENT_NO_PARAMS,
        params=None,
        response=response,
        path=path,
    )
    return _with_placement_strategy(response, PLACEMENT_NO_PARAMS)


def _with_placement_strategy(response: dict, placement_strategy: str) -> dict:
    response_copy = dict(response)
    response_copy["_placement_strategy"] = placement_strategy
    return response_copy


def _is_placement_error(error: FmcApiError) -> bool:
    if error.status_code != 400:
        return False
    body = str(error.response_body).casefold()
    indicators = (
        "category or header",
        "mandatory does not exist",
        "invalid category",
        "invalid header",
        "invalid placement",
        "invalid section",
        "provide a valid category",
    )
    return any(indicator in body for indicator in indicators)


def _record_create_diagnostic(
    diagnostics_logger: Any | None,
    *,
    placement_strategy: str,
    params: dict | None,
    response: Any,
    status: int | None = None,
    severity: str = "info",
    path: str | None = None,
) -> None:
    if not diagnostics_logger:
        return
    diagnostics_logger.event(
        stage="create_target_rule",
        severity=severity,
        decision="create_access_rule",
        reason_code=placement_strategy,
        details={
            "placement_strategy": placement_strategy,
            "query_params": params,
        },
        api_method="POST",
        api_path=path,
        api_status=status,
        api_response=response,
    )
