from __future__ import annotations

from .client import FmcClient


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
    category: str = "Mandatory",
) -> dict:
    params = {"category": category} if category else None
    return client.post(
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{target_acp_id}/accessrules",
        payload,
        params=params,
    )
