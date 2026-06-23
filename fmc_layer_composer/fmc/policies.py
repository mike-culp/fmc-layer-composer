from __future__ import annotations

from .client import FmcClient


def list_access_policies(client: FmcClient, domain_uuid: str) -> list[dict]:
    return client.get_paginated(f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies")


def get_access_policy_by_name(client: FmcClient, domain_uuid: str, name: str) -> dict | None:
    expected = name.strip()
    for policy in list_access_policies(client, domain_uuid):
        if str(policy.get("name", "")).strip() == expected:
            return policy
    return None


def create_access_policy(
    client: FmcClient,
    domain_uuid: str,
    name: str,
    default_action: str = "BLOCK",
) -> dict:
    payload = {
        "type": "AccessPolicy",
        "name": name,
        "defaultAction": {"action": default_action},
    }
    return client.post(f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies", payload)
