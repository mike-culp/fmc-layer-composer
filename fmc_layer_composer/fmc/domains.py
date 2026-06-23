from __future__ import annotations

from .client import FmcClient


def list_domains(client: FmcClient) -> list[dict]:
    return client.get_paginated("/api/fmc_platform/v1/info/domain")
