from __future__ import annotations

from .client import FmcClient


def authenticate(host: str, username: str, password: str, verify_tls: bool = True) -> FmcClient:
    client = FmcClient(host, username, password, verify_tls=verify_tls)
    client.login()
    return client
