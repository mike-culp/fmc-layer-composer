from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3


@dataclass
class FmcApiError(RuntimeError):
    method: str
    path: str
    status_code: int | None
    request_payload: dict[str, Any] | None
    response_body: Any

    def __str__(self) -> str:
        return f"FMC API {self.method} {self.path} failed with status {self.status_code}: {self.response_body}"


class FmcClient:
    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True):
        self.base_url = _normalize_base_url(base_url)
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.access_token: str | None = None
        self.refresh_token_value: str | None = None
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self) -> None:
        response = self.session.post(
            urljoin(self.base_url, "/api/fmc_platform/v1/auth/generatetoken"),
            auth=(self.username, self.password),
            verify=self.verify_tls,
        )
        if response.status_code not in (200, 204):
            raise self._error("POST", "/api/fmc_platform/v1/auth/generatetoken", response=response)
        self._capture_tokens(response)

    def refresh_token(self) -> None:
        headers = {}
        if self.refresh_token_value:
            headers["X-auth-refresh-token"] = self.refresh_token_value
        response = self.session.post(
            urljoin(self.base_url, "/api/fmc_platform/v1/auth/refreshtoken"),
            headers=headers,
            verify=self.verify_tls,
        )
        if response.status_code not in (200, 204):
            raise self._error("POST", "/api/fmc_platform/v1/auth/refreshtoken", response=response)
        self._capture_tokens(response)

    def get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        return self._request("GET", path, params=params)

    def post(self, path: str, payload: dict, params: dict | None = None) -> dict[str, Any]:
        return self._request("POST", path, payload=payload, params=params)

    def put(self, path: str, payload: dict, params: dict | None = None) -> dict[str, Any]:
        return self._request("PUT", path, payload=payload, params=params)

    def delete(self, path: str, params: dict | None = None) -> dict[str, Any]:
        return self._request("DELETE", path, params=params)

    def get_paginated(
        self,
        path: str,
        params: dict | None = None,
        limit: int = 1000,
        diagnostics_logger: Any | None = None,
    ) -> list[dict[str, Any]]:
        merged = dict(params or {})
        merged.setdefault("limit", limit)
        offset = int(merged.get("offset", 0))
        items: list[dict[str, Any]] = []
        page_number = 0
        next_path: str | None = None
        while True:
            page_number += 1
            if next_path:
                data = self.get(next_path)
            else:
                merged["offset"] = offset
                data = self.get(path, params=merged)
            page_items = data.get("items", [])
            items.extend(page_items)
            paging = data.get("paging", {})
            _record_page_diagnostic(diagnostics_logger, path, page_number, len(page_items), len(items), paging)
            next_value = paging.get("next")
            if next_value:
                next_path = _next_path(next_value)
                continue
            count = int(paging.get("count", len(page_items)) or 0)
            total = int(paging.get("total", len(items)) or len(items))
            if not page_items or len(items) >= total or count == 0:
                break
            offset += count
        return items

    def _request(self, method: str, path: str, payload: dict | None = None, params: dict | None = None) -> dict[str, Any]:
        if not self.access_token:
            self.login()
        headers = {"X-auth-access-token": self.access_token or "", "Content-Type": "application/json"}
        response = self.session.request(
            method,
            urljoin(self.base_url, path),
            headers=headers,
            json=payload,
            params=params,
            verify=self.verify_tls,
        )
        if response.status_code == 401 and self.refresh_token_value:
            self.refresh_token()
            headers["X-auth-access-token"] = self.access_token or ""
            response = self.session.request(
                method,
                urljoin(self.base_url, path),
                headers=headers,
                json=payload,
                params=params,
                verify=self.verify_tls,
            )
        if response.status_code >= 400:
            raise self._error(method, path, payload=payload, response=response)
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    def _capture_tokens(self, response: requests.Response) -> None:
        self.access_token = response.headers.get("X-auth-access-token") or response.headers.get("x-auth-access-token")
        self.refresh_token_value = response.headers.get("X-auth-refresh-token") or response.headers.get("x-auth-refresh-token")

    def _error(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        response: requests.Response | None = None,
    ) -> FmcApiError:
        body: Any = None
        status = None
        if response is not None:
            status = response.status_code
            try:
                body = response.json()
            except ValueError:
                body = response.text
        return FmcApiError(method=method, path=path, status_code=status, request_payload=payload, response_body=body)


def _normalize_base_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value


def _next_path(next_value: str) -> str:
    marker = "/api/"
    index = next_value.find(marker)
    if index >= 0:
        return next_value[index:]
    return next_value


def _record_page_diagnostic(
    diagnostics_logger: Any | None,
    path: str,
    page_number: int,
    page_count: int,
    total_returned: int,
    paging: dict[str, Any],
) -> None:
    if not diagnostics_logger:
        return
    diagnostics_logger.event(
        stage="paginated_get",
        severity="info",
        decision="fetch_page",
        details={
            "path": path,
            "page_number": page_number,
            "page_item_count": page_count,
            "total_items_returned": total_returned,
            "paging": paging,
        },
        api_method="GET",
        api_path=path,
    )
