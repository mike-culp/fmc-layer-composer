from fmc_layer_composer.fmc.client import FmcClient


def test_paginated_get_retrieves_more_than_one_page():
    client = FmcClient("https://fmc.example", "user", "password")
    calls = []
    pages = [
        {"items": [{"name": "one"}], "paging": {"count": 1, "total": 2}},
        {"items": [{"name": "two"}], "paging": {"count": 1, "total": 2}},
    ]

    def fake_get(path, params=None):
        calls.append({"path": path, "params": dict(params or {})})
        return pages.pop(0)

    client.get = fake_get  # type: ignore[method-assign]
    items = client.get_paginated("/api/fmc_config/v1/domain/domain/policy/accesspolicies/acp/accessrules", limit=1)
    assert [item["name"] for item in items] == ["one", "two"]
    assert [call["params"]["offset"] for call in calls] == [0, 1]


def test_paginated_get_honors_paging_next():
    client = FmcClient("https://fmc.example", "user", "password")
    calls = []
    pages = [
        {"items": [{"name": "one"}], "paging": {"count": 1, "total": 2, "next": "https://fmc.example/api/fmc_config/v1/next-page"}},
        {"items": [{"name": "two"}], "paging": {"count": 1, "total": 2}},
    ]

    def fake_get(path, params=None):
        calls.append({"path": path, "params": params})
        return pages.pop(0)

    client.get = fake_get  # type: ignore[method-assign]
    items = client.get_paginated("/api/fmc_config/v1/domain/domain/policy/accesspolicies/acp/accessrules", limit=1)
    assert [item["name"] for item in items] == ["one", "two"]
    assert calls[1]["path"] == "/api/fmc_config/v1/next-page"
    assert calls[1]["params"] is None
