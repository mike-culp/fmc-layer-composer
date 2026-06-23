import pytest

from fmc_layer_composer.fmc.client import FmcApiError
from fmc_layer_composer.fmc.rules import create_access_rule_from_payload


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, path, payload, params=None):
        self.calls.append({"path": path, "payload": payload, "params": params})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeDiagnostics:
    def __init__(self):
        self.events = []

    def event(self, **kwargs):
        self.events.append(kwargs)


def placement_error():
    return FmcApiError(
        method="POST",
        path="/accessrules",
        status_code=400,
        request_payload={"name": "rule"},
        response_body={"error": "Category or Header with the given name Mandatory does not exist. Provide a valid Category name."},
    )


def test_create_access_rule_does_not_send_category_mandatory():
    client = FakeClient([{"id": "new-rule"}])
    create_access_rule_from_payload(client, "domain", "target", {"name": "rule", "action": "ALLOW"})
    assert client.calls[0]["params"] == {"section": "mandatory"}
    assert "category" not in client.calls[0]["params"]
    assert client.calls[0]["params"]["section"] != "Mandatory"


def test_default_section_value_is_lowercase_mandatory():
    client = FakeClient([{"id": "new-rule"}])
    response = create_access_rule_from_payload(client, "domain", "target", {"name": "rule", "action": "ALLOW"})
    assert client.calls[0]["params"] == {"section": "mandatory"}
    assert response["_placement_strategy"] == "section_mandatory"


def test_fallback_retries_without_placement_params_after_placement_400():
    client = FakeClient([placement_error(), {"id": "new-rule"}])
    response = create_access_rule_from_payload(client, "domain", "target", {"name": "rule", "action": "ALLOW"})
    assert [call["params"] for call in client.calls] == [{"section": "mandatory"}, None]
    assert response["_placement_strategy"] == "no_placement_params"


def test_non_placement_400_does_not_retry():
    error = FmcApiError(
        method="POST",
        path="/accessrules",
        status_code=400,
        request_payload={"name": "rule"},
        response_body={"error": "Invalid rule payload."},
    )
    client = FakeClient([error])
    with pytest.raises(FmcApiError):
        create_access_rule_from_payload(client, "domain", "target", {"name": "rule"})
    assert len(client.calls) == 1


def test_diagnostics_record_placement_strategy():
    client = FakeClient([placement_error(), {"id": "new-rule"}])
    diagnostics = FakeDiagnostics()
    create_access_rule_from_payload(
        client,
        "domain",
        "target",
        {"name": "rule", "action": "ALLOW"},
        diagnostics_logger=diagnostics,
    )
    strategies = [event["details"]["placement_strategy"] for event in diagnostics.events]
    params = [event["details"]["query_params"] for event in diagnostics.events]
    assert strategies == ["section_mandatory", "no_placement_params"]
    assert params == [{"section": "mandatory"}, None]
    assert diagnostics.events[0]["api_method"] == "POST"
    assert diagnostics.events[0]["api_path"].endswith("/accessrules")
    assert diagnostics.events[0]["api_response"]
    assert diagnostics.events[1]["api_response"] == {"id": "new-rule"}
