from fmc_layer_composer.composer.executor import sanitize_access_rule_for_create
from fmc_layer_composer.composer.models import LayerCsvEntry


def test_sanitizer_removes_managed_fields_preserves_conditions_and_description_honors_disabled():
    source = {
        "id": "1",
        "links": {},
        "metadata": {},
        "version": "1",
        "commentHistoryList": [],
        "name": "rule",
        "action": "ALLOW",
        "enabled": True,
        "description": "keep",
        "sourceZones": {"objects": [{"name": "inside"}]},
    }
    entry = LayerCsvEntry(1, "[Disabled] rule", "rule", False, None, [], [], [], [], [], [], [], None, {})
    payload = sanitize_access_rule_for_create(source, {"source_acp_name": "ACP", "rule_name": "rule", "source_rule_id": "1", "csv_filename": "x.csv"}, entry)
    for field in ("id", "links", "metadata", "version", "commentHistoryList"):
        assert field not in payload
    assert payload["type"] == "AccessRule"
    assert payload["enabled"] is False
    assert payload["description"] == "keep"
    assert payload["sourceZones"] == {"objects": [{"name": "inside"}]}
    assert "newComments" in payload
