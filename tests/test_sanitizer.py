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


def test_sanitizer_sets_multi_rule_target_name_and_provenance_part():
    entry = LayerCsvEntry(107, "Clients-to-PDQ", "Clients-to-PDQ", None, None, [], [], [], [], [], [], [], None, {})
    payload = sanitize_access_rule_for_create(
        {"name": "Clients-to-PDQ-app", "action": "ALLOW"},
        {"source_acp_name": "MGM Grand", "rule_name": "Clients-to-PDQ-app", "source_rule_id": "1", "csv_filename": "x.csv"},
        entry,
        target_rule_name="Clients-to-PDQ - part 1",
        multi_rule_part_number=1,
        multi_rule_part_total=2,
        target_naming_mode="CSV_NAME_WITH_PART_SUFFIX",
    )
    assert payload["name"] == "Clients-to-PDQ - part 1"
    comment = payload["newComments"][0]
    assert "source rule 'Clients-to-PDQ-app'" in comment
    assert "CSV rule 'Clients-to-PDQ'" in comment
    assert "Multi-rule override part 1 of 2" in comment
    assert "target naming mode 'CSV_NAME_WITH_PART_SUFFIX'" in comment
