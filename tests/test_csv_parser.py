import pytest

from fmc_layer_composer.composer.csv_parser import CsvValidationError, parse_layer_csv


def test_parses_rule_names_preserves_order_and_disabled_marker():
    result = parse_layer_csv("Rule Name,Action\none,ALLOW\n[Disabled] two,BLOCK\n")
    assert [entry.rule_name for entry in result.entries] == ["one", "two"]
    assert [entry.order for entry in result.entries] == [1, 2]
    assert result.entries[1].csv_enabled is False


def test_handles_missing_optional_columns():
    result = parse_layer_csv("Name\nrule-a\n")
    assert result.entries[0].csv_action is None
    assert result.entries[0].csv_source_zones == []


def test_detects_duplicate_csv_rule_names():
    result = parse_layer_csv("Name\nrule-a\nrule-a\n")
    assert result.duplicate_rule_names == ["rule-a"]


def test_parses_multi_value_columns():
    result = parse_layer_csv("Name,Source Zone,Destination Address,Applications\nrule-a,inside;dmz,host1|host2,web-browsing\n")
    entry = result.entries[0]
    assert entry.csv_source_zones == ["inside", "dmz"]
    assert entry.csv_destination_objects == ["host1", "host2"]
    assert entry.csv_applications == ["web-browsing"]


def test_rule_name_column_required():
    with pytest.raises(CsvValidationError):
        parse_layer_csv("Action\nALLOW\n")
