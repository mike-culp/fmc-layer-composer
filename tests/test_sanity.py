from fmc_layer_composer.composer.models import LayerCsvEntry
from fmc_layer_composer.composer.sanity import (
    compare_csv_to_rule_signature,
    extract_application_names,
    extract_object_details,
    extract_object_names,
    looks_like_migration_artifact,
)


def entry(**kwargs):
    base = dict(
        order=1,
        raw_name="r",
        rule_name="r",
        csv_enabled=True,
        csv_action="ALLOW",
        csv_source_zones=["inside"],
        csv_destination_zones=["outside"],
        csv_source_objects=["SRC"],
        csv_destination_objects=["DST"],
        csv_services=["HTTP"],
        csv_applications=["web-browsing"],
        csv_urls=["example.com"],
        csv_description=None,
        raw_row={},
    )
    base.update(kwargs)
    return LayerCsvEntry(**base)


def test_detects_scalar_and_field_deltas():
    sig = {"enabled": False, "action": "BLOCK", "sourceZones": {"objects": [{"name": "dmz"}]}}
    codes = {delta.code for delta in compare_csv_to_rule_signature(entry(), sig)}
    assert "ENABLED_STATE_DELTA" in codes
    assert "ACTION_DELTA" in codes
    assert "SOURCE_ZONE_DELTA" in codes


def test_detects_object_port_application_url_deltas_and_artifacts():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "sourceZones": {"objects": [{"name": "inside"}]},
        "destinationZones": {"objects": [{"name": "dmz"}]},
        "sourceNetworks": {"objects": [{"name": "SRC_1"}]},
        "destinationNetworks": {"objects": [{"name": "OTHER"}]},
        "destinationPorts": {"objects": [{"name": "HTTPS"}]},
        "applications": {"objects": [{"name": "ssl"}]},
        "urls": {"objects": [{"name": "other.com"}]},
    }
    codes = {delta.code for delta in compare_csv_to_rule_signature(entry(), sig)}
    assert "OBJECT_NAME_ARTIFACT_DELTA" in codes
    assert "DESTINATION_ZONE_DELTA" in codes
    assert "DESTINATION_OBJECT_DELTA" in codes
    assert "PORT_DELTA" in codes
    assert "APPLICATION_MAPPING_OR_EXPANSION_DELTA" in codes
    assert "URL_DELTA" in codes
    assert looks_like_migration_artifact("NAME", "NAME_1_1")


def test_matching_source_network_object_name_ignores_id_and_type():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "sourceNetworks": {"objects": [{"name": "Zscaler-PSE", "id": "00000000-0000-0ed3-0000-064424532807", "type": "NetworkGroup"}]},
    }
    deltas = compare_csv_to_rule_signature(entry(csv_source_objects=["Zscaler-PSE"], csv_destination_objects=[], csv_applications=[]), sig)
    assert "SOURCE_OBJECT_DELTA" not in {delta.code for delta in deltas}


def test_matching_destination_network_object_name_ignores_id_and_type():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "destinationNetworks": {"objects": [{"name": "zscaler-hub-public-ip", "id": "id-1", "type": "NetworkGroup"}]},
    }
    deltas = compare_csv_to_rule_signature(entry(csv_source_objects=[], csv_destination_objects=["zscaler-hub-public-ip"], csv_applications=[]), sig)
    assert "DESTINATION_OBJECT_DELTA" not in {delta.code for delta in deltas}


def test_case_only_network_name_difference_is_not_warning_delta():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "sourceNetworks": {"objects": [{"name": "RFC1918-10.0.0.0-8", "id": "id-1", "type": "Network"}]},
    }
    deltas = compare_csv_to_rule_signature(entry(csv_source_objects=["rfc1918-10.0.0.0-8"], csv_destination_objects=[], csv_applications=[]), sig)
    assert not [delta for delta in deltas if delta.field == "sourceNetworks" and delta.severity == "warning"]


def test_extractors_do_not_include_id_type_or_duplicate_names_in_comparison_values():
    container = {"objects": [{"name": "Zscaler-PSE", "id": "id-1", "type": "NetworkGroup"}, {"name": "Zscaler-PSE", "id": "id-1", "type": "NetworkGroup"}]}
    assert extract_object_names(container) == ["Zscaler-PSE"]
    assert extract_object_details(container) == [{"name": "Zscaler-PSE", "id": "id-1", "type": "NetworkGroup"}]


def test_multiple_destination_objects_to_one_network_group_is_group_collapse_delta():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "destinationNetworks": {"objects": [{"name": "microsoft-ip-range", "id": "id-1", "type": "NetworkGroup"}]},
    }
    deltas = compare_csv_to_rule_signature(
        entry(
            csv_source_objects=[],
            csv_destination_objects=[
                "azure-public-cloud-action-group-ipv4",
                "azure-public-cloud-ipv4",
                "azure-public-cloud-o365-ipv4",
                "microsoft-ip-range",
            ],
            csv_applications=[],
        ),
        sig,
    )
    codes = {delta.code for delta in deltas}
    assert "POSSIBLE_GROUP_COLLAPSE_OR_EXPANSION_DELTA" in codes
    assert "DESTINATION_OBJECT_DELTA" not in codes


def test_application_extractor_returns_only_application_names():
    container = {"objects": [{"name": "Office 365", "id": "2812", "type": "Application", "overridable": True}, {"name": "Office 365", "id": "2812", "type": "Application"}]}
    assert extract_application_names(container) == ["Office 365"]


def test_pan_app_group_to_fmc_expanded_apps_is_application_mapping_delta():
    sig = {
        "enabled": True,
        "action": "ALLOW",
        "applications": {"objects": [{"name": "Office 365", "id": "2812", "type": "Application"}]},
    }
    deltas = compare_csv_to_rule_signature(entry(csv_source_objects=[], csv_destination_objects=[], csv_applications=["pan-office365-app-group"]), sig)
    delta = next(delta for delta in deltas if delta.code == "APPLICATION_MAPPING_OR_EXPANSION_DELTA")
    assert delta.severity == "warning"
    assert delta.blocking is False
    assert delta.fmc_value == ["Office 365"]
    assert delta.fmc_details == [{"name": "Office 365", "id": "2812", "type": "Application"}]
