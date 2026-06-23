from fmc_layer_composer.composer.models import LayerCsvEntry
from fmc_layer_composer.composer.sanity import compare_csv_to_rule_signature, looks_like_migration_artifact


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
    assert "APPLICATION_DELTA" in codes
    assert "URL_DELTA" in codes
    assert looks_like_migration_artifact("NAME", "NAME_1_1")
