from fmc_layer_composer.composer.signatures import build_rule_signature, signatures_equal


def test_builds_signature_extracting_object_name_id_type():
    sig = build_rule_signature({"action": "ALLOW", "enabled": True, "sourceZones": {"objects": [{"name": "inside", "id": "1", "type": "Zone"}]}})
    assert sig["action"] == "ALLOW"
    assert sig["sourceZones"]["objects"] == [{"name": "inside", "id": "1", "type": "Zone"}]


def test_identical_rules_same_signature_and_different_zones_differ():
    one = build_rule_signature({"action": "ALLOW", "sourceZones": {"objects": [{"name": "inside"}]}})
    two = build_rule_signature({"action": "ALLOW", "sourceZones": {"objects": [{"name": "inside"}]}})
    three = build_rule_signature({"action": "ALLOW", "sourceZones": {"objects": [{"name": "dmz"}]}})
    assert signatures_equal(one, two)
    assert not signatures_equal(one, three)
