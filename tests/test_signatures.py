from fmc_layer_composer.composer.models import SourceRuleCandidate
from fmc_layer_composer.composer.signatures import build_rule_signature, compare_candidate_signatures, signatures_equal


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


def candidate(acp_name, rule):
    return SourceRuleCandidate("id-" + acp_name, acp_name, 1, "rule-id", "Rule A", rule, build_rule_signature(rule))


def test_same_object_names_with_different_ids_are_info_only():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "sourceNetworks": {"objects": [{"name": "NET-A", "id": "1"}]}}),
            candidate("Excalibur", {"name": "Rule A", "sourceNetworks": {"objects": [{"name": "NET-A", "id": "2"}]}}),
        ]
    )
    assert len(deltas) == 1
    assert deltas[0].delta_type == "ID_ONLY_DIFFERENCE"
    assert deltas[0].severity == "info"


def test_same_values_in_different_order_are_not_blocking():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "applications": {"objects": [{"name": "A"}, {"name": "B"}]}}),
            candidate("Excalibur", {"name": "Rule A", "applications": {"objects": [{"name": "B"}, {"name": "A"}]}}),
        ]
    )
    assert all(delta.severity != "warning" for delta in deltas)
    assert {delta.delta_type for delta in deltas} == {"ORDERING_ONLY_DIFFERENCE"}


def test_missing_empty_container_vs_empty_list_has_no_delta():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A"}),
            candidate("Excalibur", {"name": "Rule A", "sourceNetworks": {"objects": []}, "applications": []}),
        ]
    )
    assert deltas == []


def test_source_and_destination_network_name_differences_are_blocking():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "sourceNetworks": {"objects": [{"name": "SRC-A"}]}, "destinationNetworks": {"objects": [{"name": "DST-A"}]}}),
            candidate("Excalibur", {"name": "Rule A", "sourceNetworks": {"objects": [{"name": "SRC-B"}]}, "destinationNetworks": {"objects": [{"name": "DST-B"}]}}),
        ]
    )
    by_field = {delta.field_path: delta for delta in deltas}
    assert by_field["sourceNetworks.objects.names"].severity == "warning"
    assert by_field["destinationNetworks.objects.names"].severity == "warning"


def test_action_and_application_differences_are_blocking():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "action": "ALLOW", "applications": {"objects": [{"name": "web-browsing"}]}}),
            candidate("Excalibur", {"name": "Rule A", "action": "BLOCK", "applications": {"objects": [{"name": "ssl"}]}}),
        ]
    )
    by_field = {delta.field_path: delta for delta in deltas}
    assert by_field["action"].severity == "warning"
    assert by_field["applications.objects.names"].severity == "warning"


def test_variable_set_name_difference_is_context_only_info():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "variableSet": {"name": "Default Set", "id": "1", "type": "VariableSet"}}),
            candidate("Excalibur", {"name": "Rule A", "variableSet": {"name": "Property Set", "id": "1", "type": "VariableSet"}}),
        ]
    )
    assert len(deltas) == 1
    assert deltas[0].field_path == "variableSet.name"
    assert deltas[0].delta_type == "CONTEXT_ONLY_DIFFERENCE"
    assert deltas[0].severity == "info"
    assert "does not block rule copy" in deltas[0].message


def test_variable_set_id_difference_is_context_only_info():
    deltas = compare_candidate_signatures(
        [
            candidate("Luxor", {"name": "Rule A", "variableSet": {"name": "Default Set", "id": "1", "type": "VariableSet"}}),
            candidate("Excalibur", {"name": "Rule A", "variableSet": {"name": "Default Set", "id": "2", "type": "VariableSet"}}),
        ]
    )
    assert len(deltas) == 1
    assert deltas[0].field_path == "variableSet.id"
    assert deltas[0].delta_type == "CONTEXT_ONLY_DIFFERENCE"
    assert deltas[0].severity == "info"


def test_variable_set_and_object_id_differences_are_non_blocking_when_names_match():
    deltas = compare_candidate_signatures(
        [
            candidate(
                "Luxor",
                {
                    "name": "Rule A",
                    "variableSet": {"name": "Default Set", "id": "1", "type": "VariableSet"},
                    "sourceNetworks": {"objects": [{"name": "NET-A", "id": "net-1"}]},
                },
            ),
            candidate(
                "Excalibur",
                {
                    "name": "Rule A",
                    "variableSet": {"name": "Property Set", "id": "2", "type": "VariableSet"},
                    "sourceNetworks": {"objects": [{"name": "NET-A", "id": "net-2"}]},
                },
            ),
        ]
    )
    assert {delta.delta_type for delta in deltas} == {"CONTEXT_ONLY_DIFFERENCE", "ID_ONLY_DIFFERENCE"}
    assert all(delta.severity == "info" for delta in deltas)
