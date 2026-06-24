from fmc_layer_composer.composer.matcher import normalize_rule_name
from fmc_layer_composer.composer.models import LayerComposerOptions, LayerCsvEntry, MatchMode, SourceAcpRef
from fmc_layer_composer.composer.planner import build_plan


def entry(name="Rule A"):
    return LayerCsvEntry(1, name, name, None, None, [], [], [], [], [], [], [], None, {})


def rule(rule_id, name, zone="inside"):
    return {"id": rule_id, "name": name, "action": "ALLOW", "enabled": True, "sourceZones": {"objects": [{"name": zone, "id": zone, "type": "Zone"}]}}


def test_exact_case_insensitive_and_normalized_whitespace():
    assert normalize_rule_name(" Rule A ", MatchMode.EXACT) == "Rule A"
    assert normalize_rule_name(" Rule A ", MatchMode.CASE_INSENSITIVE) == "rule a"
    assert normalize_rule_name(" Rule   A ", MatchMode.NORMALIZED_WHITESPACE) == "rule a"


def test_missing_rule_detection_and_skip_missing():
    acps = [SourceAcpRef("a", "ACP", 1)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(csv_filename="x.csv", entries=[entry()], duplicate_rule_names=[], source_acps=acps, source_rules_by_acp={"a": []}, options=options)
    assert plan.matches[0].status == "NO_FUZZY_CANDIDATES"
    assert not plan.commit_allowed
    options.skip_missing = True
    plan = build_plan(csv_filename="x.csv", entries=[entry()], duplicate_rule_names=[], source_acps=acps, source_rules_by_acp={"a": []}, options=options)
    assert plan.matches[0].status == "SKIPPED_BY_OPTION"


def test_priority_for_identical_candidates():
    acps = [SourceAcpRef("a", "High", 1), SourceAcpRef("b", "Low", 2)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={"a": [rule("1", "Rule A")], "b": [rule("2", "Rule A")]},
        options=options,
    )
    assert plan.matches[0].status == "MATCHED_IDENTICAL_MULTIPLE"
    assert plan.matches[0].selected_candidate.source_acp_name == "High"


def test_candidate_delta_blocks_by_default_and_override_allows():
    acps = [SourceAcpRef("a", "High", 1), SourceAcpRef("b", "Low", 2)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={"a": [rule("1", "Rule A", "inside")], "b": [rule("2", "Rule A", "dmz")]},
        options=options,
    )
    assert plan.matches[0].status == "MATCHED_MULTIPLE_WITH_DELTA"
    assert not plan.commit_allowed
    options.use_priority_despite_candidate_deltas = True
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={"a": [rule("1", "Rule A", "inside")], "b": [rule("2", "Rule A", "dmz")]},
        options=options,
    )
    assert plan.commit_allowed


def test_id_only_candidate_delta_does_not_block_plan():
    acps = [SourceAcpRef("a", "High", 1), SourceAcpRef("b", "Low", 2)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={
            "a": [{"id": "1", "name": "Rule A", "action": "ALLOW", "enabled": True, "sourceNetworks": {"objects": [{"name": "NET-A", "id": "id-1"}]}}],
            "b": [{"id": "2", "name": "Rule A", "action": "ALLOW", "enabled": True, "sourceNetworks": {"objects": [{"name": "NET-A", "id": "id-2"}]}}],
        },
        options=options,
    )
    assert plan.commit_allowed
    assert plan.matches[0].status == "MATCHED_IDENTICAL_MULTIPLE"
    assert plan.matches[0].id_only_delta_count == 1
    assert plan.matches[0].blocking_candidate_delta_count == 0


def test_variable_set_only_candidate_delta_is_identical_multiple_and_commit_allowed():
    acps = [SourceAcpRef("a", "Luxor", 1), SourceAcpRef("b", "Excalibur", 2)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={
            "a": [{"id": "1", "name": "Rule A", "action": "ALLOW", "enabled": True, "variableSet": {"name": "Default Set", "id": "vs-1", "type": "VariableSet"}}],
            "b": [{"id": "2", "name": "Rule A", "action": "ALLOW", "enabled": True, "variableSet": {"name": "Property Set", "id": "vs-2", "type": "VariableSet"}}],
        },
        options=options,
    )
    match = plan.matches[0]
    assert match.status == "MATCHED_IDENTICAL_MULTIPLE"
    assert match.selected_candidate.source_acp_name == "Luxor"
    assert match.blocking_candidate_delta_count == 0
    assert {delta.delta_type for delta in match.candidate_field_deltas} == {"CONTEXT_ONLY_DIFFERENCE"}
    assert plan.summary["matched_with_candidate_deltas"] == 0
    assert plan.summary["context_only_candidate_deltas"] == 2
    assert plan.commit_allowed


def test_variable_set_and_object_ids_only_do_not_block_commit():
    acps = [SourceAcpRef("a", "Luxor", 1), SourceAcpRef("b", "Excalibur", 2)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={
            "a": [
                {
                    "id": "1",
                    "name": "Rule A",
                    "action": "ALLOW",
                    "enabled": True,
                    "variableSet": {"name": "Default Set", "id": "vs-1", "type": "VariableSet"},
                    "sourceNetworks": {"objects": [{"name": "NET-A", "id": "net-1"}]},
                }
            ],
            "b": [
                {
                    "id": "2",
                    "name": "Rule A",
                    "action": "ALLOW",
                    "enabled": True,
                    "variableSet": {"name": "Property Set", "id": "vs-2", "type": "VariableSet"},
                    "sourceNetworks": {"objects": [{"name": "NET-A", "id": "net-2"}]},
                }
            ],
        },
        options=options,
    )
    assert plan.matches[0].status == "MATCHED_IDENTICAL_MULTIPLE"
    assert plan.matches[0].blocking_candidate_delta_count == 0
    assert plan.commit_allowed


def test_missing_with_fuzzy_candidates_but_no_selection_is_structured_skip():
    acps = [SourceAcpRef("a", "MGM Grand", 1)]
    options = LayerComposerOptions(target_acp_name="target", skip_missing=True)
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry("Clients-to-PDQ")],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={"a": [rule("1", "Clients-to-PDQ_1")]},
        options=options,
    )
    match = plan.matches[0]
    assert match.status == "SKIPPED_NO_CANDIDATE_SELECTED"
    assert match.primary_reason_code == "NO_EXACT_MATCH"
    assert match.user_decision == "SKIPPED_NO_CANDIDATE_SELECTED"
    assert match.fuzzy_candidates[0].candidate_rule_name == "Clients-to-PDQ_1"


def test_missing_with_no_fuzzy_candidates_is_no_fuzzy_candidates():
    acps = [SourceAcpRef("a", "MGM Grand", 1)]
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry("Clients-to-PDQ")],
        duplicate_rule_names=[],
        source_acps=acps,
        source_rules_by_acp={"a": [rule("1", "unrelated-rule")]},
        options=options,
    )
    match = plan.matches[0]
    assert match.status == "NO_FUZZY_CANDIDATES"
    assert match.primary_reason_code == "NO_FUZZY_CANDIDATES"
