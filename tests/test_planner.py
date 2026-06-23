from fmc_layer_composer.composer.models import LayerComposerOptions, LayerCsvEntry, SourceAcpRef
from fmc_layer_composer.composer.planner import build_plan


def entry(order=1, name="Rule A"):
    return LayerCsvEntry(order, name, name, None, None, [], [], [], [], [], [], [], None, {})


def rule(rule_id="1", name="Rule A", zone="inside"):
    return {"id": rule_id, "name": name, "action": "ALLOW", "enabled": True, "sourceZones": {"objects": [{"name": zone}]}}


def test_blocks_target_exists_no_sources_empty_csv_and_duplicates():
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(csv_filename="x.csv", entries=[], duplicate_rule_names=[], source_acps=[], source_rules_by_acp={}, options=options, target_exists=True)
    assert not plan.commit_allowed
    assert any("already exists" in blocker for blocker in plan.blockers)
    assert any("At least one source ACP" in blocker for blocker in plan.blockers)
    assert any("CSV has no rules" in blocker for blocker in plan.blockers)

    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(1), entry(2)],
        duplicate_rule_names=["Rule A"],
        source_acps=[SourceAcpRef("a", "ACP", 1)],
        source_rules_by_acp={"a": [rule()]},
        options=options,
    )
    assert not plan.commit_allowed
    assert any("duplicate" in blocker.lower() for blocker in plan.blockers)


def test_blocks_all_missing_missing_without_skip_and_preserves_order():
    options = LayerComposerOptions(target_acp_name="target")
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(2, "B"), entry(1, "A")],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("a", "ACP", 1)],
        source_rules_by_acp={"a": []},
        options=options,
    )
    assert [match.csv_entry.order for match in plan.matches] == [2, 1]
    assert not plan.commit_allowed
    assert any("All CSV rules are missing" in blocker for blocker in plan.blockers)


def test_allows_missing_with_skip_when_some_match():
    options = LayerComposerOptions(target_acp_name="target", skip_missing=True)
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(1, "Rule A"), entry(2, "Missing")],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("a", "ACP", 1)],
        source_rules_by_acp={"a": [rule()]},
        options=options,
    )
    assert plan.commit_allowed
    assert plan.matches[1].status == "SKIPPED"
