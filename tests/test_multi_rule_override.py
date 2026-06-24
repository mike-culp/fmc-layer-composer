from fmc_layer_composer.composer.fuzzy import find_split_rule_candidates, group_split_rule_candidates
from fmc_layer_composer.composer.models import FuzzyMatchOptions, LayerComposerOptions, LayerCsvEntry, SourceAcpRef, SourceRuleCandidate
from fmc_layer_composer.composer.planner import build_plan
from fmc_layer_composer.composer.reports import render_dry_run_html
from fmc_layer_composer.composer.resolution import apply_resolution_state_to_plan, build_create_tasks, csv_name_mode_disabled_reason, default_target_naming_mode


def entry(name="Clients-to-PDQ"):
    return LayerCsvEntry(107, name, name, None, None, [], [], [], [], [], [], [], None, {})


def source(name, rule_id):
    return SourceRuleCandidate("acp", "MGM Grand", 1, rule_id, name, {"id": rule_id, "name": name, "metadata": {"ruleIndex": int(rule_id)}}, {"action": "ALLOW"})


def plan_with_split_candidates():
    return build_plan(
        csv_filename="x.csv",
        entries=[entry()],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("acp", "MGM Grand", 1)],
        source_rules_by_acp={
            "acp": [
                {"id": "1", "name": "Clients-to-PDQ_1", "action": "ALLOW", "metadata": {"ruleIndex": 1}},
                {"id": "2", "name": "Clients-to-PDQ_2", "action": "ALLOW", "metadata": {"ruleIndex": 2}},
            ]
        },
        options=LayerComposerOptions(target_acp_name="target", skip_missing=True),
    )


def test_split_candidate_discovery_finds_suffix_and_l4_app_names():
    candidates = find_split_rule_candidates(
        "Clients-to-PDQ",
        [
            source("Clients-to-PDQ_1", "1"),
            source("Clients-to-PDQ_2", "2"),
            source("Clients-to-PDQ-l4", "3"),
            source("Clients-to-PDQ-app", "4"),
            source("Clients-to-PDQ-custom", "5"),
        ],
        FuzzyMatchOptions(),
    )
    assert {candidate.candidate_rule_name for candidate in candidates} >= {
        "Clients-to-PDQ_1",
        "Clients-to-PDQ_2",
        "Clients-to-PDQ-l4",
        "Clients-to-PDQ-app",
        "Clients-to-PDQ-custom",
    }


def test_split_candidates_group_by_source_acp():
    candidates = find_split_rule_candidates("Clients-to-PDQ", [source("Clients-to-PDQ_1", "1"), source("Clients-to-PDQ_2", "2")], FuzzyMatchOptions())
    groups = group_split_rule_candidates(107, "Clients-to-PDQ", candidates)
    assert len(groups) == 1
    assert groups[0].source_acp_name == "MGM Grand"
    assert len(groups[0].candidates) == 2


def test_multi_rule_resolution_flattens_to_contiguous_create_tasks():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_candidate_keys": ["acp:1", "acp:2"],
            "target_naming_mode": "AUTO",
            "selected_source_rules": [],
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    tasks, blockers = build_create_tasks(resolved.plan, state)
    assert blockers == []
    assert [task.task_order for task in tasks] == [1, 2]
    assert [task.target_rule_name for task in tasks] == ["Clients-to-PDQ_1", "Clients-to-PDQ_2"]
    assert all(task.is_multi_rule_override for task in tasks)
    assert resolved.summary["expected_create_operations"] == 2


def test_csv_name_target_naming_blocks_multi_rule_override():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_candidate_keys": ["acp:1", "acp:2"],
            "target_naming_mode": "CSV_NAME",
            "selected_source_rules": [],
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    assert not resolved.commit_allowed
    assert any("CSV_NAME target naming" in blocker for blocker in resolved.blockers)


def test_csv_name_with_part_suffix_generates_unique_names():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_candidate_keys": ["acp:1", "acp:2"],
            "target_naming_mode": "CSV_NAME_WITH_PART_SUFFIX",
            "selected_source_rules": [],
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    tasks, blockers = build_create_tasks(resolved.plan, state)
    assert blockers == []
    assert [task.target_rule_name for task in tasks] == ["Clients-to-PDQ - part 1", "Clients-to-PDQ - part 2"]


def test_csv_rule_name_under_limit_defaults_to_csv_name_for_single_override():
    assert default_target_naming_mode("A" * 50, 1) == "CSV_NAME"
    assert csv_name_mode_disabled_reason("A" * 50, 1) is None


def test_csv_rule_name_over_limit_disables_csv_name_for_single_override():
    reason = csv_name_mode_disabled_reason("A" * 51, 1)
    assert default_target_naming_mode("A" * 51, 1) == "PRESERVE_SOURCE_NAMES"
    assert reason
    assert "50 characters" in reason


def test_auto_mode_preserves_source_name_when_csv_name_is_too_long():
    plan = plan_with_split_candidates()
    long_name = "A" * 51
    plan.matches[0].csv_entry.rule_name = long_name
    state = {
        f"107:{long_name}": {
            "csv_order": 107,
            "csv_rule_name": long_name,
            "decision": "USE_SELECTED_FUZZY_CANDIDATE",
            "selected_source_rules": [
                {
                    "source_acp_id": "acp",
                    "source_acp_name": "MGM Grand",
                    "source_rule_id": "1",
                    "source_rule_name": "Short source name",
                    "selection_order": 1,
                    "selection_method": "USER_SELECTED",
                }
            ],
            "target_naming_mode": "AUTO",
            "skip": False,
        }
    }
    tasks, blockers = build_create_tasks(plan, state)
    assert blockers == []
    assert tasks[0].target_rule_name == "Short source name"
    assert tasks[0].target_rule_name_validation_status == "VALID"


def test_multi_rule_override_default_target_naming_preserves_source_names():
    assert default_target_naming_mode("Clients-to-PDQ", 2) == "PRESERVE_SOURCE_NAMES"
    assert csv_name_mode_disabled_reason("Clients-to-PDQ", 2) == "Use CSV rule name is not valid for multi-rule overrides."


def test_csv_name_with_part_suffix_blocks_generated_name_over_50():
    plan = plan_with_split_candidates()
    long_name = "A" * 45
    plan.matches[0].csv_entry.rule_name = long_name
    state = {
        f"107:{long_name}": {
            "csv_order": 107,
            "csv_rule_name": long_name,
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_source_rules": [
                {"source_acp_id": "acp", "source_acp_name": "MGM Grand", "source_rule_id": "1", "source_rule_name": "Rule 1", "selection_order": 1},
                {"source_acp_id": "acp", "source_acp_name": "MGM Grand", "source_rule_id": "2", "source_rule_name": "Rule 2", "selection_order": 2},
            ],
            "target_naming_mode": "CSV_NAME_WITH_PART_SUFFIX",
            "skip": False,
        }
    }
    tasks, blockers = build_create_tasks(plan, state)
    assert len(tasks[0].target_rule_name) > 50
    assert tasks[0].target_rule_name_validation_status == "ERROR"
    assert any("FMC maximum is 50" in blocker for blocker in blockers)


def test_custom_target_name_under_limit_is_accepted():
    plan = plan_with_split_candidates()
    long_name = "A" * 51
    plan.matches[0].csv_entry.rule_name = long_name
    state = {
        f"107:{long_name}": {
            "csv_order": 107,
            "csv_rule_name": long_name,
            "decision": "USE_SELECTED_FUZZY_CANDIDATE",
            "selected_source_rules": [
                {
                    "candidate_key": "acp:1",
                    "source_acp_id": "acp",
                    "source_acp_name": "MGM Grand",
                    "source_rule_id": "1",
                    "source_rule_name": "Rule 1",
                    "selection_order": 1,
                }
            ],
            "target_naming_mode": "CSV_NAME",
            "custom_target_rule_names": {"acp:1": "Short custom"},
            "skip": False,
        }
    }
    tasks, blockers = build_create_tasks(plan, state)
    assert blockers == []
    assert tasks[0].target_rule_name == "Short custom"
    assert tasks[0].custom_target_rule_name == "Short custom"


def test_custom_target_name_over_limit_blocks_commit():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_SELECTED_FUZZY_CANDIDATE",
            "selected_source_rules": [
                {
                    "candidate_key": "acp:1",
                    "source_acp_id": "acp",
                    "source_acp_name": "MGM Grand",
                    "source_rule_id": "1",
                    "source_rule_name": "Rule 1",
                    "selection_order": 1,
                }
            ],
            "target_naming_mode": "PRESERVE_SOURCE_NAMES",
            "custom_target_rule_names": {"acp:1": "B" * 51},
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    assert not resolved.commit_allowed
    assert any("FMC maximum is 50" in blocker for blocker in resolved.blockers)


def test_duplicate_target_rule_names_block_commit():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_candidate_keys": ["acp:1", "acp:2"],
            "target_naming_mode": "CSV_NAME_WITH_PART_SUFFIX",
            "custom_target_rule_names": {"acp:1": "Duplicate", "acp:2": "Duplicate"},
            "selected_source_rules": [],
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    assert not resolved.commit_allowed
    assert any("Duplicate target rule name" in blocker for blocker in resolved.blockers)


def test_reports_include_target_rule_name_length_and_validation_status():
    plan = plan_with_split_candidates()
    state = {
        "107:Clients-to-PDQ": {
            "csv_order": 107,
            "csv_rule_name": "Clients-to-PDQ",
            "decision": "USE_MULTI_RULE_OVERRIDE",
            "selected_candidate_keys": ["acp:1", "acp:2"],
            "target_naming_mode": "AUTO",
            "selected_source_rules": [],
            "skip": False,
        }
    }
    resolved = apply_resolution_state_to_plan(plan, state)
    html = render_dry_run_html(resolved.plan)
    assert "Target Rule Name Validation" in html
    assert "target name length" in html
    assert "validation status" in html
