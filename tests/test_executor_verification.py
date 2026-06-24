from fmc_layer_composer.composer.executor import execute_plan
from fmc_layer_composer.composer.models import LayerComposerOptions, LayerCsvEntry, SourceAcpRef
from fmc_layer_composer.composer.planner import build_plan


class PoliciesModule:
    @staticmethod
    def get_access_policy_by_name(client, domain_uuid, name):
        return None

    @staticmethod
    def create_access_policy(client, domain_uuid, name, default_action="BLOCK"):
        return {"id": "target-acp", "name": name}


class RulesModule:
    def __init__(self, target_rules):
        self.target_rules = target_rules

    @staticmethod
    def get_access_rule(client, domain_uuid, acp_id, rule_id):
        return {"id": rule_id, "name": f"Rule {rule_id}", "action": "ALLOW"}

    @staticmethod
    def create_access_rule_from_payload(client, domain_uuid, target_acp_id, payload, section="mandatory", diagnostics_logger=None):
        return {"id": "new-" + payload["name"], "name": payload["name"], "_placement_strategy": "section_mandatory"}

    def list_access_rules(self, client, domain_uuid, acp_id, expanded=True, diagnostics_logger=None):
        return self.target_rules


def entry(order, name):
    return LayerCsvEntry(order, name, name, None, None, [], [], [], [], [], [], [], None, {})


def source_rule(rule_id, name):
    return {"id": rule_id, "name": name, "action": "ALLOW", "enabled": True}


def plan_for_rules(*names, skip_missing=False):
    entries = [entry(index, name) for index, name in enumerate(names, start=1)]
    source_rules = [source_rule(str(index), name) for index, name in enumerate(names, start=1)]
    return build_plan(
        csv_filename="x.csv",
        entries=entries,
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("source", "Source ACP", 1)],
        source_rules_by_acp={"source": source_rules},
        options=LayerComposerOptions(target_acp_name="target", skip_missing=skip_missing),
    )


def test_verification_succeeds_when_target_get_returns_all_created_names():
    plan = plan_for_rules("Rule 1", "Rule 2")
    result = execute_plan(
        plan=plan,
        client=object(),
        domain_uuid="domain",
        policies_module=PoliciesModule,
        rules_module=RulesModule([{"name": "Rule 1"}, {"name": "Rule 2"}]),
    )
    assert result.expected_create_count == 2
    assert result.api_created_count == 2
    assert result.verified_target_rule_count == 2
    assert result.verification_status == "VERIFIED"
    assert result.missing_after_commit == []


def test_verification_mismatch_when_target_get_returns_fewer_rules():
    plan = plan_for_rules("Rule 1", "Rule 2")
    result = execute_plan(
        plan=plan,
        client=object(),
        domain_uuid="domain",
        policies_module=PoliciesModule,
        rules_module=RulesModule([{"name": "Rule 1"}]),
    )
    assert result.verification_status == "VERIFY_MISMATCH"
    assert result.missing_after_commit == ["Rule 2"]
    assert any(error["type"] == "VERIFY_MISMATCH" for error in result.errors)


def test_skipped_rules_include_skip_reason_and_candidate_context():
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(1, "Rule 1"), entry(2, "Missing")],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("source", "Source ACP", 1)],
        source_rules_by_acp={"source": [source_rule("1", "Rule 1")]},
        options=LayerComposerOptions(target_acp_name="target", skip_missing=True),
    )
    result = execute_plan(
        plan=plan,
        client=object(),
        domain_uuid="domain",
        policies_module=PoliciesModule,
        rules_module=RulesModule([{"name": "Rule 1"}]),
    )
    skipped = result.skipped_rules[0]
    assert skipped["csv_order"] == 2
    assert skipped["rule_name"] == "Missing"
    assert skipped["status"] == "SKIPPED"
    assert skipped["skip_reason"]
    assert "source_candidate_summary" in skipped
    assert "blockers_or_warnings" in skipped
