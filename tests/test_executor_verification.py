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
        names = {"1": "Clients-to-PDQ_1"}
        return {"id": rule_id, "name": names.get(rule_id, f"Rule {rule_id}"), "action": "ALLOW"}

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
    assert skipped["final_status"] == "SKIPPED"
    assert skipped["skip_reason"]
    assert "source_candidate_summary" in skipped
    assert "blockers_or_warnings" in skipped


def test_fuzzy_candidate_is_not_copied_unless_selected_when_skip_missing_enabled():
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(1, "Clients-to-PDQ")],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("source", "Source ACP", 1)],
        source_rules_by_acp={"source": [source_rule("1", "Clients-to-PDQ_1")]},
        options=LayerComposerOptions(target_acp_name="target", skip_missing=True),
    )
    assert plan.matches[0].status == "SKIPPED_NO_CANDIDATE_SELECTED"
    result = execute_plan(
        plan=plan,
        client=object(),
        domain_uuid="domain",
        policies_module=PoliciesModule,
        rules_module=RulesModule([]),
    )
    assert result.created_rules == []
    assert result.skipped_rules[0]["primary_reason_code"] == "NO_EXACT_MATCH"
    assert result.skipped_rules[0]["fuzzy_candidates_found"][0]["rule_name"] == "Clients-to-PDQ_1"


def test_selected_fuzzy_candidate_is_copied_in_csv_order_and_renamed_to_csv_name():
    options = LayerComposerOptions(target_acp_name="target", skip_missing=True)
    options.fuzzy_selections = {1: "source:1"}
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry(1, "Clients-to-PDQ")],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("source", "Source ACP", 1)],
        source_rules_by_acp={"source": [source_rule("1", "Clients-to-PDQ_1")]},
        options=options,
    )
    assert plan.matches[0].status == "FUZZY_SELECTED_RENAMED_TO_CSV"
    result = execute_plan(
        plan=plan,
        client=object(),
        domain_uuid="domain",
        policies_module=PoliciesModule,
        rules_module=RulesModule([{"name": "Clients-to-PDQ"}]),
    )
    assert result.created_rules[0].csv_order == 1
    assert result.created_rules[0].rule_name == "Clients-to-PDQ"
    assert result.verification_status == "VERIFIED"


def test_selected_fuzzy_provenance_records_source_and_csv_rule_names():
    from fmc_layer_composer.composer.executor import sanitize_access_rule_for_create

    payload = sanitize_access_rule_for_create(
        {"name": "Clients-to-PDQ_1", "action": "ALLOW"},
        {"source_acp_name": "MGM Grand", "rule_name": "Clients-to-PDQ_1", "source_rule_id": "1", "csv_filename": "x.csv"},
        entry(107, "Clients-to-PDQ"),
        target_rule_name="Clients-to-PDQ",
    )
    assert payload["name"] == "Clients-to-PDQ"
    comment = payload["newComments"][0]
    assert "source rule 'Clients-to-PDQ_1'" in comment
    assert "CSV rule 'Clients-to-PDQ'" in comment
    assert "renamed to the CSV rule name" in comment
