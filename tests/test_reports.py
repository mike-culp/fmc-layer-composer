from fmc_layer_composer.composer.models import LayerComposerOptions
from fmc_layer_composer.composer.planner import build_plan
from fmc_layer_composer.composer.planner import plan_to_dict
from fmc_layer_composer.composer.reports import render_dry_run_html


def test_report_renders_self_contained_html():
    plan = build_plan(
        csv_filename="x.csv",
        entries=[],
        duplicate_rule_names=[],
        source_acps=[],
        source_rules_by_acp={},
        options=LayerComposerOptions(target_acp_name="target"),
    )
    html = render_dry_run_html(plan)
    assert "<style>" in html
    assert "Executive Summary" in html
    assert "Raw JSON Summary" in html


def test_report_includes_candidate_field_deltas_table_and_json_fields():
    from fmc_layer_composer.composer.models import LayerCsvEntry, SourceAcpRef

    entry = LayerCsvEntry(1, "Rule A", "Rule A", None, None, [], [], [], [], [], [], [], None, {})
    plan = build_plan(
        csv_filename="x.csv",
        entries=[entry],
        duplicate_rule_names=[],
        source_acps=[SourceAcpRef("a", "Luxor", 1), SourceAcpRef("b", "Excalibur", 2)],
        source_rules_by_acp={
            "a": [{"id": "1", "name": "Rule A", "action": "ALLOW", "sourceNetworks": {"objects": [{"name": "NET-A"}]}}],
            "b": [{"id": "2", "name": "Rule A", "action": "ALLOW", "sourceNetworks": {"objects": [{"name": "NET-B"}]}}],
        },
        options=LayerComposerOptions(target_acp_name="target"),
    )
    html = render_dry_run_html(plan)
    assert "Candidate Field Deltas" in html
    assert "sourceNetworks.objects.names" in html
    payload = plan_to_dict(plan)
    match = payload["matches"][0]
    assert "candidate_field_deltas" in match
    assert match["semantic_candidate_delta_count"] == 1
    assert match["blocking_candidate_delta_count"] == 1
