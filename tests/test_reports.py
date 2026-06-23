from fmc_layer_composer.composer.models import LayerComposerOptions
from fmc_layer_composer.composer.planner import build_plan
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
