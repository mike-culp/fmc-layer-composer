from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .executor import result_to_dict
from .models import LayerComposerPlan, LayerComposerResult
from .planner import plan_to_dict
from .utils import safe_target_name, timestamp_for_filename


REPORT_ROOT = Path("reports/layer_composer")


def write_dry_run_report(plan: LayerComposerPlan) -> dict[str, str]:
    directory = _report_dir(plan.timestamp)
    stem = f"layer_composer_dryrun_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}"
    html_path = directory / f"{stem}.html"
    json_path = directory / f"{stem}.json"
    summary_path = directory / f"layer_composer_summary_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    missing_path = directory / f"layer_composer_missing_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    conflicts_path = directory / f"layer_composer_conflicts_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    html_path.write_text(render_dry_run_html(plan), encoding="utf-8")
    json_path.write_text(json.dumps(plan_to_dict(plan), indent=2, default=str), encoding="utf-8")
    _write_summary_csv(summary_path, plan)
    _write_missing_csv(missing_path, plan)
    _write_conflicts_csv(conflicts_path, plan)
    return {"html": str(html_path), "json": str(json_path), "summary_csv": str(summary_path), "missing_csv": str(missing_path), "conflicts_csv": str(conflicts_path)}


def write_commit_report(result: LayerComposerResult) -> dict[str, str]:
    directory = _report_dir(result.plan.timestamp)
    stem = f"layer_composer_commit_{_safe_file_part(result.target_acp_name)}_{timestamp_for_filename(result.plan.timestamp)}"
    html_path = directory / f"{stem}.html"
    json_path = directory / f"{stem}.json"
    created_path = directory / f"layer_composer_created_{_safe_file_part(result.target_acp_name)}_{timestamp_for_filename(result.plan.timestamp)}.csv"
    html_path.write_text(render_commit_html(result), encoding="utf-8")
    json_path.write_text(json.dumps(result_to_dict(result), indent=2, default=str), encoding="utf-8")
    _write_created_csv(created_path, result)
    return {"html": str(html_path), "json": str(json_path), "created_csv": str(created_path)}


def render_dry_run_html(plan: LayerComposerPlan) -> str:
    status = _readiness_sentence(plan)
    rows = []
    for match in plan.matches:
        selected = match.selected_candidate
        rows.append(
            "<tr>"
            f"<td><a id='rule-{match.csv_entry.order:04d}' href='#rule-{match.csv_entry.order:04d}'>{match.csv_entry.order}</a></td>"
            f"<td>{_e(match.csv_entry.rule_name)}</td>"
            f"<td>{_e(match.status)}</td>"
            f"<td>{_e(selected.source_acp_name if selected else '')}</td>"
            f"<td>{_e(', '.join(candidate.source_acp_name for candidate in match.candidates))}</td>"
            f"<td>{_e(', '.join(delta.code for delta in match.sanity_deltas))}</td>"
            f"<td>{_e('; '.join(match.warnings))}</td>"
            "</tr>"
        )
    return _page(
        "FMC Layer Composer Dry Run",
        [
            _section("Executive Summary", f"<p class='banner'>{_e(status)}</p>{_summary_table(plan.summary)}"),
            _section("Source ACPs and Priority", _source_acps_table(plan)),
            _section("CSV Manifest Summary", f"<p>{len(plan.entries)} CSV rules from {_e(plan.csv_filename)}.</p>"),
            _section("Match Summary", _summary_table(plan.summary)),
            _section("Commit Readiness", _list("Blockers", plan.blockers) + _list("Warnings", plan.warnings)),
            _section("Per-Rule Details", "<table><thead><tr><th>Order</th><th>Rule</th><th>Status</th><th>Selected ACP</th><th>Candidates</th><th>Deltas</th><th>Warnings</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"),
            _section("Raw JSON Summary", f"<pre>{_e(json.dumps(plan_to_dict(plan), indent=2, default=str)[:50000])}</pre>"),
        ],
    )


def render_commit_html(result: LayerComposerResult) -> str:
    status = "Commit failed." if result.failed_rule else "Commit completed."
    rows = "".join(
        "<tr>"
        f"<td>{item.csv_order}</td><td>{_e(item.rule_name)}</td><td>{_e(item.status)}</td>"
        f"<td>{_e(item.source_acp_name)}</td><td>{_e(item.target_rule_id or '')}</td><td>{_e(item.error or '')}</td>"
        "</tr>"
        for item in result.created_rules
    )
    return _page(
        "FMC Layer Composer Commit",
        [
            _section("Executive Summary", f"<p class='banner'>{_e(status)}</p>"),
            _section("Created Rules", "<table><thead><tr><th>Order</th><th>Rule</th><th>Status</th><th>Source ACP</th><th>Target Rule ID</th><th>Error</th></tr></thead><tbody>" + rows + "</tbody></table>"),
            _section("Skipped Rules", f"<pre>{_e(json.dumps(result.skipped_rules, indent=2, default=str))}</pre>"),
            _section("API Failures", f"<pre>{_e(json.dumps(result.errors, indent=2, default=str))}</pre>"),
            _section("Raw JSON Summary", f"<pre>{_e(json.dumps(result_to_dict(result), indent=2, default=str)[:50000])}</pre>"),
        ],
    )


def _report_dir(timestamp: str) -> Path:
    directory = REPORT_ROOT / timestamp_for_filename(timestamp)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _page(title: str, sections: list[str]) -> str:
    return "<!doctype html><html><head><meta charset='utf-8'><title>" + _e(title) + "</title><style>" + _css() + "</style></head><body><main><h1>" + _e(title) + "</h1>" + "".join(sections) + "</main></body></html>"


def _section(title: str, body: str) -> str:
    return f"<section><h2>{_e(title)}</h2>{body}</section>"


def _summary_table(summary: dict[str, Any]) -> str:
    rows = "".join(f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>" for key, value in summary.items())
    return f"<table>{rows}</table>"


def _source_acps_table(plan: LayerComposerPlan) -> str:
    rows = "".join(f"<tr><td>{acp.priority}</td><td>{_e(acp.name)}</td><td>{_e(acp.id)}</td></tr>" for acp in plan.source_acps)
    return "<table><thead><tr><th>Priority</th><th>Name</th><th>ID</th></tr></thead><tbody>" + rows + "</tbody></table>"


def _list(title: str, items: list[str]) -> str:
    if not items:
        return f"<h3>{_e(title)}</h3><p>None.</p>"
    return f"<h3>{_e(title)}</h3><ul>" + "".join(f"<li>{_e(item)}</li>" for item in items) + "</ul>"


def _readiness_sentence(plan: LayerComposerPlan) -> str:
    if plan.summary.get("ready_to_copy") == plan.summary.get("total_csv_rules") and plan.commit_allowed:
        return "Matched all rules. Ready to create target ACP."
    if plan.summary.get("ready_to_copy") == 0:
        return "Matched none. Selected source ACPs do not appear to contain this layer."
    if not plan.commit_allowed:
        return "Partial match. Commit blocked until missing/conflicted rules are resolved or explicitly skipped."
    return "Matched all allowed rules. Ready to create target ACP."


def _write_summary_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "rule_name", "status", "selected_source_acp", "warnings"])
        writer.writeheader()
        for match in plan.matches:
            writer.writerow(
                {
                    "csv_order": match.csv_entry.order,
                    "rule_name": match.csv_entry.rule_name,
                    "status": match.status,
                    "selected_source_acp": match.selected_candidate.source_acp_name if match.selected_candidate else "",
                    "warnings": "; ".join(match.warnings),
                }
            )


def _write_missing_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "rule_name", "status"])
        writer.writeheader()
        for match in plan.matches:
            if not match.selected_candidate:
                writer.writerow({"csv_order": match.csv_entry.order, "rule_name": match.csv_entry.rule_name, "status": match.status})


def _write_conflicts_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "rule_name", "candidate_deltas"])
        writer.writeheader()
        for match in plan.matches:
            if match.candidate_deltas:
                writer.writerow({"csv_order": match.csv_entry.order, "rule_name": match.csv_entry.rule_name, "candidate_deltas": json.dumps(match.candidate_deltas, default=str)})


def _write_created_csv(path: Path, result: LayerComposerResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "rule_name", "source_acp_name", "source_rule_id", "target_rule_id", "status", "error"])
        writer.writeheader()
        for item in result.created_rules:
            writer.writerow(asdict(item))


def _safe_file_part(value: str) -> str:
    return safe_target_name(value).replace(" ", "-") or "target"


def _e(value: Any) -> str:
    return html.escape(str(value))


def _css() -> str:
    return """
body{margin:0;background:#101418;color:#e8edf2;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px}
h1,h2,h3{color:#f7fafc}section{margin:24px 0;padding-top:8px;border-top:1px solid #2d3742}
table{border-collapse:collapse;width:100%;margin:12px 0;background:#151b22}th,td{border:1px solid #2d3742;padding:8px;text-align:left;vertical-align:top}
th{background:#202832}.banner{font-size:18px;font-weight:700;padding:12px;background:#1d2b20;border-left:4px solid #48bb78}
pre{white-space:pre-wrap;overflow:auto;background:#151b22;padding:12px;border:1px solid #2d3742}
a{color:#8cc8ff}
"""
