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
    fuzzy_candidates_path = directory / f"layer_composer_fuzzy_candidates_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    fuzzy_selected_path = directory / f"layer_composer_fuzzy_selected_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    skipped_path = directory / f"layer_composer_skipped_{_safe_file_part(plan.target_acp_name)}_{timestamp_for_filename(plan.timestamp)}.csv"
    html_path.write_text(render_dry_run_html(plan), encoding="utf-8")
    json_path.write_text(json.dumps(plan_to_dict(plan), indent=2, default=str), encoding="utf-8")
    _write_summary_csv(summary_path, plan)
    _write_missing_csv(missing_path, plan)
    _write_conflicts_csv(conflicts_path, plan)
    _write_fuzzy_candidates_csv(fuzzy_candidates_path, plan)
    _write_fuzzy_selected_csv(fuzzy_selected_path, plan)
    _write_skipped_csv(skipped_path, plan)
    return {
        "html": str(html_path),
        "json": str(json_path),
        "summary_csv": str(summary_path),
        "missing_csv": str(missing_path),
        "conflicts_csv": str(conflicts_path),
        "fuzzy_candidates_csv": str(fuzzy_candidates_path),
        "fuzzy_selected_csv": str(fuzzy_selected_path),
        "skipped_csv": str(skipped_path),
    }


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
            f"<td>{_e(_candidate_delta_preview(match))}</td>"
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
            _section("Exact Match Summary", _exact_match_summary(plan)),
            _section("Missing/Fuzzy Candidate Details", _fuzzy_candidate_details(plan)),
            _section("Fuzzy Selected Rules", _fuzzy_selected_details(plan)),
            _section("Skipped Rules", _skipped_details(plan)),
            _section("Candidate Delta Summary", _candidate_delta_summary(plan)),
            _section("Commit Readiness", _list("Blockers", plan.blockers) + _list("Warnings", plan.warnings)),
            _section("Per-Rule Details", "<table><thead><tr><th>Order</th><th>Rule</th><th>Status</th><th>Selected ACP</th><th>Candidates</th><th>CSV/FMC Deltas</th><th>Candidate Field Deltas</th><th>Warnings</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" + _sanity_delta_tables(plan) + _candidate_field_delta_tables(plan)),
            _section("Raw JSON Summary", f"<pre>{_e(json.dumps(plan_to_dict(plan), indent=2, default=str)[:50000])}</pre>"),
        ],
    )


def render_commit_html(result: LayerComposerResult) -> str:
    status = _commit_status_sentence(result)
    rows = "".join(
        "<tr>"
        f"<td>{item.csv_order}</td><td>{_e(item.rule_name)}</td><td>{_e(item.status)}</td>"
        f"<td>{_e(item.source_acp_name)}</td><td>{_e(item.target_rule_id or '')}</td><td>{_e(item.placement_strategy or '')}</td><td>{_e(item.error or '')}</td>"
        "</tr>"
        for item in result.created_rules
    )
    return _page(
        "FMC Layer Composer Commit",
        [
            _section("Executive Summary", f"<p class='banner'>{_e(status)}</p>{_commit_summary_table(result)}"),
            _section("Created Rules", "<table><thead><tr><th>Order</th><th>Rule</th><th>Status</th><th>Source ACP</th><th>Target Rule ID</th><th>Placement Strategy</th><th>Error</th></tr></thead><tbody>" + rows + "</tbody></table>"),
            _section("Skipped Rules", f"<pre>{_e(json.dumps(result.skipped_rules, indent=2, default=str))}</pre>"),
            _section("Post-Commit Verification", _verification_details(result)),
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


def _commit_summary_table(result: LayerComposerResult) -> str:
    return _summary_table(
        {
            "CSV rules": len(result.plan.entries),
            "ready to copy": result.plan.summary.get("ready_to_copy", 0),
            "skipped": len(result.skipped_rules),
            "expected creates": result.expected_create_count,
            "API-created": result.api_created_count,
            "verified target ACP count": result.verified_target_rule_count,
            "verification status": result.verification_status,
        }
    )


def _commit_status_sentence(result: LayerComposerResult) -> str:
    if result.failed_rule:
        return "Commit failed."
    if result.verification_status == "VERIFIED":
        return "Commit completed and post-commit verification passed."
    if result.verification_status == "VERIFY_MISMATCH":
        return "Commit completed, but post-commit verification found a mismatch."
    return "Commit completed, but post-commit verification failed."


def _verification_details(result: LayerComposerResult) -> str:
    return (
        _summary_table(
            {
                "verification status": result.verification_status,
                "expected creates": result.expected_create_count,
                "API-created": result.api_created_count,
                "verified target ACP count": result.verified_target_rule_count,
            }
        )
        + "<h3>Missing After Commit</h3>"
        + f"<pre>{_e(json.dumps(result.missing_after_commit, indent=2, default=str))}</pre>"
        + "<h3>Extra After Commit</h3>"
        + f"<pre>{_e(json.dumps(result.extra_after_commit, indent=2, default=str))}</pre>"
    )


def _source_acps_table(plan: LayerComposerPlan) -> str:
    rows = "".join(f"<tr><td>{acp.priority}</td><td>{_e(acp.name)}</td><td>{_e(acp.id)}</td></tr>" for acp in plan.source_acps)
    return "<table><thead><tr><th>Priority</th><th>Name</th><th>ID</th></tr></thead><tbody>" + rows + "</tbody></table>"


def _candidate_delta_summary(plan: LayerComposerPlan) -> str:
    return _summary_table(
        {
            "semantic candidate deltas": plan.summary.get("semantic_candidate_deltas", 0),
            "informational candidate deltas": plan.summary.get("informational_candidate_deltas", 0),
            "context-only candidate deltas": plan.summary.get("context_only_candidate_deltas", 0),
            "ID-only candidate deltas": plan.summary.get("id_only_candidate_deltas", 0),
            "ordering-only deltas": plan.summary.get("ordering_only_deltas", 0),
            "empty/missing normalization deltas": plan.summary.get("empty_missing_normalization_deltas", 0),
        }
    )


def _exact_match_summary(plan: LayerComposerPlan) -> str:
    return _summary_table(
        {
            "total CSV rules": plan.summary.get("total_csv_rules", 0),
            "exact matched": plan.summary.get("exact_matched", 0),
            "exact missing": plan.summary.get("exact_missing", 0),
            "fuzzy candidates found": plan.summary.get("fuzzy_candidates_found", 0),
            "fuzzy selected": plan.summary.get("fuzzy_selected", 0),
            "skipped": plan.summary.get("skipped", 0),
            "unresolved": plan.summary.get("unresolved", 0),
        }
    )


def _fuzzy_candidate_details(plan: LayerComposerPlan) -> str:
    rows = []
    for match in plan.matches:
        if not match.fuzzy_candidates and not match.primary_reason_code in {"NO_FUZZY_CANDIDATES", "NO_EXACT_MATCH"}:
            continue
        rows.append(
            "<tr>"
            f"<td>{match.csv_entry.order}</td><td>{_e(match.csv_entry.rule_name)}</td>"
            f"<td>{_e(match.primary_reason_code or '')}</td>"
            f"<td>{_e(json.dumps([asdict(candidate) for candidate in match.fuzzy_candidates], default=str))}</td>"
            f"<td>{_e(match.selected_fuzzy_candidate.candidate_rule_name if match.selected_fuzzy_candidate else '')}</td>"
            f"<td>{_e(match.user_decision or '')}</td>"
            "</tr>"
        )
    if not rows:
        return "<p>None.</p>"
    return "<table><thead><tr><th>CSV order</th><th>CSV rule</th><th>reason</th><th>fuzzy candidates</th><th>selected</th><th>decision</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _fuzzy_selected_details(plan: LayerComposerPlan) -> str:
    rows = []
    for match in plan.matches:
        if not match.selected_fuzzy_candidate:
            continue
        selected = match.selected_fuzzy_candidate
        rows.append(
            "<tr>"
            f"<td>{match.csv_entry.order}</td><td>{_e(match.csv_entry.rule_name)}</td>"
            f"<td>{_e(selected.candidate_rule_name)}</td><td>{_e(selected.source_acp_name)}</td>"
            f"<td>{_e(match.rename_to_csv_rule_name)}</td><td>{_e('; '.join(match.warnings))}</td>"
            "</tr>"
        )
    if not rows:
        return "<p>None.</p>"
    return "<table><thead><tr><th>CSV order</th><th>CSV rule</th><th>source rule</th><th>source ACP</th><th>renamed to CSV</th><th>warnings</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _skipped_details(plan: LayerComposerPlan) -> str:
    rows = []
    for match in plan.matches:
        if not str(match.status).startswith("SKIPPED"):
            continue
        rows.append(
            "<tr>"
            f"<td>{match.csv_entry.order}</td><td>{_e(match.csv_entry.rule_name)}</td>"
            f"<td>{_e(match.primary_reason_code or '')}</td><td>{_e(match.human_reason or match.skip_reason or '')}</td>"
            f"<td>{_e(match.user_decision or '')}</td><td>{_e(match.commit_impact or '')}</td>"
            "</tr>"
        )
    if not rows:
        return "<p>None.</p>"
    return "<table><thead><tr><th>CSV order</th><th>CSV rule</th><th>reason code</th><th>reason</th><th>decision</th><th>commit impact</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _candidate_field_delta_tables(plan: LayerComposerPlan) -> str:
    sections: list[str] = []
    for match in plan.matches:
        if not match.candidate_field_deltas:
            continue
        candidate_names = [candidate.source_acp_name for candidate in match.candidates]
        header = "<tr><th>field</th><th>severity</th><th>delta type</th>"
        header += "".join(f"<th>{_e(name)} value</th>" for name in candidate_names)
        header += "<th>message</th></tr>"
        rows = []
        for delta in match.candidate_field_deltas:
            row = f"<tr><td>{_e(delta.field_path)}</td><td>{_e(delta.severity)}</td><td>{_e(_delta_type_label(delta.delta_type))}</td>"
            for name in candidate_names:
                row += f"<td>{_e(json.dumps(delta.values_by_candidate.get(name), default=str))}</td>"
            row += f"<td>{_e(delta.message)}</td></tr>"
            rows.append(row)
        sections.append(
            f"<h3>Rule {match.csv_entry.order}: {_e(match.csv_entry.rule_name)} - Candidate Field Deltas</h3>"
            "<table><thead>" + header + "</thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    if not sections:
        return "<h3>Candidate Field Deltas</h3><p>None.</p>"
    return "<h3>Candidate Field Deltas</h3>" + "".join(sections)


def _sanity_delta_tables(plan: LayerComposerPlan) -> str:
    sections: list[str] = []
    for match in plan.matches:
        if not match.sanity_deltas:
            continue
        rows = []
        for delta in match.sanity_deltas:
            rows.append(
                "<tr>"
                f"<td>{_e(delta.field)}</td>"
                f"<td>{_e(delta.severity)}</td>"
                f"<td>{_e(delta.code)}</td>"
                f"<td>{_e(json.dumps(delta.csv_value, default=str))}</td>"
                f"<td>{_e(json.dumps(delta.fmc_value, default=str))}</td>"
                f"<td>{_e(json.dumps(delta.fmc_details, default=str))}</td>"
                f"<td>{_e(delta.blocking)}</td>"
                f"<td>{_e(delta.message)}</td>"
                "</tr>"
            )
        sections.append(
            f"<h3>Rule {match.csv_entry.order}: {_e(match.csv_entry.rule_name)} - CSV-to-FMC Sanity Deltas</h3>"
            "<table><thead><tr><th>field</th><th>severity</th><th>classification</th><th>CSV comparison names</th><th>FMC comparison names</th><th>FMC object details</th><th>blocking</th><th>message</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    if not sections:
        return "<h3>CSV-to-FMC Sanity Deltas</h3><p>None.</p>"
    return "<h3>CSV-to-FMC Sanity Deltas</h3>" + "".join(sections)


def _candidate_delta_preview(match: Any) -> str:
    if not match.candidate_field_deltas:
        return ""
    blocking = match.blocking_candidate_delta_count
    informational = len(match.candidate_field_deltas) - blocking
    fields = ", ".join(delta.field_path for delta in match.candidate_field_deltas[:3])
    if blocking == 0:
        noun = "delta" if informational == 1 else "deltas"
        return f"{informational} informational candidate {noun}: {fields}"
    return f"{len(match.candidate_field_deltas)} candidate deltas ({blocking} blocking, {informational} informational): {fields}"


def _delta_type_label(delta_type: str) -> str:
    labels = {
        "CONTEXT_ONLY_DIFFERENCE": "Context-only difference",
        "ID_ONLY_DIFFERENCE": "ID-only difference",
        "ORDERING_ONLY_DIFFERENCE": "Ordering-only difference",
    }
    return labels.get(delta_type, delta_type)


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
            if match.candidate_field_deltas:
                writer.writerow({"csv_order": match.csv_entry.order, "rule_name": match.csv_entry.rule_name, "candidate_deltas": json.dumps([asdict(delta) for delta in match.candidate_field_deltas], default=str)})


def _write_fuzzy_candidates_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "csv_rule_name", "candidate_rule_name", "source_acp_name", "source_rule_id", "score", "match_tier", "match_reasons", "selected", "user_decision"])
        writer.writeheader()
        for match in plan.matches:
            for candidate in match.fuzzy_candidates:
                selected = match.selected_fuzzy_candidate and match.selected_fuzzy_candidate.source_rule_id == candidate.source_rule_id and match.selected_fuzzy_candidate.source_acp_id == candidate.source_acp_id
                writer.writerow(
                    {
                        "csv_order": match.csv_entry.order,
                        "csv_rule_name": match.csv_entry.rule_name,
                        "candidate_rule_name": candidate.candidate_rule_name,
                        "source_acp_name": candidate.source_acp_name,
                        "source_rule_id": candidate.source_rule_id,
                        "score": candidate.score,
                        "match_tier": candidate.match_tier,
                        "match_reasons": ";".join(candidate.match_reasons),
                        "selected": bool(selected),
                        "user_decision": match.user_decision or "",
                    }
                )


def _write_fuzzy_selected_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "csv_rule_name", "selected_source_rule_name", "source_acp_name", "source_rule_id", "renamed_to_csv_rule_name"])
        writer.writeheader()
        for match in plan.matches:
            if match.selected_fuzzy_candidate:
                writer.writerow(
                    {
                        "csv_order": match.csv_entry.order,
                        "csv_rule_name": match.csv_entry.rule_name,
                        "selected_source_rule_name": match.selected_fuzzy_candidate.candidate_rule_name,
                        "source_acp_name": match.selected_fuzzy_candidate.source_acp_name,
                        "source_rule_id": match.selected_fuzzy_candidate.source_rule_id,
                        "renamed_to_csv_rule_name": match.rename_to_csv_rule_name,
                    }
                )


def _write_skipped_csv(path: Path, plan: LayerComposerPlan) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "csv_rule_name", "final_status", "primary_reason_code", "human_reason", "user_decision", "commit_impact"])
        writer.writeheader()
        for match in plan.matches:
            if str(match.status).startswith("SKIPPED"):
                writer.writerow(
                    {
                        "csv_order": match.csv_entry.order,
                        "csv_rule_name": match.csv_entry.rule_name,
                        "final_status": "SKIPPED",
                        "primary_reason_code": match.primary_reason_code or "",
                        "human_reason": match.human_reason or match.skip_reason or "",
                        "user_decision": match.user_decision or "",
                        "commit_impact": match.commit_impact or "",
                    }
                )


def _write_created_csv(path: Path, result: LayerComposerResult) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["csv_order", "rule_name", "source_acp_name", "source_rule_id", "target_rule_id", "status", "placement_strategy", "error"])
        writer.writeheader()
        for item in result.created_rules:
            row = asdict(item)
            writer.writerow({field: row.get(field) for field in writer.fieldnames})


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
