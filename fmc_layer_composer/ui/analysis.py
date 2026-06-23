from __future__ import annotations

from dataclasses import asdict

import pandas as pd
import streamlit as st

from fmc_layer_composer.composer.csv_parser import CsvValidationError, parse_layer_csv
from fmc_layer_composer.composer.models import LayerComposerOptions, MatchMode, SourceAcpRef
from fmc_layer_composer.composer.planner import build_plan
from fmc_layer_composer.composer.reports import write_dry_run_report
from fmc_layer_composer.composer.utils import normalize_layer_name
from fmc_layer_composer.fmc import policies, rules


def render_analysis(client: object | None, domain_uuid: str | None, selected_policies: list[dict]) -> object | None:
    st.header("3. CSV upload")
    upload = st.file_uploader("Upload one Panorama/FMT layer CSV", type=["csv"])
    if not upload:
        return None
    content = upload.getvalue()
    try:
        parsed = parse_layer_csv(content)
    except CsvValidationError as exc:
        st.error(str(exc))
        return None

    st.write(
        {
            "filename": upload.name,
            "detected rule-name column": parsed.rule_name_column,
            "rule count": len(parsed.entries),
            "disabled count": sum(1 for entry in parsed.entries if entry.csv_enabled is False),
            "duplicates": parsed.duplicate_rule_names,
        }
    )
    st.dataframe(pd.DataFrame([asdict(entry) for entry in parsed.entries[:10]]))

    st.header("4. Target ACP")
    target_default = normalize_layer_name(upload.name)
    target_name = st.text_input("Target ACP name", value=st.session_state.get("target_acp_name", target_default))
    st.warning("The target ACP will be created only during commit. The tool will not deploy or assign devices.")

    st.header("5. Analysis options")
    match_mode = st.selectbox("Match mode", [mode.value for mode in MatchMode])
    options = LayerComposerOptions(
        match_mode=MatchMode(match_mode),
        use_priority_for_identical_candidates=st.checkbox("Use source ACP priority for identical candidates", value=True),
        use_priority_despite_candidate_deltas=st.checkbox("Override candidate signature deltas using source ACP priority", value=False),
        skip_missing=st.checkbox("Skip missing/unmatched rules", value=False),
        honor_csv_disabled=st.checkbox("Honor CSV disabled state", value=True),
        stop_on_first_failure=st.checkbox("Stop on first create failure", value=True),
        target_acp_name=target_name,
    )

    if not st.button("Analyze / Dry Run", type="primary"):
        return st.session_state.get("plan")
    if not client or not domain_uuid:
        st.error("Connect to FMC first.")
        return None
    if not selected_policies:
        st.error("Select at least one source ACP.")
        return None

    with st.spinner("Fetching source ACP rules and building plan"):
        source_acps = [
            SourceAcpRef(id=str(policy["id"]), name=str(policy["name"]), priority=index)
            for index, policy in enumerate(selected_policies, start=1)
        ]
        source_rules = {acp.id: rules.list_access_rules(client, domain_uuid, acp.id, expanded=True) for acp in source_acps}
        target_exists = policies.get_access_policy_by_name(client, domain_uuid, target_name) is not None
        plan = build_plan(
            csv_filename=upload.name,
            entries=parsed.entries,
            duplicate_rule_names=parsed.duplicate_rule_names,
            source_acps=source_acps,
            source_rules_by_acp=source_rules,
            options=options,
            target_exists=target_exists,
        )
        plan.report_paths = write_dry_run_report(plan)  # type: ignore[attr-defined]
        st.session_state["plan"] = plan
        st.session_state["domain_uuid"] = domain_uuid
    _render_plan(plan)
    return plan


def _render_plan(plan: object) -> None:
    st.header("6. Dry-run result")
    st.write({"commit_allowed": plan.commit_allowed, "summary": plan.summary})
    if plan.blockers:
        st.error("\n".join(plan.blockers))
    if plan.warnings:
        st.warning("\n".join(plan.warnings))
    rows = []
    for match in plan.matches:
        rows.append(
            {
                "CSV order": match.csv_entry.order,
                "rule name": match.csv_entry.rule_name,
                "status": match.status,
                "selected source ACP": match.selected_candidate.source_acp_name if match.selected_candidate else "",
                "candidate ACPs": ", ".join(candidate.source_acp_name for candidate in match.candidates),
                "warnings": "; ".join(match.warnings),
                "deltas": "; ".join(delta.code for delta in match.sanity_deltas),
                "candidate deltas": _candidate_delta_preview(match),
                "commit action": "create" if match.selected_candidate else "skip/block",
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    for label, path in getattr(plan, "report_paths", {}).items():
        with open(path, "rb") as handle:
            st.download_button(f"Download {label}", handle, file_name=path.split("/")[-1])


def _candidate_delta_preview(match: object) -> str:
    deltas = getattr(match, "candidate_field_deltas", [])
    if not deltas:
        return ""
    fields = ", ".join(delta.field_path for delta in deltas[:3])
    blocking = getattr(match, "blocking_candidate_delta_count", 0)
    informational = len(deltas) - blocking
    return f"{len(deltas)} candidate deltas: {fields} ({blocking} blocking, {informational} informational)"
