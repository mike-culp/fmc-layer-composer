from __future__ import annotations

from dataclasses import asdict

import pandas as pd
import streamlit as st

from fmc_layer_composer.composer.csv_parser import CsvValidationError, parse_layer_csv
from fmc_layer_composer.composer.models import LayerComposerOptions, MatchMode, SourceAcpRef
from fmc_layer_composer.composer.planner import build_plan
from fmc_layer_composer.composer.resolution import apply_resolution_state_to_plan, candidate_key, initialize_resolution_state
from fmc_layer_composer.composer.reports import write_dry_run_report
from fmc_layer_composer.composer.state import build_plan_signature, sha256_bytes, make_rule_key
from fmc_layer_composer.composer.utils import normalize_layer_name
from fmc_layer_composer.fmc import policies, rules


def render_analysis(client: object | None, domain_uuid: str | None, selected_policies: list[dict]) -> object | None:
    st.header("3. CSV upload")
    upload = st.file_uploader("Upload one Panorama/FMT layer CSV", type=["csv"])
    if upload:
        content = upload.getvalue()
        st.session_state["uploaded_csv_name"] = upload.name
        st.session_state["uploaded_csv_bytes"] = content
        st.session_state["uploaded_csv_sha256"] = sha256_bytes(content)
    if not st.session_state.get("uploaded_csv_bytes"):
        return None
    content = st.session_state["uploaded_csv_bytes"]
    csv_name = st.session_state["uploaded_csv_name"]
    try:
        parsed = parse_layer_csv(content)
    except CsvValidationError as exc:
        st.error(str(exc))
        return None

    st.write(
        {
            "filename": csv_name,
            "sha256": st.session_state.get("uploaded_csv_sha256"),
            "detected rule-name column": parsed.rule_name_column,
            "rule count": len(parsed.entries),
            "disabled count": sum(1 for entry in parsed.entries if entry.csv_enabled is False),
            "duplicates": parsed.duplicate_rule_names,
        }
    )
    st.dataframe(pd.DataFrame([asdict(entry) for entry in parsed.entries[:10]]))

    st.header("4. Target ACP")
    target_default = normalize_layer_name(csv_name)
    target_name = st.text_input("Target ACP name", value=st.session_state.get("target_acp_name", target_default))
    st.warning("The target ACP will be created only during commit. The tool will not deploy or assign devices.")
    st.info(
        "Rules will be created in the Mandatory section when supported by the FMC API. "
        "The tool will not create custom rule categories/headers in v1."
    )

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
    options.fuzzy.threshold = st.slider("Fuzzy candidate threshold", min_value=0.5, max_value=1.0, value=0.72, step=0.01)
    options.fuzzy.min_score = options.fuzzy.threshold
    options.fuzzy.auto_accept_single_deterministic_artifact = st.checkbox("Auto-accept single deterministic artifact matches", value=False)
    options.fuzzy.auto_select_single_artifact_match = options.fuzzy.auto_accept_single_deterministic_artifact
    options.target_rule_name_mode = st.selectbox("Target rule naming", ["csv", "source"], format_func=lambda value: "Use CSV rule name" if value == "csv" else "Preserve selected source rule name")
    options.fuzzy_selections = _fuzzy_selections_from_resolution_state(st.session_state.get("resolution_state", {}))
    options.fuzzy_skips = _fuzzy_skips_from_resolution_state(st.session_state.get("resolution_state", {}))

    signature = build_plan_signature(
        fmc_host=st.session_state.get("fmc_host", ""),
        domain_uuid=domain_uuid or "",
        selected_source_acps=selected_policies,
        csv_filename=csv_name,
        csv_sha256=st.session_state.get("uploaded_csv_sha256", ""),
        target_acp_name=target_name,
        match_options={
            "match_mode": options.match_mode.value,
            "skip_missing": options.skip_missing,
            "fuzzy_threshold": options.fuzzy.threshold,
            "auto_accept_single_artifact": options.fuzzy.auto_accept_single_deterministic_artifact,
            "target_rule_name_mode": options.target_rule_name_mode,
        },
    )
    old_signature = st.session_state.get("analysis_plan_signature")
    if st.session_state.get("analysis_plan") and old_signature and old_signature != signature:
        st.warning("Inputs changed since the last analysis. Re-running analysis will clear existing manual selections unless you keep compatible selections.")
        st.session_state["inputs_changed_since_analysis"] = True
    col1, col2, col3 = st.columns(3)
    analyze_keep = col1.button("Analyze / Dry Run", type="primary")
    rerun_keep = col2.button("Re-run analysis and keep compatible selections")
    rerun_clear = col3.button("Re-run analysis and clear selections")
    if st.button("Clear all manual selections"):
        st.session_state["resolution_state"] = {}
        st.session_state["resolved_plan"] = None
        st.rerun()
    should_analyze = analyze_keep or rerun_keep or rerun_clear
    if not should_analyze:
        plan = st.session_state.get("analysis_plan")
        if plan:
            _render_plan(plan)
        return st.session_state.get("resolved_plan") or plan
    if not client or not domain_uuid:
        st.error("Connect to FMC first.")
        return None
    if not selected_policies:
        st.error("Select at least one source ACP.")
        return None

    with st.spinner("Fetching source ACP rules and building plan"):
        if rerun_clear or (old_signature and old_signature != signature and not rerun_keep):
            st.session_state["resolution_state"] = {}
        source_acps = [
            SourceAcpRef(id=str(policy["id"]), name=str(policy["name"]), priority=index)
            for index, policy in enumerate(selected_policies, start=1)
        ]
        source_rules = {acp.id: rules.list_access_rules(client, domain_uuid, acp.id, expanded=True) for acp in source_acps}
        target_exists = policies.get_access_policy_by_name(client, domain_uuid, target_name) is not None
        plan = build_plan(
            csv_filename=csv_name,
            entries=parsed.entries,
            duplicate_rule_names=parsed.duplicate_rule_names,
            source_acps=source_acps,
            source_rules_by_acp=source_rules,
            options=options,
            target_exists=target_exists,
        )
        st.session_state["analysis_plan"] = plan
        st.session_state["plan"] = plan
        st.session_state["analysis_plan_signature"] = signature
        st.session_state["analysis_plan_id"] = signature[:12]
        st.session_state["analysis_result_timestamp"] = plan.timestamp
        st.session_state["resolution_state"] = initialize_resolution_state(plan, st.session_state.get("resolution_state", {}))
        resolved = apply_resolution_state_to_plan(plan, st.session_state["resolution_state"])
        plan.plan_signature = signature
        plan.resolution_state = st.session_state["resolution_state"]
        plan.resolved_plan_summary = resolved.summary
        plan.report_paths = write_dry_run_report(plan)  # type: ignore[attr-defined]
        st.session_state["domain_uuid"] = domain_uuid
    _render_plan(plan)
    return st.session_state.get("resolved_plan") or plan


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
                "deltas": _sanity_delta_preview(match),
                "candidate deltas": _candidate_delta_preview(match),
                "commit action": "create" if match.selected_candidate else "skip/block",
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    _render_fuzzy_resolution(plan)
    resolved = apply_resolution_state_to_plan(plan, st.session_state.get("resolution_state", {}))
    resolved.plan.plan_signature = st.session_state.get("analysis_plan_signature")
    resolved.plan.resolution_state = st.session_state.get("resolution_state", {})
    resolved.plan.resolved_plan_summary = resolved.summary
    st.session_state["resolved_plan"] = resolved.plan
    _render_resolved_summary(resolved)
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
    if blocking == 0:
        noun = "delta" if informational == 1 else "deltas"
        return f"{informational} informational candidate {noun}: {fields}"
    return f"{len(deltas)} candidate deltas: {fields} ({blocking} blocking, {informational} informational)"


def _sanity_delta_preview(match: object) -> str:
    deltas = getattr(match, "sanity_deltas", [])
    messages: list[str] = []
    for delta in deltas:
        if delta.code == "POSSIBLE_GROUP_COLLAPSE_OR_EXPANSION_DELTA":
            messages.append(f"{delta.code}: {delta.message}")
        elif delta.code == "APPLICATION_MAPPING_OR_EXPANSION_DELTA":
            messages.append(f"{delta.code}: CSV app/app-group names differ from FMC application names.")
        elif delta.severity == "info":
            messages.append(f"{delta.code}: {delta.field}")
        else:
            messages.append(delta.code)
    return "; ".join(messages)


def _render_fuzzy_resolution(plan: object) -> None:
    fuzzy_matches = [match for match in plan.matches if getattr(match, "fuzzy_candidates", [])]
    if not fuzzy_matches:
        return
    st.header("Missing / Fuzzy Match Resolution")
    st.subheader("Bulk actions")
    state = dict(st.session_state.get("resolution_state", {}))
    bulk1, bulk2, bulk3, bulk4 = st.columns(4)
    if bulk1.button("Select recommended artifact-only"):
        _bulk_select_artifacts(plan, state)
    if bulk2.button("Mark no-candidate rules skipped"):
        _bulk_skip_no_candidates(plan, state)
    if bulk3.button("Mark unresolved fuzzy skipped"):
        _bulk_skip_unresolved_fuzzy(plan, state)
    if bulk4.button("Clear selections"):
        state = initialize_resolution_state(plan, {})
    st.session_state["resolution_state"] = state
    for match in fuzzy_matches:
        with st.expander(f"{match.csv_entry.order}. {match.csv_entry.rule_name} ({match.status})"):
            st.write(
                {
                    "CSV action": match.csv_entry.csv_action,
                    "CSV source": match.csv_entry.csv_source_objects,
                    "CSV destination": match.csv_entry.csv_destination_objects,
                    "CSV apps": match.csv_entry.csv_applications,
                    "CSV services": match.csv_entry.csv_services,
                    "exact status": match.status,
                }
            )
            rows = []
            labels = ["Skip rule", "Mark not found", "Clear selection"]
            keys = ["__skip__", "__not_found__", "__clear__"]
            for candidate in match.fuzzy_candidates:
                key = f"{candidate.source_acp_id}:{candidate.source_rule_id}"
                labels.append(f"{candidate.candidate_rule_name} | {candidate.source_acp_name} | {candidate.score}")
                keys.append(key)
                rows.append(
                    {
                        "candidate rule name": candidate.candidate_rule_name,
                        "source ACP": candidate.source_acp_name,
                        "source rule ID": candidate.source_rule_id,
                        "score": candidate.score,
                        "match tier": candidate.match_tier,
                        "match reasons": ", ".join(candidate.match_reasons),
                        "semantic blockers count": len(candidate.blocking_candidate_deltas),
                        "informational warnings count": len(candidate.informational_candidate_deltas),
                    }
                )
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
            rule_key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
            state.setdefault(rule_key, initialize_resolution_state(plan, {}).get(rule_key, {}))
            current_state = state[rule_key]
            current = current_state.get("selected_candidate_key")
            if current_state.get("skip"):
                current = "__skip__"
            index = keys.index(current) if current in keys else 2
            choice = st.radio("Resolution", labels, index=index, key=f"fuzzy_resolution_{match.csv_entry.order}")
            selected_key = keys[labels.index(choice)]
            if selected_key == "__skip__":
                current_state.update({"decision": "SKIP", "skip": True, "selected_candidate_key": None, "selection_method": "USER_SKIPPED"})
            elif selected_key == "__not_found__":
                current_state.update({"decision": "MARK_NOT_FOUND", "skip": True, "selected_candidate_key": None, "selection_method": "USER_SKIPPED"})
            elif selected_key == "__clear__":
                current_state.update({"decision": "UNRESOLVED", "skip": False, "selected_candidate_key": None, "selection_method": None})
            else:
                selected = next(candidate for candidate in match.fuzzy_candidates if f"{candidate.source_acp_id}:{candidate.source_rule_id}" == selected_key)
                current_state.update(
                    {
                        "decision": "USE_SELECTED_FUZZY_CANDIDATE",
                        "selected_candidate_key": selected_key,
                        "selected_source_acp_id": selected.source_acp_id,
                        "selected_source_acp_name": selected.source_acp_name,
                        "selected_source_rule_id": selected.source_rule_id,
                        "selected_source_rule_name": selected.candidate_rule_name,
                        "skip": False,
                        "selection_method": "USER_SELECTED",
                    }
                )
            current_state["rename_to_csv_rule_name"] = st.checkbox("Rename target rule to CSV rule name", value=bool(current_state.get("rename_to_csv_rule_name", True)), key=f"rename_to_csv_{st.session_state.get('analysis_plan_id')}_{match.csv_entry.order}_{match.csv_entry.rule_name}")
            current_state["notes"] = st.text_input("Notes", value=str(current_state.get("notes", "")), key=f"notes_{st.session_state.get('analysis_plan_id')}_{match.csv_entry.order}_{match.csv_entry.rule_name}")
            state[rule_key] = current_state
            st.session_state["resolution_state"] = state
    st.caption("Selections are stored immediately and persist across reruns. Commit uses the resolved plan shown below.")


def _render_resolved_summary(resolved: object) -> None:
    st.header("Resolved Commit Readiness")
    st.write(resolved.summary)
    if resolved.blockers:
        st.error("\n".join(resolved.blockers))


def _bulk_select_artifacts(plan: object, state: dict) -> None:
    template = initialize_resolution_state(plan, state)
    for match in plan.matches:
        if len(match.fuzzy_candidates) == 1 and match.fuzzy_candidates[0].match_tier == "ARTIFACT_SUFFIX":
            key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
            candidate = match.fuzzy_candidates[0]
            template[key].update(
                {
                    "decision": "USE_SELECTED_FUZZY_CANDIDATE",
                    "selected_candidate_key": f"{candidate.source_acp_id}:{candidate.source_rule_id}",
                    "selected_source_acp_id": candidate.source_acp_id,
                    "selected_source_acp_name": candidate.source_acp_name,
                    "selected_source_rule_id": candidate.source_rule_id,
                    "selected_source_rule_name": candidate.candidate_rule_name,
                    "skip": False,
                    "selection_method": "BULK_SELECTED_ARTIFACT_ONLY",
                }
            )
    st.session_state["resolution_state"] = template


def _bulk_skip_no_candidates(plan: object, state: dict) -> None:
    template = initialize_resolution_state(plan, state)
    for match in plan.matches:
        if not match.fuzzy_candidates and not match.selected_candidate:
            key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
            if key in template:
                template[key].update({"decision": "MARK_NOT_FOUND", "skip": True, "selection_method": "BULK_SKIPPED"})
    st.session_state["resolution_state"] = template


def _bulk_skip_unresolved_fuzzy(plan: object, state: dict) -> None:
    template = initialize_resolution_state(plan, state)
    for match in plan.matches:
        key = make_rule_key(match.csv_entry.order, match.csv_entry.rule_name)
        if match.fuzzy_candidates and key in template and template[key].get("decision") == "UNRESOLVED":
            template[key].update({"decision": "SKIP", "skip": True, "selection_method": "BULK_SKIPPED"})
    st.session_state["resolution_state"] = template


def _fuzzy_selections_from_resolution_state(state: dict) -> dict[int, str]:
    return {
        int(value["csv_order"]): value["selected_candidate_key"]
        for value in state.values()
        if value.get("decision") == "USE_SELECTED_FUZZY_CANDIDATE" and value.get("selected_candidate_key")
    }


def _fuzzy_skips_from_resolution_state(state: dict) -> set[int]:
    return {int(value["csv_order"]) for value in state.values() if value.get("skip")}
