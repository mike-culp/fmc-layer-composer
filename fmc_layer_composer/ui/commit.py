from __future__ import annotations

import streamlit as st

from fmc_layer_composer.composer.executor import execute_plan
from fmc_layer_composer.composer import reports
from fmc_layer_composer.fmc import policies, rules


def render_commit(client: object | None, domain_uuid: str | None, plan: object | None) -> None:
    st.header("7. Commit")
    if not plan:
        st.info("Run a dry run first.")
        return
    st.write(
        {
            "Commit allowed": plan.commit_allowed,
            "CSV rules": plan.summary.get("total_csv_rules"),
            "Exact ready": plan.summary.get("exact_ready", plan.summary.get("exact_matched")),
            "Fuzzy selected": plan.summary.get("fuzzy_selected"),
            "Priority overrides selected": plan.summary.get("priority_overrides_selected", 0),
            "Skipped": plan.summary.get("skipped"),
            "Unresolved": plan.summary.get("unresolved"),
            "Blocked": plan.summary.get("blocked", len(plan.blockers)),
            "Expected creates": plan.summary.get("expected_creates", plan.summary.get("ready_to_copy")),
        }
    )
    if plan.blockers:
        st.error("\n".join(plan.blockers))
    confirmed = st.checkbox("I understand this will create a new ACP and copy the resolved rules into it. It will not deploy.")
    if st.button("Commit", disabled=not (plan.commit_allowed and confirmed), type="primary"):
        with st.spinner("Creating target ACP and copying rules"):
            result = execute_plan(
                plan=plan,
                client=client,
                domain_uuid=domain_uuid,
                policies_module=policies,
                rules_module=rules,
                reports_module=reports,
            )
            st.session_state["commit_result"] = result
    result = st.session_state.get("commit_result")
    if result:
        if result.failed_rule:
            st.error(f"Commit failed at rule {result.failed_rule.csv_order}: {result.failed_rule.error}")
        elif result.verification_status == "VERIFIED":
            st.success(f"Commit completed and verified. Target ACP ID: {result.target_acp_id}")
        elif result.verification_status == "VERIFY_MISMATCH":
            st.warning(
                "Commit completed, but post-commit verification found a mismatch. "
                f"Expected {result.expected_create_count}, API-created {result.api_created_count}, "
                f"target ACP currently has {result.verified_target_rule_count} rule(s)."
            )
        else:
            st.error(f"Commit completed, but post-commit verification failed. Target ACP ID: {result.target_acp_id}")
        for label, path in result.report_paths.items():
            with open(path, "rb") as handle:
                st.download_button(f"Download commit {label}", handle, file_name=path.split("/")[-1])
