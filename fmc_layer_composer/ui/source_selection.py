from __future__ import annotations

import streamlit as st

from fmc_layer_composer.fmc.policies import list_access_policies


def render_source_selection(client: object | None, domain_uuid: str | None) -> list[dict]:
    st.header("2. Source ACP selection")
    if not client or not domain_uuid:
        st.info("Connect to FMC and select a domain first.")
        return []
    if st.button("Load / refresh ACPs"):
        st.session_state["access_policies"] = list_access_policies(client, domain_uuid)
        st.session_state["available_acps"] = st.session_state["access_policies"]
    policies = st.session_state.get("access_policies", st.session_state.get("available_acps", []))
    labels = [f"{policy.get('name')} ({policy.get('id')})" for policy in policies]
    default_labels = [
        f"{policy.get('name')} ({policy.get('id')})"
        for policy in st.session_state.get("selected_source_acps", [])
        if f"{policy.get('name')} ({policy.get('id')})" in labels
    ]
    selected_labels = st.multiselect("Source ACPs in priority order", labels, default=default_labels)
    selected = [policies[labels.index(label)] for label in selected_labels]
    st.session_state["selected_source_acps"] = selected
    st.session_state["source_acp_priority"] = [policy.get("id") for policy in selected]
    for priority, policy in enumerate(selected, start=1):
        st.caption(f"{priority}. {policy.get('name')}")
    return selected
