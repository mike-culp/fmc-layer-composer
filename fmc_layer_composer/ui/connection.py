from __future__ import annotations

import streamlit as st

from fmc_layer_composer.fmc.auth import authenticate
from fmc_layer_composer.fmc.domains import list_domains


def render_connection() -> tuple[object | None, str | None]:
    st.header("1. FMC connection")
    host = st.text_input("FMC host/IP", value=st.session_state.get("fmc_host", ""))
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    verify_tls = st.checkbox("Verify TLS", value=True)
    if st.button("Connect", type="primary"):
        with st.spinner("Connecting to FMC"):
            client = authenticate(host, username, password, verify_tls=verify_tls)
            domains = list_domains(client)
            st.session_state["client"] = client
            st.session_state["domains"] = domains
            st.session_state["fmc_host"] = host
            st.success("Connected")
    client = st.session_state.get("client")
    domains = st.session_state.get("domains", [])
    domain_uuid = None
    if client and domains:
        labels = [f"{domain.get('name', domain.get('uuid'))} ({domain.get('uuid')})" for domain in domains]
        selected = st.selectbox("Domain", labels)
        domain_uuid = domains[labels.index(selected)].get("uuid")
        st.caption(f"API session active. Domain UUID: {domain_uuid}")
    return client, domain_uuid
