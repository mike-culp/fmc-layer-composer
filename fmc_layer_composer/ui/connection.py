from __future__ import annotations

import streamlit as st

from fmc_layer_composer.composer.state import save_user_config
from fmc_layer_composer.fmc.auth import authenticate
from fmc_layer_composer.fmc.domains import list_domains


def render_connection() -> tuple[object | None, str | None]:
    st.header("1. FMC connection")
    host = st.text_input("FMC host/IP", value=st.session_state.get("fmc_host", ""))
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    verify_tls = st.checkbox(
        "Verify TLS certificate",
        value=bool(st.session_state.get("verify_tls", False)),
        help="Leave unchecked for lab/self-signed FMC certificates. Enable for trusted production certificates.",
    )
    st.caption("FMC host and TLS preference are saved locally. Credentials are never saved.")
    if host != st.session_state.get("fmc_host") or verify_tls != st.session_state.get("verify_tls"):
        st.session_state["fmc_host"] = host
        st.session_state["verify_tls"] = verify_tls
        save_user_config({"fmc_host": host, "verify_tls": verify_tls, "last_domain_uuid": st.session_state.get("domain_uuid"), "last_domain_name": st.session_state.get("domain_name")})
    if st.button("Connect", type="primary"):
        with st.spinner("Connecting to FMC"):
            client = authenticate(host, username, password, verify_tls=verify_tls)
            domains = list_domains(client)
            st.session_state["client"] = client
            st.session_state["domains"] = domains
            st.session_state["fmc_host"] = host
            st.session_state["verify_tls"] = verify_tls
            st.session_state["connected"] = True
            save_user_config({"fmc_host": host, "verify_tls": verify_tls})
            st.success("Connected")
    client = st.session_state.get("client")
    domains = st.session_state.get("domains", [])
    domain_uuid = None
    if client and domains:
        labels = [f"{domain.get('name', domain.get('uuid'))} ({domain.get('uuid')})" for domain in domains]
        selected = st.selectbox("Domain", labels)
        domain_uuid = domains[labels.index(selected)].get("uuid")
        domain_name = domains[labels.index(selected)].get("name")
        st.session_state["domain_uuid"] = domain_uuid
        st.session_state["domain_name"] = domain_name
        save_user_config({"fmc_host": st.session_state.get("fmc_host", ""), "verify_tls": st.session_state.get("verify_tls", False), "last_domain_uuid": domain_uuid, "last_domain_name": domain_name})
        st.caption(f"API session active. Domain UUID: {domain_uuid}")
    return client, domain_uuid
