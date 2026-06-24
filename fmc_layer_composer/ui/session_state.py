from __future__ import annotations

import streamlit as st

from fmc_layer_composer.composer.state import load_user_config


def init_session_state() -> None:
    config = load_user_config()
    defaults = {
        "fmc_host": config.get("fmc_host", ""),
        "verify_tls": config.get("verify_tls", False),
        "connected": False,
        "client": None,
        "domain_uuid": config.get("last_domain_uuid"),
        "domain_name": config.get("last_domain_name"),
        "available_acps": [],
        "selected_source_acps": [],
        "source_acp_priority": [],
        "uploaded_csv_name": None,
        "uploaded_csv_bytes": None,
        "uploaded_csv_sha256": None,
        "target_acp_name": "",
        "analysis_plan": None,
        "analysis_plan_id": None,
        "analysis_plan_signature": None,
        "analysis_result_timestamp": None,
        "resolution_state": {},
        "conflict_resolution_state": {},
        "fuzzy_resolution_state": {},
        "skip_resolution_state": {},
        "resolved_plan": None,
        "commit_result": None,
        "inputs_changed_since_analysis": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def reset_app_state() -> None:
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    init_session_state()
