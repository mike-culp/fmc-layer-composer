from __future__ import annotations

import streamlit as st

from fmc_layer_composer.ui.session_state import init_session_state, reset_app_state
from fmc_layer_composer.ui.analysis import render_analysis
from fmc_layer_composer.ui.commit import render_commit
from fmc_layer_composer.ui.connection import render_connection
from fmc_layer_composer.ui.source_selection import render_source_selection


def main() -> None:
    st.set_page_config(page_title="FMC Layer Composer", layout="wide")
    init_session_state()
    st.title("FMC Layer Composer")
    st.caption("Dry-run first. Commit creates a new ACP, copies selected FMC-native rules in CSV order, and does not deploy.")
    if st.sidebar.button("Reset app state"):
        reset_app_state()
        st.rerun()
    client, domain_uuid = render_connection()
    selected_policies = render_source_selection(client, domain_uuid)
    plan = render_analysis(client, domain_uuid, selected_policies)
    render_commit(client, domain_uuid, plan)


if __name__ == "__main__":
    main()
