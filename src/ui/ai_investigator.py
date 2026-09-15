"""
TraceONE — AI Investigator Module UI
Evidence-grounded natural language investigation interface backed by Qwen3:8B / Ollama or Mistral Cloud API and TraceONE tools.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import time

from src.ai.agent import TraceONEAgent
from src.ai.config import AIConfig
from src.ai.llm.ollama_provider import OllamaProvider
from src.ai.llm.mistral_provider import MistralProvider


def render_ai_investigator():
    """Render the TRACEONE AI Investigator UI Module."""

    # ---------------------------------------------------------
    # HEADER & TITLE
    # ---------------------------------------------------------
    st.markdown('<div class="traceone-title">TRACEONE / AI INVESTIGATOR</div>', unsafe_allow_html=True)
    st.markdown('<div class="traceone-subtitle">Evidence-Grounded AI Security Assistant & Query Copilot</div>', unsafe_allow_html=True)

    # Initialize Agent in Session State
    if 'ai_agent' not in st.session_state:
        st.session_state['ai_agent'] = TraceONEAgent()
    
    agent: TraceONEAgent = st.session_state['ai_agent']

    # Initialize Chat History
    if 'ai_chat_history' not in st.session_state:
        st.session_state['ai_chat_history'] = []

    # Initialize Provider Choice
    # Initialize Provider Choice
    ollama_online = OllamaProvider().check_health()
    has_mistral_key = bool(AIConfig.get_mistral_key())

    if 'selected_provider_type' not in st.session_state:
        if has_mistral_key or not ollama_online:
            st.session_state['selected_provider_type'] = "mistral"
        else:
            st.session_state['selected_provider_type'] = "ollama"

    agent.set_provider(st.session_state['selected_provider_type'])

    # Provider Toolbar options
    qwen_option = "Qwen3:8B (Local Ollama)" if ollama_online else "Qwen3:8B (Local only)"
    mistral_option = "Mistral (Cloud API)"

    provider_options = [qwen_option, mistral_option]
    default_index = 1 if st.session_state['selected_provider_type'] == "mistral" else 0

    col_prov1, col_prov2 = st.columns([2, 3])

    with col_prov1:
        provider_choice = st.radio(
            "Select AI Model Provider",
            options=provider_options,
            index=default_index,
            label_visibility="collapsed",
            key="provider_radio",
            horizontal=True
        )
        
        target_provider_name = "mistral" if "Mistral" in provider_choice else "ollama"
        if target_provider_name != st.session_state['selected_provider_type']:
            st.session_state['selected_provider_type'] = target_provider_name
            agent.set_provider(target_provider_name)

    current_provider_type = st.session_state['selected_provider_type']

    if current_provider_type == "ollama":
        model_display = AIConfig.LLM_MODEL
        status_color = "#00E676" if ollama_online else "#8B949E"
        status_text = "LOCAL ● ONLINE" if ollama_online else "LOCAL ● OFFLINE"
        privacy_text = "Model runs locally through Ollama."
    else: # mistral
        mistral_prov = MistralProvider()
        mistral_status = mistral_prov.status()
        model_display = AIConfig.MISTRAL_MODEL
        privacy_text = "Selected investigation evidence is sent to the Mistral API."
        
        if mistral_status == "CONFIGURED":
            status_color = "#00E676"
            status_text = "CLOUD ● READY"
        elif mistral_status == "NOT_CONFIGURED":
            status_color = "#FFA500"
            status_text = "CLOUD ● MISSING MISTRAL_API_KEY"
        else:
            status_color = "#FF5252"
            status_text = "CLOUD ● SDK MISSING"

    with col_prov2:
        st.markdown(f"""
        <div style="text-align: right; padding-top: 4px;">
            <span class="badge" style="background: rgba(22,27,34,0.9); color: {status_color}; border: 1px solid {status_color}; font-size: 0.8rem;">
                {model_display} &nbsp;|&nbsp; {status_text}
            </span><br/>
            <span style="font-size: 0.72rem; color: #8B949E;"><i>{privacy_text}</i></span>
        </div>
        """, unsafe_allow_html=True)

    # ---------------------------------------------------------
    # FALLBACK PROMPT BANNER IF MISTRAL UNCONFIGURED
    # ---------------------------------------------------------
    if current_provider_type == "mistral" and mistral_status != "CONFIGURED":
        st.warning("⚠️ Mistral Cloud API key is not configured in environment (`MISTRAL_API_KEY`). Displaying deterministic TraceONE analytics fallback.")
        if st.button("🔄 Switch to Qwen3 Local", key="switch_to_ollama_fallback_btn"):
            st.session_state['selected_provider_type'] = "ollama"
            agent.set_provider("ollama")
            st.rerun()

    st.markdown("---")

    # ---------------------------------------------------------
    # CHAT HISTORY DISPLAY
    # ---------------------------------------------------------
    for msg in st.session_state['ai_chat_history']:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if "figure" in msg and msg["figure"] is not None:
                st.plotly_chart(msg["figure"], use_container_width=True)
            
            if "trace" in msg and msg["trace"]:
                with st.expander("▸ Investigation details", expanded=False):
                    trace = msg["trace"]
                    plan_info = trace.get("plan", {})
                    t_col1, t_col2 = st.columns(2)
                    with t_col1:
                        st.markdown(f"**Intent:** `{plan_info.get('intent')}`")
                        st.markdown(f"**Entity ID:** `{plan_info.get('entity_id') or 'null (Global query)'}`")
                        st.markdown(f"**Tools:** `{', '.join(plan_info.get('tools', []))}`")
                    with t_col2:
                        st.markdown(f"**Visualization:** `{trace.get('visualization_type')}`")
                        st.markdown(f"**Data Source:** `user_risk_scores.csv & canonical_events.csv`")
                        st.markdown(f"**Provider:** `{trace.get('llm_provider')} ({trace.get('model_name')})` (`{trace.get('execution_time_sec')}s`)")

    # ---------------------------------------------------------
    # QUERY INPUT & SUGGESTED QUERY CHIPS
    # ---------------------------------------------------------
    query_to_run = None

    if 'pending_query' in st.session_state and st.session_state['pending_query']:
        query_to_run = st.session_state.pop('pending_query')

    user_input = st.chat_input("Ask a security question (e.g., 'Why is EMP10194 high risk?')...")
    if user_input:
        query_to_run = user_input

    # Compact Suggested Queries Bar
    st.markdown("<div style='font-size:0.8rem; color:#8B949E; margin-bottom:4px;'>Suggested Security Investigations:</div>", unsafe_allow_html=True)
    chip_col1, chip_col2, chip_col3, chip_col4 = st.columns(4)
    
    with chip_col1:
        if st.button("📌 Why is EMP10194 high risk?", key="chip_1", use_container_width=True):
            query_to_run = "Why is EMP10194 high risk?"
    with chip_col2:
        if st.button("📌 Critical users by department", key="chip_2", use_container_width=True):
            query_to_run = "Show critical users by department."
    with chip_col3:
        if st.button("📌 Timeline for EMP10194", key="chip_3", use_container_width=True):
            query_to_run = "Show the temporal sequence involving EMP10194."
    with chip_col4:
        if st.button("📌 Shared IP for EMP10194", key="chip_4", use_container_width=True):
            query_to_run = "Which users share the same IP as EMP10194?"

    with st.expander("▸ More Example Queries", expanded=False):
        ex_col1, ex_col2, ex_col3, ex_col4 = st.columns(4)
        with ex_col1:
            if st.button("Behavior anomalies EMP10194", key="chip_5"):
                query_to_run = "Show the behavioral anomalies for EMP10194."
        with ex_col2:
            if st.button("Compare EMP10194 peers", key="chip_6"):
                query_to_run = "Compare EMP10194 with R&D peers."
        with ex_col3:
            if st.button("Data quality limitations", key="chip_7"):
                query_to_run = "What are the data quality limitations affecting this investigation?"
        with ex_col4:
            if st.button("Graph for EMP10194", key="chip_8"):
                query_to_run = "Show the graph relationships for EMP10194."

    # ---------------------------------------------------------
    # QUERY PROCESSING
    # ---------------------------------------------------------
    if query_to_run:
        st.session_state['ai_chat_history'].append({"role": "user", "content": query_to_run})

        with st.chat_message("user"):
            st.markdown(query_to_run)

        with st.chat_message("assistant"):
            with st.spinner("🤖 Agent analyzing request ➔ resolving entities ➔ building evidence package..."):
                agent.set_provider(st.session_state['selected_provider_type'])
                response = agent.query(query_to_run)

            # Display Answer Text
            st.markdown(response["answer"])

            # Display Plotly Figure if generated
            if response.get("figure") is not None:
                st.plotly_chart(response["figure"], use_container_width=True)

            # Data Trust Lineage Reference
            st.markdown("<div style='font-size:0.78rem; color:#8B949E; margin-top:4px;'>Evidence Source: <code>user_risk_scores.csv & canonical_events.csv</code>. <i>Full lineage available in Data Trust Center.</i></div>", unsafe_allow_html=True)

            # Display Observability Trace Expander (Compact metadata, collapsed by default)
            with st.expander("▸ Investigation details", expanded=False):
                plan_info = response.get("plan", {})
                t_col1, t_col2 = st.columns(2)
                with t_col1:
                    st.markdown(f"**Intent:** `{plan_info.get('intent')}`")
                    st.markdown(f"**Entity ID:** `{plan_info.get('entity_id') or 'null (Global query)'}`")
                    st.markdown(f"**Tools:** `{', '.join(plan_info.get('tools', []))}`")
                with t_col2:
                    st.markdown(f"**Visualization:** `{response.get('visualization_type')}`")
                    st.markdown(f"**Data Source:** `user_risk_scores.csv & canonical_events.csv`")
                    st.markdown(f"**Provider:** `{response.get('llm_provider')} ({response.get('model_name')})` (`{response.get('execution_time_sec')}s`)")

            # Append Assistant Message to Chat History
            st.session_state['ai_chat_history'].append({
                "role": "assistant",
                "content": response["answer"],
                "figure": response.get("figure"),
                "trace": response
            })

    # Clear History Button
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🧹 Clear Chat History", key="clear_chat_btn"):
        st.session_state['ai_chat_history'] = []
        st.rerun()
