"""
TraceONE — AI Investigator Module UI
Phase M & Phase Expansion: Agentic Graph AI / AI Investigator Interface
Renders evidence-first natural language investigation interface backed by Qwen3:8B / Ollama or Mistral Cloud API and TraceONE tools.
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
    st.markdown('<div class="traceone-title">🤖 TRACEONE AI INVESTIGATOR</div>', unsafe_allow_html=True)
    st.markdown('<div class="traceone-tagline">Evidence-First Agentic Threat Reasoning & Natural Language Querying</div>', unsafe_allow_html=True)

    # Initialize Agent in Session State
    if 'ai_agent' not in st.session_state:
        st.session_state['ai_agent'] = TraceONEAgent()
    
    agent: TraceONEAgent = st.session_state['ai_agent']

    # Initialize Chat History
    if 'ai_chat_history' not in st.session_state:
        st.session_state['ai_chat_history'] = []

    # Initialize Provider Choice
    if 'selected_provider_type' not in st.session_state:
        st.session_state['selected_provider_type'] = AIConfig.LLM_PROVIDER if AIConfig.LLM_PROVIDER in ["ollama", "mistral"] else "ollama"

    # ---------------------------------------------------------
    # MODEL & PROVIDER SELECTOR TOOLBAR
    # ---------------------------------------------------------
    col_prov1, col_prov2 = st.columns([1, 2])

    with col_prov1:
        st.markdown("##### ⚙️ Select AI Model Provider")
        provider_choice = st.radio(
            "Model Provider",
            options=["Qwen3:8B — Local Ollama", "Mistral — Cloud API"],
            index=0 if st.session_state['selected_provider_type'] == "ollama" else 1,
            label_visibility="collapsed",
            key="provider_radio"
        )
        
        target_provider_name = "ollama" if "Ollama" in provider_choice else "mistral"
        if target_provider_name != st.session_state['selected_provider_type']:
            st.session_state['selected_provider_type'] = target_provider_name
            agent.set_provider(target_provider_name)

    # ---------------------------------------------------------
    # STATUS & PRIVACY BANNER
    # ---------------------------------------------------------
    current_provider_type = st.session_state['selected_provider_type']

    if current_provider_type == "ollama":
        ollama_online = OllamaProvider().check_health()
        model_display = AIConfig.LLM_MODEL
        endpoint_display = AIConfig.OLLAMA_BASE_URL
        status_color = "#00E676" if ollama_online else "#FFA500"
        status_text = "ONLINE (qwen3:8b)" if ollama_online else "OFFLINE / FALLBACK MODE"
        provider_label = "Local Ollama Engine"
        privacy_badge = "LOCAL — telemetry remains on this machine."
        privacy_color = "rgba(0, 230, 118, 0.15)"
        privacy_border = "#00E676"
    else: # mistral
        mistral_prov = MistralProvider()
        mistral_status = mistral_prov.status()
        model_display = AIConfig.MISTRAL_MODEL
        endpoint_display = "https://api.mistral.ai"
        
        if mistral_status == "CONFIGURED":
            status_color = "#00E676"
            status_text = f"CONFIGURED ({AIConfig.MISTRAL_MODEL})"
            provider_label = "Mistral Cloud API"
            privacy_badge = "CLOUD API — selected evidence is sent to the Mistral API."
            privacy_color = "rgba(124, 77, 255, 0.15)"
            privacy_border = "#7C4DFF"
        elif mistral_status == "NOT_CONFIGURED":
            status_color = "#FFA500"
            status_text = "NOT CONFIGURED (Missing MISTRAL_API_KEY)"
            provider_label = "Mistral Cloud API"
            privacy_badge = "CLOUD API — Set MISTRAL_API_KEY environment variable to enable."
            privacy_color = "rgba(255, 165, 0, 0.15)"
            privacy_border = "#FFA500"
        else: # SDK_MISSING
            status_color = "#FF5252"
            status_text = "UNAVAILABLE (mistralai SDK missing)"
            provider_label = "Mistral Cloud API"
            privacy_badge = "CLOUD API — Install 'mistralai' Python package."
            privacy_color = "rgba(255, 82, 82, 0.15)"
            privacy_border = "#FF5252"

    with col_prov2:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(124,77,255,0.08) 0%, rgba(22,27,34,0.95) 100%); border: 1px solid {privacy_border}; border-radius: 8px; padding: 12px; margin-top: 4px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span class="badge badge-cyan">MODEL: {model_display}</span>
                    <span class="badge" style="background-color:{privacy_color}; color:{privacy_border}; border:1px solid {privacy_border};">MODE: {privacy_badge}</span>
                    <h5 style="color:{privacy_border} !important; margin-top:6px; margin-bottom:2px;">TRACEONE AGENTIC REASONING BACKPLANE</h5>
                    <p style="font-size:0.8rem; color:#C9D1D9; margin:0;">
                        <b>Core Policy:</b> <i>"No claim without evidence."</i> TraceONE deterministic tools remain the sole source of truth.
                    </p>
                </div>
                <div style="text-align:right; min-width:180px;">
                    <div style="font-size:1.0rem; font-weight:700; color:{status_color};">{status_text}</div>
                    <div style="font-size:0.75rem; color:#8B949E; text-transform:uppercase;">{provider_label}</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ---------------------------------------------------------
    # FALLBACK PROMPT BANNER IF MISTRAL UNCONFIGURED
    # ---------------------------------------------------------
    if current_provider_type == "mistral" and mistral_status != "CONFIGURED":
        st.warning("⚠️ Mistral Cloud API key is not configured in the environment (`MISTRAL_API_KEY`). Queries will use evidence-grounded fallback responses unless you switch to Local Ollama.")
        if st.button("🔄 Switch to Qwen3:8B Local (Ollama)", key="switch_to_ollama_fallback_btn"):
            st.session_state['selected_provider_type'] = "ollama"
            agent.set_provider("ollama")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------------------------------------------------------
    # DEMO QUERY SHORTCUTS (TEST 1 - TEST 8)
    # ---------------------------------------------------------
    st.markdown("#### ⚡ Pre-Configured Demo Investigation Queries (Phase M & Expansion Acceptance Tests)")
    
    demo_queries = [
        ("TEST 1", "Why is EMP10194 high risk?"),
        ("TEST 2", "Show the behavioral anomalies for EMP10194."),
        ("TEST 3", "Compare EMP10194 with R&D peers."),
        ("TEST 4", "Show the temporal sequence involving EMP10194."),
        ("TEST 5", "Which users share the same IP as EMP10194?"),
        ("TEST 6", "Show critical users by department."),
        ("TEST 7", "What are the data quality limitations affecting this investigation?"),
        ("TEST 8", "Show the graph relationships for EMP10194.")
    ]

    # Render in 2 rows of 4 buttons
    col_row1 = st.columns(4)
    for idx, (label, text) in enumerate(demo_queries[:4]):
        with col_row1[idx]:
            if st.button(f"📌 {label}\n{text[:26]}...", key=f"demo_btn_{idx}", help=text, use_container_width=True):
                st.session_state['pending_query'] = text

    col_row2 = st.columns(4)
    for idx, (label, text) in enumerate(demo_queries[4:]):
        with col_row2[idx]:
            if st.button(f"📌 {label}\n{text[:26]}...", key=f"demo_btn_{idx+4}", help=text, use_container_width=True):
                st.session_state['pending_query'] = text

    st.markdown("<br>", unsafe_allow_html=True)

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
    # QUERY INPUT PROCESSING
    # ---------------------------------------------------------
    query_to_run = None

    # Check if demo button was clicked
    if 'pending_query' in st.session_state and st.session_state['pending_query']:
        query_to_run = st.session_state.pop('pending_query')

    # Chat input field
    user_input = st.chat_input("Ask AI Investigator a natural language security question...")
    if user_input:
        query_to_run = user_input

    if query_to_run:
        # Append User Message to Chat History
        st.session_state['ai_chat_history'].append({"role": "user", "content": query_to_run})

        with st.chat_message("user"):
            st.markdown(query_to_run)

        # Execute Agentic Investigation Pipeline
        with st.chat_message("assistant"):
            with st.spinner("🤖 Agent analyzing request ➔ resolving entities ➔ querying deterministic tools ➔ building evidence package..."):
                # Ensure active agent provider matches selected UI provider
                agent.set_provider(st.session_state['selected_provider_type'])
                response = agent.query(query_to_run)

            # Display Answer Text
            st.markdown(response["answer"])

            # Display Plotly Figure if generated
            if response.get("figure") is not None:
                st.plotly_chart(response["figure"], use_container_width=True)

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
