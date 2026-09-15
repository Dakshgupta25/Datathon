"""
TraceONE — AI Investigator Module UI
Phase M: Agentic Graph AI / AI Investigator Interface
Renders evidence-first natural language investigation interface backed by Qwen3:8B / Ollama and TraceONE tools.
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


def render_ai_investigator():
    """Render the TRACEONE AI Investigator UI Module."""

    # ---------------------------------------------------------
    # HEADER & TITLE
    # ---------------------------------------------------------
    st.markdown('<div class="traceone-title">🤖 TRACEONE AI INVESTIGATOR</div>', unsafe_allow_html=True)
    st.markdown('<div class="traceone-tagline">Evidence-First Agentic Threat Reasoning & Natural Language Querying (Qwen3:8B)</div>', unsafe_allow_html=True)

    # Initialize Agent in Session State
    if 'ai_agent' not in st.session_state:
        st.session_state['ai_agent'] = TraceONEAgent()
    
    agent: TraceONEAgent = st.session_state['ai_agent']

    # Initialize Chat History
    if 'ai_chat_history' not in st.session_state:
        st.session_state['ai_chat_history'] = []

    # ---------------------------------------------------------
    # STATUS & PROVIDER BANNER
    # ---------------------------------------------------------
    ollama_online = OllamaProvider().check_health()
    provider_name = "Ollama Local Adapter" if ollama_online else "Deterministic Fallback Adapter"
    status_color = "#00E676" if ollama_online else "#FFA500"
    status_text = "ONLINE (qwen3:8b)" if ollama_online else "FALLBACK (Deterministic Summary)"

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, rgba(124,77,255,0.08) 0%, rgba(22,27,34,0.95) 100%); border: 1px solid #7C4DFF; border-radius: 8px; padding: 14px; margin-bottom: 20px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <span class="badge badge-cyan">MODEL: {AIConfig.LLM_MODEL}</span>
                <span class="badge" style="background-color:rgba(124,77,255,0.2); color:#7C4DFF; border:1px solid #7C4DFF;">ENDPOINT: {AIConfig.OLLAMA_BASE_URL}</span>
                <h4 style="color:#7C4DFF !important; margin-top:8px; margin-bottom:2px;">AGENTIC THREAT REASONING ENGINE</h4>
                <p style="font-size:0.85rem; color:#C9D1D9; margin:0;">
                    <b>Core Policy:</b> <i>"No claim without evidence."</i> Qwen3:8B orchestrates queries and synthesizes explanations. TraceONE deterministic tools remain the sole source of truth.
                </p>
            </div>
            <div style="text-align:right; min-width:160px;">
                <div style="font-size:1.1rem; font-weight:700; color:{status_color};">{status_text}</div>
                <div style="font-size:0.75rem; color:#8B949E; text-transform:uppercase;">{provider_name}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ---------------------------------------------------------
    # DEMO QUERY SHORTCUTS (TEST 1 - TEST 8)
    # ---------------------------------------------------------
    st.markdown("#### ⚡ Pre-Configured Demo Investigation Queries (Phase M Acceptance Tests)")
    
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
                with st.expander("🔍 Observability Pipeline Trace (Plan ➔ Tools ➔ Evidence ➔ Provenance)", expanded=False):
                    trace = msg["trace"]
                    t_col1, t_col2, t_col3 = st.columns(3)
                    with t_col1:
                        st.markdown(f"**Intent:** `{trace['plan'].get('intent')}`")
                        st.markdown(f"**Entity ID:** `{trace['plan'].get('entity_id')}`")
                    with t_col2:
                        st.markdown(f"**Tools Executed:** `{', '.join(trace['plan'].get('tools', []))}`")
                        st.markdown(f"**Visualization:** `{trace.get('visualization_type')}`")
                    with t_col3:
                        st.markdown(f"**Execution Time:** `{trace.get('execution_time_sec')}s`")
                        st.markdown(f"**LLM Provider:** `{trace.get('llm_provider')}`")

                    st.markdown("---")
                    st.markdown("**Structured Plan JSON:**")
                    st.json(trace['plan'])

                    st.markdown("**Evidence Package Summary:**")
                    st.json(trace['evidence_package'])

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
                response = agent.query(query_to_run)

            # Display Answer Text
            st.markdown(response["answer"])

            # Display Plotly Figure if generated
            if response.get("figure") is not None:
                st.plotly_chart(response["figure"], use_container_width=True)

            # Display Observability Trace Expander
            with st.expander("🔍 Observability Pipeline Trace (Plan ➔ Tools ➔ Evidence ➔ Provenance)", expanded=True):
                t_col1, t_col2, t_col3 = st.columns(3)
                with t_col1:
                    st.markdown(f"**Intent:** `{response['plan'].get('intent')}`")
                    st.markdown(f"**Resolved Entity:** `{response['plan'].get('entity_id')}`")
                with t_col2:
                    st.markdown(f"**Tools Executed:** `{', '.join(response['plan'].get('tools', []))}`")
                    st.markdown(f"**Visualization Type:** `{response.get('visualization_type')}`")
                with t_col3:
                    st.markdown(f"**Execution Time:** `{response.get('execution_time_sec')}s`")
                    st.markdown(f"**LLM Provider:** `{response.get('llm_provider')}`")

                st.markdown("---")
                st.markdown("**Structured Query Plan (Generated by Qwen3/Planner):**")
                st.json(response["plan"])

                st.markdown("**Retrieved Deterministic Evidence Package:**")
                st.json(response["evidence_package"])

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
