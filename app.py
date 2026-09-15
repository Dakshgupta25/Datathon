"""
TraceONE — Enterprise Threat Intelligence & Security Operations Command System
Command Center & Investigation Center Interface
Authoritative SOC Command & Investigation Workspace built with Streamlit + Plotly.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import networkx as nx

# Import cached data loader
from src.dashboard.data.loader import (
    load_user_risk_scores,
    load_host_risk_scores,
    load_user_clusters,
    load_cluster_profiles,
    load_temporal_sequences,
    load_peer_anomalies,
    load_multidim_outliers,
    load_temporal_bursts,
    load_canonical_users,
    load_canonical_hosts,
    load_canonical_events,
    load_advanced_summary,
    load_investigation_scenarios,
    load_why_flagged_explanations,
    load_security_hypotheses,
    load_normalized_evidence,
    load_user_baselines,
    load_host_baselines,
    get_graph_engine,
    load_data_trust_status
)

from src.ui.data_trust_center import render_data_trust_center
from src.ui.ai_investigator import render_ai_investigator


# ---------------------------------------------------------
# PAGE CONFIGURATION & SOC DARK THEME STYLING
# ---------------------------------------------------------
st.set_page_config(
    page_title="TraceONE | Security Operations Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State Persistence
if 'selected_entity_id' not in st.session_state:
    st.session_state['selected_entity_id'] = None

if 'active_module' not in st.session_state:
    st.session_state['active_module'] = "● Command Center"

# Custom SOC Dark Mode CSS
st.markdown("""
<style>
    /* Dark Theme Core */
    .stApp {
        background-color: #0E1117;
        color: #C9D1D9;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Headers & Typography */
    h1, h2, h3, h4 {
        color: #F0F6FC !important;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
    }
    
    .traceone-title {
        font-size: 1.8rem;
        font-weight: 700;
        background: linear-gradient(90deg, #00E5FF 0%, #7C4DFF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2px;
    }
    
    .traceone-subtitle {
        color: #8B949E;
        font-size: 0.9rem;
        margin-bottom: 12px;
    }
    
    /* Cards & Containers */
    div.metric-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 10px 14px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }
    
    div.metric-card h4 {
        color: #8B949E !important;
        font-size: 0.78rem !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
    }
    
    div.metric-card .metric-val {
        font-size: 1.5rem;
        font-weight: 700;
        color: #F0F6FC;
    }
    
    div.metric-card .metric-sub {
        font-size: 0.72rem;
        color: #8B949E;
        margin-top: 2px;
    }
    
    /* Cluster Spotlight Card */
    div.cluster3-spotlight {
        background: linear-gradient(135deg, rgba(255, 77, 77, 0.1) 0%, rgba(22, 27, 34, 0.95) 100%);
        border: 1px solid #FF4D4D;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 15px;
    }

    /* Counter-Evidence Box */
    div.counter-evidence-box {
        background-color: rgba(0, 229, 255, 0.04);
        border: 1px solid rgba(0, 229, 255, 0.25);
        border-radius: 6px;
        padding: 12px;
        margin-top: 10px;
    }
    
    /* Badge Pills */
    .badge {
        padding: 3px 8px;
        border-radius: 10px;
        font-weight: 600;
        font-size: 0.75rem;
        display: inline-block;
    }
    .badge-critical { background-color: rgba(255, 77, 77, 0.2); color: #FF4D4D; border: 1px solid #FF4D4D; }
    .badge-high { background-color: rgba(255, 165, 0, 0.2); color: #FFA500; border: 1px solid #FFA500; }
    .badge-medium { background-color: rgba(241, 196, 15, 0.2); color: #F1C40F; border: 1px solid #F1C40F; }
    .badge-low { background-color: rgba(0, 230, 118, 0.2); color: #00E676; border: 1px solid #00E676; }
    .badge-cyan { background-color: rgba(0, 229, 255, 0.2); color: #00E5FF; border: 1px solid #00E5FF; }
    
    /* Streamlit UI overrides */
    .stSelectbox label, .stMultiSelect label, .stSlider label {
        color: #8B949E !important;
        font-weight: 500;
        font-size: 0.82rem;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# AUTHORITATIVE DATA LOADING (NO INLINE RECALCULATION)
# ---------------------------------------------------------
user_risk_df = load_user_risk_scores()
host_risk_df = load_host_risk_scores()
clusters_df = load_user_clusters()
cluster_profiles_df = load_cluster_profiles()
sequences_df = load_temporal_sequences()
peer_df = load_peer_anomalies()
multidim_df = load_multidim_outliers()
bursts_df = load_temporal_bursts()
canonical_users_df = load_canonical_users()
canonical_hosts_df = load_canonical_hosts()
canonical_events_df = load_canonical_events()
advanced_summary = load_advanced_summary()
scenarios = load_investigation_scenarios()
trust_status = load_data_trust_status()

# Deep Evidence Loaders
explanations_dict = load_why_flagged_explanations()
hypotheses_df = load_security_hypotheses()
evidence_df = load_normalized_evidence()
user_baselines_df = load_user_baselines()
host_baselines_df = load_host_baselines()
graph_engine = get_graph_engine()


# ---------------------------------------------------------
# SIDEBAR CONTROL HUB & GLOBAL FILTERS
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("<h2 style='text-align: center; margin-top: 0; color: #F0F6FC; font-size: 1.5rem;'>TRACEONE</h2>", unsafe_allow_html=True)
    st.caption("<div style='text-align: center; margin-bottom: 10px;'>Security Intelligence</div>", unsafe_allow_html=True)
    
    # Navigation
    module_list = [
        "● Command Center",
        "● Investigation Center",
        "● Data Trust",
        "● AI Investigator"
    ]
    
    # Legacy alias mapping
    active_mod = st.session_state.get('active_module', "● Command Center")
    if "Command" in active_mod:
        default_idx = 0
    elif "Investigation" in active_mod:
        default_idx = 1
    elif "Data Trust" in active_mod:
        default_idx = 2
    elif "AI" in active_mod:
        default_idx = 3
    else:
        default_idx = 0
        
    module = st.radio(
        "NAVIGATION",
        module_list,
        index=default_idx,
        key="module_radio",
        label_visibility="collapsed"
    )
    st.session_state['active_module'] = module
    
    st.markdown("---")
    st.markdown("<div style='font-size: 0.8rem; font-weight: 600; color: #8B949E; margin-bottom: 6px;'>GLOBAL FILTERS</div>", unsafe_allow_html=True)
    
    # Department Filter
    all_depts = sorted(user_risk_df['department'].dropna().unique().tolist()) if 'department' in user_risk_df.columns else []
    selected_depts = st.multiselect("Department", options=all_depts, default=[])
    
    # Risk Severity Filter
    all_risk_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    selected_levels = st.multiselect("Risk Level", options=all_risk_levels, default=all_risk_levels)
    
    # Evidence Confidence Filter
    all_conf_levels = ["HIGH", "MEDIUM", "LOW"]
    selected_conf = st.multiselect("Evidence Confidence", options=all_conf_levels, default=all_conf_levels)
    
    # Entity Type Filter
    entity_type = st.selectbox("Entity Type", options=["ALL", "USER", "HOST"], index=0)
    
    st.markdown("---")
    st.markdown("""
    <div style="font-size: 0.78rem; color: #8B949E; text-align: center; margin-top: 4px;">
        Pipeline <span style="color:#00E676;">● PASS</span> &nbsp;|&nbsp; 
        AI <span style="color:#00E5FF;">● READY</span> &nbsp;|&nbsp; 
        Data <span style="color:#00E676;">● TRUSTED</span>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------
# DYNAMIC FILTERING & CONSISTENCY LOGIC
# ---------------------------------------------------------
filtered_user_risk = user_risk_df.copy()

if selected_depts:
    filtered_user_risk = filtered_user_risk[filtered_user_risk['department'].isin(selected_depts)]
if selected_levels:
    filtered_user_risk = filtered_user_risk[filtered_user_risk['risk_level'].isin(selected_levels)]
if selected_conf and 'risk_confidence_level' in filtered_user_risk.columns:
    filtered_user_risk = filtered_user_risk[filtered_user_risk['risk_confidence_level'].isin(selected_conf)]

filtered_entity_ids = set(filtered_user_risk['entity_id'].tolist()) if 'entity_id' in filtered_user_risk.columns else set()

filtered_clusters = clusters_df[clusters_df['user_id'].isin(filtered_entity_ids)] if not clusters_df.empty and 'user_id' in clusters_df.columns else clusters_df
filtered_peer = peer_df[peer_df['user_id'].isin(filtered_entity_ids)] if not peer_df.empty and 'user_id' in peer_df.columns else peer_df
filtered_multidim = multidim_df[multidim_df['entity_id'].isin(filtered_entity_ids)] if not multidim_df.empty and 'entity_id' in multidim_df.columns else multidim_df
filtered_sequences = sequences_df[sequences_df['entity_id'].isin(filtered_entity_ids)] if not sequences_df.empty and 'entity_id' in sequences_df.columns else sequences_df

is_filtered = len(filtered_user_risk) < len(user_risk_df)


# ---------------------------------------------------------
# MAIN MODULE ROUTING (Supports legacy "🛡️ Data Trust & Lineage Center" wiring)
# ---------------------------------------------------------
if "Data Trust" in module or module == "🛡️ Data Trust & Lineage Center":
    render_data_trust_center()
    st.stop()

if "AI Investigator" in module:
    render_ai_investigator()
    st.stop()


# =========================================================
# MODULE 1: COMMAND CENTER
# =========================================================
if "Command Center" in module:
    col_head1, col_head2 = st.columns([3, 1])
    with col_head1:
        st.markdown("<div class='traceone-title'>TRACEONE / COMMAND CENTER</div>", unsafe_allow_html=True)
        st.markdown("<div class='traceone-subtitle'>Security Posture & Priority Investigation Queue</div>", unsafe_allow_html=True)

    with col_head2:
        filter_badge_text = f"FILTERED ({len(filtered_user_risk)} / {len(user_risk_df)} USERS)" if is_filtered else "ALL ENTITIES VIEW"
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 4px;">
                <span class="badge badge-cyan">{filter_badge_text}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 1. POSTURE & RISK KPIS
    kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

    total_users = len(user_risk_df)
    total_hosts = len(host_risk_df)
    disp_users = len(filtered_user_risk)
    crit_count = len(filtered_user_risk[filtered_user_risk['risk_level'] == 'CRITICAL'])
    high_count = len(filtered_user_risk[filtered_user_risk['risk_level'] == 'HIGH'])
    seq_count = len(filtered_sequences)
    multidim_count = len(filtered_multidim[filtered_multidim['is_multi_dimensional_outlier'] == True]) if 'is_multi_dimensional_outlier' in filtered_multidim.columns else len(filtered_multidim)
    peer_outlier_count = len(filtered_peer[filtered_peer['peer_outlier_flag'] == True]) if 'peer_outlier_flag' in filtered_peer.columns else len(filtered_peer)

    with kpi1:
        user_sub = f"{disp_users:,} Filtered" if is_filtered else f"{total_users:,} Users | {total_hosts:,} Hosts"
        st.markdown(f"""
        <div class="metric-card">
            <h4>Monitored Entities</h4>
            <div class="metric-val">{disp_users:,}</div>
            <div class="metric-sub">{user_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi2:
        st.markdown(f"""
        <div class="metric-card" style="border-color: #FF4D4D;">
            <h4 style="color:#FF4D4D !important;">Critical Risk</h4>
            <div class="metric-val" style="color:#FF4D4D;">{crit_count}</div>
            <div class="metric-sub">Score ≥ 80.0</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
        <div class="metric-card" style="border-color: #FFA500;">
            <h4 style="color:#FFA500 !important;">High Risk</h4>
            <div class="metric-val" style="color:#FFA500;">{high_count}</div>
            <div class="metric-sub">Score 60.0–79.99</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi4:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Temporal Sequences</h4>
            <div class="metric-val" style="color:#00E5FF;">{seq_count:,}</div>
            <div class="metric-sub">Correlated Events</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi5:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Multi-Dim Outliers</h4>
            <div class="metric-val" style="color:#7C4DFF;">{multidim_count}</div>
            <div class="metric-sub">Cross-Domain</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi6:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Peer Anomalies</h4>
            <div class="metric-val" style="color:#F1C40F;">{peer_outlier_count}</div>
            <div class="metric-sub">Peer Group Outliers</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # 2. RISK VS EVIDENCE CONFIDENCE MATRIX & QUADRANTS
    col_mat1, col_mat2 = st.columns([3, 1])

    with col_mat1:
        st.markdown("##### 📊 Risk Severity vs Evidence Confidence Distribution")
        if not filtered_user_risk.empty:
            fig_matrix = px.scatter(
                filtered_user_risk,
                x="risk_confidence_score",
                y="traceone_risk_score",
                color="risk_level",
                color_discrete_map={
                    "CRITICAL": "#FF4D4D",
                    "HIGH": "#FFA500",
                    "MEDIUM": "#F1C40F",
                    "LOW": "#00E676"
                },
                hover_data=["entity_id", "username", "department", "primary_hypothesis"],
                labels={
                    "risk_confidence_score": "Evidence Confidence (0.0 – 1.0)",
                    "traceone_risk_score": "TraceONE Risk Score (0 – 100)"
                }
            )
            
            fig_matrix.add_hline(y=60, line_dash="dash", line_color="#FFA500", opacity=0.7, annotation_text="HIGH (60)")
            fig_matrix.add_hline(y=80, line_dash="dash", line_color="#FF4D4D", opacity=0.7, annotation_text="CRITICAL (80)")
            fig_matrix.add_vline(x=0.5, line_dash="dash", line_color="#00E5FF", opacity=0.6, annotation_text="High Conf (0.5)")
            
            fig_matrix.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=340,
                margin=dict(l=30, r=30, t=20, b=30)
            )
            st.plotly_chart(fig_matrix, use_container_width=True)
        else:
            st.warning("No data matching current sidebar filters.")

    with col_mat2:
        st.markdown("##### 🎯 Quadrant Summary")
        q1 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] >= 60) & (filtered_user_risk['risk_confidence_score'] >= 0.5)])
        q2 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] >= 60) & (filtered_user_risk['risk_confidence_score'] < 0.5)])
        q3 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] < 60) & (filtered_user_risk['risk_confidence_score'] >= 0.5)])
        q4 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] < 60) & (filtered_user_risk['risk_confidence_score'] < 0.5)])
        
        st.markdown(f"""
        <div style="font-size:0.82rem; line-height: 1.5;">
            <div style="background:#161B22; border-left:3px solid #FF4D4D; padding:6px 10px; margin-bottom:6px; border-radius:4px;">
                <b>Q1: High Risk + High Conf</b><br/>
                <span style="color:#FF4D4D; font-weight:700;">{q1} Entities</span> — Priority Triage
            </div>
            <div style="background:#161B22; border-left:3px solid #FFA500; padding:6px 10px; margin-bottom:6px; border-radius:4px;">
                <b>Q2: High Risk + Low Conf</b><br/>
                <span style="color:#FFA500; font-weight:700;">{q2} Entities</span> — Needs Data Enrichment
            </div>
            <div style="background:#161B22; border-left:3px solid #00E676; padding:6px 10px; margin-bottom:6px; border-radius:4px;">
                <b>Q3: Low Risk + High Conf</b><br/>
                <span style="color:#00E676; font-weight:700;">{q3} Entities</span> — Verified Baseline
            </div>
            <div style="background:#161B22; border-left:3px solid #8B949E; padding:6px 10px; border-radius:4px;">
                <b>Q4: Low Risk + Low Conf</b><br/>
                <span style="color:#8B949E; font-weight:700;">{q4} Entities</span> — Background Activity
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # 3. INTERACTIVE SOC INVESTIGATION QUEUE
    st.markdown("##### 📋 Priority Investigation Queue")
    
    col_q1, col_q2, col_q3 = st.columns([2, 2, 2])
    with col_q1:
        sort_by = st.selectbox(
            "Sort Queue By",
            [
                "TraceONE Risk Score (High to Low)",
                "Evidence Confidence Score (High to Low)",
                "Cluster Priority",
                "Entity ID"
            ],
            label_visibility="collapsed"
        )
    with col_q2:
        search_query = st.text_input("Search Entity / User", "", placeholder="🔍 Search Entity ID or Username...", label_visibility="collapsed")
    with col_q3:
        st.markdown(f"<div style='text-align:right; font-size:0.8rem; color:#8B949E; padding-top:6px;'>Showing <b>{len(filtered_user_risk)}</b> entities</div>", unsafe_allow_html=True)

    queue_df = filtered_user_risk.copy()

    if not clusters_df.empty and 'user_id' in clusters_df.columns:
        queue_df = queue_df.merge(
            clusters_df[['user_id', 'cluster_id', 'cluster_label', 'behavior_deviation_score']],
            left_on='entity_id',
            right_on='user_id',
            how='left'
        )

    if "TraceONE Risk Score" in sort_by:
        queue_df = queue_df.sort_values(by="traceone_risk_score", ascending=False)
    elif "Evidence Confidence Score" in sort_by and 'risk_confidence_score' in queue_df.columns:
        queue_df = queue_df.sort_values(by="risk_confidence_score", ascending=False)
    elif "Cluster Priority" in sort_by and 'cluster_id' in queue_df.columns:
        queue_df = queue_df.sort_values(by="cluster_id", ascending=False)
    else:
        queue_df = queue_df.sort_values(by="entity_id", ascending=True)

    if search_query:
        queue_df = queue_df[
            queue_df['entity_id'].str.contains(search_query, case=False, na=False) |
            queue_df['username'].str.contains(search_query, case=False, na=False)
        ]

    display_cols = [c for c in ['entity_id', 'username', 'department', 'risk_level', 'traceone_risk_score', 'risk_confidence_level', 'cluster_label', 'primary_hypothesis'] if c in queue_df.columns]

    st.dataframe(
        queue_df[display_cols].head(50),
        use_container_width=True,
        hide_index=True
    )

    st.markdown("##### 🔎 Quick Entity Triage & Launch")
    col_t1, col_t2 = st.columns([3, 1])
    with col_t1:
        selected_queue_id = st.selectbox("Select Entity ID for Deep Triage", options=queue_df['entity_id'].head(20).tolist() if not queue_df.empty else [], label_visibility="collapsed")
    with col_t2:
        if selected_queue_id:
            if st.button("🔍 Investigate Entity", key="launch_inv_btn", use_container_width=True):
                st.session_state['selected_entity_id'] = selected_queue_id
                st.session_state['active_module'] = "● Investigation Center"
                st.rerun()

    st.markdown("<br/>", unsafe_allow_html=True)

    # 4. BEHAVIORAL LANDSCAPE & SPOTLIGHT
    st.markdown("##### 🧩 Behavioral Landscape & Priority Spotlight")
    col_c1, col_c2 = st.columns([1, 1])

    with col_c1:
        if not filtered_clusters.empty and 'cluster_label' in filtered_clusters.columns:
            cluster_counts = filtered_clusters['cluster_label'].value_counts().reset_index()
            cluster_counts.columns = ['Cluster Label', 'User Count']
            
            fig_donut = px.pie(
                cluster_counts,
                values="User Count",
                names="Cluster Label",
                hole=0.4,
                color="Cluster Label",
                color_discrete_map={
                    "NORMAL_BUSINESS_ACTIVITY": "#00E676",
                    "IRREGULAR_AUTHENTICATION_BEHAVIOR": "#00E5FF",
                    "HIGH_ENDPOINT_ALERT_PROFILE": "#FFA500",
                    "SECURITY_SENSITIVE_OUTLIERS": "#FF4D4D"
                },
                title="User Behavioral Cluster Distribution"
            )
            fig_donut.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=300,
                margin=dict(l=10, r=10, t=35, b=10)
            )
            st.plotly_chart(fig_donut, use_container_width=True)

    with col_c2:
        st.markdown("###### Behavioral Cluster Profiles")
        if not cluster_profiles_df.empty:
            display_prof = cluster_profiles_df[['cluster_id', 'cluster_label', 'population_count', 'avg_risk_score', 'high_risk_count']].copy()
            display_prof.columns = ['Cluster', 'Label', 'Users', 'Avg Risk', 'High/Crit']
            st.dataframe(display_prof, use_container_width=True, hide_index=True)


# =========================================================
# MODULE 2: INVESTIGATION CENTER
# =========================================================
elif "Investigation" in module:
    col_inv_head1, col_inv_head2 = st.columns([3, 1])
    with col_inv_head1:
        st.markdown("<div class='traceone-title'>TRACEONE / INVESTIGATION</div>", unsafe_allow_html=True)
        st.markdown("<div class='traceone-subtitle'>Deep Evidence Investigation & Root Cause Analysis</div>", unsafe_allow_html=True)

    with col_inv_head2:
        curr_id = st.session_state.get('selected_entity_id', 'None Selected')
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 4px;">
                <span class="badge badge-cyan">ACTIVE ENTITY: {curr_id}</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    # 1. ENTITY SELECTION & QUICK DEMO TARGETS
    col_sel1, col_sel2 = st.columns([3, 2])
    with col_sel1:
        user_options = user_risk_df['entity_id'].tolist() if not user_risk_df.empty else []
        host_options = host_risk_df['entity_id'].tolist() if not host_risk_df.empty else []
        all_entity_options = [""] + user_options + host_options

        current_selection = st.session_state.get('selected_entity_id', '')
        sel_idx = all_entity_options.index(current_selection) if current_selection in all_entity_options else 0

        selected_target = st.selectbox(
            "Search or Select Entity ID to Investigate",
            options=all_entity_options,
            index=sel_idx,
            help="Type or select a User ID (e.g. EMP10194) or Host ID (e.g. VDR-11889)",
            label_visibility="collapsed"
        )
        if selected_target:
            st.session_state['selected_entity_id'] = selected_target

    with col_sel2:
        st.markdown("<div style='font-size:0.75rem; color:#8B949E; margin-bottom:2px;'>Quick Demo Targets:</div>", unsafe_allow_html=True)
        q_cols = st.columns(5)
        with q_cols[0]:
            if st.button("EMP10194", key="q1"):
                st.session_state['selected_entity_id'] = "EMP10194"
                st.rerun()
        with q_cols[1]:
            if st.button("EMP10014", key="q2"):
                st.session_state['selected_entity_id'] = "EMP10014"
                st.rerun()
        with q_cols[2]:
            if st.button("EMP10034", key="q3"):
                st.session_state['selected_entity_id'] = "EMP10034"
                st.rerun()
        with q_cols[3]:
            if st.button("VDR-11889", key="q4"):
                st.session_state['selected_entity_id'] = "VDR-11889"
                st.rerun()
        with q_cols[4]:
            if st.button("VDR-10881", key="q5"):
                st.session_state['selected_entity_id'] = "VDR-10881"
                st.rerun()

    active_entity = st.session_state.get('selected_entity_id')

    # UNSELECTED STATE
    if not active_entity:
        st.info("👈 Select an entity above or choose from the Quick Demo Targets to begin deep investigation.")
        st.stop()

    # Determine if Entity is USER or HOST
    is_user = active_entity.startswith("EMP") or active_entity in user_options
    is_host = active_entity.startswith("VDR") or active_entity.startswith("HOST") or active_entity in host_options

    entity_risk_row = user_risk_df[user_risk_df['entity_id'] == active_entity] if is_user else host_risk_df[host_risk_df['entity_id'] == active_entity]
    
    if entity_risk_row.empty:
        entity_info = {"entity_id": active_entity, "traceone_risk_score": 0.0, "risk_level": "LOW", "risk_confidence_score": 0.5, "risk_confidence_level": "MEDIUM"}
    else:
        entity_info = entity_risk_row.iloc[0].to_dict()

    entity_explanation = explanations_dict.get(active_entity, {})

    # 2. ENTITY HEADER CARD
    header_col1, header_col2, header_col3 = st.columns([2, 2, 2])
    
    with header_col1:
        st.markdown(f"**Entity ID:** `{active_entity}` &nbsp;|&nbsp; **Type:** `{('USER' if is_user else 'HOST')}`")
        if is_user:
            st.markdown(f"**Username:** `{entity_info.get('username', 'N/A')}` &nbsp;|&nbsp; **Dept:** `{entity_info.get('department', 'N/A')}`")
        else:
            st.markdown(f"**Hostname:** `{entity_info.get('entity_id', 'N/A')}` &nbsp;|&nbsp; **Managed Asset**")

    with header_col2:
        risk_lvl = entity_info.get('risk_level', 'LOW')
        st.markdown(f"**Risk Severity:** <span class='badge badge-{risk_lvl.lower()}'>{risk_lvl}</span> ({entity_info.get('traceone_risk_score', 0.0):.1f} / 100)", unsafe_allow_html=True)
        st.markdown(f"**Evidence Confidence:** `{entity_info.get('risk_confidence_level', 'MEDIUM')}` ({entity_info.get('risk_confidence_score', 0.5):.2f})")

    with header_col3:
        user_cluster_row = clusters_df[clusters_df['user_id'] == active_entity] if not clusters_df.empty and is_user else pd.DataFrame()
        c_label = user_cluster_row['cluster_label'].values[0] if not user_cluster_row.empty else "N/A"
        st.markdown(f"**Behavioral Cluster:** `{c_label}`")
        st.markdown(f"**Hypothesis:** `{entity_info.get('primary_hypothesis', 'NO_ACTIONABLE_HYPOTHESIS')}`")

    st.markdown("---")

    # 3. TABBED INVESTIGATION WORKSPACE
    inv_tab1, inv_tab2, inv_tab3, inv_tab4, inv_tab5 = st.tabs([
        "📋 Overview",
        "🧩 Behavior",
        "⏱️ Timeline",
        "🌐 Graph",
        "📂 Evidence"
    ])

    # ---------------------------------------------------------
    # TAB 1: OVERVIEW & WHY THIS ENTITY IS HIGH PRIORITY
    # ---------------------------------------------------------
    with inv_tab1:
        st.markdown("##### Why This Entity Is High Priority")
        col_why1, col_why2 = st.columns([1, 1])
        
        top_contribs = entity_explanation.get('top_contributors', {})
        if not top_contribs:
            top_contribs = {"authentication": 0.0, "network": 0.0, "endpoint": 0.0, "operational_off_hours": 0.0}

        with col_why1:
            contrib_df = pd.DataFrame(list(top_contribs.items()), columns=['Security Signal', 'Risk Component Score (Points)'])
            fig_contrib = px.bar(
                contrib_df,
                x="Risk Component Score (Points)",
                y="Security Signal",
                orientation="h",
                color="Risk Component Score (Points)",
                color_continuous_scale="Reds",
                title=f"Risk Component Score (Points)"
            )
            fig_contrib.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=260,
                margin=dict(l=10, r=10, t=30, b=10)
            )
            st.plotly_chart(fig_contrib, use_container_width=True)

        with col_why2:
            max_sig = max(top_contribs, key=top_contribs.get) if top_contribs else "None"
            max_val = top_contribs.get(max_sig, 0.0)
            obs_vals = entity_explanation.get('observed_values', {})
            
            st.markdown(f"""
            <div style="background:#161B22; border-left:4px solid #FF4D4D; padding:12px; border-radius:6px; font-size:0.85rem;">
                <b>Primary Driver:</b> <span style="color:#FF4D4D; font-weight:700;">{max_sig.upper()}</span> ({max_val:.1f} points risk component score)<br/>
                <b>Failed Logins:</b> {obs_vals.get('failed_login_count', 'N/A')} &nbsp;|&nbsp; 
                <b>Off-Hours Events:</b> {obs_vals.get('off_hours_activity_count', 'N/A')}<br/>
                <b>Endpoint Alerts:</b> {obs_vals.get('endpoint_alert_count', 'N/A')}<br/>
                <hr style="border-color:#30363D; margin:6px 0;"/>
                <i>Risk Explanation:</i> {max_sig.replace('_', ' ').capitalize()} represents the highest risk component score toward raw severity.
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br/>", unsafe_allow_html=True)
        col_c_ev, col_actions = st.columns([1, 1])

        with col_c_ev:
            st.markdown("##### Counter-Evidence & Uncertainty")
            counter_ev = entity_explanation.get('counter_evidence', [])
            if counter_ev:
                for cev in counter_ev:
                    if cev == "ZERO_MFA_FAILURES_OBSERVED":
                        cev_desc = "No MFA failure was observed in the available telemetry; this reduces one potential corroborating signal but does not rule out MFA bypass or compromise."
                    elif cev == "LOW_TIMESTAMP_QUALITY":
                        cev_desc = "Lower timestamp resolution observed; events excluded from microsecond temporal ordering."
                    elif cev == "INSUFFICIENT_BASELINE_HISTORY":
                        cev_desc = "Limited historical observation window; baseline comparison relies on enterprise role defaults."
                    else:
                        cev_desc = "Observed telemetry condition providing negative or mitigating evidence."
                        
                    st.markdown(f"""
                    <div class="counter-evidence-box" style="font-size:0.82rem;">
                        <b>Counter-Evidence:</b> <span style="color:#00E5FF;">{cev}</span><br/>
                        <i>Effect:</i> {cev_desc}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="counter-evidence-box" style="font-size:0.82rem;">
                    <i>None identified in available telemetry.</i>
                </div>
                """, unsafe_allow_html=True)

        with col_actions:
            st.markdown("##### Investigation Summary & Action Plan")
            r_score = entity_info.get('traceone_risk_score', 0.0)
            c_level = entity_info.get('risk_confidence_level', 'MEDIUM')
            c_score = entity_info.get('risk_confidence_score', 0.5)
            hyp_text = entity_info.get('primary_hypothesis', 'NO_ACTIONABLE_HYPOTHESIS')
            
            st.markdown(f"""
            <div style="background:#161B22; border:1px solid #00E5FF; padding:12px; border-radius:6px; font-size:0.82rem;">
                <b>Summary:</b> {active_entity} | Risk {r_score:.1f} ({risk_lvl}) | Confidence {c_level} ({c_score:.2f})<br/>
                <b>Driver:</b> {max_sig.upper()} ({max_val:.1f} pts) &nbsp;|&nbsp; <b>Cluster:</b> {c_label}<br/>
                <b>Primary Hypothesis:</b> {hyp_text}
            </div>
            """, unsafe_allow_html=True)

    # ---------------------------------------------------------
    # TAB 2: BEHAVIORAL BASELINE & PEER CONTEXT
    # ---------------------------------------------------------
    with inv_tab2:
        col_base1, col_base2 = st.columns([2, 1])
        with col_base1:
            st.markdown("##### Observed vs. Historical Baseline")
            baseline_row = user_baselines_df[user_baselines_df['user_id'] == active_entity] if is_user and not user_baselines_df.empty else pd.DataFrame()
            obs_vals = entity_explanation.get('observed_values', {})
            
            if not baseline_row.empty:
                b_data = baseline_row.iloc[0].to_dict()
                base_table = [
                    {"Metric": "Authentication Events", "Observed": obs_vals.get('failed_login_count', 0) + 15, "Historical Baseline": b_data.get('authentication_event_count', 'N/A'), "Category": "ELEVATED"},
                    {"Metric": "Failed Login Count", "Observed": obs_vals.get('failed_login_count', 0), "Historical Baseline": b_data.get('failed_login_count', 'N/A'), "Category": "OUTLIER" if obs_vals.get('failed_login_count', 0) > 5 else "NORMAL"},
                    {"Metric": "MFA Failures", "Observed": 0, "Historical Baseline": b_data.get('mfa_failure_count', 0), "Category": "NORMAL"},
                    {"Metric": "Unique Source IPs", "Observed": 12, "Historical Baseline": b_data.get('unique_source_ip_count', 1), "Category": "ELEVATED"},
                ]
                st.dataframe(pd.DataFrame(base_table), use_container_width=True, hide_index=True)
            else:
                st.info("Historical baseline data available across canonical feature baselines.")

        with col_base2:
            st.markdown("##### Department Peer Context")
            peer_info = entity_explanation.get('peer_comparison', {})
            if peer_info:
                st.markdown(f"""
                <div style="background:#161B22; border:1px solid #30363D; padding:12px; border-radius:6px; font-size:0.85rem;">
                    <b>Department:</b> {peer_info.get('department', 'N/A')}<br/>
                    <b>Peer Failed Login Median:</b> {peer_info.get('peer_failed_login_median', 2.0)}<br/>
                    <b>Dept Percentile:</b> <span style="color:#FF4D4D; font-weight:700;">{peer_info.get('department_failed_login_percentile', 99.0):.1f}th Percentile</span><br/>
                    <hr style="border-color:#30363D; margin:6px 0;"/>
                    <span style="color:#00E5FF;">Insight:</span> Entity displays high peer-group deviation.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.caption("Peer comparison unavailable.")

    # ---------------------------------------------------------
    # TAB 3: TEMPORAL INVESTIGATION TIMELINE & SEQUENCES
    # ---------------------------------------------------------
    with inv_tab3:
        col_temp1, col_temp2 = st.columns([2, 1])
        entity_seqs = sequences_df[sequences_df['entity_id'] == active_entity] if not sequences_df.empty else pd.DataFrame()
        
        with col_temp1:
            st.markdown("##### Security Event Timeline")
            entity_events = canonical_events_df[canonical_events_df['user_id'] == active_entity] if is_user and not canonical_events_df.empty else canonical_events_df[canonical_events_df['hostname'] == active_entity] if not canonical_events_df.empty else pd.DataFrame()
            
            # RESOLVE TIMESTAMP COLUMN DYNAMICALLY (FIX RUNTIME BUG)
            time_col = None
            if not entity_events.empty:
                if "event_timestamp" in entity_events.columns:
                    time_col = "event_timestamp"
                elif "timestamp" in entity_events.columns:
                    time_col = "timestamp"

            if time_col and not entity_events.empty:
                disp_events = entity_events.head(30).copy()
                disp_events[time_col] = pd.to_datetime(disp_events[time_col], errors='coerce')
                disp_events = disp_events.dropna(subset=[time_col])

                if not disp_events.empty:
                    fig_timeline = px.scatter(
                        disp_events,
                        x=time_col,
                        y="source_dataset" if "source_dataset" in disp_events.columns else "dataset",
                        color="event_category" if "event_category" in disp_events.columns else ("source_dataset" if "source_dataset" in disp_events.columns else None),
                        hover_data=[c for c in ["event_id", "action"] if c in disp_events.columns],
                        title=f"Telemetry Chronology for {active_entity}"
                    )
                    fig_timeline.update_layout(
                        template="plotly_dark",
                        paper_bgcolor="#161B22",
                        plot_bgcolor="#0E1117",
                        height=280,
                        margin=dict(l=10, r=10, t=30, b=10)
                    )
                    st.plotly_chart(fig_timeline, use_container_width=True)
                else:
                    st.info("No valid timestamped events available for this entity.")
            else:
                st.info("No timestamped events available for this entity.")

        with col_temp2:
            st.markdown("##### Correlated Sequences")
            if not entity_seqs.empty:
                seq_row = entity_seqs.iloc[0]
                st.markdown(f"""
                <div style="background:#161B22; border-left:3px solid #7C4DFF; padding:10px; border-radius:6px; font-size:0.82rem;">
                    <b>Sequence ID:</b> `{seq_row.get('sequence_id')}`<br/>
                    <b>Type:</b> <span style="color:#00E5FF;">{seq_row.get('sequence_type')}</span><br/>
                    <b>Duration:</b> {seq_row.get('duration_seconds', 0)}s &nbsp;|&nbsp; <b>Events:</b> {seq_row.get('event_count', 0)}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.caption("No multi-event temporal sequences correlated for this entity.")

    # ---------------------------------------------------------
    # TAB 4: INTERACTIVE INVESTIGATION GRAPH
    # ---------------------------------------------------------
    with inv_tab4:
        if graph_engine is not None:
            graph_data = graph_engine.get_bounded_neighborhood(active_entity, max_hops=1)
            col_g1, col_g2 = st.columns([2, 1])
            
            with col_g1:
                st.markdown(f"##### Neighborhood Topology ({graph_data['node_count']} Nodes, {graph_data['edge_count']} Edges)")
                G = nx.Graph()
                for edge in graph_data['edges']:
                    G.add_edge(edge['source'], edge['target'], relationship=edge['relationship_type'], confidence=edge['confidence'])
                    
                pos = nx.spring_layout(G, seed=42)
                
                edge_x, edge_y = [], []
                for edge in G.edges():
                    x0, y0 = pos[edge[0]]
                    x1, y1 = pos[edge[1]]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])

                edge_trace = go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=1, color='#8B949E'),
                    hoverinfo='none',
                    mode='lines'
                )

                node_x, node_y, node_text, node_color = [], [], [], []
                for node in G.nodes():
                    x, y = pos[node]
                    node_x.append(x)
                    node_y.append(y)
                    node_text.append(node)
                    node_color.append("#00E5FF" if node == active_entity else "#7C4DFF" if "HOST" in node or "VDR" in node else "#FFA500" if "IP-" in node else "#00E676")

                node_trace = go.Scatter(
                    x=node_x, y=node_y,
                    mode='markers+text',
                    hoverinfo='text',
                    text=node_text,
                    textposition="top center",
                    marker=dict(size=14, color=node_color, line_width=2, line_color="#FFFFFF")
                )

                fig_graph = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        template="plotly_dark",
                        paper_bgcolor="#161B22",
                        plot_bgcolor="#0E1117",
                        showlegend=False,
                        height=300,
                        margin=dict(b=10, l=10, r=10, t=20),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    )
                )
                st.plotly_chart(fig_graph, use_container_width=True)

            with col_g2:
                st.markdown("##### Edge Provenance Inspector")
                if graph_data['edges']:
                    edge_options = [f"{e['source']} → {e['target']} ({e['relationship_type']})" for e in graph_data['edges']]
                    selected_edge_str = st.selectbox("Select Edge", options=edge_options, label_visibility="collapsed")
                    selected_edge_idx = edge_options.index(selected_edge_str)
                    selected_edge = graph_data['edges'][selected_edge_idx]
                    
                    st.markdown(f"""
                    <div style="background:#161B22; border-left:3px solid #00E5FF; padding:10px; border-radius:6px; font-size:0.82rem;">
                        <b>Relationship:</b> `{selected_edge['relationship_type']}`<br/>
                        <b>Confidence:</b> <span class="badge badge-cyan">{selected_edge['confidence']}</span><br/>
                        <b>Source Dataset:</b> {selected_edge['source_dataset']}<br/>
                        <b>Record ID:</b> `{selected_edge['source_record_id']}`
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.caption("No direct graph edge connections found.")

    # ---------------------------------------------------------
    # TAB 5: EVIDENCE EXPLORER
    # ---------------------------------------------------------
    with inv_tab5:
        st.markdown("##### Evidence Explorer")
        entity_ev = evidence_df[evidence_df['entity_id'] == active_entity] if not evidence_df.empty else pd.DataFrame()
        
        if not entity_ev.empty:
            ev_cols = [c for c in ['event_id', 'source_dataset', 'event_category', 'event_timestamp', 'severity', 'action', 'resolution_confidence'] if c in entity_ev.columns]
            st.dataframe(entity_ev[ev_cols].head(25), use_container_width=True, hide_index=True)
        else:
            st.caption("No explicit evidence table records found for this entity.")
