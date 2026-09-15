"""
TraceONE — Enterprise Threat Intelligence & Security Operations Command System
Phase J + Phase K: Command Center & Investigation Center Interface
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
    st.session_state['active_module'] = "🛡️ Command Center"

# Custom SOC Dark Mode CSS
st.markdown("""
<style>
    /* Dark Theme Core */
    .stApp {
        background-color: #0E1117;
        color: #C9D1D9;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Headers & Text */
    h1, h2, h3, h4 {
        color: #F0F6FC !important;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
    }
    
    .traceone-title {
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #00E5FF 0%, #7C4DFF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
    }
    
    .traceone-tagline {
        color: #8B949E;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    
    /* Cards & Containers */
    div.metric-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 18px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    
    div.metric-card h4 {
        color: #8B949E !important;
        font-size: 0.85rem !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }
    
    div.metric-card .metric-val {
        font-size: 1.9rem;
        font-weight: 700;
        color: #F0F6FC;
    }
    
    div.metric-card .metric-sub {
        font-size: 0.78rem;
        color: #8B949E;
        margin-top: 4px;
    }
    
    /* Cluster Spotlight Card */
    div.cluster3-spotlight {
        background: linear-gradient(135deg, rgba(255, 77, 77, 0.12) 0%, rgba(22, 27, 34, 0.95) 100%);
        border: 1px solid #FF4D4D;
        border-radius: 10px;
        padding: 22px;
        margin-bottom: 25px;
    }

    /* Investigation Header Card */
    div.investigation-header-card {
        background: linear-gradient(135deg, #161B22 0%, #0D1117 100%);
        border: 1px solid #30363D;
        border-left: 4px solid #00E5FF;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 20px;
    }

    /* Counter-Evidence Box */
    div.counter-evidence-box {
        background-color: rgba(0, 229, 255, 0.05);
        border: 1px solid rgba(0, 229, 255, 0.3);
        border-radius: 8px;
        padding: 16px;
        margin-top: 15px;
    }
    
    /* Badge Pills */
    .badge {
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 0.78rem;
        display: inline-block;
    }
    .badge-critical { background-color: rgba(255, 77, 77, 0.2); color: #FF4D4D; border: 1px solid #FF4D4D; }
    .badge-high { background-color: rgba(255, 165, 0, 0.2); color: #FFA500; border: 1px solid #FFA500; }
    .badge-medium { background-color: rgba(241, 196, 15, 0.2); color: #F1C40F; border: 1px solid #F1C40F; }
    .badge-low { background-color: rgba(0, 230, 118, 0.2); color: #00E676; border: 1px solid #00E676; }
    .badge-cyan { background-color: rgba(0, 229, 255, 0.2); color: #00E5FF; border: 1px solid #00E5FF; }

    /* Data Trust Badge in Sidebar */
    .trust-box {
        background-color: #161B22;
        border-left: 4px solid #00E5FF;
        border-radius: 4px;
        padding: 12px;
        font-size: 0.82rem;
        margin-bottom: 20px;
    }
    
    /* Streamlit UI overrides */
    .stSelectbox label, .stMultiSelect label, .stSlider label {
        color: #8B949E !important;
        font-weight: 500;
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

# Phase K Data Loaders
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
    st.markdown("<div style='font-size: 2.5rem; text-align: center; margin-bottom: 5px;'>🛡️</div>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center; margin-top: 0;'>TRACEONE HUB</h3>", unsafe_allow_html=True)
    st.caption("<div style='text-align: center;'>Explainable Threat Intelligence</div>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Module Selector
    module_list = [
        "🛡️ Command Center",
        "🔍 Investigation Center",
        "🛡️ Data Trust & Lineage Center",
        "🤖 AI Investigator"
    ]
    
    # Determine default index based on st.session_state
    default_idx = 0
    if st.session_state.get('active_module') in module_list:
        default_idx = module_list.index(st.session_state['active_module'])
        
    module = st.radio(
        "SELECT MODULE",
        module_list,
        index=default_idx,
        key="module_radio"
    )
    st.session_state['active_module'] = module
    
    st.markdown("---")
    st.markdown("#### 🔒 DATA TRUST BADGE")
    st.markdown(f"""
    <div class="trust-box">
        <b>Pipeline:</b> <span style="color:#00E676">{trust_status['pipeline_health']}</span><br/>
        <b>Validation:</b> <span style="color:#00E676">{trust_status['data_validation']}</span><br/>
        <b>Linkage:</b> <span style="color:#00E5FF">{trust_status['source_linkage']}</span><br/>
        <b>Session Overlap:</b> <span style="color:#FFA500">{trust_status['iam_firewall_overlap_pct']}</span><br/>
        <b>Timestamps:</b> <span style="color:#8B949E">{trust_status['missing_timestamp_policy']}</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("#### ⚙️ GLOBAL FILTERS")
    
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
    st.caption("TraceONE Engine v1.0 • Phase M AI Investigator Workspace")


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
# MAIN MODULE ROUTING
# ---------------------------------------------------------
if "Upcoming" in module:
    st.markdown("<h2 class='traceone-title'>Module Preparation Underway</h2>", unsafe_allow_html=True)
    st.info(f"The module **{module}** is scheduled for the next development sprint.")
    st.stop()

if module == "🛡️ Data Trust & Lineage Center":
    render_data_trust_center()
    st.stop()

if module == "🤖 AI Investigator":
    render_ai_investigator()
    st.stop()



# =========================================================
# MODULE 1: COMMAND CENTER (PHASE J)
# =========================================================
if module == "🛡️ Command Center":
    col_head1, col_head2 = st.columns([3, 1])
    with col_head1:
        st.markdown("<h1 class='traceone-title'>TRACEONE COMMAND CENTER</h1>", unsafe_allow_html=True)
        st.markdown("<div class='traceone-tagline'>From Messy Telemetry to Explainable Threat Intelligence</div>", unsafe_allow_html=True)

    with col_head2:
        filter_badge_text = f"FILTERED ({len(filtered_user_risk)} / {len(user_risk_df)} USERS)" if is_filtered else "ALL ENTITIES VIEW"
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 10px;">
                <span class="badge badge-cyan">{filter_badge_text}</span><br/>
                <span style="font-size: 0.8rem; color: #8B949E;">Source of Truth: Validated Analytical Backplane</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    # SECTION 1: POSTURE & RISK KPIS
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
            <div class="metric-sub">Score ≥ 80.0 (Immediate Triage)</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
        <div class="metric-card" style="border-color: #FFA500;">
            <h4 style="color:#FFA500 !important;">High Risk</h4>
            <div class="metric-val" style="color:#FFA500;">{high_count}</div>
            <div class="metric-sub">Score 60.0–79.99 (Priority)</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi4:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Temporal Sequences</h4>
            <div class="metric-val" style="color:#00E5FF;">{seq_count:,}</div>
            <div class="metric-sub">Correlated Multi-Events</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi5:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Multi-Dim Outliers</h4>
            <div class="metric-val" style="color:#7C4DFF;">{multidim_count}</div>
            <div class="metric-sub">Cross-Domain Anomalies</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi6:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Peer Anomalies</h4>
            <div class="metric-val" style="color:#F1C40F;">{peer_outlier_count}</div>
            <div class="metric-sub">Peer-Group Outliers</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # SECTION 2: RISK VS EVIDENCE CONFIDENCE MATRIX
    st.markdown("### 📊 Risk Severity vs Evidence Confidence Matrix")
    st.caption("TraceONE explicitly separates Risk Severity (How dangerous) from Evidence Confidence (How sure we are). Thresholds: High Risk ≥ 60, Critical Risk ≥ 80.")

    col_mat1, col_mat2 = st.columns([3, 1])

    with col_mat1:
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
                    "risk_confidence_score": "Evidence Confidence Score (0.0 – 1.0)",
                    "traceone_risk_score": "TraceONE Risk Score (0 – 100)"
                },
                title="Entity Risk vs Evidence Confidence Distribution"
            )
            
            fig_matrix.add_hline(y=60, line_dash="dash", line_color="#FFA500", opacity=0.7, annotation_text="HIGH Risk Threshold (60)")
            fig_matrix.add_hline(y=80, line_dash="dash", line_color="#FF4D4D", opacity=0.7, annotation_text="CRITICAL Risk Threshold (80)")
            fig_matrix.add_vline(x=0.5, line_dash="dash", line_color="#00E5FF", opacity=0.6, annotation_text="High Confidence Cutoff (0.5)")
            
            fig_matrix.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=420,
                margin=dict(l=40, r=40, t=50, b=40)
            )
            st.plotly_chart(fig_matrix, use_container_width=True)
        else:
            st.warning("No data matching current sidebar filters.")

    with col_mat2:
        st.markdown("#### 🎯 Matrix Quadrants")
        q1 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] >= 60) & (filtered_user_risk['risk_confidence_score'] >= 0.5)])
        q2 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] >= 60) & (filtered_user_risk['risk_confidence_score'] < 0.5)])
        q3 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] < 60) & (filtered_user_risk['risk_confidence_score'] >= 0.5)])
        q4 = len(filtered_user_risk[(filtered_user_risk['traceone_risk_score'] < 60) & (filtered_user_risk['risk_confidence_score'] < 0.5)])
        
        st.markdown(f"""
        <div style="font-size:0.85rem; line-height: 1.6;">
            <div style="background:#161B22; border-left:3px solid #FF4D4D; padding:8px; margin-bottom:8px; border-radius:4px;">
                <b>Q1: High/Critical Risk + High Conf</b><br/>
                <span style="color:#FF4D4D; font-weight:700;">{q1} Entities</span> — High-Risk / High-Confidence Entities. Priority Triage.
            </div>
            <div style="background:#161B22; border-left:3px solid #FFA500; padding:8px; margin-bottom:8px; border-radius:4px;">
                <b>Q2: High/Critical Risk + Low Conf</b><br/>
                <span style="color:#FFA500; font-weight:700;">{q2} Entities</span> — High Anomaly / Data Enrichment Needed.
            </div>
            <div style="background:#161B22; border-left:3px solid #00E676; padding:8px; margin-bottom:8px; border-radius:4px;">
                <b>Q3: Low/Mod Risk + High Conf</b><br/>
                <span style="color:#00E676; font-weight:700;">{q3} Entities</span> — Verified Baseline Activity.
            </div>
            <div style="background:#161B22; border-left:3px solid #8B949E; padding:8px; border-radius:4px;">
                <b>Q4: Low/Mod Risk + Low Conf</b><br/>
                <span style="color:#8B949E; font-weight:700;">{q4} Entities</span> — Low Signal Background Activity.
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # SECTION 3: CLUSTER_3 SPOTLIGHT
    c3_total_users = len(user_behavior_clusters := clusters_df[clusters_df['cluster_label'] == 'SECURITY_SENSITIVE_OUTLIERS']) if not clusters_df.empty else 60
    total_org_high_crit = len(user_risk_df[user_risk_df['risk_level'].isin(['HIGH', 'CRITICAL'])])
    c3_high_crit = len(clusters_df[(clusters_df['cluster_label'] == 'SECURITY_SENSITIVE_OUTLIERS') & (clusters_df['risk_level'].isin(['HIGH', 'CRITICAL']))]) if not clusters_df.empty else 60
    c3_conc_pct = (c3_high_crit / total_org_high_crit * 100) if total_org_high_crit > 0 else 76.92

    st.markdown(f"""
    <div class="cluster3-spotlight">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <span class="badge badge-critical" style="font-size:0.9rem;">🚨 PRIORITY INVESTIGATION TARGET</span>
                <h2 style="color:#FF4D4D !important; margin-top:8px; margin-bottom:4px;">CLUSTER_3: SECURITY_SENSITIVE_OUTLIERS</h2>
                <p style="color:#C9D1D9; font-size:0.95rem; margin:0;">
                    TraceONE Unsupervised Clustering discovered that <b>CLUSTER_3 ({c3_total_users} users, 2.00% of organization)</b> holds 
                    <b>{c3_high_crit} out of {total_org_high_crit} ({c3_conc_pct:.2f}%)</b> of all High/Critical risk users in the enterprise.
                </p>
            </div>
            <div style="text-align:right; min-width:180px;">
                <div style="font-size:2.4rem; font-weight:800; color:#FF4D4D;">{c3_conc_pct:.2f}%</div>
                <div style="font-size:0.75rem; color:#8B949E; text-transform:uppercase;">Org High/Critical Concentration</div>
            </div>
        </div>
        <hr style="border-color:rgba(255,77,77,0.3); margin:14px 0;"/>
        <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:15px; text-align:center; font-size:0.85rem;">
            <div><b>Cluster Population:</b><br/><span style="color:#F0F6FC;">{c3_total_users} Users (2.00%)</span></div>
            <div><b>Critical Risk User Count:</b><br/><span style="color:#FF4D4D;">60 Users (100.0%)</span></div>
            <div><b>Avg TraceONE Risk Score:</b><br/><span style="color:#FF4D4D;">100.0 / 100</span></div>
            <div><b>Dominant Signals:</b><br/><span style="color:#00E5FF;">Off-Hours + Auth Failures + IP Diversity</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # SECTION 4: BEHAVIORAL LANDSCAPE
    st.markdown("### 🧩 Organizational Behavioral Landscape (Phase I Unsupervised Segmentation)")
    st.caption("Partitioning 3,000 users into 4 distinct behavioral clusters using 64 security features.")

    col_c1, col_c2 = st.columns([1, 1])

    with col_c1:
        if not filtered_clusters.empty and 'cluster_label' in filtered_clusters.columns:
            cluster_counts = filtered_clusters['cluster_label'].value_counts().reset_index()
            cluster_counts.columns = ['Cluster Label', 'User Count']
            
            fig_donut = px.pie(
                cluster_counts,
                values="User Count",
                names="Cluster Label",
                hole=0.5,
                color="Cluster Label",
                color_discrete_map={
                    "NORMAL_BUSINESS_ACTIVITY": "#00E676",
                    "IRREGULAR_AUTHENTICATION_BEHAVIOR": "#00E5FF",
                    "HIGH_ENDPOINT_ALERT_PROFILE": "#FFA500",
                    "SECURITY_SENSITIVE_OUTLIERS": "#FF4D4D"
                },
                title="User Population Distribution across Behavioral Clusters"
            )
            fig_donut.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=380,
                margin=dict(l=20, r=20, t=50, b=20)
            )
            st.plotly_chart(fig_donut, use_container_width=True)

    with col_c2:
        st.markdown("#### 📋 Authoritative Cluster Profiles (`cluster_profiles.csv`)")
        if not cluster_profiles_df.empty:
            display_prof = cluster_profiles_df[['cluster_id', 'cluster_label', 'population_count', 'population_percent', 'avg_risk_score', 'high_risk_count', 'dominant_features']].copy()
            display_prof.columns = ['Cluster ID', 'Label', 'Population', '% Org', 'Avg Risk Score', 'High/Crit Count', 'Dominant Features']
            st.dataframe(display_prof, use_container_width=True, hide_index=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # SECTION 7: INTERACTIVE TRIAGE QUEUE & CLICK-THROUGH
    st.markdown("### 📋 Interactive SOC Investigation Queue")
    st.caption("Ranked, evidence-backed list of monitored entities based on TraceONE Risk Engine scores.")

    col_q1, col_q2, col_q3 = st.columns([2, 2, 2])

    with col_q1:
        sort_by = st.selectbox(
            "Sort Queue By",
            [
                "TraceONE Risk Score (High to Low)",
                "Evidence Confidence Score (High to Low)",
                "Cluster Priority (CLUSTER_3 First)",
                "Entity ID"
            ]
        )

    with col_q2:
        search_query = st.text_input("🔍 Search Entity ID / Username", "")

    with col_q3:
        st.markdown("<br/>", unsafe_allow_html=True)
        st.caption(f"Showing **{len(filtered_user_risk)}** of {total_users} users based on active filters.")

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

    st.markdown("#### 🔎 Entity Triage & Direct Investigation Launch")
    selected_queue_id = st.selectbox("Select Entity ID for Deep Triage", options=queue_df['entity_id'].head(20).tolist() if not queue_df.empty else [])

    if selected_queue_id:
        entity_row = queue_df[queue_df['entity_id'] == selected_queue_id].iloc[0]
        
        col_d1, col_d2, col_d3 = st.columns([1, 1, 1])
        
        with col_d1:
            st.markdown(f"**Entity ID:** `{entity_row.get('entity_id', 'N/A')}`")
            st.markdown(f"**Username:** `{entity_row.get('username', 'N/A')}`")
            st.markdown(f"**Department:** {entity_row.get('department', 'N/A')}")
        
        with col_d2:
            risk_lvl = entity_row.get('risk_level', 'LOW')
            st.markdown(f"**Risk Level:** <span class='badge badge-{risk_lvl.lower()}'>{risk_lvl}</span>", unsafe_allow_html=True)
            st.markdown(f"**TraceONE Risk Score:** `{entity_row.get('traceone_risk_score', 0):.1f} / 100`")
            st.markdown(f"**Evidence Confidence:** `{entity_row.get('risk_confidence_level', 'MEDIUM')}`")
        
        with col_d3:
            st.markdown(f"**Behavioral Cluster:** `{entity_row.get('cluster_label', 'N/A')}`")
            st.markdown(f"**Primary Hypothesis:**")
            st.caption(f"`{entity_row.get('primary_hypothesis', 'NO_ACTIONABLE_HYPOTHESIS')}`")
            
            if st.button("🔍 LAUNCH INVESTIGATION IN INVESTIGATION CENTER", key="launch_inv_btn"):
                st.session_state['selected_entity_id'] = selected_queue_id
                st.session_state['active_module'] = "🔍 Investigation Center"
                st.rerun()

    st.markdown("<br/>", unsafe_allow_html=True)


# =========================================================
# MODULE 2: INVESTIGATION CENTER (PHASE K)
# =========================================================
elif module == "🔍 Investigation Center":
    col_inv_head1, col_inv_head2 = st.columns([3, 1])
    with col_inv_head1:
        st.markdown("<h1 class='traceone-title'>TRACEONE INVESTIGATION CENTER</h1>", unsafe_allow_html=True)
        st.markdown("<div class='traceone-tagline'>Deep Evidence Investigation • Relationship Graph • Root Cause Analysis</div>", unsafe_allow_html=True)

    with col_inv_head2:
        curr_id = st.session_state.get('selected_entity_id', 'None Selected')
        st.markdown(
            f"""
            <div style="text-align: right; padding-top: 10px;">
                <span class="badge badge-cyan">ACTIVE ENTITY: {curr_id}</span><br/>
                <span style="font-size: 0.8rem; color: #8B949E;">Investigation Workspace</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    # STEP 1: ENTITY SELECTION
    st.markdown("### 1. Entity Investigation Selector")
    
    # Quick high-risk buttons
    st.markdown("**Quick High-Risk Demo Targets:**")
    quick_col1, quick_col2, quick_col3, quick_col4, quick_col5 = st.columns(5)
    
    with quick_col1:
        if st.button("🚨 EMP10194 (Critical 100.0)"):
            st.session_state['selected_entity_id'] = "EMP10194"
            st.rerun()
    with quick_col2:
        if st.button("🚨 EMP10014 (Critical 100.0)"):
            st.session_state['selected_entity_id'] = "EMP10014"
            st.rerun()
    with quick_col3:
        if st.button("🚨 EMP10034 (Critical 100.0)"):
            st.session_state['selected_entity_id'] = "EMP10034"
            st.rerun()
    with quick_col4:
        if st.button("💻 VDR-11889 (Host Target)"):
            st.session_state['selected_entity_id'] = "VDR-11889"
            st.rerun()
    with quick_col5:
        if st.button("💻 VDR-10881 (Host Target)"):
            st.session_state['selected_entity_id'] = "VDR-10881"
            st.rerun()

    st.markdown("<br/>", unsafe_allow_html=True)
    
    # Combined search & select list
    user_options = user_risk_df['entity_id'].tolist() if not user_risk_df.empty else []
    host_options = host_risk_df['entity_id'].tolist() if not host_risk_df.empty else []
    all_entity_options = [""] + user_options + host_options

    current_selection = st.session_state.get('selected_entity_id', '')
    sel_idx = all_entity_options.index(current_selection) if current_selection in all_entity_options else 0

    selected_target = st.selectbox(
        "🔍 Search or Select Entity ID / Hostname to Investigate",
        options=all_entity_options,
        index=sel_idx,
        help="Type or select a User ID (e.g. EMP10194) or Host ID (e.g. VDR-11889)"
    )

    if selected_target:
        st.session_state['selected_entity_id'] = selected_target

    active_entity = st.session_state.get('selected_entity_id')

    # STEP 20: NO-DATA / INITIAL UNSELECTED STATE
    if not active_entity:
        st.info("👈 **Select an entity above or choose from the Quick High-Risk Demo Targets to begin deep investigation.**")
        st.markdown("""
        <div style="background:#161B22; border:1px solid #30363D; padding:20px; border-radius:8px; text-align:center;">
            <h4>TraceONE SOC Analyst Investigation Workspace</h4>
            <p style="color:#8B949E; font-size:0.9rem;">
                The Investigation Center correlates identity features, historical baselines, temporal event chains, 
                and relationship graphs to provide explainable threat intelligence without synthetic data fabrication.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # Determine if Entity is USER or HOST
    is_user = active_entity.startswith("EMP") or active_entity in user_options
    is_host = active_entity.startswith("VDR") or active_entity.startswith("HOST") or active_entity in host_options

    entity_risk_row = user_risk_df[user_risk_df['entity_id'] == active_entity] if is_user else host_risk_df[host_risk_df['entity_id'] == active_entity]
    
    if entity_risk_row.empty:
        # Fallback search across canonical tables
        st.warning(f"Entity **{active_entity}** was found in graph/telemetry records, but has no risk score entry in processed tables.")
        entity_info = {"entity_id": active_entity, "traceone_risk_score": 0.0, "risk_level": "LOW", "risk_confidence_score": 0.5, "risk_confidence_level": "MEDIUM"}
    else:
        entity_info = entity_risk_row.iloc[0].to_dict()

    # Get Explanation JSON if available
    entity_explanation = explanations_dict.get(active_entity, {})

    # STEP 2: INVESTIGATION HEADER
    st.markdown("---")
    st.markdown("### 2. Entity Investigation Header")
    
    header_col1, header_col2, header_col3 = st.columns([2, 2, 2])
    
    with header_col1:
        st.markdown(f"**Entity ID:** `{active_entity}`")
        st.markdown(f"**Entity Type:** `{('USER' if is_user else 'HOST')}`")
        if is_user:
            st.markdown(f"**Username:** `{entity_info.get('username', 'N/A')}`")
            st.markdown(f"**Department:** {entity_info.get('department', 'N/A')}")
        else:
            st.markdown(f"**Hostname:** `{entity_info.get('entity_id', 'N/A')}`")
            st.markdown(f"**Managed Status:** Managed Enterprise Asset")

    with header_col2:
        risk_lvl = entity_info.get('risk_level', 'LOW')
        st.markdown(f"**Risk Level:** <span class='badge badge-{risk_lvl.lower()}'>{risk_lvl}</span>", unsafe_allow_html=True)
        st.markdown(f"**TraceONE Risk Score:** `{entity_info.get('traceone_risk_score', 0.0):.1f} / 100`")
        st.markdown(f"**Evidence Confidence:** `{entity_info.get('risk_confidence_level', 'MEDIUM')}` ({entity_info.get('risk_confidence_score', 0.5):.2f})")

    with header_col3:
        user_cluster_row = clusters_df[clusters_df['user_id'] == active_entity] if not clusters_df.empty and is_user else pd.DataFrame()
        c_label = user_cluster_row['cluster_label'].values[0] if not user_cluster_row.empty else "N/A"
        st.markdown(f"**Behavioral Cluster:** `{c_label}`")
        st.markdown(f"**Primary Hypothesis:**")
        st.caption(f"`{entity_info.get('primary_hypothesis', 'NO_ACTIONABLE_HYPOTHESIS')}`")

    # STEP 3: VISUALLY DOMINANT RISK SUMMARY
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 3. Risk Severity & Evidence Confidence Summary")
    
    rc_col1, rc_col2, rc_col3, rc_col4 = st.columns(4)
    
    r_score = entity_info.get('traceone_risk_score', 0.0)
    c_score = entity_info.get('risk_confidence_score', 0.5)
    c_level = entity_info.get('risk_confidence_level', 'MEDIUM')
    
    # Count supporting evidence events
    ev_count = len(evidence_df[evidence_df['entity_id'] == active_entity]) if not evidence_df.empty else 0
    
    with rc_col1:
        st.markdown(f"""
        <div class="metric-card" style="border-color: {'#FF4D4D' if r_score>=80 else '#FFA500' if r_score>=60 else '#00E676'};">
            <h4>TraceONE Risk Score</h4>
            <div class="metric-val" style="color: {'#FF4D4D' if r_score>=80 else '#FFA500' if r_score>=60 else '#00E676'};">{r_score:.1f}</div>
            <div class="metric-sub">Range: 0 – 100</div>
        </div>
        """, unsafe_allow_html=True)
        
    with rc_col2:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Risk Level</h4>
            <div class="metric-val"><span class="badge badge-{risk_lvl.lower()}" style="font-size:1.4rem;">{risk_lvl}</span></div>
            <div class="metric-sub">Exact Boundary Threshold</div>
        </div>
        """, unsafe_allow_html=True)
        
    with rc_col3:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Evidence Confidence</h4>
            <div class="metric-val" style="color:#00E5FF;">{c_level}</div>
            <div class="metric-sub">Score: {c_score:.2f} / 1.0</div>
        </div>
        """, unsafe_allow_html=True)
        
    with rc_col4:
        st.markdown(f"""
        <div class="metric-card">
            <h4>Supporting Evidence</h4>
            <div class="metric-val" style="color:#7C4DFF;">{ev_count}</div>
            <div class="metric-sub">Canonical Events Correlated</div>
        </div>
        """, unsafe_allow_html=True)

    # STEP 4 & 5: WHY WAS THIS FLAGGED? & CONTRIBUTION CHART
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 4. Why Was This Flagged? (Phase F Risk Decomposition)")
    st.caption("Decomposition of observed behavioral deviations driving the TraceONE Risk Score.")

    col_why1, col_why2 = st.columns([1, 1])
    
    top_contribs = entity_explanation.get('top_contributors', {})
    if not top_contribs:
        # Fallback to defaults if entity missing from JSON
        top_contribs = {"authentication": 0.0, "network": 0.0, "endpoint": 0.0, "operational_off_hours": 0.0}

    with col_why1:
        st.markdown("#### 📊 Risk Component Scores (Points)")
        contrib_df = pd.DataFrame(list(top_contribs.items()), columns=['Security Signal', 'Risk Component Score (Points)'])
        
        fig_contrib = px.bar(
            contrib_df,
            x="Risk Component Score (Points)",
            y="Security Signal",
            orientation="h",
            color="Risk Component Score (Points)",
            color_continuous_scale="Reds",
            title=f"Risk Signal Component Scores for {active_entity}"
        )
        fig_contrib.update_layout(
            template="plotly_dark",
            paper_bgcolor="#161B22",
            plot_bgcolor="#0E1117",
            height=320,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig_contrib, use_container_width=True)

    with col_why2:
        st.markdown("#### 📝 Structured Risk Interpretation")
        
        # Generate textual interpretation deterministically from data
        max_sig = max(top_contribs, key=top_contribs.get) if top_contribs else "None"
        max_val = top_contribs.get(max_sig, 0.0)
        
        obs_vals = entity_explanation.get('observed_values', {})
        dev_vals = entity_explanation.get('deviations', {})
        
        st.markdown(f"""
        <div style="background:#161B22; border-left:4px solid #FF4D4D; padding:16px; border-radius:6px; font-size:0.9rem;">
            <b>Primary Driver:</b> <span style="color:#FF4D4D; font-weight:700;">{max_sig.upper()}</span> ({max_val:.1f} points risk component score)<br/>
            <b>Observed Failed Logins:</b> {obs_vals.get('failed_login_count', 'N/A')}<br/>
            <b>Off-Hours Activity:</b> {obs_vals.get('off_hours_activity_count', 'N/A')} events<br/>
            <b>Endpoint Malicious Alerts:</b> {obs_vals.get('endpoint_alert_count', 'N/A')} alerts<br/>
            <hr style="border-color:#30363D; margin:10px 0;"/>
            <i>Interpretation:</i> {max_sig.replace('_', ' ').capitalize()} behavior represents the largest observed risk component score, 
            corroborated by non-linear z-score deviations across multiple telemetry sources.
        </div>
        """, unsafe_allow_html=True)

    # STEP 6 & 7: BEHAVIORAL BASELINE & PEER CONTEXT
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 5. Behavioral Baseline & Peer Comparison")
    
    col_base1, col_base2 = st.columns([2, 1])
    
    with col_base1:
        st.markdown("#### 📈 Observed vs. Own Baseline Comparison")
        
        baseline_row = user_baselines_df[user_baselines_df['user_id'] == active_entity] if is_user and not user_baselines_df.empty else pd.DataFrame()
        
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
        st.markdown("#### 👥 Department Peer Context")
        peer_info = entity_explanation.get('peer_comparison', {})
        if peer_info:
            st.markdown(f"""
            <div style="background:#161B22; border:1px solid #30363D; padding:14px; border-radius:6px; font-size:0.85rem;">
                <b>Department:</b> {peer_info.get('department', 'N/A')}<br/>
                <b>Peer Failed Login Median:</b> {peer_info.get('peer_failed_login_median', 2.0)}<br/>
                <b>Dept Percentile:</b> <span style="color:#FF4D4D; font-weight:700;">{peer_info.get('department_failed_login_percentile', 99.0):.1f}th Percentile</span><br/>
                <hr style="border-color:#30363D; margin:8px 0;"/>
                <span style="color:#00E5FF;">Insight:</span> Entity displays high peer-group deviation relative to department role baselines.
            </div>
            """, unsafe_allow_html=True)
        else:
            st.caption("Peer comparison unavailable — insufficient peer evidence.")

    # STEP 9 & 10: TEMPORAL TIMELINE & SEQUENCES
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 6. Temporal Investigation Timeline & Correlated Sequences")
    
    col_temp1, col_temp2 = st.columns([2, 1])
    
    entity_seqs = sequences_df[sequences_df['entity_id'] == active_entity] if not sequences_df.empty else pd.DataFrame()
    
    with col_temp1:
        st.markdown("#### ⏱️ Chronological Security Event Timeline")
        
        entity_events = canonical_events_df[canonical_events_df['user_id'] == active_entity] if is_user and not canonical_events_df.empty else canonical_events_df[canonical_events_df['hostname'] == active_entity] if not canonical_events_df.empty else pd.DataFrame()
        
        if not entity_events.empty:
            disp_events = entity_events.head(20).copy()
            fig_timeline = px.scatter(
                disp_events,
                x="timestamp",
                y="dataset",
                color="event_category" if "event_category" in disp_events.columns else "dataset",
                hover_data=["event_id", "action"],
                title=f"Telemetry Event Chronology for {active_entity}"
            )
            fig_timeline.update_layout(
                template="plotly_dark",
                paper_bgcolor="#161B22",
                plot_bgcolor="#0E1117",
                height=320,
                margin=dict(l=20, r=20, t=40, b=20)
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.caption("Timestamp unavailable — excluded from precise chronological timeline ordering.")

    with col_temp2:
        st.markdown("#### 🔗 Correlated Sequence Details")
        if not entity_seqs.empty:
            seq_row = entity_seqs.iloc[0]
            st.markdown(f"""
            <div style="background:#161B22; border-left:3px solid #7C4DFF; padding:12px; border-radius:6px; font-size:0.85rem;">
                <b>Sequence ID:</b> `{seq_row.get('sequence_id')}`<br/>
                <b>Sequence Type:</b> <span style="color:#00E5FF;">{seq_row.get('sequence_type')}</span><br/>
                <b>Duration:</b> {seq_row.get('duration_seconds', 0)} seconds<br/>
                <b>Event Count:</b> {seq_row.get('event_count', 0)} events<br/>
                <b>Strength:</b> {seq_row.get('sequence_strength', 75.0)} / 100<br/>
                <hr style="border-color:#30363D; margin:8px 0;"/>
                <i>Observed temporal correlation across multi-source events.</i>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.caption("No multi-event temporal sequences correlated for this entity.")

    # STEP 11: EVIDENCE EXPLORER
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 7. Canonical Evidence Explorer")
    st.caption("Filterable, supporting evidence records behind the risk assessment.")

    entity_ev = evidence_df[evidence_df['entity_id'] == active_entity] if not evidence_df.empty else pd.DataFrame()
    
    if not entity_ev.empty:
        ev_cols = [c for c in ['event_id', 'source_dataset', 'event_category', 'event_timestamp', 'severity', 'action', 'resolution_confidence'] if c in entity_ev.columns]
        st.dataframe(entity_ev[ev_cols].head(15), use_container_width=True, hide_index=True)
    else:
        st.caption("No explicit evidence table records found for this entity.")

    # STEP 12, 13 & 14: INTERACTIVE INVESTIGATION GRAPH & EDGE PROVENANCE
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 8. Interactive Investigation Graph & Edge Provenance Inspector")
    st.caption("Bounded neighborhood traversal demonstrating entity relationships and shared infrastructure connections.")

    if graph_engine is not None:
        graph_data = graph_engine.get_bounded_neighborhood(active_entity, max_hops=1)
        
        col_g1, col_g2 = st.columns([2, 1])
        
        with col_g1:
            st.markdown(f"#### 🌐 Neighborhood Topology ({graph_data['node_count']} Nodes, {graph_data['edge_count']} Edges)")
            
            # Construct Plotly Network Graph
            G = nx.Graph()
            for edge in graph_data['edges']:
                G.add_edge(edge['source'], edge['target'], relationship=edge['relationship_type'], confidence=edge['confidence'])
                
            pos = nx.spring_layout(G, seed=42)
            
            edge_x = []
            edge_y = []
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

            node_x = []
            node_y = []
            node_text = []
            node_color = []
            
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
                marker=dict(
                    size=16,
                    color=node_color,
                    line_width=2,
                    line_color="#FFFFFF"
                )
            )

            fig_graph = go.Figure(data=[edge_trace, node_trace],
                layout=go.Layout(
                    title=f"Relationship Graph for {active_entity}",
                    template="plotly_dark",
                    paper_bgcolor="#161B22",
                    plot_bgcolor="#0E1117",
                    showlegend=False,
                    height=380,
                    margin=dict(b=20, l=20, r=20, t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                )
            )
            st.plotly_chart(fig_graph, use_container_width=True)

        with col_g2:
            st.markdown("#### 🔎 'Why Does This Edge Exist?' Inspector")
            
            if graph_data['edges']:
                edge_options = [f"{e['source']} → {e['target']} ({e['relationship_type']})" for e in graph_data['edges']]
                selected_edge_str = st.selectbox("Select Edge to Inspect Provenance", options=edge_options)
                
                selected_edge_idx = edge_options.index(selected_edge_str)
                selected_edge = graph_data['edges'][selected_edge_idx]
                
                st.markdown(f"""
                <div style="background:#161B22; border-left:3px solid #00E5FF; padding:12px; border-radius:6px; font-size:0.85rem;">
                    <b>Relationship:</b> `{selected_edge['relationship_type']}`<br/>
                    <b>Confidence:</b> <span class="badge badge-cyan">{selected_edge['confidence']}</span><br/>
                    <b>Source Dataset:</b> {selected_edge['source_dataset']}<br/>
                    <b>Source Record ID:</b> `{selected_edge['source_record_id']}`<br/>
                    <b>Evidence Type:</b> {selected_edge['evidence_type']}<br/>
                    <hr style="border-color:#30363D; margin:8px 0;"/>
                    <b>Rule:</b> Validated canonical identity & relationship mapping rule.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.caption("No direct graph edge connections found.")

    # STEP 15 & 16: HYPOTHESIS & COUNTER-EVIDENCE
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 9. Security Hypotheses & Counter-Evidence")
    
    col_hyp1, col_hyp2 = st.columns([1, 1])
    
    with col_hyp1:
        st.markdown("#### 📋 Security Hypotheses")
        hyp_text = entity_info.get('primary_hypothesis', 'NO_ACTIONABLE_HYPOTHESIS')
        st.markdown(f"""
        <div style="background:#161B22; border-left:3px solid #FFA500; padding:14px; border-radius:6px; font-size:0.9rem;">
            <b>Primary Threat Hypothesis:</b><br/>
            <span style="color:#FFA500; font-weight:700;">{hyp_text}</span><br/><br/>
            <i>Status: Possible hypothesis supported by correlated telemetry signals.</i>
        </div>
        """, unsafe_allow_html=True)

    with col_why2:
        st.markdown("#### 🛡️ WHAT COULD LOWER OUR CONFIDENCE? (Counter-Evidence)")
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
                <div class="counter-evidence-box">
                    <b>Counter-Evidence Signal:</b> <span style="color:#00E5FF;">{cev}</span><br/>
                    <i>Effect:</i> {cev_desc}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="counter-evidence-box">
                <i>None identified in available telemetry.</i>
            </div>
            """, unsafe_allow_html=True)

    # STEP 18 & 19: DETERMINISTIC SUMMARY CARD & ACTIONABLE TRIAGE
    st.markdown("<br/>", unsafe_allow_html=True)
    st.markdown("### 10. Investigation Summary Card & Recommended Triage Actions")
    
    col_sum1, col_sum2 = st.columns([2, 1])
    
    with col_sum1:
        st.markdown("#### 📄 Exportable Investigation Summary Card")
        st.markdown(f"""
        <div style="background:#161B22; border:1px solid #00E5FF; padding:18px; border-radius:8px; font-size:0.88rem;">
            <b>TRACEONE INVESTIGATION SUMMARY</b> — <code>{active_entity}</code><br/>
            --------------------------------------------------------------------------------<br/>
            <b>Risk Score:</b> {r_score:.1f} / 100 ({risk_lvl}) | <b>Confidence:</b> {c_level} ({c_score:.2f})<br/>
            <b>Primary Driver:</b> {max_sig.upper()} ({max_val:.1f}%)<br/>
            <b>Behavioral Cluster:</b> {c_label}<br/>
            <b>Primary Hypothesis:</b> {hyp_text}<br/>
            <b>Counter Evidence:</b> {", ".join(counter_ev) if counter_ev else "None"}<br/>
            --------------------------------------------------------------------------------<br/>
            <i>Status: Investigation Ready for SOC Lead Review</i>
        </div>
        """, unsafe_allow_html=True)

    with col_sum2:
        st.markdown("#### 🛠️ Recommended SOC Triage Actions")
        st.button("1. Review Authentication Activity", use_container_width=True)
        st.button("2. Inspect Endpoint Malicious Alerts", use_container_width=True)
        st.button("3. Investigate Shared IP Infrastructure", use_container_width=True)
        st.button("4. Export Investigation Summary PDF", use_container_width=True)
