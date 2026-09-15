"""
Semantic Visualization Selector & Chart Engine for TraceONE AI Investigator.
Translates structured visualization specifications into Plotly dark-themed charts and Streamlit components.
All chart DATA comes strictly from deterministic backend results.
"""

from typing import Dict, Any, Optional
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


class VisualizationSelector:

    @staticmethod
    def render_spec(viz_type: str, data_package: dict, title_override: str = None) -> Optional[go.Figure]:
        """Generate Plotly figure based on semantic visualization type and backend data package."""
        
        # 1. Bar Chart (e.g. Critical Users by Department or Risk Component Breakdown)
        if viz_type == "bar_chart":
            high_risk_list = data_package.get("high_risk_list", [])
            if high_risk_list:
                df = pd.DataFrame(high_risk_list)
                if 'department' in df.columns:
                    dept_counts = df['department'].value_counts().reset_index()
                    dept_counts.columns = ['Department', 'Critical Users']
                    fig = px.bar(
                        dept_counts,
                        x='Department',
                        y='Critical Users',
                        color='Critical Users',
                        color_continuous_scale='Reds',
                        title=title_override or "Critical Risk Users by Department"
                    )
                    fig.update_layout(template="plotly_dark", paper_bgcolor="#161B22", plot_bgcolor="#0E1117", height=340)
                    return fig

            risk_rec = data_package.get("risk_assessment", {})
            top_contribs = risk_rec.get("top_contributors", {})
            if top_contribs:
                df = pd.DataFrame(list(top_contribs.items()), columns=['Security Signal', 'Risk Component Score (Points)'])
                fig = px.bar(
                    df,
                    x='Risk Component Score (Points)',
                    y='Security Signal',
                    orientation='h',
                    color='Risk Component Score (Points)',
                    color_continuous_scale='Reds',
                    title=title_override or f"Risk Component Scores for {data_package.get('entity', {}).get('entity_id', 'Entity')}"
                )
                fig.update_layout(template="plotly_dark", paper_bgcolor="#161B22", plot_bgcolor="#0E1117", height=340)
                return fig

        # 2. Timeline (e.g. Temporal Sequences)
        elif viz_type == "timeline":
            seq_data = data_package.get("temporal_sequences", {})
            seq_list = seq_data.get("sequences", [])
            if seq_list:
                df = pd.DataFrame(seq_list)
                if 'start_time' in df.columns and 'end_time' in df.columns:
                    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
                    df['end_time'] = pd.to_datetime(df['end_time'], errors='coerce')
                    df['duration_sec'] = df['duration_seconds'] if 'duration_seconds' in df.columns else 60
                    
                    fig = px.bar(
                        df,
                        x="duration_sec",
                        y="sequence_type",
                        color="sequence_confidence" if "sequence_confidence" in df.columns else None,
                        orientation="h",
                        title=title_override or f"Temporal Sequence Timeline ({len(df)} Sequences Chained)"
                    )
                    fig.update_layout(template="plotly_dark", paper_bgcolor="#161B22", plot_bgcolor="#0E1117", height=340)
                    return fig

        # 3. Scatter Plot / Risk Matrix
        elif viz_type in ["risk_matrix", "scatter_plot"]:
            risk_rec = data_package.get("risk_assessment", {})
            if risk_rec.get("traceone_risk_score") is not None:
                r_score = risk_rec.get("traceone_risk_score", 0.0)
                c_score = risk_rec.get("risk_confidence_score", 0.95)
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=[c_score],
                    y=[r_score],
                    mode='markers+text',
                    text=[risk_rec.get('entity_id', 'Target')],
                    textposition="top center",
                    marker=dict(size=18, color='#FF4D4D', symbol='diamond', line=dict(width=2, color='#FFFFFF'))
                ))
                fig.update_layout(
                    xaxis_title="Evidence Confidence Score",
                    yaxis_title="TraceONE Risk Score",
                    xaxis=dict(range=[0, 1.05]),
                    yaxis=dict(range=[0, 105]),
                    template="plotly_dark",
                    paper_bgcolor="#161B22",
                    plot_bgcolor="#0E1117",
                    title=title_override or "Risk vs. Evidence Confidence Positioning Matrix",
                    height=340
                )
                return fig

        return None
