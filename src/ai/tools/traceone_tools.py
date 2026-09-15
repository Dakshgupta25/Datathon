"""
Deterministic TraceONE Tools for AI Investigator.
Exposes read-only analytical backend engines (Risk, DuckDB/Pandas, Baselines, Temporal, Graph, Data Trust)
Returning structured evidence payloads with complete source provenance.
"""

from typing import Dict, List, Optional
import pandas as pd

from src.dashboard.data.loader import (
    load_user_risk_scores,
    load_host_risk_scores,
    load_user_clusters,
    load_cluster_profiles,
    load_temporal_sequences,
    load_peer_anomalies,
    load_multidim_outliers,
    load_why_flagged_explanations,
    load_security_hypotheses,
    load_normalized_evidence,
    load_user_baselines,
    load_host_baselines,
    get_graph_engine,
    load_data_trust_status,
    load_provenance_record
)


class TraceONEToolkit:

    def __init__(self):
        self.user_risk_df = load_user_risk_scores()
        self.host_risk_df = load_host_risk_scores()
        self.clusters_df = load_user_clusters()
        self.cluster_prof_df = load_cluster_profiles()
        self.sequences_df = load_temporal_sequences()
        self.peer_df = load_peer_anomalies()
        self.multidim_df = load_multidim_outliers()
        self.explanations = load_why_flagged_explanations()
        self.hypotheses_df = load_security_hypotheses()
        self.evidence_df = load_normalized_evidence()
        self.user_base_df = load_user_baselines()
        self.host_base_df = load_host_baselines()
        self.graph_engine = get_graph_engine()

    def get_user_risk(self, entity_id: str) -> dict:
        """Retrieve user risk score, confidence level, and hypothesis."""
        if self.user_risk_df.empty:
            return {"found": False, "source": "user_risk_scores.csv"}
        
        match = self.user_risk_df[self.user_risk_df['entity_id'].astype(str) == str(entity_id)]
        if match.empty:
            return {"found": False, "entity_id": entity_id, "source": "user_risk_scores.csv"}
            
        row = match.iloc[0].to_dict()
        exp = self.explanations.get(entity_id, {})
        
        return {
            "found": True,
            "entity_id": entity_id,
            "traceone_risk_score": float(row.get('traceone_risk_score', 0.0)),
            "risk_level": str(row.get('risk_level', 'LOW')),
            "risk_confidence_score": float(row.get('risk_confidence_score', 0.95)),
            "risk_confidence_level": str(row.get('risk_confidence_level', 'HIGH')),
            "department": str(row.get('department', 'Unknown')),
            "primary_hypothesis": str(row.get('primary_hypothesis', 'POSSIBLE_CREDENTIAL_COMPROMISE')),
            "top_contributors": exp.get('top_contributors', {}),
            "counter_evidence": exp.get('counter_evidence', []),
            "source": "data/processed/user_risk_scores.csv",
            "provenance": "Phase F Risk Engine Engine Execution"
        }

    def get_host_risk(self, entity_id: str) -> dict:
        """Retrieve host device risk score and baseline information."""
        if self.host_risk_df.empty:
            return {"found": False, "source": "host_risk_scores.csv"}
            
        match = self.host_risk_df[self.host_risk_df['entity_id'].astype(str) == str(entity_id)]
        if match.empty:
            return {"found": False, "entity_id": entity_id, "source": "host_risk_scores.csv"}
            
        row = match.iloc[0].to_dict()
        return {
            "found": True,
            "entity_id": entity_id,
            "traceone_risk_score": float(row.get('traceone_risk_score', 0.0)),
            "risk_level": str(row.get('risk_level', 'LOW')),
            "risk_confidence_score": float(row.get('risk_confidence_score', 0.90)),
            "source": "data/processed/host_risk_scores.csv"
        }

    def get_behavior_profile(self, entity_id: str) -> dict:
        """Retrieve behavioral baseline and cluster assignment."""
        exp = self.explanations.get(entity_id, {})
        obs_vals = exp.get('observed_values', {})
        dev_vals = exp.get('deviations', {})
        
        c_match = self.clusters_df[self.clusters_df['user_id'].astype(str) == str(entity_id)] if not self.clusters_df.empty else pd.DataFrame()
        c_label = c_match.iloc[0]['cluster_label'] if not c_match.empty and 'cluster_label' in c_match.columns else "CLUSTER_0"
        
        return {
            "entity_id": entity_id,
            "cluster_label": c_label,
            "observed_values": obs_vals,
            "z_deviations": dev_vals,
            "source": "data/processed/user_behavior_baselines.csv & user_behavior_clusters.csv"
        }

    def get_peer_comparison(self, entity_id: str) -> dict:
        """Retrieve department peer group context and deviation metrics."""
        exp = self.explanations.get(entity_id, {})
        peer_ctx = exp.get('peer_comparison', {})
        
        p_match = self.peer_df[self.peer_df['user_id'].astype(str) == str(entity_id)] if not self.peer_df.empty else pd.DataFrame()
        is_outlier = bool(p_match.iloc[0]['peer_outlier_flag']) if not p_match.empty and 'peer_outlier_flag' in p_match.columns else False
        
        return {
            "entity_id": entity_id,
            "peer_outlier_flag": is_outlier,
            "department": peer_ctx.get('department', 'R&D'),
            "department_failed_login_percentile": peer_ctx.get('department_failed_login_percentile', 99.0),
            "department_median_failed_logins": peer_ctx.get('department_median_failed_logins', 0.0),
            "source": "data/processed/peer_group_outliers.csv"
        }

    def get_temporal_sequences(self, entity_id: str) -> dict:
        """Retrieve chained temporal sequence events for entity."""
        if self.sequences_df.empty:
            return {"entity_id": entity_id, "sequence_count": 0, "sequences": []}
            
        matches = self.sequences_df[self.sequences_df['entity_id'].astype(str) == str(entity_id)]
        seq_list = matches.head(5).to_dict(orient="records") if not matches.empty else []
        
        return {
            "entity_id": entity_id,
            "sequence_count": len(matches),
            "sequences": seq_list,
            "source": "data/processed/temporal_sequences.csv",
            "rule": "Exact temporal ordering on valid timestamps; unknown timestamps excluded"
        }

    def get_graph_neighbors(self, entity_id: str) -> dict:
        """Retrieve bounded graph neighborhood connections."""
        if self.graph_engine is None:
            return {"entity_id": entity_id, "node_count": 0, "edge_count": 0, "edges": []}
            
        return self.graph_engine.get_bounded_neighborhood(entity_id, max_hops=1)

    def get_shared_ip_connections(self, entity_id: str) -> dict:
        """Find users and hosts connected by shared IP infrastructure."""
        if self.graph_engine is None:
            return {"entity_id": entity_id, "shared_ip_count": 0, "connections": []}
            
        graph_data = self.graph_engine.get_bounded_neighborhood(entity_id, max_hops=1)
        ip_edges = [e for e in graph_data.get('edges', []) if e.get('relationship_type') in ['SHARED_IP', 'AUTHENTICATED_FROM_IP', 'TRAFFIC_FROM_IP']]
        
        return {
            "entity_id": entity_id,
            "shared_ip_count": len(ip_edges),
            "connections": ip_edges,
            "source": "data/processed/graph_edges.csv"
        }

    def get_endpoint_evidence(self, entity_id: str) -> list:
        """Retrieve normalized endpoint alert evidence."""
        if self.evidence_df.empty:
            return []
        match = self.evidence_df[(self.evidence_df['entity_id'].astype(str) == str(entity_id)) & (self.evidence_df['source_dataset'] == 'Endpoint')]
        return match.head(10).to_dict(orient="records")

    def get_firewall_evidence(self, entity_id: str) -> list:
        """Retrieve normalized firewall network traffic evidence."""
        if self.evidence_df.empty:
            return []
        match = self.evidence_df[(self.evidence_df['entity_id'].astype(str) == str(entity_id)) & (self.evidence_df['source_dataset'] == 'Firewall')]
        return match.head(10).to_dict(orient="records")

    def get_authentication_evidence(self, entity_id: str) -> list:
        """Retrieve normalized IAM authentication evidence."""
        if self.evidence_df.empty:
            return []
        match = self.evidence_df[(self.evidence_df['entity_id'].astype(str) == str(entity_id)) & (self.evidence_df['source_dataset'] == 'IAM')]
        return match.head(10).to_dict(orient="records")

    def get_provenance(self, entity_id: str) -> dict:
        """Retrieve complete raw-to-SOC lineage."""
        return load_provenance_record("User / Host", entity_id)

    def get_data_quality_context(self) -> dict:
        """Retrieve Data Trust Center telemetry context and quality status."""
        return load_data_trust_status()

    def get_cluster_profile(self, cluster_id: str) -> dict:
        """Retrieve cluster summary profile."""
        if self.cluster_prof_df.empty:
            return {}
        match = self.cluster_prof_df[self.cluster_prof_df['cluster_id'] == cluster_id]
        return match.iloc[0].to_dict() if not match.empty else {}

    def get_high_risk_entities(self, department: str = None, risk_level: str = "CRITICAL") -> list:
        """Filter high/critical risk entities by department or severity level."""
        df = self.user_risk_df.copy()
        if df.empty:
            return []
        if risk_level:
            df = df[df['risk_level'] == risk_level]
        if department:
            df = df[df['department'] == department]
        return df[['entity_id', 'department', 'traceone_risk_score', 'risk_level', 'risk_confidence_level']].head(20).to_dict(orient="records")
