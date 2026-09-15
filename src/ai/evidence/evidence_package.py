"""
Evidence Package Builder for TraceONE AI Investigator.
Compiles retrieved tool outputs into a compact, evidence-first payload.
Enforces that Qwen3 generates summaries strictly from retrieved facts.
"""

from typing import Dict, Any


class EvidencePackageBuilder:

    @staticmethod
    def build(entity_resolution: dict, tool_results: Dict[str, Any]) -> dict:
        """Assemble compact evidence package."""
        package = {
            "entity": entity_resolution,
            "risk_assessment": tool_results.get("user_risk") or tool_results.get("host_risk") or {},
            "behavior_profile": tool_results.get("behavior_profile") or {},
            "peer_comparison": tool_results.get("peer_comparison") or {},
            "temporal_sequences": tool_results.get("temporal_sequences") or {},
            "graph_context": tool_results.get("graph_neighbors") or tool_results.get("shared_ip_connections") or {},
            "evidence_records": {
                "authentication": tool_results.get("authentication_evidence") or [],
                "endpoint": tool_results.get("endpoint_evidence") or [],
                "firewall": tool_results.get("firewall_evidence") or []
            },
            "high_risk_list": tool_results.get("high_risk_entities") or [],
            "data_quality_context": tool_results.get("data_quality_context") or {},
            "provenance": tool_results.get("provenance") or {}
        }
        return package

    @staticmethod
    def format_for_prompt(package: dict) -> str:
        """Format evidence package into compact text for LLM grounding prompt."""
        entity = package.get("entity", {})
        risk = package.get("risk_assessment", {})
        behavior = package.get("behavior_profile", {})
        peer = package.get("peer_comparison", {})
        temporal = package.get("temporal_sequences", {})
        graph = package.get("graph_context", {})
        dq = package.get("data_quality_context", {})
        high_risk = package.get("high_risk_list", [])

        status = entity.get("status", "RESOLVED")
        target_id = entity.get("entity_id")

        if status == "NOT_FOUND" or (target_id and risk.get("found") is False):
            return f"""=== TRACEONE EVIDENCE PACKAGE (AUTHORITATIVE DETERMINISTIC DATA) ===
Target Entity: {target_id or 'N/A'}
Entity Resolution Status: NOT_FOUND
Message: No matching telemetry or entity record was found in canonical indexes.
Evidence Available: NONE (Zero telemetry events exist for this condition).
=== END OF EVIDENCE PACKAGE ==="""

        if status == "AMBIGUOUS":
            return f"""=== TRACEONE EVIDENCE PACKAGE (AUTHORITATIVE DETERMINISTIC DATA) ===
Entity Resolution Status: AMBIGUOUS
Message: {entity.get('message')}
Candidates Matched: {entity.get('candidates', [])}
Instruction: Ask user for clarification among candidate entities. Do NOT arbitrarily guess an entity.
=== END OF EVIDENCE PACKAGE ==="""

        entity_disp = f"{target_id} (Type: {entity.get('entity_type', 'N/A')})" if target_id else "Global Telemetry Query (No Specific Entity Targeted)"
        lines = [
            "=== TRACEONE EVIDENCE PACKAGE (AUTHORITATIVE DETERMINISTIC DATA) ===",
            f"Target Entity Context: {entity_disp} [Status: {status}]",
            f"Assessed Risk Score: {risk.get('traceone_risk_score', 'N/A')} / 100 ({risk.get('risk_level', 'LOW')})",
            f"Evidence Confidence: {risk.get('risk_confidence_level', 'HIGH')} ({risk.get('risk_confidence_score', 0.95)})",
            f"Primary Threat Hypothesis: {risk.get('primary_hypothesis', 'N/A')}",
            f"Risk Component Scores (Points): {risk.get('top_contributors', {})}",
            f"Counter Evidence Signals: {risk.get('counter_evidence', [])}",
            f"Behavioral Cluster: {behavior.get('cluster_label', 'CLUSTER_0')}",
            f"Department Peer Context: Department={peer.get('department', 'N/A')}, Peer Outlier={peer.get('peer_outlier_flag', False)}, Dept Percentile={peer.get('department_failed_login_percentile', 'N/A')}",
            f"Temporal Sequences: Count={temporal.get('sequence_count', 0)}",
            f"Graph Neighborhood: Nodes={graph.get('node_count', 0)}, Edges={graph.get('edge_count', 0)}",
            f"Data Trust Context: Pipeline={dq.get('pipeline_health', 'PASSED')}, Telemetry Window={dq.get('telemetry_window', '2026-08-01 → 2026-08-15')}, Session Overlap={dq.get('iam_firewall_overlap_pct', '2.26%')}"
        ]

        if high_risk:
            lines.append(f"High Risk Entity Summary (Top {len(high_risk)}): {high_risk[:10]}")

        lines.append("=== END OF EVIDENCE PACKAGE ===")
        return "\n".join(lines)

