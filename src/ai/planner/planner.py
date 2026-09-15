"""
Query Planner for TraceONE AI Investigator.
Converts natural language user requests into a strict, validated StructuredQueryPlan JSON object.
Never executes unrestricted Python or SQL.
"""

import re
import json
from typing import Optional, Dict, Any, List
from src.ai.planner.intents import SUPPORTED_INTENTS, StructuredQueryPlan
from src.ai.llm.provider import LLMProvider



class QueryPlanner:

    def __init__(self, llm_provider: LLMProvider):
        self.llm = llm_provider

    def plan(self, user_query: str, active_context_entity: str = None) -> StructuredQueryPlan:
        query_clean = user_query.strip()
        query_lower = query_clean.lower()

        # Extract explicit entity present in query text
        extracted_entity = self._extract_entity_id(query_clean)

        # Resolve context entity only if query is a contextual follow-up
        context_entity = self._resolve_context_entity(query_lower, extracted_entity, active_context_entity)

        target_entity = extracted_entity or context_entity

        # Fast Deterministic Intent & Entity Extractor Pass
        # 1. Critical Users / High Risk Entities / Global Aggregations (Check before peer comparison)
        if "critical" in query_lower or "high risk" in query_lower or "high-risk" in query_lower or "anomalous users" in query_lower or "all critical" in query_lower:
            if not target_entity:
                filters = {"risk_level": "CRITICAL"}
                if "department" in query_lower or "departments" in query_lower or "by department" in query_lower:
                    filters["group_by"] = "department"
                return StructuredQueryPlan(
                    intent="find_high_risk_entities",
                    entity_type="user",
                    entity_id=None,
                    filters=filters,
                    tools=["high_risk_entities"],
                    visualization="bar_chart"
                )

        # 2. Peer comparison (Requires explicit peer/compare keywords)
        if "peer" in query_lower or "compare" in query_lower or "peer comparison" in query_lower:
            return StructuredQueryPlan(
                intent="peer_comparison",
                entity_type="user" if target_entity else None,
                entity_id=target_entity,
                tools=["peer_comparison", "risk"],
                visualization="bar_chart"
            )

        # 3. Shared IP / Graph / Connections
        if "shared ip" in query_lower or "same ip" in query_lower or "connected" in query_lower or "graph" in query_lower or "relationship" in query_lower:
            return StructuredQueryPlan(
                intent="analyze_shared_ip" if "ip" in query_lower else "graph_relationship",
                entity_type="user" if target_entity else None,
                entity_id=target_entity,
                tools=["shared_ip", "graph", "provenance"],
                visualization="graph"
            )

        # 4. Temporal Sequence / Burst / Timeline
        if "sequence" in query_lower or "timeline" in query_lower or "burst" in query_lower or "followed by" in query_lower:
            return StructuredQueryPlan(
                intent="analyze_temporal_sequence",
                entity_type="user" if target_entity else None,
                entity_id=target_entity,
                tools=["temporal", "authentication", "endpoint"],
                visualization="timeline"
            )

        # 5. Data Quality / Limitations / Trust
        if "data quality" in query_lower or "limitation" in query_lower or "trust" in query_lower or "missing" in query_lower or "timestamp" in query_lower:
            return StructuredQueryPlan(
                intent="data_quality_question",
                entity_type=None,
                entity_id=None,
                tools=["data_quality", "provenance"],
                visualization="table"
            )

        # 6. Entity Investigation / Why High Risk / Behavioral Anomalies
        if target_entity:
            return StructuredQueryPlan(
                intent="investigate_entity",
                entity_type="host" if target_entity.startswith("VDR") or target_entity.startswith("WS") or target_entity.startswith("LPT") else "user",
                entity_id=target_entity,
                tools=["risk", "behavior", "peer", "temporal", "graph", "provenance"],
                visualization="investigation_summary"
            )

        # LLM Reasoning Fallback for Complex Intent Parsing
        try:
            prompt = f"Parse the user security investigation query into a query plan JSON:\nQuery: \"{user_query}\"\nContext Entity: {context_entity}"
            schema_desc = json.dumps({
                "intent": "one of " + ", ".join(SUPPORTED_INTENTS),
                "entity_type": "user or host or null",
                "entity_id": "resolved entity ID string or null",
                "tools": ["list of tool names"],
                "visualization": "one of bar_chart, timeline, graph, table, investigation_summary, text_summary"
            })
            plan_dict = self.llm.generate_structured(prompt, schema_description=schema_desc)
            if isinstance(plan_dict, dict) and "intent" in plan_dict and plan_dict["intent"] in SUPPORTED_INTENTS:
                return StructuredQueryPlan(
                    intent=plan_dict.get("intent", "general_security_summary"),
                    entity_type=plan_dict.get("entity_type"),
                    entity_id=plan_dict.get("entity_id") or context_entity,
                    tools=plan_dict.get("tools", ["user_risk"]),
                    visualization=plan_dict.get("visualization", "text_summary")
                )
        except Exception:
            pass

        return StructuredQueryPlan(
            intent="general_security_summary",
            entity_type=None,
            entity_id=context_entity,
            tools=["user_risk"],
            visualization="text_summary"
        )

    def _resolve_context_entity(self, query_lower: str, extracted_entity: Optional[str], active_context_entity: Optional[str]) -> Optional[str]:
        """Resolve previous entity context ONLY when query explicitly references it via contextual language."""
        if extracted_entity:
            return None
        if not active_context_entity:
            return None

        # Contextual indicators that refer to the previously investigated entity
        context_indicators = [
            "his", "her", "their", "its",
            "this user", "that user", "this host", "that host", "that ip", "this ip",
            "that entity", "this entity", "that sequence",
            "he ", "him ", "she ",
            "same ip", "connected to that", "what about", "how about", "tell me more"
        ]

        if any(ind in query_lower for ind in context_indicators):
            return active_context_entity

        return None

    def _extract_entity_id(self, text: str) -> Optional[str]:
        """Extract user ID (EMP...), host ID (VDR.../WS.../LPT...), IP, sequence ID, or custom entity tokens from text."""
        # User ID (EMP...)
        m_user = re.search(r'\b(EMP\d+)\b', text, re.IGNORECASE)
        if m_user:
            return m_user.group(1).upper()

        # Host ID (VDR... / WS... / LPT...)
        m_host = re.search(r'\b(VDR-\d+|WS-\d+|LPT-\d+|VDR_\d+|WS_\d+|LPT_\d+)\b', text, re.IGNORECASE)
        if m_host:
            return m_host.group(1).upper().replace('_', '-')

        # Custom Entity tokens (e.g., USER_XYZ, DOES_NOT_EXIST, HOST_ABC)
        m_custom = re.search(r'\b(USER_[A-Z0-9_\-]+|HOST_[A-Z0-9_\-]+|DOES_NOT_EXIST|[A-Z]+_\d{5,})\b', text, re.IGNORECASE)
        if m_custom:
            return m_custom.group(1).upper()

        # Named Host extraction (e.g., "host MYHOST")
        m_host_named = re.search(r'\bhost\s+([A-Za-z0-9_\-]+)\b', text, re.IGNORECASE)
        if m_host_named:
            return m_host_named.group(1).upper()

        # Sequence ID
        m_seq = re.search(r'\b(SEQ-[A-Z]+-\d+|SEQ_\d+)\b', text, re.IGNORECASE)
        if m_seq:
            return m_seq.group(1).upper()

        # IP Address
        m_ip = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        if m_ip:
            return m_ip.group(1)

        return None



