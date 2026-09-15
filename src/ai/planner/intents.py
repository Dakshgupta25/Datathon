"""
Supported Natural Language Intents & Query Plan Schema for TraceONE AI Investigator.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional

SUPPORTED_INTENTS = [
    "investigate_entity",
    "compare_entities",
    "find_high_risk_entities",
    "find_anomalous_users",
    "find_anomalous_hosts",
    "analyze_temporal_sequence",
    "analyze_shared_ip",
    "explain_risk",
    "explain_cluster",
    "peer_comparison",
    "graph_relationship",
    "data_quality_question",
    "provenance_question",
    "general_security_summary",
    "unknown_intent"
]

@dataclass
class StructuredQueryPlan:
    intent: str
    entity_type: Optional[str] = None  # 'user', 'host', 'ip', 'session', 'sequence', 'cluster'
    entity_id: Optional[str] = None
    time_range: Optional[str] = None
    filters: Dict = field(default_factory=dict)
    metrics: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    visualization: str = "text_summary"

    def to_dict(self) -> dict:
        return {
            "intent": self.intent,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "time_range": self.time_range,
            "filters": self.filters,
            "metrics": self.metrics,
            "tools": self.tools,
            "visualization": self.visualization
        }
