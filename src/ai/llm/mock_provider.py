"""
Mock Provider for TraceONE AI Investigator.
Used in unit testing and offline fallback mode. Guarantees deterministic LLM responses without network calls.
"""

import json
from src.ai.llm.provider import LLMProvider


class MockProvider(LLMProvider):

    def __init__(self, mock_responses: dict = None):
        self.mock_responses = mock_responses or {}

    def health_check(self) -> bool:
        return True

    def get_available_models(self) -> list:
        return ["qwen3:8b", "mock_model"]

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        prompt_lower = prompt.lower()
        
        # Check custom mock responses
        for key, resp in self.mock_responses.items():
            if key.lower() in prompt_lower:
                return resp
                
        # Default deterministic mock responses for intent parsing or query summaries
        if "structured" in prompt_lower or "schema" in prompt_lower or "intent" in prompt_lower:
            if "emp10194" in prompt_lower:
                return json.dumps({
                    "intent": "investigate_entity",
                    "entity_type": "user",
                    "entity_id": "EMP10194",
                    "time_range": "2026-08-01 → 2026-08-15",
                    "filters": {},
                    "tools": ["risk", "behavior", "peer", "temporal", "graph", "provenance"],
                    "visualization": "investigation_summary"
                })
            elif "r&d" in prompt_lower or "peers" in prompt_lower:
                return json.dumps({
                    "intent": "peer_comparison",
                    "entity_type": "user",
                    "entity_id": "EMP10194",
                    "time_range": None,
                    "filters": {"department": "R&D"},
                    "tools": ["peer_comparison"],
                    "visualization": "bar_chart"
                })
            elif "shared ip" in prompt_lower or "ip" in prompt_lower:
                return json.dumps({
                    "intent": "analyze_shared_ip",
                    "entity_type": "user",
                    "entity_id": "EMP10194",
                    "time_range": None,
                    "filters": {},
                    "tools": ["shared_ip", "graph"],
                    "visualization": "graph"
                })
            else:
                return json.dumps({
                    "intent": "general_security_summary",
                    "entity_type": None,
                    "entity_id": None,
                    "time_range": None,
                    "filters": {},
                    "tools": ["user_risk"],
                    "visualization": "table"
                })
                
        if "not_found" in prompt_lower or "zero telemetry events exist" in prompt_lower:
            return "No matching telemetry or entity record was found in canonical indexes."

        return "Deterministic Mock Explanation: Based on supplied telemetry evidence, entity displays elevated behavioral deviations."

