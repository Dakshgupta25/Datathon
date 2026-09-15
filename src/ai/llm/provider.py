"""
Abstract Base Class for TraceONE LLM Providers.
Keeps AI Investigator independent of Ollama or specific model implementation details.
"""

from abc import ABC, abstractmethod
import json


class LLMProvider(ABC):

    @abstractmethod
    def health_check(self) -> bool:
        """Check if LLM backend server is reachable."""
        pass

    def check_health(self) -> bool:
        """Alias for health_check()."""
        return self.health_check()


    @abstractmethod
    def get_available_models(self) -> list:
        """Return list of available local models."""
        pass

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate free-form text response."""
        pass

    def generate_structured(self, prompt: str, schema_description: str = None, system_prompt: str = None) -> dict:
        """Generate structured JSON response parsed into dict."""
        full_prompt = prompt
        if schema_description:
            full_prompt += f"\n\nReturn ONLY a valid JSON object strictly matching this schema:\n{schema_description}\nDo NOT wrap in markdown code blocks."

        raw_output = self.generate(full_prompt, system_prompt=system_prompt)

        # Clean markdown code blocks if present
        clean_str = raw_output.strip()
        if clean_str.startswith("```json"):
            clean_str = clean_str[7:]
        elif clean_str.startswith("```"):
            clean_str = clean_str[3:]
        if clean_str.endswith("```"):
            clean_str = clean_str[:-3]
        clean_str = clean_str.strip()

        try:
            return json.loads(clean_str)
        except Exception:
            # Try finding first { and last }
            start = clean_str.find("{")
            end = clean_str.rfind("}")
            if start != -1 and end != -1:
                try:
                    return json.loads(clean_str[start:end+1])
                except Exception:
                    pass
            return {"error": "Failed to parse structured JSON from LLM", "raw": raw_output}
