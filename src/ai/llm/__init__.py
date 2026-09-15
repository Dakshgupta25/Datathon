"""
TraceONE LLM Provider Abstraction Subpackage.
Exposes LLMProvider, OllamaProvider, MistralProvider, MockProvider, and provider factory functions.
"""

from src.ai.llm.provider import LLMProvider
from src.ai.llm.ollama_provider import OllamaProvider
from src.ai.llm.mistral_provider import MistralProvider
from src.ai.llm.mock_provider import MockProvider
from src.ai.config import AIConfig


def get_provider(provider_name: str = None) -> LLMProvider:
    """
    Factory function to return requested LLM provider.
    Defaults to AIConfig.LLM_PROVIDER ('ollama').
    """
    name = (provider_name or AIConfig.LLM_PROVIDER or "ollama").lower().strip()
    
    if name == "mistral":
        return MistralProvider()
    elif name == "mock":
        return MockProvider()
    else:
        # Default to Ollama provider
        return OllamaProvider()


__all__ = [
    "LLMProvider",
    "OllamaProvider",
    "MistralProvider",
    "MockProvider",
    "get_provider"
]
