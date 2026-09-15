"""
TraceONE AI Investigator Configuration
Provides environment variable overrides and provider settings for local LLM orchestration.
"""

import os

class AIConfig:
    LLM_PROVIDER: str = os.getenv("TRACEONE_LLM_PROVIDER", "ollama")
    LLM_MODEL: str = os.getenv("TRACEONE_LLM_MODEL", "qwen3:8b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    TIMEOUT: int = int(os.getenv("TRACEONE_LLM_TIMEOUT", "30"))

    @classmethod
    def to_dict(cls) -> dict:
        return {
            "provider": cls.LLM_PROVIDER,
            "model": cls.LLM_MODEL,
            "ollama_url": cls.OLLAMA_BASE_URL,
            "timeout": cls.TIMEOUT
        }
