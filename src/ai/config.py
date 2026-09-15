"""
TraceONE AI Investigator Configuration
Provides environment variable overrides, local .env loader, Streamlit secrets lookup, and provider settings for local Ollama and Mistral Cloud LLM orchestration.
"""

import os
from pathlib import Path

# Load local .env file if present (without overwriting explicit environment variables)
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if env_path.exists():
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass


class _AIConfigMeta(type):
    @property
    def LLM_PROVIDER(cls) -> str:
        return cls.get_provider_name()

    @property
    def MISTRAL_API_KEY(cls) -> str:
        return cls.get_mistral_key()


class AIConfig(metaclass=_AIConfigMeta):
    LLM_MODEL: str = os.getenv("TRACEONE_LLM_MODEL", "qwen3:8b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    MISTRAL_MODEL: str = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
    TIMEOUT: int = int(os.getenv("TRACEONE_LLM_TIMEOUT", "30"))

    @classmethod
    def get_mistral_key(cls) -> str:
        """
        Safely retrieve Mistral API Key from environment or Streamlit secrets.
        Never hardcodes, prints, logs, or leaks the key.
        """
        key = os.getenv("MISTRAL_API_KEY", "").strip()
        if not key:
            try:
                import streamlit as st
                if hasattr(st, "secrets"):
                    if "MISTRAL_API_KEY" in st.secrets:
                        key = str(st.secrets["MISTRAL_API_KEY"]).strip()
                    elif "mistral" in st.secrets and "api_key" in st.secrets["mistral"]:
                        key = str(st.secrets["mistral"]["api_key"]).strip()
            except Exception:
                pass
        return key

    @classmethod
    def get_provider_name(cls) -> str:
        """Determine default LLM provider name ('mistral' or 'ollama')."""
        override = os.getenv("TRACEONE_LLM_PROVIDER")
        if override:
            return override.lower()
        if cls.get_mistral_key():
            return "mistral"
        return "ollama"

    @classmethod
    def to_dict(cls) -> dict:
        return {
            "provider": cls.get_provider_name(),
            "model": cls.LLM_MODEL,
            "ollama_url": cls.OLLAMA_BASE_URL,
            "mistral_model": cls.MISTRAL_MODEL,
            "has_mistral_key": bool(cls.get_mistral_key()),
            "timeout": cls.TIMEOUT
        }
