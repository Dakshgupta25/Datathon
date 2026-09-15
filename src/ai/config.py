"""
TraceONE AI Investigator Configuration
Provides environment variable overrides, local .env loader, and provider settings for local Ollama and Mistral Cloud LLM orchestration.
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


class AIConfig:
    LLM_PROVIDER: str = os.getenv("TRACEONE_LLM_PROVIDER", "ollama").lower()
    LLM_MODEL: str = os.getenv("TRACEONE_LLM_MODEL", "qwen3:8b")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    
    MISTRAL_API_KEY: str = os.getenv("MISTRAL_API_KEY", "")
    MISTRAL_MODEL: str = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
    
    TIMEOUT: int = int(os.getenv("TRACEONE_LLM_TIMEOUT", "30"))

    @classmethod
    def to_dict(cls) -> dict:
        return {
            "provider": cls.LLM_PROVIDER,
            "model": cls.LLM_MODEL,
            "ollama_url": cls.OLLAMA_BASE_URL,
            "mistral_model": cls.MISTRAL_MODEL,
            "has_mistral_key": bool(cls.MISTRAL_API_KEY.strip()),
            "timeout": cls.TIMEOUT
        }
