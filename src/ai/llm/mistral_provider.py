"""
Mistral Cloud API Provider for TraceONE AI Investigator.
Uses the official mistralai SDK (mistralai.client.Mistral) to interact with Mistral Cloud models (default: mistral-small-latest).
Enforces strict API key privacy, error handling, rate-limit safety, and non-blocking status checks.
"""

import os
import json
from src.ai.config import AIConfig
from src.ai.llm.provider import LLMProvider


class MistralProvider(LLMProvider):

    def __init__(self, api_key: str = None, model: str = None, timeout: int = None):
        self.api_key = (api_key if api_key is not None else AIConfig.MISTRAL_API_KEY).strip()
        self.model = model or AIConfig.MISTRAL_MODEL or "mistral-small-latest"
        self.timeout = timeout or AIConfig.TIMEOUT
        self._client = None

    def _has_sdk(self) -> bool:
        """Dynamically check if mistralai.client package is installed."""
        try:
            from mistralai.client import Mistral
            return True
        except ImportError:
            return False

    def _get_client(self):
        """Lazy instantiation of Mistral SDK client."""
        if not self._has_sdk():
            return None
        if not self.api_key:
            return None
        if self._client is None:
            try:
                from mistralai.client import Mistral
                self._client = Mistral(api_key=self.api_key)
            except Exception:
                self._client = None
        return self._client

    def status(self) -> str:
        """
        Return human-readable provider status string:
        - 'NOT_CONFIGURED': Missing API Key
        - 'SDK_MISSING': mistralai package not installed
        - 'CONFIGURED': Valid API Key present
        """
        if not self._has_sdk():
            return "SDK_MISSING"
        if not self.api_key:
            return "NOT_CONFIGURED"
        return "CONFIGURED"

    def health_check(self) -> bool:
        """Lightweight check to verify if Mistral API key is configured and SDK available."""
        return self._has_sdk() and bool(self.api_key)

    def get_available_models(self) -> list:
        """Return supported Mistral model list."""
        return ["mistral-small-latest", "mistral-medium-latest", "mistral-large-latest", "open-mixtral-8x7b"]

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Send generation request to Mistral Cloud API."""
        if not self._has_sdk():
            return "MISTRAL_UNAVAILABLE_ERROR: mistralai Python package is not installed. Please run 'pip install mistralai'."

        if not self.api_key:
            return "MISTRAL_UNAVAILABLE_ERROR: Mistral API key is not configured. Please set the MISTRAL_API_KEY environment variable or switch to Qwen3:8B Local."

        client = self._get_client()
        if not client:
            return "MISTRAL_UNAVAILABLE_ERROR: Failed to initialize Mistral client."

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = client.chat.complete(
                model=self.model,
                messages=messages,
                temperature=0.1
            )
            
            if response and response.choices and len(response.choices) > 0:
                content = response.choices[0].message.content
                if isinstance(content, list):
                    content = "".join([chunk.get("text", "") if isinstance(chunk, dict) else str(chunk) for chunk in content])
                return str(content).strip()
            return "MISTRAL_UNAVAILABLE_ERROR: Received empty response from Mistral API."

        except Exception as e:
            err_msg = str(e).lower()
            if "401" in err_msg or "unauthorized" in err_msg or "invalid api key" in err_msg:
                return "MISTRAL_UNAVAILABLE_ERROR: Invalid Mistral API key (401 Unauthorized). Please check MISTRAL_API_KEY environment variable."
            elif "429" in err_msg or "rate limit" in err_msg or "quota" in err_msg:
                return "MISTRAL_UNAVAILABLE_ERROR: Mistral API rate limit exceeded (429 Rate Limited). Please try again later or switch to Qwen3:8B Local."
            elif "timeout" in err_msg or "connect" in err_msg or "unreachable" in err_msg:
                return "MISTRAL_UNAVAILABLE_ERROR: Could not reach Mistral Cloud API. Please check your internet connection or switch to Qwen3:8B Local."
            else:
                return f"MISTRAL_UNAVAILABLE_ERROR: Mistral API request failed ({e}). Switch to Qwen3:8B Local."
