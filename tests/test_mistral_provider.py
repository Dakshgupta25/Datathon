"""
Unit & Integration Tests for Mistral Provider and Dual LLM Orchestration.
Verifies MistralProvider initialization, status checking, error handling, mock response parsing, API key privacy, and live integration (when MISTRAL_API_KEY is available).
"""

import os
import pytest
from unittest.mock import MagicMock, patch

from src.ai.config import AIConfig
from src.ai.llm.mistral_provider import MistralProvider
from src.ai.llm.ollama_provider import OllamaProvider
from src.ai.llm.mock_provider import MockProvider
from src.ai.llm import get_provider
from src.ai.agent import TraceONEAgent


def test_mistral_provider_initialization():
    """Verify MistralProvider initializes with custom or default model and API key."""
    provider = MistralProvider(api_key="test_secret_key", model="mistral-small-latest")
    assert provider.model == "mistral-small-latest"
    assert provider.api_key == "test_secret_key"
    assert provider.health_check() is True


def test_mistral_provider_missing_key():
    """Verify MistralProvider status and generation behavior when API key is missing."""
    provider = MistralProvider(api_key="")
    assert provider.status() == "NOT_CONFIGURED"
    assert provider.health_check() is False
    
    resp = provider.generate("Test prompt")
    assert "MISTRAL_UNAVAILABLE_ERROR" in resp
    assert "not configured" in resp


def test_mistral_provider_successful_response():
    """Verify MistralProvider successfully parses completion response from mocked SDK client."""
    mock_sdk_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Executive Summary: User EMP10194 exhibits critical authentication risk."
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_sdk_client.chat.complete.return_value = mock_response

    provider = MistralProvider(api_key="mock_key")
    with patch.object(provider, '_get_client', return_value=mock_sdk_client):
        output = provider.generate("Why is EMP10194 high risk?", system_prompt="System safety prompt")
        assert "EMP10194" in output
        assert "critical authentication risk" in output


def test_mistral_provider_structured_json_parsing():
    """Verify generate_structured cleanly strips markdown fences and parses JSON from Mistral."""
    mock_sdk_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = '```json\n{"intent": "investigate_user", "entity_id": "EMP10194"}\n```'
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_sdk_client.chat.complete.return_value = mock_response

    provider = MistralProvider(api_key="mock_key")
    with patch.object(provider, '_get_client', return_value=mock_sdk_client):
        structured = provider.generate_structured("Plan query", schema_description="Return json")
        assert isinstance(structured, dict)
        assert structured.get("intent") == "investigate_user"
        assert structured.get("entity_id") == "EMP10194"


def test_mistral_provider_401_unauthorized():
    """Verify 401 Unauthorized errors are handled gracefully without exposing API keys."""
    mock_sdk_client = MagicMock()
    mock_sdk_client.chat.complete.side_effect = Exception("401 Unauthorized: Invalid API key")

    provider = MistralProvider(api_key="secret_invalid_key_12345")
    with patch.object(provider, '_get_client', return_value=mock_sdk_client):
        output = provider.generate("Test query")
        assert "MISTRAL_UNAVAILABLE_ERROR" in output
        assert "401 Unauthorized" in output
        assert "secret_invalid_key_12345" not in output


def test_mistral_provider_429_rate_limit():
    """Verify 429 Rate Limit errors return a clear human-readable error string."""
    mock_sdk_client = MagicMock()
    mock_sdk_client.chat.complete.side_effect = Exception("429 Rate limit exceeded")

    provider = MistralProvider(api_key="mock_key")
    with patch.object(provider, '_get_client', return_value=mock_sdk_client):
        output = provider.generate("Test query")
        assert "MISTRAL_UNAVAILABLE_ERROR" in output
        assert "429 Rate Limited" in output


def test_mistral_provider_connection_timeout():
    """Verify timeout and connection failure errors return friendly fallback notices."""
    mock_sdk_client = MagicMock()
    mock_sdk_client.chat.complete.side_effect = Exception("Connection timeout while reaching api.mistral.ai")

    provider = MistralProvider(api_key="mock_key")
    with patch.object(provider, '_get_client', return_value=mock_sdk_client):
        output = provider.generate("Test query")
        assert "MISTRAL_UNAVAILABLE_ERROR" in output
        assert "Could not reach Mistral Cloud API" in output


def test_api_key_never_appears_in_logs_or_output():
    """Verify API keys never leak in provider string representations or generation responses."""
    secret_key = "super_secret_mistral_api_token_xyz"
    provider = MistralProvider(api_key=secret_key)
    
    # Check string representations
    assert secret_key not in str(provider)
    assert secret_key not in repr(provider)

    # Check error response
    resp = provider.generate("Query")
    assert secret_key not in resp


def test_provider_factory_and_agent_switching():
    """Verify TraceONEAgent can dynamically switch between Ollama, Mistral, and Mock providers."""
    agent = TraceONEAgent(provider_override=MockProvider())
    assert isinstance(agent.llm, MockProvider)

    # Switch to Mistral provider
    agent.set_provider("mistral")
    assert isinstance(agent.llm, MistralProvider)

    # Switch to Ollama provider
    agent.set_provider("ollama")
    assert isinstance(agent.llm, OllamaProvider)


def test_agent_query_with_mistral_fallback():
    """Verify TraceONEAgent produces valid investigation response package using MistralProvider fallback."""
    provider = MistralProvider(api_key="") # Missing key triggers fallback
    agent = TraceONEAgent(provider_override=provider)

    res = agent.query("Why is EMP10194 high risk?")
    assert res["query"] == "Why is EMP10194 high risk?"
    assert res["entity_resolution"]["status"] == "RESOLVED"
    assert res["evidence_package"]["risk_assessment"]["traceone_risk_score"] > 0
    assert "Executive Summary" in res["answer"]
    assert res["llm_provider"] == "MistralProvider"
    assert res["model_name"] == "mistral-small-latest"


@pytest.mark.skipif(not os.getenv("MISTRAL_API_KEY"), reason="MISTRAL_API_KEY environment variable not set")
def test_live_mistral_integration():
    """Optional live integration test against Mistral API when key is available."""
    api_key = os.getenv("MISTRAL_API_KEY")
    provider = MistralProvider(api_key=api_key)
    
    assert provider.health_check() is True
    output = provider.generate("Hello, state in one word if you are online.")
    assert len(output) > 0
    if "MISTRAL_UNAVAILABLE_ERROR" in output:
        assert ("429 Rate Limited" in output or "401" in output or "quota" in output.lower())
    else:
        assert len(output) > 0
