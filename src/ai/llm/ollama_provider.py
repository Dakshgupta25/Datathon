"""
Ollama Provider for TraceONE AI Investigator.
Connects to local Ollama server (http://localhost:11434) running qwen3:8b using standard urllib HTTP requests.
Handles timeouts, model checks, and graceful fallback errors without crashing the dashboard.
"""

import urllib.request
import json
import socket
from src.ai.config import AIConfig
from src.ai.llm.provider import LLMProvider


class OllamaProvider(LLMProvider):

    def __init__(self, base_url: str = None, model: str = None, timeout: int = None):
        self.base_url = (base_url or AIConfig.OLLAMA_BASE_URL).rstrip('/')
        self.model = model or AIConfig.LLM_MODEL
        self.timeout = timeout or AIConfig.TIMEOUT

    def health_check(self) -> bool:
        """Check if Ollama server is online and reachable."""
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_available_models(self) -> list:
        """Return list of models registered in Ollama."""
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return [m.get('name') for m in data.get('models', [])]
        except Exception:
            return []

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Send generation request to Ollama /api/generate endpoint."""
        url = f"{self.base_url}/api/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            data_bytes = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=data_bytes, headers={"Content-Type": "application/json"})
            
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                return result.get('response', '').strip()
                
        except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
            return f"OLLAMA_UNAVAILABLE_ERROR: Could not reach Ollama at {self.base_url} ({e})"
        except Exception as e:
            return f"OLLAMA_GENERATION_ERROR: {e}"
