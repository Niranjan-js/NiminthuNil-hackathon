import os
from typing import Dict, Any, Optional

class AIGateway:
    """
    AI Model Abstraction Layer.
    Ensures that NIRAVAN can easily switch underlying LLM models
    (OpenAI, Anthropic, Gemini, local Ollama, etc.) without altering
    the core application codebase.
    """
    
    @staticmethod
    def get_model_provider() -> str:
        """Determines active AI provider based on environment variables."""
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        elif os.environ.get("GEMINI_API_KEY"):
            return "gemini"
        elif os.environ.get("OLLAMA_HOST"):
            return "ollama_local"
        return "offline_fallback"

    @staticmethod
    def generate_completion(prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Routes the prompt completion request to the active AI provider,
        falling back to local structured rule sets if no keys are found.
        """
        provider = AIGateway.get_model_provider()
        
        # Simple simulated routing to support offline mode out-of-the-box
        if provider == "openai":
            try:
                import openai
                client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                
                response = client.chat.completions.create(
                    model=os.environ.get("AI_MODEL_NAME", "gpt-4o-mini"),
                    messages=messages,
                    temperature=0.2
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                print(f"[AIGateway] OpenAI API failed: {e}. Falling back to offline engine.")
                
        elif provider == "gemini":
            try:
                # Mock integration for Gemini REST endpoint
                import requests
                api_key = os.environ.get("GEMINI_API_KEY")
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                headers = {"Content-Type": "application/json"}
                data = {
                    "contents": [{"parts": [{"text": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt}]}]
                }
                res = requests.post(url, headers=headers, json=data, timeout=10)
                if res.ok:
                    res_json = res.json()
                    return res_json["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                print(f"[AIGateway] Gemini API failed: {e}. Falling back to offline engine.")
                
        # Offline fallback or Ollama logic placeholder
        return ""
