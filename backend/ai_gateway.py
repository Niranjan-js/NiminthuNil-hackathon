import os
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ai_gateway")

class AIGateway:
    """
    AI Model Abstraction Layer.
    Ensures that NIRAVAN can easily switch underlying LLM models
    (Anthropic, OpenAI, Gemini, local Ollama, etc.) without altering
    the core application codebase.
    """
    
    @staticmethod
    def get_model_provider() -> str:
        """Determines active AI provider based on environment variables."""
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
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
        model_name = os.environ.get("AI_MODEL_NAME")
        
        if provider == "anthropic":
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
                
                # Default to Claude 3.5 Sonnet
                model = model_name or "claude-3-5-sonnet-20241022"
                
                messages = [{"role": "user", "content": prompt}]
                
                kwargs = {
                    "model": model,
                    "max_tokens": 4000,
                    "messages": messages,
                    "temperature": 0.2
                }
                if system_prompt:
                    kwargs["system"] = system_prompt
                    
                response = client.messages.create(**kwargs)
                return response.content[0].text or ""
            except Exception as e:
                logger.error(f"[AIGateway] Anthropic API failed: {e}. Falling back to offline.")
                
        elif provider == "openai":
            try:
                import openai
                client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})
                
                response = client.chat.completions.create(
                    model=model_name or "gpt-4o-mini",
                    messages=messages,
                    temperature=0.2
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"[AIGateway] OpenAI API failed: {e}. Falling back to offline.")
                
        elif provider == "gemini":
            try:
                import requests
                api_key = os.environ.get("GEMINI_API_KEY")
                # Default to gemini-1.5-flash
                model = model_name or "gemini-1.5-flash"
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                headers = {"Content-Type": "application/json"}
                data = {
                    "contents": [{"parts": [{"text": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt}]}]
                }
                res = requests.post(url, headers=headers, json=data, timeout=10)
                if res.ok:
                    res_json = res.json()
                    return res_json["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                logger.error(f"[AIGateway] Gemini API failed: {e}. Falling back to offline.")
                
        # Offline fallback or Ollama logic placeholder
        return ""

    @staticmethod
    def generate_completion_with_tools(prompt: str, tools: List[Dict[str, Any]], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """
        Claude tool-use completion routing.
        Returns the parsed message content and any tool calls generated.
        """
        provider = AIGateway.get_model_provider()
        
        if provider == "anthropic":
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
                model = os.environ.get("AI_MODEL_NAME", "claude-3-5-sonnet-20241022")
                
                kwargs = {
                    "model": model,
                    "max_tokens": 4000,
                    "messages": [{"role": "user", "content": prompt}],
                    "tools": tools,
                    "temperature": 0.2
                }
                if system_prompt:
                    kwargs["system"] = system_prompt
                    
                response = client.messages.create(**kwargs)
                
                text_content = ""
                tool_calls = []
                
                for content_block in response.content:
                    if content_block.type == "text":
                        text_content += content_block.text
                    elif content_block.type == "tool_use":
                        tool_calls.append({
                            "id": content_block.id,
                            "name": content_block.name,
                            "input": content_block.input
                        })
                        
                return {
                    "text": text_content,
                    "tool_calls": tool_calls,
                    "stop_reason": response.stop_reason
                }
            except Exception as e:
                logger.error(f"[AIGateway] Anthropic Tool-Use API failed: {e}")
                
        # If no Anthropic key or failed, return empty structured response for offline routing
        return {
            "text": "",
            "tool_calls": [],
            "stop_reason": "failed_or_offline"
        }
