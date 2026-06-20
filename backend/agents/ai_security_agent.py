import logging
from typing import Dict, Any
from backend.ai_security.prompt_guard import PromptGuard

logger = logging.getLogger("niravan.agents.ai_security_agent")

class AISecurityAgent:
    """
    AI Security Agent monitors interactions with the copilot, enforcing firewalls against injection and leakage.
    """
    def check_input_safety(self, prompt: str) -> Dict[str, Any]:
        res = PromptGuard.inspect_prompt(prompt)
        score = 0.95 if not res["safe"] else 0.05
        return {
            "status": "success",
            "score": score,
            "guard_action": res["action"],
            "reason": res["reason"]
        }
