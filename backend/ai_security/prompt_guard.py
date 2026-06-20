import re
from typing import Dict, Any

class PromptGuard:
    INJECTION_PATTERNS = [
        r"ignore\s+previous\s+instructions",
        r"reveal\s+system\s+prompt",
        r"you\s+are\s+now\s+a\s+malicious",
        r"override\s+safety\s+guidelines",
        r"jailbreak",
        r"ignore\s+rules",
        r"forget\s+everything"
    ]

    @classmethod
    def inspect_prompt(cls, prompt: str) -> Dict[str, Any]:
        cleaned = prompt.lower().strip()
        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, cleaned):
                return {
                    "safe": False,
                    "reason": f"Prompt injection detected: matched safety pattern '{pattern}'",
                    "action": "BLOCK"
                }
        return {"safe": True, "reason": "No anomalies found.", "action": "ALLOW"}
