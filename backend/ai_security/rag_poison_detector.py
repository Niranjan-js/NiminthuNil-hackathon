import re
from typing import Dict, Any

class RAGPoisonDetector:
    ADVERSARIAL_INSTRUCTIONS = [
        r"do\s+not\s+mention\s+this\s+vulnerability",
        r"flag\s+this\s+incident\s+as\s+false\s+positive",
        r"override\s+incident\s+severity",
        r"force\s+critical\s+threat\s+to\s+low"
    ]

    @classmethod
    def scan_document(cls, text: str) -> Dict[str, Any]:
        """Scans external RAG text/documents for poisoned instructions trying to manipulate the LLM's responses."""
        lower_text = text.lower()
        for pattern in cls.ADVERSARIAL_INSTRUCTIONS:
            if re.search(pattern, lower_text):
                return {
                    "poisoned": True,
                    "reason": f"Adversarial instruction pattern matched: '{pattern}'",
                    "confidence": 0.95
                }
        return {"poisoned": False, "reason": "No poisoned instructions found.", "confidence": 0.0}
