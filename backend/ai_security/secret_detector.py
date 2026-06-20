import re
from typing import List, Dict, Any

class SecretDetector:
    # Scan for common secrets (AWS API keys, private keys, generic password fields)
    PATTERNS = {
        "AWS_KEY": r"\b(AKIA|ASCA|AAAA)[A-Z0-9]{16}\b",
        "PRIVATE_KEY": r"-----BEGIN\s+([A-Z0-9\s_]+)\s+PRIVATE\s+KEY-----",
        "PASSWORD_IN_URL": r"mongodb\+srv://[^:]+:([^@]+)@"
    }

    @classmethod
    def scan_for_secrets(cls, text: str) -> List[Dict[str, Any]]:
        found = []
        for name, regex in cls.PATTERNS.items():
            matches = re.finditer(regex, text, re.IGNORECASE)
            for m in matches:
                found.append({
                    "type": name,
                    "secret": m.group(0),
                    "start": m.start(),
                    "end": m.end()
                })
        return found
