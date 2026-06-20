import math
from typing import Dict, Any

class DNSTunnelingAnalyzer:
    @staticmethod
    def inspect_query(domain: str) -> Dict[str, Any]:
        """Measures character entropy of subdomains to identify high-data DNS tunneling payloads."""
        subdomain = domain.split(".", 1)[0]
        if not subdomain:
            return {"tunneling_detected": False, "entropy": 0.0}

        # Calculate character entropy
        length = len(subdomain)
        counts = {}
        for char in subdomain:
            counts[char] = counts.get(char, 0) + 1

        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)

        tunneling = entropy > 4.2 and length > 25
        return {
            "query": domain,
            "subdomain_length": length,
            "subdomain_entropy": round(entropy, 3),
            "tunneling_detected": tunneling,
            "alerts": ["DNS Tunneling C2 Channel Suspicion"] if tunneling else []
        }
