from typing import List, Dict, Any

class APTAttributionEngine:
    @staticmethod
    def correlate_ttps_to_actor(ttps: List[str]) -> Dict[str, Any]:
        """Compares observed incident techniques with target threat actor profiles."""
        apt29_sigs = ["T1566", "T1059.001", "T1003.001"]
        matches = [t for t in ttps if t in apt29_sigs]
        confidence = len(matches) / len(apt29_sigs) if apt29_sigs else 0.0

        return {
            "matched_actor": "APT29" if confidence >= 0.6 else "Unknown Actor Group",
            "similarity_score": round(confidence, 2),
            "signature_hits": matches
        }
