from typing import Dict, Any, List

class ProbabilityEngine:
    @staticmethod
    def calculate_conditional_probabilities(incidents: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculates historical probabilities of threats given a source asset type or incident category."""
        category_counts = {}
        compromise_counts = {}
        for inc in incidents:
            cat = inc.get("category", "General")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            if inc.get("severity") in ["critical", "high"]:
                compromise_counts[cat] = compromise_counts.get(cat, 0) + 1
        
        rates = {}
        for cat, count in category_counts.items():
            comp_count = compromise_counts.get(cat, 0)
            rates[cat] = round((comp_count + 1) / (count + 2), 3)  # Laplace smoothing
        return rates
