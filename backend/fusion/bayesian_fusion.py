import math
from typing import Dict, List, Any

class BayesianFusion:
    def __init__(self, prior_probability: float = 0.05):
        self.prior = prior_probability

    @staticmethod
    def prob_to_odds(p: float) -> float:
        p = max(0.0001, min(0.9999, p))
        return p / (1.0 - p)

    @staticmethod
    def odds_to_prob(o: float) -> float:
        return o / (1.0 + o)

    def fuse_evidence(self, agent_confidences: Dict[str, float]) -> Dict[str, Any]:
        """Combines multiple independent agent probability assessments using log-odds Bayesian updating."""
        if not agent_confidences:
            return {"confidence": self.prior, "severity": "low"}

        prior_odds = self.prob_to_odds(self.prior)
        total_log_odds = math.log(prior_odds)

        for agent, prob in agent_confidences.items():
            # Treat the agent confidence as posterior P(T | Agent_i)
            prob_cal = max(0.01, min(0.99, prob))
            agent_odds = self.prob_to_odds(prob_cal)
            # Log-likelihood contribution
            total_log_odds += (math.log(agent_odds) - math.log(prior_odds))

        fused_prob = self.odds_to_prob(math.exp(total_log_odds))
        fused_prob = round(fused_prob, 3)

        severity = "low"
        if fused_prob >= 0.85:
            severity = "critical"
        elif fused_prob >= 0.60:
            severity = "high"
        elif fused_prob >= 0.30:
            severity = "medium"

        return {
            "confidence": fused_prob,
            "severity": severity,
            "inputs": agent_confidences
        }
