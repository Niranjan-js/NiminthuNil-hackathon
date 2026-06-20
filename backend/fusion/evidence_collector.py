from typing import Dict, Any

class EvidenceCollector:
    def __init__(self):
        self.evidence: Dict[str, float] = {}

    def collect_agent_evidence(self, agent_name: str, confidence_score: float):
        """Stores reports from specialist agents for Bayesian correlation."""
        self.evidence[agent_name] = max(0.0, min(1.0, confidence_score))

    def flush(self):
        self.evidence.clear()
