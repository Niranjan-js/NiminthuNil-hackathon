from typing import List, Dict, Any
from .reinforcement_engine import ReinforcementLearningEngine

class HistoricalMitigationRanker:
    def __init__(self, rl_engine: ReinforcementLearningEngine):
        self.rl = rl_engine

    def rank_mitigations(self, incident_title: str) -> List[Dict[str, Any]]:
        # Proposes mitigations ranked by historical success
        options = ["Isolate Host", "Block IP", "Reset Password", "Reboot Service"]
        ranked = []
        for opt in options:
            success_rate = self.rl.get_playbook_success_rate(opt)
            # Recommending playbook
            ranked.append({
                "playbook": opt,
                "confidence_score": success_rate,
                "reason": f"Historical success rate of {success_rate * 100}%"
            })
        ranked.sort(key=lambda x: x["confidence_score"], reverse=True)
        return ranked
