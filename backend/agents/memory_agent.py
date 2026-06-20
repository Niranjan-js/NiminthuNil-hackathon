import logging
from typing import Dict, Any, List
from backend.memory.historical_ranker import HistoricalMitigationRanker
from backend.memory.reinforcement_engine import ReinforcementLearningEngine

logger = logging.getLogger("niravan.agents.memory_agent")
rl_engine = ReinforcementLearningEngine()
ranker = HistoricalMitigationRanker(rl_engine)

class MemoryAgent:
    """
    Memory Agent queries similarity indices and historical outcomes to recommend highest-ROI playbooks.
    """
    def recommend_mitigations(self, incident_title: str) -> Dict[str, Any]:
        recommendations = ranker.rank_mitigations(incident_title)
        return {
            "status": "success",
            "recommended_playbooks": recommendations,
            "best_playbook": recommendations[0]["playbook"] if recommendations else None
        }
