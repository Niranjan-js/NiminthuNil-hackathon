from typing import List, Dict, Any

class IncidentMemoryCache:
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}

    def cache_incident_remediation(self, incident_id: str, playbook: str, outcome: str, success: bool):
        self._cache[incident_id] = {
            "playbook": playbook,
            "outcome": outcome,
            "success": success,
            "feedback_rating": 5.0 if success else 1.0
        }

    def get_resolution_history(self) -> Dict[str, Dict[str, Any]]:
        return self._cache
