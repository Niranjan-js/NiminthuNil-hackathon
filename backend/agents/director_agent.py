import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.director_agent")

class DirectorAgent:
    """
    Director Agent acts as the swarm commander, decomposing cases into sub-tasks
    and delegating them to appropriate specialist agents.
    """
    def delegate_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        title = incident_data.get("title", "").lower()
        delegation_plan = []

        # Route dynamically
        if "modbus" in title or "ics" in title or "bacnet" in title:
            delegation_plan.extend(["OTAgent", "NetworkAgent"])
        elif "malware" in title or "trojan" in title or "mimikatz" in title:
            delegation_plan.extend(["MalwareAgent", "ForensicsAgent"])
        elif "cloud" in title or "s3" in title:
            delegation_plan.extend(["CloudAgent", "IdentityAgent"])
        else:
            delegation_plan.extend(["HunterAgent", "ForensicsAgent"])

        return {
            "status": "success",
            "delegation_plan": delegation_plan,
            "orchestrated_by": "DirectorAgent 3.0"
        }
