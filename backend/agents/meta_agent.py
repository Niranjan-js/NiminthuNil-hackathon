import logging
from typing import List

logger = logging.getLogger("niravan.agents.meta_agent")

class MetaAgent:
    """
    Meta Agent dynamically determines the most effective subset of specialized agents
    to run for a given incident. This prevents wasted computational resources (and LLM API costs)
    for low-priority alerts, while ensuring full-coverage analysis for critical incidents.
    """

    @staticmethod
    def select_agents_to_run(severity: str, incident_type: str) -> List[str]:
        """
        Returns a list of agent identifiers that should be executed for the incident.
        """
        severity = (severity or "low").lower()
        incident_type = (incident_type or "").lower()
        
        # Base agents that always run for any incident
        selected = ["threat_analyst", "mitigation_agent"]
        
        if severity == "low":
            # For low severity, only need threat analysis and basic mitigation recommendation
            pass
        elif severity == "medium":
            # Medium severity gets impact analysis and compliance check
            selected.extend(["impact_agent", "compliance_agent"])
        elif severity == "high" or severity == "critical" or "ransomware" in incident_type or "apt" in incident_type:
            # High/critical or specific advanced threats trigger the full agent swarm
            selected.extend([
                "impact_agent", 
                "compliance_agent", 
                "hunter_agent", 
                "forensics_agent"
            ])
            
        logger.info(f"MetaAgent: Selected agents {selected} to run for severity '{severity}' and type '{incident_type}'")
        return selected
