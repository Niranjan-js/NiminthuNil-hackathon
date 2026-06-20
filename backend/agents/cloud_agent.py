import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.agents.cloud_agent")

class CloudAgent:
    """
    Cloud Agent monitors AWS, Azure, Entra ID, and GCP logs for configuration leaks or anomalous accesses.
    """
    def check_cloud_security(self, db, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        desc = incident_data.get("description", "").lower()
        score = 0.1
        
        if "s3 exposure" in desc or "public bucket" in desc:
            score = 0.8
        elif "entra id" in desc or "impossible travel" in desc or "mfa bypass" in desc:
            score = 0.85
            
        return {
            "status": "success",
            "score": score,
            "cloud_compromise_detected": score > 0.5
        }
