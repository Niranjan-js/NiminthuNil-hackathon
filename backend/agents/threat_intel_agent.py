import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.agents.threat_intel_agent")

class ThreatIntelAgent:
    """
    Threat Intel Agent correlates incident indicators against CISA KEV and other threat feeds.
    """
    def correlate_threat_intel(self, db, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = incident_data.get("cve_id") or incident_data.get("raw_payload", {}).get("cve_id")
        score = 0.1
        matched_feed = "None"
        
        if cve_id:
            # Look up in CISA KEV or CVE database
            from main import CVEModel
            cve = db.query(CVEModel).filter(CVEModel.id == cve_id).first()
            if cve:
                score = 0.9 if cve.severity == "critical" else 0.7
                matched_feed = "CISA KEV Feed / Local OpenVAS database"
        elif "cve" in incident_data.get("description", "").lower():
            score = 0.6
            matched_feed = "Generic CVE threat intelligence matches"
            
        return {
            "status": "success",
            "score": score,
            "matched_feed": matched_feed
        }
