import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.agents.ot_agent")

class OTAgent:
    """
    OT Agent monitors Industrial Control Systems (ICS) and Operational Technology (OT) traffic for protocols anomalies.
    """
    def check_industrial_safety(self, payload_hex: str) -> Dict[str, Any]:
        compromised = False
        # If write packet to Modbus target (e.g. coil modification)
        if payload_hex.startswith("05"): 
            compromised = True

        return {
            "status": "success",
            "score": 0.90 if compromised else 0.1,
            "industrial_threat_detected": compromised,
            "protocol": "ModbusTCP"
        }
