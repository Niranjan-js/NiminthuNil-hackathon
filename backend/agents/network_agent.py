import logging
from typing import Dict, Any, List
from backend.network_intelligence.netflow_analyzer import NetflowAnalyzer

logger = logging.getLogger("niravan.agents.network_agent")

class NetworkAgent:
    """
    Network Agent monitors network anomalies, BGP route advertisements, and DNS traffic.
    """
    def check_flow_beaconing(self, timestamps: List[float]) -> Dict[str, Any]:
        res = NetflowAnalyzer.detect_c2_beaconing(timestamps)
        score = 0.85 if res["beaconing_detected"] else 0.1
        return {
            "status": "success",
            "score": score,
            "beaconing_results": res
        }
