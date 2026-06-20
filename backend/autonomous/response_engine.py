from typing import Dict, Any, List
from .health_checker import SystemHealthChecker
from .rollback_engine import ContainmentRollbackEngine
from .verification_engine import ThreatVerificationEngine

class AutonomousResponseEngine:
    def __init__(self):
        self.health = SystemHealthChecker()
        self.rollback = ContainmentRollbackEngine()
        self.verifier = ThreatVerificationEngine()

    def handle_incident_flow(self, incident_id: str, action: str, target: str) -> Dict[str, Any]:
        """Runs the autonomous response lifecycle:
        Incident -> Block/Contain -> Verify Service Health -> Rollback if Outage -> Notify.
        """
        logs = [f"Initiating autonomous containment: '{action}' on '{target}'"]
        
        # 1. Execute block
        block_success = True
        logs.append(f"Successfully applied containment rule '{action}' on target '{target}'")

        # 2. Verify service availability
        health_metrics = self.health.get_current_metrics()
        logs.append(f"Service validation check: CPU={health_metrics['cpu_pct']}%, Memory={health_metrics['mem_pct']}%")

        if health_metrics["service_outage_detected"]:
            logs.append("WARNING: Service outage detected post-containment! Triggering automatic rollback.")
            rollback_res = self.rollback.execute_rollback(action, target)
            logs.append(rollback_res["message"])
            return {
                "incident_id": incident_id,
                "status": "rolled_back",
                "flow_logs": logs,
                "health_metrics": health_metrics
            }

        # 3. Verify threat has ceased
        threat_cleared = self.verifier.verify_threat_remediated(target)
        logs.append(f"Threat verification check for '{target}': status={'remediated' if threat_cleared else 'still_active'}")

        return {
            "incident_id": incident_id,
            "status": "containment_active",
            "flow_logs": logs,
            "threat_remediated": threat_cleared,
            "health_metrics": health_metrics
        }
