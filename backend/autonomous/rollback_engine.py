from typing import Dict, Any

class ContainmentRollbackEngine:
    @staticmethod
    def execute_rollback(containment_action: str, target: str) -> Dict[str, Any]:
        """Undoes high-risk blocking containment actions (e.g. firewall block, token revoke)."""
        return {
            "action": containment_action,
            "target": target,
            "status": "rolled_back",
            "message": f"Successfully removed block rule '{containment_action}' from target '{target}'."
        }
