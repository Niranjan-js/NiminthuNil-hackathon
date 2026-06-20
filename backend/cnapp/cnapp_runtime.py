from typing import Dict, Any

class CNAPPRuntimeDefender:
    @staticmethod
    def audit_k8s_admission(pod_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Validates if pod execution request violates container boundary limits."""
        privileged = pod_spec.get("privileged", False)
        run_as_root = pod_spec.get("runAsRoot", True)
        
        allowed = not privileged and not run_as_root
        return {
            "allowed": allowed,
            "reason": "Pod is requesting root or privileged context" if not allowed else "Safe Pod config",
            "score": 0.90 if not allowed else 0.05
        }
