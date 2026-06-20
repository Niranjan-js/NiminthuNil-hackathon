import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.core.explanation_engine")

class ExplanationEngine:
    """
    Explanation Engine that details the rationale behind autonomous decisions,
    reconstructing a checklist of why actions were approved, deferred, or rate-limited.
    """

    @staticmethod
    def generate_explanation(incident_data: Dict[str, Any], consensus: Dict[str, Any], confidence: float, validation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a human-readable reason checklist for the autonomous decision.
        """
        try:
            reasons = []
            
            # 1. Threat factors
            title = incident_data.get("title", "")
            inc_type = incident_data.get("type", "")
            reasons.append(f"Incident Type identified as: '{inc_type}' ({title})")
            
            # 2. Correlated findings
            findings = consensus.get("key_findings", [])
            for f in findings[:2]:
                # Extract clean message
                msg = f.split(":", 1)[-1].strip() if ":" in f else f
                reasons.append(f"Observation: {msg}")
                
            # 3. Graph/Impact factors
            impact = consensus.get("impact_summary", {})
            citizens = impact.get("citizens_at_risk", 0)
            if citizens > 1000:
                reasons.append(f"Public Safety Risk: Est. {citizens.toLocaleString() if hasattr(citizens, 'toLocaleString') else citizens} citizen records potentially exposed")
            
            depts = impact.get("departments_at_risk", [])
            if depts and depts != ["Default"]:
                reasons.append(f"Target Surface: Directly impacts department(s): {', '.join(depts)}")
                
            # 4. Confidence calibration
            reasons.append(f"Calibrated Bayesian Confidence Score: {int(confidence * 100)}%")
            
            # 5. Validation and Safety Gate decisions
            is_approved = validation.get("approved", False)
            if is_approved:
                reasons.append("Safety Gate: Whitelist checks passed; rate limit within bounds (<5 actions/10m)")
                reasons.append("Decision: Safe for autonomous auto-remediation execution")
            else:
                reasons.append(f"Safety Gate: Execution paused. Reason: {validation.get('reason', 'Requires manual intervention')}")
                reasons.append("Decision: Deferred to command analyst for manual approval")

            return {
                "decision_approved": is_approved,
                "reason_checklist": reasons,
                "confidence_score": confidence
            }
        except Exception as e:
            logger.error(f"Error in ExplanationEngine: {e}")
            return {
                "decision_approved": False,
                "reason_checklist": [f"Explanation query error: {e}"],
                "confidence_score": confidence
            }
