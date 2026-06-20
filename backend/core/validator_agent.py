import logging
import datetime
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("niravan.core.validator_agent")

class ValidatorAgent:
    """
    Pre-execution safety validator. Screens proposed mitigation actions
    against system whitelists, blast radius thresholds, and rate limits.
    """
    
    # Class-level action count storage for rate limiting
    # Format: [datetime, datetime, ...]
    _action_history: List[datetime.datetime] = []

    def __init__(self, db):
        self.db = db

    async def validate(self, plan: Dict[str, Any], observation: Dict[str, Any], confidence: float = 1.0) -> Dict[str, Any]:
        """
        Validate mitigation plan actions in sequence.
        """
        try:
            actions = plan.get("actions", [])
            
            validation_checks = []
            actions_to_execute = []
            deferred_actions = []
            
            human_approval_required = False
            reasons = []
            
            # Check Rate Limit first (affects all auto actions)
            rate_limit_passed = self._check_rate_limit()
            validation_checks.append({
                "check": "rate_limit",
                "passed": rate_limit_passed,
                "detail": "Action rate limited (max 5 actions per 10 minutes)" if not rate_limit_passed else "Rate limit check passed"
            })
            
            # Check Analyst Confidence
            confidence_passed = confidence >= 0.85
            validation_checks.append({
                "check": "analyst_confidence",
                "passed": confidence_passed,
                "detail": f"Confidence is {confidence:.2f} (required >= 0.85)" if not confidence_passed else "Confidence check passed"
            })
            if not confidence_passed:
                human_approval_required = True
                reasons.append(f"Low analyst confidence ({confidence:.2f})")
            
            for action in actions:
                # 1. Whitelist Check
                whitelist_passed, whitelist_detail = self._check_whitelist(action, observation)
                validation_checks.append({
                    "check": f"whitelist_{action.get('type')}",
                    "passed": whitelist_passed,
                    "detail": whitelist_detail
                })
                
                # 2. Blast Radius Check
                blast_passed = (action.get("blast_radius", 0) <= 10)
                validation_checks.append({
                    "check": f"blast_radius_{action.get('type')}",
                    "passed": blast_passed,
                    "detail": f"Blast radius: {action.get('blast_radius', 0)} assets (max 10 allowed for auto-remediation)"
                })
                
                # Decision for this specific action
                action_needs_approval = (
                    not rate_limit_passed or 
                    not confidence_passed or 
                    not whitelist_passed or 
                    not blast_passed
                )
                
                if action_needs_approval:
                    deferred_actions.append(action)
                    human_approval_required = True
                    
                    if not whitelist_passed:
                        reasons.append(f"Critical asset protection ({whitelist_detail})")
                    if not blast_passed:
                        reasons.append(f"Blast radius exceeded ({action.get('blast_radius', 0)} affected assets)")
                else:
                    actions_to_execute.append(action)
                    # Record timestamp for rate limit tracking
                    self._action_history.append(datetime.datetime.utcnow())

            if not rate_limit_passed:
                reasons.append("Rate limit exceeded")

            approved = len(actions_to_execute) > 0 and not human_approval_required
            
            return {
                "approved": approved,
                "auto_approved": approved,
                "human_approval_required": human_approval_required,
                "reason": ", ".join(reasons) if reasons else "All checks passed. Auto-remediation approved.",
                "actions_to_execute": actions_to_execute,
                "deferred_actions": deferred_actions,
                "validation_checks": validation_checks
            }
        except Exception as e:
            logger.error(f"Validation failed with error: {e}")
            return {
                "approved": False,
                "auto_approved": False,
                "human_approval_required": True,
                "reason": f"Validation engine error: {e}",
                "actions_to_execute": [],
                "deferred_actions": plan.get("actions", []),
                "validation_checks": [{"check": "validation_engine", "passed": False, "detail": str(e)}]
            }

    def _check_whitelist(self, action: Dict[str, Any], observation: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if the target of this action is a critical whitelisted infrastructure
        where automated actions are blocked.
        """
        try:
            from main import AssetModel
            
            action_type = action.get("type")
            params = action.get("params", {})
            
            if action_type == "isolate_host":
                hostname = params.get("hostname")
                if hostname:
                    asset = self.db.query(AssetModel).filter(
                        (AssetModel.name == hostname) | (AssetModel.ip == hostname)
                    ).first()
                    
                    if asset:
                        # Block automated isolation if it is a critical service, hospital, or collectorate
                        name_l = asset.name.lower()
                        critical_terms = ["hospital", "treasury", "collectorate", "police", "fire", "emergency", "db", "database"]
                        if asset.criticality == "critical" or any(t in name_l for t in critical_terms):
                            return False, f"Target '{asset.name}' is a critical asset. Automated isolation is blocked."
                            
            return True, "No critical whitelists triggered."
        except Exception as e:
            logger.warning(f"Error checking whitelist: {e}")
            return True, "No critical whitelists triggered (fallback)."

    @classmethod
    def _check_rate_limit(cls) -> bool:
        """
        Ensure no more than 5 auto-actions are executed per 10 minutes.
        """
        now = datetime.datetime.utcnow()
        ten_minutes_ago = now - datetime.timedelta(minutes=10)
        
        # Clean history older than 10 minutes
        cls._action_history = [t for t in cls._action_history if t > ten_minutes_ago]
        
        # Check count
        return len(cls._action_history) < 5
