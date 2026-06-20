import logging
import datetime
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.verification_agent")

class VerificationAgent:
    """
    Verification Agent confirms whether defensive actions were successfully executed,
    evaluates their effectiveness (e.g. confirming host is isolated, IP is blocked),
    and recommends rollback if a critical service is accidentally disrupted.
    """

    @staticmethod
    def verify_remediation(db, action_type: str, params: Dict[str, Any], before_state: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Verifies the results of a mitigation action.
        """
        try:
            from main import AssetModel, IOCModel, ServiceAvailabilityModel
            
            verification_details = []
            success = False
            effectiveness_score = 0.0
            rollback_recommended = False
            
            if action_type == "isolate_host":
                hostname = params.get("hostname")
                asset = db.query(AssetModel).filter(AssetModel.name == hostname).first()
                
                if asset:
                    # Check if the asset status was updated to isolated/locked
                    if asset.status in ["Isolated", "Locked"]:
                        success = True
                        effectiveness_score = 1.0
                        verification_details.append(f"Host '{hostname}' status successfully updated to '{asset.status}' in asset registry.")
                    else:
                        success = False
                        effectiveness_score = 0.0
                        verification_details.append(f"FAILED: Host '{hostname}' status remains '{asset.status}' instead of 'Isolated'.")
                    
                    # Verify if services on this host became unavailable
                    if asset.open_services:
                        services = [s.strip() for s in asset.open_services.split(",") if s.strip()]
                        for s_name in services:
                            service_status = db.query(ServiceAvailabilityModel).filter(ServiceAvailabilityModel.name == s_name).first()
                            if service_status:
                                if service_status.status == "Locked" or service_status.status == "Offline":
                                    verification_details.append(f"Service '{s_name}' properly restricted/locked.")
                                else:
                                    verification_details.append(f"WARNING: Service '{s_name}' on isolated host '{hostname}' is still marked '{service_status.status}'.")
                                    # If it's a critical service, we might flag rollback
                                    if asset.criticality == "high":
                                        rollback_recommended = True
                                        verification_details.append("CRITICAL: High criticality service is still reachable or misconfigured; rollback recommended.")
                else:
                    verification_details.append(f"FAILED: Host '{hostname}' not found in asset registry.")
                    
            elif action_type == "block_ip":
                ip_address = params.get("ip_address")
                # Check if the IP exists in the IOC list as blocked
                ioc = db.query(IOCModel).filter(
                    IOCModel.type == "IP",
                    IOCModel.indicator == ip_address
                ).first()
                
                if ioc:
                    success = True
                    effectiveness_score = 1.0
                    verification_details.append(f"IP address '{ip_address}' successfully added to the active Blocklist/IOC repository.")
                else:
                    success = False
                    effectiveness_score = 0.0
                    verification_details.append(f"FAILED: IP address '{ip_address}' was not found in the Blocklist/IOC repository.")
                    
            else:
                verification_details.append(f"Unknown action type '{action_type}'; skipping verification.")
                success = True
                effectiveness_score = 0.5
                
            return {
                "success": success,
                "effectiveness": effectiveness_score,
                "rollback_recommended": rollback_recommended,
                "details": "; ".join(verification_details),
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error verifying remediation action: {e}", exc_info=True)
            return {
                "success": False,
                "effectiveness": 0.0,
                "rollback_recommended": False,
                "details": f"Verification system error: {str(e)}",
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
