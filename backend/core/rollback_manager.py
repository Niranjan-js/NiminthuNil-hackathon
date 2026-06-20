import logging
import datetime
from typing import Dict, Any

logger = logging.getLogger("niravan.core.rollback_manager")

class RollbackManager:
    """
    Rollback Manager oversees reverting defensive actions when they lead to unintended disruption,
    fail verification, or are manually requested by an administrator.
    """

    @staticmethod
    def execute_rollback(db, action_type: str, params: Dict[str, Any], initiator: str = "SYSTEM") -> Dict[str, Any]:
        """
        Reverses the state change introduced by a specific mitigation action type.
        """
        try:
            from main import AssetModel, IOCModel, AuditLogModel, CaseNoteModel
            
            rollback_details = []
            success = False
            
            if action_type == "isolate_host":
                hostname = params.get("hostname")
                asset = db.query(AssetModel).filter(AssetModel.name == hostname).first()
                if asset:
                    if asset.status in ["Isolated", "Locked"]:
                        # Revert status to Active (or online)
                        old_status = asset.status
                        asset.status = "Active"
                        db.commit()
                        success = True
                        rollback_details.append(f"Host '{hostname}' restored from '{old_status}' to 'Active'.")
                    else:
                        rollback_details.append(f"Host '{hostname}' already has status '{asset.status}', no rollback needed.")
                        success = True
                else:
                    rollback_details.append(f"FAILED: Host '{hostname}' not found in asset registry.")
                    
            elif action_type == "block_ip":
                ip_address = params.get("ip_address")
                # Remove IP from the IOC blocklist
                ioc = db.query(IOCModel).filter(
                    IOCModel.type == "IP",
                    IOCModel.indicator == ip_address
                ).first()
                
                if ioc:
                    db.delete(ioc)
                    db.commit()
                    success = True
                    rollback_details.append(f"IP address '{ip_address}' successfully removed from blocklist.")
                else:
                    rollback_details.append(f"IP address '{ip_address}' not found in blocklist, nothing to rollback.")
                    success = True
                    
            else:
                rollback_details.append(f"Unsupported rollback for action type '{action_type}'.")
                
            # Log to AuditLog and CaseNotes if successful
            detail_msg = "; ".join(rollback_details)
            if success:
                audit_entry = AuditLogModel(
                    user_email=initiator,
                    action="ROLLBACK_ACTION",
                    detail=f"Rollback {action_type}: {detail_msg}",
                    ip_address="127.0.0.1"
                )
                db.add(audit_entry)
                
                # If there's an associated case, we should document the rollback in case notes
                # (For simplicity we log a general audit log, but can log case note if case_id in params)
                case_id = params.get("case_id")
                if case_id:
                    note_entry = CaseNoteModel(
                        case_id=case_id,
                        author=initiator,
                        note=f"[ROLLBACK] Automated rollback executed: {detail_msg}"
                    )
                    db.add(note_entry)
                db.commit()
                
            logger.info(f"Rollback executed: {action_type}. Success: {success}. Details: {detail_msg}")
            return {
                "success": success,
                "details": detail_msg,
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error executing rollback for '{action_type}': {e}", exc_info=True)
            return {
                "success": False,
                "details": f"Rollback system error: {str(e)}",
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
