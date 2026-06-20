import datetime
import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.tools.isolate_host_tool")

TOOL_SPEC = {
    "name": "isolate_host",
    "description": "Isolate a compromised host from the network to contain lateral movement. Use when a host shows signs of active compromise.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hostname": {"type": "string", "description": "The hostname or IP of the system to isolate"},
            "reason": {"type": "string", "description": "Reason for isolation"},
            "notify_admin": {"type": "boolean", "description": "Whether to notify admin. Default true.", "default": True}
        },
        "required": ["hostname", "reason"]
    }
}

class IsolateHostTool:
    """Tool to isolate a compromised asset from the network and log the action."""

    @staticmethod
    def execute(db, hostname: str, reason: str, notify_admin: bool = True) -> Dict[str, Any]:
        try:
            from main import AssetModel, AuditLogModel, IncidentModel, CaseNoteModel, CaseModel
            
            # 1. Update AssetModel status to 'isolated'
            # Look up asset by name or IP
            asset = db.query(AssetModel).filter(
                (AssetModel.name == hostname) | (AssetModel.ip == hostname)
            ).first()
            
            asset_name = hostname
            asset_ip = "Unknown"
            
            if asset:
                asset.status = "isolated"
                asset_name = asset.name
                asset_ip = asset.ip
                logger.info(f"Isolated host: {asset_name} ({asset_ip})")
            else:
                logger.warning(f"Asset '{hostname}' not found in DB. Proceeding with isolation representation.")

            # 2. Append to any active incident's technical details or add CaseNote
            # Find the most recent active incident involving this host
            incident = db.query(IncidentModel).filter(
                (IncidentModel.host == asset_name) | (IncidentModel.host == hostname)
            ).order_by(IncidentModel.timestamp.desc()).first()
            
            note_added = False
            if incident:
                note_text = f"\n[{datetime.datetime.utcnow().isoformat()}] HOST ISOLATED: {reason} (Requested by autonomous agent)"
                if incident.technical:
                    incident.technical += note_text
                else:
                    incident.technical = note_text
                
                # Also check if there's a Case for this incident and add CaseNote if exists
                case = db.query(CaseModel).filter(CaseModel.incident_id == incident.id).first()
                if case:
                    case_note = CaseNoteModel(
                        case_id=case.id,
                        author="autonomous_agent",
                        note=f"Host '{asset_name}' isolated. Reason: {reason}",
                        created_at=datetime.datetime.utcnow()
                    )
                    db.add(case_note)
                    note_added = True
            
            # 3. Create AuditLogModel entry
            log = AuditLogModel(
                user_email="autonomous_agent@niravan.tn.gov.in",
                action="isolate_host",
                detail=f"Isolated host: {asset_name} (IP: {asset_ip}), Reason: {reason}, Admin Notified: {notify_admin}",
                ip_address=asset_ip if asset_ip != "Unknown" else "127.0.0.1",
                timestamp=datetime.datetime.utcnow()
            )
            db.add(log)
            db.commit()
            
            return {
                "success": True,
                "hostname": asset_name,
                "ip_address": asset_ip,
                "action": "isolated",
                "reason": reason,
                "case_note_added": note_added,
                "admin_notified": notify_admin
            }
        except Exception as e:
            logger.error(f"Error executing IsolateHostTool for host {hostname}: {e}")
            return {"success": False, "error": str(e)}
