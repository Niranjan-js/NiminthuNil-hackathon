import datetime
import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.tools.block_ip_tool")

TOOL_SPEC = {
    "name": "block_ip",
    "description": "Block a malicious IP address in the firewall and blacklist it. Use this when you've identified an attacker's IP address with high confidence.",
    "input_schema": {
        "type": "object",
        "properties": {
            "ip_address": {"type": "string", "description": "The IPv4 or IPv6 address to block"},
            "reason": {"type": "string", "description": "Reason for blocking this IP"},
            "duration_hours": {"type": "integer", "description": "How many hours to block. Default 24.", "default": 24}
        },
        "required": ["ip_address", "reason"]
    }
}

class BlockIPTool:
    """Tool to block a malicious IP address and record the action in the database."""

    @staticmethod
    def execute(db, ip_address: str, reason: str, duration_hours: int = 24) -> Dict[str, Any]:
        try:
            from main import IOCModel, AuditLogModel, AssetModel
            
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=duration_hours)
            
            # 1. Add to IOC Model
            # First check if it already exists
            existing_ioc = db.query(IOCModel).filter(IOCModel.indicator == ip_address).first()
            if not existing_ioc:
                ioc = IOCModel(
                    type="ip",
                    indicator=ip_address,
                    actor="autonomous_agent",
                    confidence=95,
                    lastSeen=datetime.datetime.utcnow().isoformat(),
                    threat=f"Malicious IP blocked: {reason}"
                )
                db.add(ioc)
            
            # 2. Update assets associated with this IP to status='isolated'
            affected_assets = db.query(AssetModel).filter(AssetModel.ip == ip_address).all()
            for asset in affected_assets:
                asset.status = "isolated"
                logger.info(f"Asset isolated: {asset.name} ({ip_address})")
                
            # 3. Add to Audit Log
            log = AuditLogModel(
                user_email="autonomous_agent@niravan.tn.gov.in",
                action="block_ip",
                detail=f"Blocked IP: {ip_address}, Reason: {reason}, Duration: {duration_hours}h",
                ip_address=ip_address,
                timestamp=datetime.datetime.utcnow()
            )
            db.add(log)
            db.commit()
            
            logger.info(f"Blocked IP {ip_address} successfully. Expires at: {expires_at}")
            return {
                "success": True,
                "ip": ip_address,
                "action": "blocked",
                "expires_at": expires_at.isoformat(),
                "reason": reason,
                "assets_isolated": len(affected_assets)
            }
        except Exception as e:
            logger.error(f"Error executing BlockIPTool for IP {ip_address}: {e}")
            return {"success": False, "error": str(e)}
