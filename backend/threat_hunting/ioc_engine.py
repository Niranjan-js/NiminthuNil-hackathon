from sqlalchemy.orm import Session
from main import IOCModel
from typing import Dict, Any, List

class IOCEngine:
    """
    IOCEngine matches indicator-of-compromise signatures (IPs, hashes, domains)
    against incoming threat feeds and logs.
    """
    @staticmethod
    def match_ioc(db: Session, indicator: str, ioc_type: str = "IP") -> Dict[str, Any]:
        match = db.query(IOCModel).filter(
            IOCModel.value == indicator,
            IOCModel.type == ioc_type
        ).first()
        
        if match:
            return {
                "matched": True,
                "ioc_id": match.id,
                "threat": match.threat,
                "confidence": getattr(match, "confidence", 85)
            }
        return {"matched": False}
