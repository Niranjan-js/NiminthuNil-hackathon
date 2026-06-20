from sqlalchemy.orm import Session
from main import AssetModel, CVEModel
from typing import List, Dict, Any

class CVEMapper:
    """
    CVEMapper maps CISA KEV vulnerabilities to monitored assets.
    """
    @staticmethod
    def map_cves_to_assets(db: Session) -> List[Dict[str, Any]]:
        assets = db.query(AssetModel).all()
        cves = db.query(CVEModel).all()
        
        mappings = []
        for asset in assets:
            for cve in cves:
                # Basic string match overlap on affected assets
                affected_desc = (cve.affected or "").lower()
                asset_services = (asset.open_services or "").lower()
                asset_name = (asset.name or "").lower()
                
                if affected_desc in asset_name or any(s in affected_desc for s in asset_services.split(",") if len(s.strip()) > 2):
                    mappings.append({
                        "asset_id": asset.id,
                        "asset_name": asset.name,
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "score": cve.score
                    })
        return mappings
