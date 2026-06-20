from sqlalchemy.orm import Session
from typing import List, Dict, Any
from threat_hunting.kev_sync import KEVSyncEngine
from threat_hunting.cve_mapper import CVEMapper
from main import IncidentModel
import datetime
import uuid

class CampaignManager:
    """
    CampaignManager manages the execution of CISA KEV Threat Hunt Campaigns.
    It coordinates log scans, maps vulnerable assets, and generates high-fidelity incidents.
    """
    @staticmethod
    def run_hunt_campaign(db: Session) -> Dict[str, Any]:
        # 1. Sync CISA KEV feed
        synced = KEVSyncEngine.sync_kev(db)
        
        # 2. Map vulnerable assets
        vulnerable_mappings = CVEMapper.map_cves_to_assets(db)
        
        # 3. Create active hunt incidents for high-risk mappings
        incidents_created = []
        for mapping in vulnerable_mappings:
            if mapping["score"] >= 9.0:
                # Check if incident already exists for this mapping
                existing = db.query(IncidentModel).filter(
                    IncidentModel.host == mapping["asset_name"],
                    IncidentModel.type == "VULNERABILITY_EXPOSURE",
                    IncidentModel.status == "open"
                ).first()
                
                if not existing:
                    inc_id = f"inc-{uuid.uuid4().hex[:6]}"
                    incident = IncidentModel(
                        id=inc_id,
                        title=f"CISA KEV Vulnerability Exposure: {mapping['cve_id']}",
                        type="VULNERABILITY_EXPOSURE",
                        severity="critical" if mapping["severity"] == "critical" else "high",
                        description=f"Automated threat hunt discovered {mapping['asset_name']} is exposed to known active exploit {mapping['cve_id']}.",
                        status="open",
                        host=mapping["asset_name"],
                        category="Initial Access",
                        timestamp=datetime.datetime.utcnow(),
                        mitre="T1190"
                    )
                    db.add(incident)
                    incidents_created.append({
                        "incident_id": inc_id,
                        "asset": mapping["asset_name"],
                        "cve_id": mapping["cve_id"]
                    })
        db.commit()
        
        return {
            "status": "completed",
            "cves_synced": synced,
            "assets_mapped": len(vulnerable_mappings),
            "incidents_generated": incidents_created
        }
