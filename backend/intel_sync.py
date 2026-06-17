import datetime
from sqlalchemy.orm import Session
from typing import Dict, Any, List, Optional
# Import models from main.py
from main import IOCModel

class ThreatIOC:
    def __init__(self, ioc_type: str, value: str, confidence: int, source: str, first_seen: Optional[str] = None):
        self.type = ioc_type
        self.value = value
        self.confidence = confidence
        self.source = source
        self.first_seen = first_seen or datetime.datetime.utcnow().strftime("%Y-%m-%d")

class IntelSync:
    @staticmethod
    def normalize_indicator(feed_source: str, raw_data: Dict[str, Any]) -> ThreatIOC:
        """Normalizes external threat feeds (OTX, AbuseIPDB, MISP) into a common schema."""
        if feed_source == "OTX":
            return ThreatIOC(
                ioc_type=raw_data.get("type", "ip"),
                value=raw_data.get("indicator", ""),
                confidence=raw_data.get("confidence", 85),
                source="AlienVault OTX"
            )
        elif feed_source == "AbuseIPDB":
            return ThreatIOC(
                ioc_type="ip",
                value=raw_data.get("ipAddress", ""),
                confidence=raw_data.get("abuseConfidenceScore", 90),
                source="AbuseIPDB"
            )
        elif feed_source == "MISP":
            return ThreatIOC(
                ioc_type=raw_data.get("type", "domain"),
                value=raw_data.get("value", ""),
                confidence=95,
                source="State MISP Server"
            )
        else:
            return ThreatIOC(
                ioc_type=raw_data.get("type", "ip"),
                value=raw_data.get("value", ""),
                confidence=raw_data.get("confidence", 70),
                source=feed_source
            )

    @staticmethod
    def sync_otx_indicators(db: Session) -> int:
        """Pulls and parses public indicators of compromise to sync in the db table."""
        # Simulated sync payload representing live indicators from external OTX / AbuseIPDB feeds
        mock_raw_feeds = [
            {"source": "OTX", "data": {"type": "ip", "indicator": "185.220.101.47", "confidence": 98}},
            {"source": "AbuseIPDB", "data": {"ipAddress": "45.77.12.89", "abuseConfidenceScore": 95}},
            {"source": "MISP", "data": {"type": "domain", "value": "security-update-tn-gov.org", "confidence": 95}}
        ]
        
        synced_count = 0
        for item in mock_raw_feeds:
            normalized = IntelSync.normalize_indicator(item["source"], item["data"])
            
            # Check if indicator already exists in IOCModel table
            existing = db.query(IOCModel).filter(
                IOCModel.type == normalized.type,
                IOCModel.indicator == normalized.value
            ).first()
            
            if not existing:
                new_ioc = IOCModel(
                    type=normalized.type,
                    indicator=normalized.value,
                    actor="Rogue Actor Group",
                    confidence=normalized.confidence,
                    lastSeen=normalized.first_seen,
                    threat="Malicious Infrastructure"
                )
                db.add(new_ioc)
                synced_count += 1
                
        db.commit()
        return synced_count

    @staticmethod
    def match_ip_to_threat_intel(db: Session, ip_address: str) -> Optional[IOCModel]:
        """Checks incoming IP logs against normalized IOC table to match malicious nodes."""
        return db.query(IOCModel).filter(
            IOCModel.type == "ip",
            IOCModel.indicator == ip_address
        ).first()
