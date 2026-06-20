import datetime
from sqlalchemy.orm import Session
from main import CVEModel

class KEVSyncEngine:
    """
    KEVSyncEngine downloads/simulates CISA KEV (Known Exploited Vulnerabilities)
    and syncs them to NIRAVAN's local CVE repository.
    """
    @staticmethod
    def sync_kev(db: Session) -> int:
        # Mock feed of fresh exploits from CISA KEV
        feed = [
            {
                "id": "CVE-2024-3400",
                "score": 10.0,
                "severity": "critical",
                "desc": "Palo Alto Networks PAN-OS command injection vulnerability in GlobalProtect gateway.",
                "affected": "Firewall Gateway",
            },
            {
                "id": "CVE-2024-21887",
                "score": 9.8,
                "severity": "critical",
                "desc": "Ivanti Connect Secure command injection vulnerability allowing remote execution.",
                "affected": "VPN Gateway",
            },
            {
                "id": "CVE-2023-38606",
                "score": 7.8,
                "severity": "high",
                "desc": "Apple iOS kernel vulnerability used in state-sponsored spyware campaigns.",
                "affected": "iOS Devices",
            }
        ]
        
        added = 0
        for item in feed:
            cve = db.query(CVEModel).filter(CVEModel.id == item["id"]).first()
            if not cve:
                cve = CVEModel(
                    id=item["id"],
                    score=item["score"],
                    severity=item["severity"],
                    desc=item["desc"],
                    affected=item["affected"],
                    published=datetime.datetime.utcnow().isoformat()
                )
                db.add(cve)
                added += 1
        db.commit()
        return added
