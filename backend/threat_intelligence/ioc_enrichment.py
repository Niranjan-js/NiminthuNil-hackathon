from typing import Dict, Any

class IOCEnrichmentEngine:
    @staticmethod
    def enrich_ip(ip: str) -> Dict[str, Any]:
        """Queries MISP, OTX, and AbuseIPDB mock datasets for IP reputation score."""
        reputation = "clean"
        abuse_score = 0
        notes = "No reports found."

        if ip in ["185.220.101.47", "91.240.118.12", "192.0.2.1"]:
            reputation = "malicious"
            abuse_score = 100
            notes = "Flagged as Tor Exit Node or active C2 controller."

        return {
            "ip": ip,
            "reputation": reputation,
            "abuse_score": abuse_score,
            "enrichment_source": "MISP/AbuseIPDB",
            "notes": notes
        }

    @staticmethod
    def enrich_hash(sha256: str) -> Dict[str, Any]:
        """Queries VirusTotal mock data for file hashes."""
        positives = 0
        status = "unknown"
        if len(sha256) == 64 and sha256.startswith("a"):
            positives = 54
            status = "malicious"

        return {
            "sha256": sha256,
            "virus_total_positives": positives,
            "status": status,
            "enrichment_source": "VirusTotal"
        }
