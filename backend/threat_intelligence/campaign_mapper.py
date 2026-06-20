from typing import List, Dict, Any

class CampaignMapper:
    @staticmethod
    def map_indicators_to_campaign(iocs: List[str]) -> Dict[str, Any]:
        """Correlates indicators with active campaign descriptors."""
        matched_campaign = "Unknown Campaign"
        actor = "Unknown Actor"
        confidence = 0.1

        for ioc in iocs:
            if ioc in ["185.220.101.47", "91.240.118.12"]:
                matched_campaign = "Operation Cozy-Netflow"
                actor = "APT29"
                confidence = 0.90
                break

        return {
            "campaign_name": matched_campaign,
            "threat_actor": actor,
            "correlation_confidence": confidence,
            "associated_iocs": iocs
        }
