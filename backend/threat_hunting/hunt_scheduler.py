from sqlalchemy.orm import Session
from threat_hunting.campaign_manager import CampaignManager
import logging

logger = logging.getLogger("niravan.threat_hunting.hunt_scheduler")

class HuntScheduler:
    """
    HuntScheduler triggers scheduled CISA KEV Threat Hunt campaigns.
    """
    @staticmethod
    def execute_scheduled_campaign(db: Session):
        logger.info("Executing scheduled CISA KEV Threat Hunt campaign...")
        res = CampaignManager.run_hunt_campaign(db)
        logger.info(f"Campaign completed. Generated {len(res['incidents_generated'])} incidents.")
        return res
