import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.impact_agent")

DEPARTMENT_CITIZEN_IMPACT = {
    "Hospital": 50000,
    "School": 5000,
    "Treasury": 200000,
    "Collectorate": 100000,
    "Police": 75000,
    "Default": 2000
}

class ImpactAgent:
    """
    Impact Agent calculates potential citizen impact, financial impact, and downtime
    risks associated with compromised services and assets.
    """

    def estimate_impact(self, db, incident_data: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Estimate the impact of a security incident.
        """
        try:
            from main import AssetModel, ServiceAvailabilityModel
            
            host = incident_data.get("host")
            severity = analysis.get("severity") or incident_data.get("severity") or "medium"
            attack_type = analysis.get("attack_pattern") or incident_data.get("type") or "Unknown"
            
            # 1. Resolve targeted asset
            asset = None
            if host:
                asset = db.query(AssetModel).filter(
                    (AssetModel.name == host) | (AssetModel.ip == host)
                ).first()

            # 2. Determine affected department and services
            departments = set()
            services = set()
            
            if asset:
                # Deduce department based on asset attributes
                asset_owner = asset.owner or ""
                asset_name = asset.name.lower()
                
                # Check keywords
                matched_dept = False
                for dept_key in DEPARTMENT_CITIZEN_IMPACT.keys():
                    if dept_key.lower() in asset_name or dept_key.lower() in asset_owner.lower():
                        departments.add(dept_key)
                        matched_dept = True
                
                if not matched_dept:
                    departments.add("Default")
                    
                # Add open services
                if asset.open_services:
                    for s in asset.open_services.split(","):
                        services.add(s.strip())
            else:
                # If no asset is resolved, use defaults based on incident data
                departments.add("Default")
                if "department" in incident_data:
                    departments.add(incident_data["department"])
                if "service" in incident_data:
                    services.add(incident_data["service"])

            # 3. Fetch all active services from DB to check for matches
            db_services = db.query(ServiceAvailabilityModel).all()
            for ds in db_services:
                if ds.name in services or any(ds.name.lower() in str(d).lower() for d in departments):
                    services.add(ds.name)

            # 4. Calculate Citizen Impact
            total_citizens = 0
            for dept in departments:
                total_citizens += DEPARTMENT_CITIZEN_IMPACT.get(dept, DEPARTMENT_CITIZEN_IMPACT["Default"])
                
            # Scale citizen impact slightly based on severity
            severity_mult = {"critical": 2.0, "high": 1.2, "medium": 0.8, "low": 0.2}
            citizens_at_risk = int(total_citizens * severity_mult.get(severity.lower(), 1.0))
            if citizens_at_risk == 0:
                citizens_at_risk = 100

            # 5. Downtime and Financial Impact Estimations
            downtime_map = {"critical": 24.0, "high": 12.0, "medium": 4.0, "low": 1.0}
            estimated_downtime = downtime_map.get(severity.lower(), 4.0)
            
            # Ransomware usually leads to longer downtime
            if "ransomware" in attack_type.lower() or "encrypt" in attack_type.lower():
                estimated_downtime *= 3.0
                
            # Financial Impact in Lakhs (INR) - 1 Lakh = 100,000 INR
            # Base financial impact per hour of downtime
            base_hourly_loss = 1.5  # 1.5 Lakhs per hour
            for dept in departments:
                if dept == "Treasury":
                    base_hourly_loss += 5.0
                elif dept == "Hospital":
                    base_hourly_loss += 3.0
                elif dept == "Collectorate":
                    base_hourly_loss += 2.0
                    
            financial_impact_lakhs = round(estimated_downtime * base_hourly_loss, 2)
            
            # Recovery Priority
            priority_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            recovery_priority = priority_map.get(severity.lower(), "medium")

            logger.info(f"Estimated impact for {attack_type}: {citizens_at_risk} citizens at risk, priority {recovery_priority}")
            return {
                "citizens_at_risk": citizens_at_risk,
                "services_at_risk": list(services),
                "departments_at_risk": list(departments),
                "estimated_downtime_hours": estimated_downtime,
                "financial_impact_lakhs": financial_impact_lakhs,
                "recovery_priority": recovery_priority
            }
        except Exception as e:
            logger.error(f"Error estimating impact: {e}")
            return {
                "citizens_at_risk": 500,
                "services_at_risk": [],
                "departments_at_risk": ["Default"],
                "estimated_downtime_hours": 4.0,
                "financial_impact_lakhs": 5.0,
                "recovery_priority": "medium"
            }
        
# Module-level mapping dict as requested
DEPARTMENT_CITIZEN_IMPACT = DEPARTMENT_CITIZEN_IMPACT
