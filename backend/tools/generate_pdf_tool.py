import logging
import datetime
from typing import Dict, Any

logger = logging.getLogger("niravan.tools.generate_pdf_tool")

TOOL_SPEC = {
    "name": "generate_report",
    "description": "Generate a comprehensive security incident report including MITRE ATT&CK mapping, citizen impact analysis, timeline, and recommended remediation steps.",
    "input_schema": {
        "type": "object",
        "properties": {
            "incident_id": {"type": "string", "description": "The incident ID to generate report for"},
            "report_type": {"type": "string", "enum": ["executive", "technical", "compliance", "citizen_impact"], "description": "Type of report to generate"},
            "include_recommendations": {"type": "boolean", "default": True}
        },
        "required": ["incident_id", "report_type"]
    }
}

class GeneratePDFTool:
    """Tool to generate a structured JSON report for a security incident."""

    @staticmethod
    def execute(db, incident_id: str, report_type: str, include_recommendations: bool = True) -> Dict[str, Any]:
        try:
            from main import IncidentModel, AssetModel, CaseModel, IOCModel
            
            # 1. Fetch incident
            incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if not incident:
                return {"success": False, "error": f"Incident with ID '{incident_id}' not found."}
            
            # 2. Fetch related Case
            case = db.query(CaseModel).filter(CaseModel.incident_id == incident_id).first()
            
            # 3. Fetch related Asset
            asset = None
            if incident.host:
                asset = db.query(AssetModel).filter(
                    (AssetModel.name == incident.host) | (AssetModel.ip == incident.host)
                ).first()
                
            # 4. Fetch indicators associated with the incident IP
            ioc_list = []
            if asset and asset.ip:
                iocs = db.query(IOCModel).filter(IOCModel.indicator == asset.ip).all()
                for ioc in iocs:
                    ioc_list.append({
                        "type": ioc.type,
                        "indicator": ioc.indicator,
                        "actor": ioc.actor,
                        "threat": ioc.threat,
                        "confidence": ioc.confidence
                    })

            # Build report JSON
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.datetime.utcnow().isoformat(),
                    "report_type": report_type,
                    "incident_id": incident_id,
                    "classification": "CONFIDENTIAL - GOVERNMENT OF TAMIL NADU"
                },
                "incident_details": {
                    "id": incident.id,
                    "title": incident.title,
                    "type": incident.type,
                    "severity": incident.severity,
                    "description": incident.description,
                    "status": incident.status,
                    "timestamp": incident.timestamp.isoformat() if incident.timestamp else None,
                    "kill_chain_stage": incident.category or "Actions on Objectives",
                    "mitre_techniques": [t.strip() for t in incident.mitre.split(",")] if incident.mitre else []
                },
                "impact_assessment": {
                    "citizens_affected": incident.affected_citizens or 0,
                    "services_affected": [s.strip() for s in incident.affected_services.split(",")] if incident.affected_services and incident.affected_services != "None" else [],
                    "departments_affected": [d.strip() for d in incident.affected_departments.split(",")] if incident.affected_departments and incident.affected_departments != "None" else [],
                    "recovery_time_estimate": incident.estimated_recovery_time or "Unknown"
                }
            }

            if asset:
                report_data["target_asset"] = {
                    "id": asset.id,
                    "name": asset.name,
                    "ip": asset.ip,
                    "type": asset.type,
                    "criticality": asset.criticality,
                    "risk_score": asset.riskScore,
                    "operating_system": asset.operating_system
                }
            
            if case:
                report_data["case_context"] = {
                    "id": case.id,
                    "title": case.title,
                    "status": case.status,
                    "assignee": case.assignee,
                    "created_at": case.created_at.isoformat() if case.created_at else None
                }

            report_data["threat_intelligence"] = {
                "identified_iocs": ioc_list
            }

            if include_recommendations:
                # Add default mitigation steps based on incident type
                recommendations = []
                if incident.type == "Ransomware" or incident.type == "Malware":
                    recommendations = [
                        "Isolate the affected asset from the network immediately using the `isolate_host` tool.",
                        "Perform an offline antivirus scan and backup verification.",
                        "Block all egress communication to identified command-and-control (C2) servers."
                    ]
                elif incident.type == "Brute Force" or incident.type == "Credential Access":
                    recommendations = [
                        "Rotate credentials for compromised user accounts.",
                        "Enable multi-factor authentication (MFA) across all administrative portals.",
                        "Audit system logs for any signs of privilege escalation."
                    ]
                else:
                    recommendations = [
                        "Examine system logs for unauthorized activity.",
                        "Check firewall and network security group settings.",
                        "Validate system configuration against security baselines."
                    ]
                report_data["remediation_steps"] = recommendations

            logger.info(f"Generated structured incident report for {incident_id}")
            return {
                "success": True,
                "incident_id": incident_id,
                "report_type": report_type,
                "report_data": report_data
            }
        except Exception as e:
            logger.error(f"Error generating report for incident {incident_id}: {e}")
            return {"success": False, "error": str(e)}
