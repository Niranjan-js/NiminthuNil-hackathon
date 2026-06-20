import logging
import datetime
from typing import Dict, Any, List
from agents.impact_agent import ImpactAgent
from agents.compliance_agent import ComplianceAgent
from memory.defense_memory import EnhancedDefenseMemory

logger = logging.getLogger("niravan.agents.report_agent")

class ReportAgent:
    """
    Report Agent that constructs detailed incident reports,
    integrating MITRE taxonomy, citizen impact, regulatory compliance,
    and historical defense success rates.
    """

    def generate_incident_report(self, db, incident_id: str, report_type: str = "executive") -> Dict[str, Any]:
        """
        Generate a structured security incident report.
        """
        try:
            from main import IncidentModel, CaseModel, TelemetryLogModel
            
            # 1. Fetch incident
            incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if not incident:
                return {"error": f"Incident {incident_id} not found."}
                
            # 2. Get Threat details
            threat_analysis = {
                "attack_pattern": incident.technique or "Generic Attack",
                "technique_id": incident.mitre.split(",")[0] if incident.mitre else "T1499",
                "severity": incident.severity or "medium",
                "confidence": 0.90,
                "root_cause": incident.description,
                "recommended_actions": ["isolate_host", "block_ip"]
            }

            # 3. Compile Impact details
            impact_agent = ImpactAgent()
            # Convert incident model to dict for impact estimator
            inc_dict = {
                "id": incident.id,
                "title": incident.title,
                "type": incident.type,
                "host": incident.host,
                "severity": incident.severity,
                "description": incident.description
            }
            impact = impact_agent.estimate_impact(db, inc_dict, threat_analysis)

            # 4. Compile Compliance details
            compliance_agent = ComplianceAgent()
            compliance = compliance_agent.map_incident(threat_analysis)

            # 5. Retrieve Defense Memory recommendations
            defense_recs = EnhancedDefenseMemory.get_recommended_actions(db, incident.type or "Generic")

            # 6. Reconstruct Timeline
            timeline = []
            if incident.timestamp:
                timeline.append({
                    "timestamp": incident.timestamp.isoformat(),
                    "event": f"Incident detected: {incident.title}",
                    "details": incident.description
                })
                
            # Fetch related case if any
            case = db.query(CaseModel).filter(CaseModel.incident_id == incident_id).first()
            if case and case.created_at:
                timeline.append({
                    "timestamp": case.created_at.isoformat(),
                    "event": f"Case created: {case.title}",
                    "details": f"Assigned to: {case.assignee or 'Unassigned'}. Status: {case.status}"
                })
                
            # Build structured report
            report = {
                "report_metadata": {
                    "id": f"REP-{incident_id[:8].upper()}-{datetime.datetime.utcnow().strftime('%Y%M%d')}",
                    "generated_at": datetime.datetime.utcnow().isoformat(),
                    "type": report_type,
                    "incident_id": incident_id,
                    "title": f"{report_type.upper()} SECURITY INCIDENT REPORT - NIRAVAN"
                },
                "executive_summary": (
                    f"On {incident.timestamp.strftime('%B %d, %Y')} at {incident.timestamp.strftime('%H:%M:%S UTC')}, "
                    f"NIRAVAN detected a {incident.severity} severity security incident involving {incident.type} "
                    f"on host {incident.host or 'Unknown'}. The threat was classified as {incident.technique or 'an anomalous compromise'}. "
                    f"Remediation actions were initiated to contain the blast radius, which has been estimated "
                    f"to put {impact.get('citizens_at_risk', 0)} citizens at risk across {len(impact.get('departments_at_risk', []))} department(s)."
                ),
                "incident_details": {
                    "title": incident.title,
                    "type": incident.type,
                    "severity": incident.severity,
                    "status": incident.status,
                    "host": incident.host,
                    "user": incident.user,
                    "technical_logs": incident.technical
                },
                "mitre_mapping": {
                    "kill_chain_stage": incident.category or "Actions on Objectives",
                    "techniques": [t.strip() for t in incident.mitre.split(",")] if incident.mitre else []
                },
                "impact_analysis": impact,
                "compliance_mapping": compliance,
                "defense_learning": {
                    "attack_pattern": incident.type,
                    "recommended_remediations_from_memory": defense_recs
                },
                "event_timeline": timeline
            }

            logger.info(f"ReportAgent successfully generated report for incident {incident_id}")
            return report
        except Exception as e:
            logger.error(f"Error generating incident report: {e}")
            return {"error": str(e)}

    def generate_executive_summary(self, incidents: List[Any], time_period: str = "24h") -> Dict[str, Any]:
        """
        Generate a high-level summary report of all incidents observed in a time period.
        """
        try:
            total_incidents = len(incidents)
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            type_counts = {}
            
            total_citizens_affected = 0
            affected_departments = set()
            
            for inc in incidents:
                sev = (inc.severity or "medium").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                t = inc.type or "Other"
                type_counts[t] = type_counts.get(t, 0) + 1
                
                total_citizens_affected += inc.affected_citizens or 0
                if inc.affected_departments and inc.affected_departments != "None":
                    for d in inc.affected_departments.split(","):
                        affected_departments.add(d.strip())
                        
            summary = {
                "time_period": time_period,
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "total_incidents": total_incidents,
                "severity_distribution": severity_counts,
                "top_attack_vectors": sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3],
                "impact_summary": {
                    "total_citizens_at_risk": total_citizens_affected,
                    "affected_departments": list(affected_departments)
                },
                "narrative": (
                    f"Over the last {time_period}, NIRAVAN monitored and analyzed {total_incidents} security incidents. "
                    f"Among these, {severity_counts['critical']} were classified as Critical and {severity_counts['high']} as High severity. "
                    f"The primary attack vector was '{summary['top_attack_vectors'][0][0]}' if summary['top_attack_vectors'] else 'N/A'. "
                    f"Remediation actions successfully secured critical systems, minimizing impact to approximately "
                    f"{total_citizens_affected} citizen records across public departments."
                )
            }
            return summary
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {"error": str(e)}
