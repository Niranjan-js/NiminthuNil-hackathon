import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.consensus_agent")

class ConsensusAgent:
    """
    Consensus Agent that merges the parallel outputs of the specialized swarm agents
    (Threat, Impact, Compliance, Hunter, Forensics) into a unified incident summary.
    """

    def merge_assessments(
        self,
        threat: Dict[str, Any],
        impact: Dict[str, Any],
        compliance: Dict[str, Any],
        hunter: Dict[str, Any],
        forensics: Dict[str, Any],
        identity: Dict[str, Any] = None,
        cloud: Dict[str, Any] = None,
        intel: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Merge the assessments into a unified consensus dictionary and calculate final weighted score.
        """
        try:
            # 1. Determine Severity Consensus
            severities = [
                threat.get("severity", "low").lower(),
                impact.get("recovery_priority", "low").lower(),
                compliance.get("severity_for_compliance", "low").lower(),
                hunter.get("risk_assessment", "benign").lower()
            ]
            if identity:
                id_score = identity.get("score", 0.1)
                if id_score >= 0.8:
                    severities.append("critical")
                elif id_score >= 0.5:
                    severities.append("high")
            
            # Map benign/suspicious to low/high
            mapped_sevs = []
            for s in severities:
                if s == "confirmed_threat" or s == "critical":
                    mapped_sevs.append("critical")
                elif s == "suspicious" or s == "high":
                    mapped_sevs.append("high")
                elif s == "medium":
                    mapped_sevs.append("medium")
                else:
                    mapped_sevs.append("low")
                    
            if "critical" in mapped_sevs:
                severity_consensus = "critical"
            elif mapped_sevs.count("high") >= 2:
                severity_consensus = "critical"
            elif "high" in mapped_sevs:
                severity_consensus = "high"
            elif "medium" in mapped_sevs:
                severity_consensus = "medium"
            else:
                severity_consensus = "low"

            # 2. Consolidate Key Findings
            key_findings = []
            if threat.get("root_cause"):
                key_findings.append(f"Threat Analyst: {threat['root_cause']}")
            if hunter.get("recommended_investigation"):
                key_findings.append(f"Hunter: {hunter['recommended_investigation']}")
            if forensics.get("forensic_findings"):
                key_findings.extend([f"Forensics: {f}" for f in forensics["forensic_findings"]])
            if identity and identity.get("anomaly_type") != "None":
                key_findings.append(f"Identity Agent: {identity['anomaly_type']} anomaly detected (Score: {identity['score']})")

            # 3. Consolidate Mitigation Suggestions
            mitigations = list(threat.get("recommended_actions", []))
            comp_actions = compliance.get("compliance_actions", [])
            if identity and identity.get("recommendations"):
                mitigations.extend(identity["recommendations"])
                
            # 4. Consensus Score 2.0 Calculation
            hunter_val = hunter.get("score") or (1.0 if hunter.get("risk_assessment") == "suspicious" else 0.1)
            forensics_val = forensics.get("score") or (0.9 if forensics.get("total_events_correlated", 0) > 5 else 0.4)
            
            fin_lakhs = float(impact.get("financial_impact_lakhs", 0.0))
            impact_val = min(fin_lakhs / 50.0, 1.0) if fin_lakhs > 0 else 0.2
            
            identity_val = identity.get("score", 0.1) if identity else 0.1
            cloud_val = cloud.get("score", 0.1) if cloud else 0.1
            intel_val = intel.get("score", 0.1) if intel else 0.1
            
            final_score = (
                0.25 * hunter_val +
                0.20 * forensics_val +
                0.15 * impact_val +
                0.10 * identity_val +
                0.10 * cloud_val +
                0.20 * intel_val
            )
            
            logger.info(f"Consensus achieved. Severity: {severity_consensus}. Consensus Score: {round(final_score, 2)}")
            
            return {
                "severity_consensus": severity_consensus,
                "consensus_score": round(final_score, 2),
                "key_findings": key_findings,
                "recommended_actions": list(set(mitigations)),
                "compliance_summary": {
                    "cert_in_reportable": compliance.get("cert_in_reportable", False),
                    "cert_in_deadline": compliance.get("cert_in_deadline"),
                    "dpdp_notifiable": compliance.get("dpdp_notifiable", False),
                    "compliance_actions": comp_actions
                },
                "impact_summary": {
                    "citizens_at_risk": impact.get("citizens_at_risk", 0),
                    "services_at_risk": impact.get("services_at_risk", []),
                    "departments_at_risk": impact.get("departments_at_risk", []),
                    "estimated_downtime_hours": impact.get("estimated_downtime_hours", 0.0),
                    "financial_impact_lakhs": fin_lakhs
                },
                "forensics_summary": {
                    "events_correlated": forensics.get("total_events_correlated", 0),
                    "findings": forensics.get("forensic_findings", [])
                }
            }
        except Exception as e:
            logger.error(f"Error merging assessments in ConsensusAgent: {e}")
            return {
                "severity_consensus": "medium",
                "consensus_score": 0.5,
                "key_findings": ["Failed to build consensus due to engine error."],
                "recommended_actions": ["isolate_host"],
                "compliance_summary": {"cert_in_reportable": False},
                "impact_summary": {"citizens_at_risk": 500},
                "forensics_summary": {"events_correlated": 0}
            }
