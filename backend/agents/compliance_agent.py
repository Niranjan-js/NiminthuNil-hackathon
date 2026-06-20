import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.compliance_agent")

class ComplianceAgent:
    """
    Compliance Agent that maps incident profiles to legal and regulatory frameworks
    (CERT-IN, DPDP Act, NIST, ISO 27001) to identify reporting requirements and deadlines.
    """

    def map_incident(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map analyzed incident properties to regulatory and compliance frameworks.
        """
        try:
            severity = (analysis.get("severity") or "medium").lower()
            attack_pattern = analysis.get("attack_pattern", "").lower()
            technique_id = analysis.get("technique_id", "").lower()
            root_cause = analysis.get("root_cause", "").lower()
            
            # Determine if Personal Data was involved (e.g. credential access, dumping, customer database targeted)
            is_data_breach = any(x in attack_pattern or x in root_cause for x in [
                "credential", "dumping", "phishing", "exfiltration", "unauthorized access", "user", "brute force"
            ])
            
            # 1. CERT-IN Rules: 6h reporting requirement for critical incidents, ransomware, APT, data breach
            cert_in_reportable = (
                severity in ["critical", "high"] or 
                "ransomware" in attack_pattern or 
                "exfiltration" in attack_pattern or
                is_data_breach
            )
            cert_in_deadline = "Within 6 hours of identification" if cert_in_reportable else None
            
            # 2. DPDP Act 2023: Personal data breach notification (usually within 72h to Board and affected users)
            dpdp_notifiable = is_data_breach and severity in ["critical", "high", "medium"]
            
            # 3. IT Act 2000 Section 70B: Critical infrastructure incidents
            # Applicable if critical severity or critical assets/services targeted
            it_act_applicable = severity == "critical" or "criticality" in str(analysis).lower()
            
            # 4. NIST CSF mapping
            nist_functions = ["Detect", "Respond"]
            if severity == "critical":
                nist_functions.append("Recover")
            if "block_ip" in str(analysis.get("recommended_actions")):
                nist_functions.append("Protect")
                
            # 5. ISO 27001 mapping (Incident management controls)
            iso_controls = ["A.16.1.1 (Reporting)", "A.16.1.5 (Responding to Security Incidents)"]
            if severity == "critical":
                iso_controls.append("A.17.1 (Information Security Continuity)")
                
            # 6. RBI Guidelines: If financial systems (Treasury) are affected
            rbi_applicable = "treasury" in root_cause or "financial" in root_cause or "payment" in root_cause or "bank" in root_cause
            
            # Build list of compliance actions required
            compliance_actions = []
            if cert_in_reportable:
                compliance_actions.append("Mandatory: Report incident details to CERT-IN within 6 hours (Section 70B IT Act).")
            if dpdp_notifiable:
                compliance_actions.append("DPDP Act 2023: Notify the Data Protection Board of India and affected data principals.")
            if rbi_applicable:
                compliance_actions.append("RBI Guidelines: Notify Reserve Bank of India within 6 hours of detection.")
            if severity == "critical":
                compliance_actions.append("Disaster Recovery: Invoke Business Continuity Plan (BCP) and incident recovery playbook.")
            
            if not compliance_actions:
                compliance_actions.append("Log incident and review security posture internally.")

            logger.info(f"Compliance mapping done. CERT-IN Reportable: {cert_in_reportable}")
            return {
                "cert_in_reportable": cert_in_reportable,
                "cert_in_deadline": cert_in_deadline,
                "dpdp_notifiable": dpdp_notifiable,
                "it_act_applicable": it_act_applicable,
                "nist_functions": nist_functions,
                "iso27001_controls": iso_controls,
                "rbi_applicable": rbi_applicable,
                "compliance_actions": compliance_actions,
                "severity_for_compliance": severity
            }
        except Exception as e:
            logger.error(f"Error mapping compliance details: {e}")
            return {
                "cert_in_reportable": False,
                "cert_in_deadline": None,
                "dpdp_notifiable": False,
                "it_act_applicable": False,
                "nist_functions": ["Detect", "Respond"],
                "iso27001_controls": ["A.16.1.5"],
                "rbi_applicable": False,
                "compliance_actions": ["Log and review incident internally."],
                "severity_for_compliance": "medium"
            }
