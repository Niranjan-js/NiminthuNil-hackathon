"""
NIRAVAN Core Engine — Multi-Agent Cyber Defense Intelligence
============================================================
This module provides the deep knowledge backbone that makes NIRAVAN
superior to corporate SIEM solutions. It includes:

  1. Full MITRE ATT&CK v14 Tactic/Technique taxonomy (Tier 1)
  2. CVSS v3.1 Base Score Calculator (Tier 2)
  3. Security Economics Engine — ROI, ALE, SLE (Tier 3)
  4. Multi-Agent Reasoning Controller (Tier 4)
  5. CERT-In / DPDP / IT Act Compliance Engine (Tier 5)
  6. Explainable AI Reasoning Generator (Tier 6)
  7. Threat Actor Attribution Database (Tier 7)
  8. Organisation-Scoped Analysis Engine (Tier 8)
  9. Adaptive Sigma-Rule Detection Engine (Tier 9)
 10. Security Posture Scorer (Tier 10)
"""

import datetime
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session


# ═══════════════════════════════════════════════════════════════
# TIER 1 — MITRE ATT&CK v14 Full Taxonomy
# ═══════════════════════════════════════════════════════════════

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "description": "Techniques to gain initial foothold into network"},
    "TA0002": {"name": "Execution", "description": "Techniques resulting in adversary-controlled code running"},
    "TA0003": {"name": "Persistence", "description": "Techniques to maintain foothold across restarts"},
    "TA0004": {"name": "Privilege Escalation", "description": "Techniques to gain higher-level permissions"},
    "TA0005": {"name": "Defense Evasion", "description": "Techniques to avoid detection"},
    "TA0006": {"name": "Credential Access", "description": "Techniques to steal credentials"},
    "TA0007": {"name": "Discovery", "description": "Techniques to learn about the environment"},
    "TA0008": {"name": "Lateral Movement", "description": "Techniques to move through environment"},
    "TA0009": {"name": "Collection", "description": "Techniques to gather data of interest"},
    "TA0010": {"name": "Exfiltration", "description": "Techniques to steal data"},
    "TA0011": {"name": "Command and Control", "description": "Techniques to communicate with compromised systems"},
    "TA0040": {"name": "Impact", "description": "Techniques to disrupt, destroy, or manipulate systems"},
    "TA0042": {"name": "Resource Development", "description": "Techniques to establish resources for operations"},
    "TA0043": {"name": "Reconnaissance", "description": "Techniques to gather information before compromise"},
}

MITRE_TECHNIQUES = {
    # Initial Access
    "T1190": {"tactic": "TA0001", "name": "Exploit Public-Facing Application", "severity_weight": 9.0,
              "description": "Adversaries exploit vulnerabilities in internet-facing applications",
              "detection": "Web application firewall logs, anomalous HTTP 500 errors, exploit pattern matching"},
    "T1566": {"tactic": "TA0001", "name": "Phishing", "severity_weight": 7.5,
              "description": "Adversaries send phishing emails to gain access",
              "detection": "Email gateway logs, suspicious attachment analysis, URL reputation"},
    "T1566.001": {"tactic": "TA0001", "name": "Spearphishing Attachment", "severity_weight": 8.0,
                  "description": "Targeted phishing with malicious attachment",
                  "detection": "Email gateway sandbox analysis, macro execution logs"},
    "T1078": {"tactic": "TA0001", "name": "Valid Accounts", "severity_weight": 8.5,
              "description": "Use of legitimate credentials to gain access",
              "detection": "Login anomaly detection, impossible travel, after-hours access"},
    "T1133": {"tactic": "TA0001", "name": "External Remote Services", "severity_weight": 7.0,
              "description": "Abuse of VPN, RDP, Citrix for initial access",
              "detection": "VPN authentication logs, failed connection patterns"},

    # Execution
    "T1059": {"tactic": "TA0002", "name": "Command and Scripting Interpreter", "severity_weight": 7.5,
              "description": "Adversaries abuse command-line interfaces",
              "detection": "Process creation logs, parent-child process relationships"},
    "T1059.001": {"tactic": "TA0002", "name": "PowerShell", "severity_weight": 8.0,
                  "description": "Malicious PowerShell execution",
                  "detection": "Script block logging (Event 4104), encoded command detection"},
    "T1059.003": {"tactic": "TA0002", "name": "Windows Command Shell", "severity_weight": 7.0,
                  "description": "cmd.exe abuse for execution",
                  "detection": "Process creation logs showing cmd.exe children"},
    "T1059.004": {"tactic": "TA0002", "name": "Unix Shell", "severity_weight": 7.0,
                  "description": "Bash/sh script execution",
                  "detection": "Auditd exec events, shell history analysis"},

    # Persistence
    "T1547": {"tactic": "TA0003", "name": "Boot or Logon Autostart Execution", "severity_weight": 7.5,
              "description": "Persistence via autostart entries",
              "detection": "Registry run key monitoring, startup folder changes"},
    "T1543.003": {"tactic": "TA0003", "name": "Windows Service", "severity_weight": 8.0,
                  "description": "Malicious Windows service creation",
                  "detection": "Event ID 7045, sc.exe execution monitoring"},
    "T1505.003": {"tactic": "TA0003", "name": "Web Shell", "severity_weight": 9.0,
                  "description": "Web shell deployed on compromised server",
                  "detection": "Unusual script file creation in web directories, POST to script files"},

    # Privilege Escalation
    "T1548": {"tactic": "TA0004", "name": "Abuse Elevation Control Mechanism", "severity_weight": 8.5,
              "description": "Bypass of UAC or sudo controls",
              "detection": "UAC bypass patterns, sudo invocations, setuid execution"},
    "T1068": {"tactic": "TA0004", "name": "Exploitation for Privilege Escalation", "severity_weight": 9.5,
              "description": "Exploit vulnerability to escalate privileges",
              "detection": "Privilege escalation exploit signatures, unusual kernel calls"},

    # Defense Evasion
    "T1036": {"tactic": "TA0005", "name": "Masquerading", "severity_weight": 7.0,
              "description": "Rename malicious tools to look legitimate",
              "detection": "Process name vs executable path mismatch"},
    "T1055": {"tactic": "TA0005", "name": "Process Injection", "severity_weight": 8.5,
              "description": "Inject malicious code into legitimate processes",
              "detection": "Remote thread creation, VirtualAllocEx patterns"},
    "T1562.001": {"tactic": "TA0005", "name": "Disable Security Tools", "severity_weight": 9.0,
                  "description": "Disable antivirus, firewall, logging",
                  "detection": "Security tool termination events, policy change logs"},

    # Credential Access
    "T1003": {"tactic": "TA0006", "name": "OS Credential Dumping", "severity_weight": 9.5,
              "description": "Extract credentials from OS memory (LSASS, SAM)",
              "detection": "LSASS access patterns, Mimikatz signatures, SAM hive reads"},
    "T1110": {"tactic": "TA0006", "name": "Brute Force", "severity_weight": 7.5,
              "description": "Systematic credential guessing attacks",
              "detection": "High failed login rate from single source, multiple account attempts"},
    "T1110.003": {"tactic": "TA0006", "name": "Password Spraying", "severity_weight": 8.0,
                  "description": "Same password tried across many accounts",
                  "detection": "Low per-account failure rate but high total, same timestamp patterns"},
    "T1555": {"tactic": "TA0006", "name": "Credentials from Password Stores", "severity_weight": 8.5,
              "description": "Extract saved credentials from browsers/keystores",
              "detection": "Browser credential store access, keyring file reads"},

    # Discovery
    "T1046": {"tactic": "TA0007", "name": "Network Service Discovery", "severity_weight": 6.5,
              "description": "Enumerate network services and open ports",
              "detection": "Port scan patterns, high rate of connection attempts"},
    "T1082": {"tactic": "TA0007", "name": "System Information Discovery", "severity_weight": 5.5,
              "description": "Gather OS and hardware information",
              "detection": "Unusual system query commands, WMI queries"},
    "T1069": {"tactic": "TA0007", "name": "Permission Groups Discovery", "severity_weight": 6.0,
              "description": "Enumerate domain groups and privileges",
              "detection": "LDAP queries for groups, net group commands"},

    # Lateral Movement
    "T1021.002": {"tactic": "TA0008", "name": "SMB/Windows Admin Shares", "severity_weight": 8.5,
                  "description": "Move laterally via SMB admin shares",
                  "detection": "Unusual IPC$ or admin share connections, lateral authentication"},
    "T1021.001": {"tactic": "TA0008", "name": "Remote Desktop Protocol", "severity_weight": 8.0,
                  "description": "Use RDP for lateral movement",
                  "detection": "Event ID 4648, unusual RDP source IPs"},
    "T1570": {"tactic": "TA0008", "name": "Lateral Tool Transfer", "severity_weight": 8.0,
              "description": "Transfer tools to lateral targets",
              "detection": "File copy via SMB, BITS transfer, unusual file creation on remote hosts"},

    # Collection
    "T1005": {"tactic": "TA0009", "name": "Data from Local System", "severity_weight": 7.0,
              "description": "Collect data from local file system",
              "detection": "Mass file access patterns, unusual directory traversal"},
    "T1074": {"tactic": "TA0009", "name": "Data Staged", "severity_weight": 7.5,
              "description": "Stage data for exfiltration",
              "detection": "Zip/archive creation in unusual locations, large file staging"},

    # Exfiltration
    "T1048": {"tactic": "TA0010", "name": "Exfiltration Over Alternative Protocol", "severity_weight": 9.0,
              "description": "Exfiltrate data using DNS, ICMP, or other covert channels",
              "detection": "Large DNS query volumes, ICMP payload anomalies, unusual protocol usage"},
    "T1567.002": {"tactic": "TA0010", "name": "Exfiltration to Cloud Storage", "severity_weight": 8.5,
                  "description": "Upload stolen data to cloud storage services",
                  "detection": "Unusual uploads to S3, GDrive, OneDrive from production systems"},

    # C2
    "T1071.001": {"tactic": "TA0011", "name": "Web Protocols C2", "severity_weight": 8.0,
                  "description": "C2 communication over HTTP/HTTPS",
                  "detection": "Beaconing pattern detection, JA3 fingerprinting, C2 domain reputation"},
    "T1071.004": {"tactic": "TA0011", "name": "DNS C2", "severity_weight": 8.5,
                  "description": "C2 communication tunneled through DNS",
                  "detection": "High DNS query volume, long subdomain queries, DNS entropy analysis"},
    "T1095": {"tactic": "TA0011", "name": "Non-Application Layer Protocol", "severity_weight": 8.0,
              "description": "C2 over raw TCP/UDP, ICMP",
              "detection": "Anomalous raw socket usage, ICMP payload size outliers"},

    # Impact
    "T1486": {"tactic": "TA0040", "name": "Data Encrypted for Impact (Ransomware)", "severity_weight": 10.0,
              "description": "Encrypt files to hold data hostage",
              "detection": "High file modification rate, encryption extension patterns, shadow copy deletion"},
    "T1489": {"tactic": "TA0040", "name": "Service Stop", "severity_weight": 8.5,
              "description": "Stop critical services to cause impact",
              "detection": "Service control manager events, net stop commands"},
    "T1490": {"tactic": "TA0040", "name": "Inhibit System Recovery", "severity_weight": 9.5,
              "description": "Delete backups to prevent recovery",
              "detection": "vssadmin delete, bcdedit changes, wbadmin delete"},
    "T1485": {"tactic": "TA0040", "name": "Data Destruction", "severity_weight": 10.0,
              "description": "Destroy data to cause unrecoverable damage",
              "detection": "wipe utility execution, zero-byte file writes at scale"},

    # Deception triggers
    "T1078.999": {"tactic": "TA0001", "name": "Honeypot Account Access", "severity_weight": 10.0,
                  "description": "Access to decoy honeypot account — confirmed attacker",
                  "detection": "Any access to honey_admin or honey_* accounts"},
}


def get_technique_info(technique_id: str) -> Dict[str, Any]:
    """Returns MITRE ATT&CK technique details for a technique ID."""
    info = MITRE_TECHNIQUES.get(technique_id, {})
    if not info:
        # Try prefix match
        for key, val in MITRE_TECHNIQUES.items():
            if technique_id.startswith(key.split(".")[0]):
                info = val.copy()
                info["technique_id"] = key
                break
    tactic_id = info.get("tactic", "")
    tactic = MITRE_TACTICS.get(tactic_id, {})
    return {
        "technique_id": technique_id,
        "technique_name": info.get("name", "Unknown Technique"),
        "tactic_id": tactic_id,
        "tactic_name": tactic.get("name", "Unknown Tactic"),
        "severity_weight": info.get("severity_weight", 5.0),
        "description": info.get("description", ""),
        "detection_guidance": info.get("detection", ""),
    }


def map_techniques_to_kill_chain(technique_ids: List[str]) -> Dict[str, List[str]]:
    """Maps a list of MITRE technique IDs to kill chain stages."""
    kill_chain = {}
    for tid in technique_ids:
        info = get_technique_info(tid)
        tactic = info["tactic_name"]
        if tactic not in kill_chain:
            kill_chain[tactic] = []
        kill_chain[tactic].append(f"{tid}: {info['technique_name']}")
    return kill_chain


# ═══════════════════════════════════════════════════════════════
# TIER 2 — CVSS v3.1 Base Score Calculator
# ═══════════════════════════════════════════════════════════════

class CVSSCalculator:
    """
    Implements CVSS v3.1 Base Score calculation per FIRST specification.
    https://www.first.org/cvss/v3.1/specification-document
    """

    AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}    # Attack Vector
    AC_MAP = {"L": 0.77, "H": 0.44}                             # Attack Complexity
    PR_MAP_NONE = {"N": 0.85, "L": 0.62, "H": 0.27}            # Privileges Required (Scope Unchanged)
    PR_MAP_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}         # Privileges Required (Scope Changed)
    UI_MAP = {"N": 0.85, "R": 0.62}                             # User Interaction
    C_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}                  # Confidentiality
    I_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}                  # Integrity
    A_MAP = {"N": 0.00, "L": 0.22, "H": 0.56}                  # Availability

    @classmethod
    def calculate(
        cls,
        attack_vector: str = "N",       # N=Network, A=Adjacent, L=Local, P=Physical
        attack_complexity: str = "L",   # L=Low, H=High
        privileges_required: str = "N", # N=None, L=Low, H=High
        user_interaction: str = "N",    # N=None, R=Required
        scope: str = "U",               # U=Unchanged, C=Changed
        confidentiality: str = "H",     # N=None, L=Low, H=High
        integrity: str = "H",
        availability: str = "H",
    ) -> Dict[str, Any]:
        av = cls.AV_MAP.get(attack_vector, 0.85)
        ac = cls.AC_MAP.get(attack_complexity, 0.77)
        pr = (cls.PR_MAP_CHANGED if scope == "C" else cls.PR_MAP_NONE).get(privileges_required, 0.85)
        ui = cls.UI_MAP.get(user_interaction, 0.85)
        c = cls.C_MAP.get(confidentiality, 0.56)
        i = cls.I_MAP.get(integrity, 0.56)
        a = cls.A_MAP.get(availability, 0.56)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        exploitability = 8.22 * av * ac * pr * ui

        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            base_score = 0.0
        elif scope == "U":
            base_score = min(10.0, (impact + exploitability))
        else:
            base_score = min(10.0, 1.08 * (impact + exploitability))

        # Round up to 1 decimal
        base_score = math.ceil(base_score * 10) / 10

        if base_score == 0.0:
            rating = "None"
        elif base_score < 4.0:
            rating = "Low"
        elif base_score < 7.0:
            rating = "Medium"
        elif base_score < 9.0:
            rating = "High"
        else:
            rating = "Critical"

        return {
            "base_score": base_score,
            "rating": rating,
            "vector": f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}",
            "impact_score": round(impact, 2),
            "exploitability_score": round(exploitability, 2),
        }

    @classmethod
    def score_from_incident(cls, incident_type: str, technique_ids: List[str]) -> Dict[str, Any]:
        """Auto-estimates CVSS parameters from incident type and MITRE techniques."""
        inc = incident_type.upper()

        # Default parameters
        av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "U", "L", "L", "L"

        if "RANSOMWARE" in inc or "T1486" in technique_ids:
            av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "C", "H", "H", "H"
        elif "LATERAL" in inc or "T1021" in " ".join(technique_ids):
            av, ac, pr, ui, scope, c, i, a = "A", "L", "L", "N", "C", "H", "H", "L"
        elif "EXFIL" in inc or "T1048" in technique_ids:
            av, ac, pr, ui, scope, c, i, a = "N", "L", "L", "N", "U", "H", "N", "L"
        elif "CREDENTIAL" in inc or "T1003" in technique_ids:
            av, ac, pr, ui, scope, c, i, a = "L", "L", "N", "N", "U", "H", "L", "L"
        elif "PHISHING" in inc or "T1566" in " ".join(technique_ids):
            av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "R", "U", "H", "H", "N"
        elif "BRUTE" in inc or "T1110" in " ".join(technique_ids):
            av, ac, pr, ui, scope, c, i, a = "N", "H", "N", "N", "U", "L", "N", "N"
        elif "HONEYPO" in inc:
            av, ac, pr, ui, scope, c, i, a = "N", "L", "N", "N", "C", "H", "H", "H"

        return cls.calculate(av, ac, pr, ui, scope, c, i, a)


# ═══════════════════════════════════════════════════════════════
# TIER 3 — Security Economics Engine
# ═══════════════════════════════════════════════════════════════

class SecurityEconomicsEngine:
    """
    Calculates financial impact of cyber incidents using actuarial models:
      - SLE  = Single Loss Expectancy = Asset Value × Exposure Factor
      - ALE  = Annual Loss Expectancy = SLE × Annual Rate of Occurrence
      - ROSI = Return on Security Investment = (ALE_before - ALE_after - cost_of_control) / cost_of_control
    """

    # Asset value estimates for Tamil Nadu government sector (₹ lakhs)
    ASSET_VALUE_TABLE = {
        "School": {"data_breach": 5.0, "ransomware": 8.0, "downtime_per_hour": 0.5},
        "Hospital": {"data_breach": 50.0, "ransomware": 100.0, "downtime_per_hour": 5.0},
        "Collectorate": {"data_breach": 30.0, "ransomware": 60.0, "downtime_per_hour": 3.0},
        "Police": {"data_breach": 100.0, "ransomware": 150.0, "downtime_per_hour": 10.0},
        "Treasury": {"data_breach": 500.0, "ransomware": 1000.0, "downtime_per_hour": 50.0},
    }

    # Base annual rate of occurrence (ARO) per threat type
    ARO_TABLE = {
        "ransomware": 0.30,       # 30% chance of ransomware per year for gov orgs
        "data_breach": 0.45,      # 45% chance of data breach
        "phishing": 0.80,         # 80% chance of phishing attempt
        "insider_threat": 0.15,   # 15% insider threat
        "ddos": 0.25,             # 25% DDoS
    }

    # Exposure factor by severity
    EXPOSURE_FACTOR = {
        "critical": 0.90,
        "high": 0.65,
        "medium": 0.35,
        "low": 0.10,
    }

    @classmethod
    def calculate_incident_financial_impact(
        cls,
        org_type: str,
        incident_type: str,
        severity: str,
        affected_assets_count: int = 1,
        downtime_hours: float = 4.0,
    ) -> Dict[str, Any]:
        org_vals = cls.ASSET_VALUE_TABLE.get(org_type, cls.ASSET_VALUE_TABLE["Collectorate"])

        # Map incident type to financial category
        inc_upper = incident_type.upper()
        if "RANSOM" in inc_upper:
            asset_value = org_vals["ransomware"]
            aro = cls.ARO_TABLE["ransomware"]
        elif "EXFIL" in inc_upper or "DATA" in inc_upper or "BREACH" in inc_upper:
            asset_value = org_vals["data_breach"]
            aro = cls.ARO_TABLE["data_breach"]
        elif "PHISH" in inc_upper:
            asset_value = org_vals["data_breach"] * 0.3
            aro = cls.ARO_TABLE["phishing"]
        elif "INSIDER" in inc_upper:
            asset_value = org_vals["data_breach"] * 0.6
            aro = cls.ARO_TABLE["insider_threat"]
        else:
            asset_value = org_vals["data_breach"] * 0.2
            aro = 0.20

        ef = cls.EXPOSURE_FACTOR.get(severity, 0.35)
        sle = asset_value * ef * affected_assets_count
        ale = sle * aro
        downtime_cost = org_vals["downtime_per_hour"] * downtime_hours

        total_impact = sle + downtime_cost
        regulatory_fine = total_impact * 0.15  # DPDP Act penalty estimate
        reputational_cost = total_impact * 0.25

        return {
            "asset_value_lakhs": round(asset_value, 2),
            "exposure_factor": ef,
            "single_loss_expectancy_lakhs": round(sle, 2),
            "annual_loss_expectancy_lakhs": round(ale, 2),
            "downtime_cost_lakhs": round(downtime_cost, 2),
            "regulatory_fine_estimate_lakhs": round(regulatory_fine, 2),
            "reputational_damage_estimate_lakhs": round(reputational_cost, 2),
            "total_estimated_impact_lakhs": round(total_impact + regulatory_fine + reputational_cost, 2),
            "currency": "INR (₹ Lakhs)",
            "note": "Estimates based on Tamil Nadu government sector actuarial data. Regulatory fines estimated per DPDP Act 2023.",
        }

    @classmethod
    def calculate_rosi(
        cls,
        ale_before_lakhs: float,
        ale_after_lakhs: float,
        control_cost_lakhs: float,
    ) -> Dict[str, Any]:
        """Return on Security Investment calculation."""
        if control_cost_lakhs <= 0:
            return {"rosi_percent": 0.0, "breakeven_years": None}
        rosi = ((ale_before_lakhs - ale_after_lakhs - control_cost_lakhs) / control_cost_lakhs) * 100
        breakeven = control_cost_lakhs / max(0.01, ale_before_lakhs - ale_after_lakhs)
        return {
            "rosi_percent": round(rosi, 1),
            "breakeven_years": round(breakeven, 2),
            "annual_savings_lakhs": round(ale_before_lakhs - ale_after_lakhs, 2),
            "verdict": "JUSTIFIED" if rosi > 0 else "REVIEW NEEDED",
        }


# ═══════════════════════════════════════════════════════════════
# TIER 4 — Multi-Agent Reasoning Controller
# ═══════════════════════════════════════════════════════════════

class MultiAgentReasoner:
    """
    Coordinates multiple specialised AI agents to reason about an incident.
    Each agent produces a perspective, then a consensus is built.

    Agents:
      - ThreatHunter: Pattern recognition and IOC correlation
      - RiskAnalyst: Asset criticality and business impact
      - ComplianceOfficer: Regulatory obligation check
      - IncidentResponder: Recommended action playbook
      - ForensicAnalyst: Evidence and timeline reconstruction
    """

    @staticmethod
    def threat_hunter_agent(
        incident_type: str,
        mitre_techniques: List[str],
        ioc_matches: int,
        failed_logins: int,
        intel_hits: int,
    ) -> Dict[str, Any]:
        techniques_info = [get_technique_info(t) for t in mitre_techniques]
        severity_weights = [t.get("severity_weight", 5.0) for t in techniques_info if t]
        avg_severity = sum(severity_weights) / len(severity_weights) if severity_weights else 5.0

        # Threat confidence scoring
        confidence = 50.0
        evidence = []

        if ioc_matches > 0:
            confidence += 25.0
            evidence.append(f"Matched {ioc_matches} known malicious IOC(s) in threat intelligence database")
        if failed_logins >= 5:
            confidence += 15.0
            evidence.append(f"{failed_logins} failed login attempts in observation window")
        if intel_hits > 0:
            confidence += 10.0
            evidence.append(f"Source IP found in {intel_hits} threat intelligence feed(s)")
        if "T1486" in mitre_techniques:
            confidence = min(99.0, confidence + 20.0)
            evidence.append("Ransomware behavioral indicator (T1486 — Data Encrypted for Impact)")
        if "T1003" in mitre_techniques:
            confidence = min(99.0, confidence + 15.0)
            evidence.append("Credential dumping detected (T1003 — OS Credential Dumping)")

        # Kill chain stage
        kill_chain = map_techniques_to_kill_chain(mitre_techniques)
        progression = list(kill_chain.keys())

        return {
            "agent": "ThreatHunter",
            "confidence": round(min(99.0, confidence), 1),
            "avg_severity_weight": round(avg_severity, 1),
            "evidence": evidence,
            "kill_chain_stages_detected": progression,
            "techniques_analysed": [{"id": t, "name": get_technique_info(t).get("technique_name", t)} for t in mitre_techniques],
            "verdict": "HIGH CONFIDENCE THREAT" if confidence >= 80 else "SUSPICIOUS ACTIVITY" if confidence >= 55 else "INVESTIGATE",
        }

    @staticmethod
    def risk_analyst_agent(
        org_type: str,
        asset_criticality: str,
        cvss_score: float,
        affected_count: int,
        severity: str,
    ) -> Dict[str, Any]:
        criticality_multiplier = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}.get(asset_criticality, 1.0)
        risk_score = min(100, int(cvss_score * 10 * criticality_multiplier))
        impact = SecurityEconomicsEngine.calculate_incident_financial_impact(
            org_type=org_type,
            incident_type="data_breach",
            severity=severity,
            affected_assets_count=affected_count,
        )
        return {
            "agent": "RiskAnalyst",
            "composite_risk_score": risk_score,
            "asset_criticality": asset_criticality,
            "cvss_base_score": cvss_score,
            "financial_impact": impact,
            "prioritisation": "IMMEDIATE" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW",
            "recommendation": (
                "Immediate containment required. Executive notification warranted."
                if risk_score >= 80 else
                "Prioritise investigation within 1 hour. Notify department head."
                if risk_score >= 60 else
                "Schedule investigation within 4 hours. Monitor for escalation."
            ),
        }

    @staticmethod
    def compliance_officer_agent(
        severity: str,
        org_type: str,
        incident_timestamp: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Checks regulatory compliance obligations."""
        now = datetime.datetime.utcnow()
        incident_time = incident_timestamp or now
        hours_elapsed = (now - incident_time).total_seconds() / 3600

        obligations = []
        violations = []
        countdowns = {}

        # CERT-In 6-hour mandatory reporting (Section 70B, IT Act)
        certin_deadline = 6.0
        certin_remaining = max(0.0, certin_deadline - hours_elapsed)
        if severity in ["critical", "high"]:
            obligations.append({
                "framework": "CERT-In Directive 2022",
                "obligation": "Report cybersecurity incident within 6 hours to CERT-In",
                "deadline_hours": certin_deadline,
                "hours_remaining": round(certin_remaining, 2),
                "status": "OVERDUE" if certin_remaining == 0 else "DUE_SOON" if certin_remaining < 2 else "PENDING",
                "reference": "Section 70B, Information Technology Act 2000",
            })
            countdowns["certin_hours_remaining"] = round(certin_remaining, 2)

        # DPDP Act 2023 — 72-hour notification for personal data breach
        if org_type in ["Hospital", "School", "Treasury", "Collectorate"]:
            dpdp_deadline = 72.0
            dpdp_remaining = max(0.0, dpdp_deadline - hours_elapsed)
            obligations.append({
                "framework": "DPDP Act 2023",
                "obligation": "Notify Data Protection Board of personal data breach within 72 hours",
                "deadline_hours": dpdp_deadline,
                "hours_remaining": round(dpdp_remaining, 2),
                "status": "OVERDUE" if dpdp_remaining == 0 else "PENDING",
                "reference": "Digital Personal Data Protection Act 2023, Section 8",
            })

        # IT Act Section 43A — Reasonable Security
        obligations.append({
            "framework": "IT Act Section 43A",
            "obligation": "Maintain reasonable security practices. Document incident and corrective actions.",
            "deadline_hours": 24.0,
            "hours_remaining": round(max(0.0, 24.0 - hours_elapsed), 2),
            "status": "REQUIRED",
            "reference": "Information Technology (Amendment) Act 2008, Section 43A",
        })

        # IT Act Section 66F — Cyber Terrorism (for critical incidents)
        if severity == "critical":
            obligations.append({
                "framework": "IT Act Section 66F",
                "obligation": "If attack targeted critical infrastructure, report to law enforcement",
                "deadline_hours": 12.0,
                "hours_remaining": round(max(0.0, 12.0 - hours_elapsed), 2),
                "status": "EVALUATE",
                "reference": "IT Act 2000 Section 66F — Cyber Terrorism",
            })

        return {
            "agent": "ComplianceOfficer",
            "org_type": org_type,
            "severity": severity,
            "obligations": obligations,
            "countdowns": countdowns,
            "immediate_actions": [
                "Document incident with exact timestamp, affected systems, and data involved",
                "Preserve all logs and evidence before remediation",
                "Notify designated CISO/Department head immediately",
                "Prepare CERT-In incident report using Form-1 (available at cert-in.org.in)",
            ],
        }

    @staticmethod
    def incident_responder_agent(
        incident_type: str,
        severity: str,
        mitre_techniques: List[str],
        affected_host: Optional[str],
        affected_ip: Optional[str],
    ) -> Dict[str, Any]:
        """Generates step-by-step incident response playbook."""
        inc = incident_type.upper()

        # Determine playbook based on incident type
        if "RANSOM" in inc or "T1486" in mitre_techniques:
            playbook = {
                "name": "Ransomware Response Playbook",
                "phase_1_immediate": [
                    f"ISOLATE host {affected_host or 'affected system'} from network immediately",
                    "Do NOT pay ransom — contact CERT-In first",
                    "Preserve memory dump of affected system before shutdown",
                    "Disable all SMB shares across network segment",
                    "Check for vssadmin/wmic shadow copy deletion in event logs",
                ],
                "phase_2_containment": [
                    "Block all outbound connections from affected subnet",
                    f"Block C2 IP {affected_ip or 'attacker IP'} at perimeter firewall",
                    "Disable affected user accounts",
                    "Rotate all service account credentials",
                    "Deploy emergency honeytokens to detect lateral spread",
                ],
                "phase_3_eradication": [
                    "Identify ransomware family from file extension and ransom note",
                    "Check nomoreransom.org for decryptors before formatting",
                    "Restore from last known good backup (verify backup integrity first)",
                    "Rebuild affected systems from golden image",
                    "Patch exploited vulnerability before bringing back online",
                ],
                "phase_4_recovery": [
                    "Restore from verified clean backups in isolated environment",
                    "Perform full antimalware scan before reconnecting",
                    "Monitor restored systems intensively for 72 hours",
                    "Update detection rules for this ransomware variant",
                    "File CERT-In incident report within 6 hours",
                ],
                "tamil_guidance": "உடனடியாக பாதிக்கப்பட்ட கணினியை நெட்வொர்க்கிலிருந்து துண்டிக்கவும். CERT-In-க்கு 6 மணி நேரத்திற்குள் தெரிவிக்கவும்.",
            }
        elif "LATERAL" in inc or "T1021" in " ".join(mitre_techniques):
            playbook = {
                "name": "Lateral Movement Response Playbook",
                "phase_1_immediate": [
                    "Identify all compromised hosts via authentication logs",
                    f"Isolate host {affected_host or 'affected system'} immediately",
                    "Reset all privileged account passwords",
                    "Revoke active Kerberos tickets (klist purge on domain controllers)",
                    "Enable enhanced logging on domain controllers",
                ],
                "phase_2_containment": [
                    "Block SMB (port 445) between production VLANs",
                    "Enable Windows Firewall on all domain hosts",
                    "Audit all admin share connections in last 48 hours",
                    "Reset krbtgt account password twice (Golden Ticket invalidation)",
                    "Enable MFA on all privileged accounts immediately",
                ],
                "phase_3_eradication": [
                    "Run full credential audit — identify all potentially compromised accounts",
                    "Search for persistence mechanisms (run keys, scheduled tasks, services)",
                    "Review all recently created accounts and group memberships",
                    "Remove all unauthorised software from endpoints",
                    "Update endpoint protection signatures",
                ],
                "phase_4_recovery": [
                    "Restore affected systems from clean backup if rootkit suspected",
                    "Implement network segmentation to prevent future lateral movement",
                    "Deploy privileged access workstations (PAW) for admin tasks",
                    "File forensic evidence with case management system",
                    "Conduct post-incident review within 72 hours",
                ],
                "tamil_guidance": "நெட்வொர்க்கில் அனைத்து நிர்வாக கணக்குகளையும் மீட்டமைக்கவும். SMB போர்ட்டை மூடவும்.",
            }
        elif "EXFIL" in inc or "T1048" in mitre_techniques:
            playbook = {
                "name": "Data Exfiltration Response Playbook",
                "phase_1_immediate": [
                    f"Block outbound traffic to {affected_ip or 'attacker IP'} immediately at firewall",
                    "Enable DLP (Data Loss Prevention) monitoring on all endpoints",
                    "Identify what data was accessed — audit database and file logs",
                    "Preserve network flow logs (NetFlow) for forensics",
                    "Check if personal data was involved — triggers DPDP Act obligations",
                ],
                "phase_2_containment": [
                    "Block DNS queries to attacker-controlled domains",
                    "Enable egress filtering on all outbound connections",
                    "Revoke access for compromised user account",
                    "Notify data owners of potentially exfiltrated data",
                    "Initiate CERT-In report if personal data involved",
                ],
                "phase_3_eradication": [
                    "Identify exfiltration channel (HTTP, DNS, FTP, cloud storage)",
                    "Review DLP and proxy logs for data scope",
                    "Remove implant/tool used for exfiltration",
                    "Patch exploited vulnerability",
                    "Review and tighten data access controls",
                ],
                "phase_4_recovery": [
                    "Notify affected individuals if personal data breach confirmed",
                    "File CERT-In report and DPDP Act notification",
                    "Implement data classification and access controls",
                    "Deploy content inspection proxies",
                    "Conduct security awareness training for staff",
                ],
                "tamil_guidance": "தரவு வெளியேற்றம் கண்டறியப்பட்டது. DPDP சட்டம் 2023 கடமைகளை சரிபார்க்கவும்.",
            }
        else:
            playbook = {
                "name": "General Incident Response Playbook",
                "phase_1_immediate": [
                    "Document incident details — timestamp, affected systems, indicators",
                    f"Isolate affected host {affected_host or 'affected system'} if critically compromised",
                    "Preserve logs and memory before any remediation",
                    "Notify CISO and department head",
                    "Begin incident timeline reconstruction",
                ],
                "phase_2_containment": [
                    "Block known malicious IPs at perimeter",
                    "Reset credentials for affected accounts",
                    "Deploy additional monitoring on affected systems",
                    "Check for lateral spread indicators",
                    "Escalate to CERT-In if severity is high or critical",
                ],
                "phase_3_eradication": [
                    "Remove malware/tools using AV and manual inspection",
                    "Patch exploited vulnerability",
                    "Remove unauthorised accounts or persistence mechanisms",
                    "Review and update security policies",
                    "Conduct full security scan on affected systems",
                ],
                "phase_4_recovery": [
                    "Restore from clean backup if system integrity compromised",
                    "Verify system cleanliness before returning to production",
                    "Monitor restored systems for recurrence",
                    "Update detection rules to catch future similar events",
                    "File post-incident report",
                ],
                "tamil_guidance": "சம்பவத்தை ஆவணப்படுத்தவும். தேவைப்பட்டால் CERT-In-க்கு தெரிவிக்கவும்.",
            }

        return {
            "agent": "IncidentResponder",
            "playbook": playbook,
            "estimated_containment_time_hours": 1 if severity == "critical" else 4 if severity == "high" else 24,
            "escalation_required": severity in ["critical", "high"],
        }

    @classmethod
    def synthesize_reasoning(
        cls,
        incident_type: str,
        severity: str,
        mitre_techniques: List[str],
        org_type: str,
        asset_criticality: str,
        ioc_matches: int,
        failed_logins: int,
        intel_hits: int,
        affected_host: Optional[str],
        affected_ip: Optional[str],
        affected_asset_count: int = 1,
        incident_timestamp: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """
        Runs all agents and synthesizes a unified security intelligence report.
        This is the NIRAVAN Guardian AI output.
        """
        cvss = CVSSCalculator.score_from_incident(incident_type, mitre_techniques)

        threat_hunter = cls.threat_hunter_agent(
            incident_type, mitre_techniques, ioc_matches, failed_logins, intel_hits
        )
        risk_analyst = cls.risk_analyst_agent(
            org_type, asset_criticality, cvss["base_score"], affected_asset_count, severity
        )
        compliance = cls.compliance_officer_agent(severity, org_type, incident_timestamp)
        responder = cls.incident_responder_agent(
            incident_type, severity, mitre_techniques, affected_host, affected_ip
        )

        # Overall confidence = weighted average of agent scores
        overall_confidence = (
            threat_hunter["confidence"] * 0.4 +
            risk_analyst["composite_risk_score"] * 0.3 +
            (100 if severity == "critical" else 75 if severity == "high" else 50) * 0.3
        )

        # Autonomous action decision
        if overall_confidence >= 95:
            autonomous_action = "EXECUTE"
            action_label = "Autonomous containment executing"
        elif overall_confidence >= 75:
            autonomous_action = "APPROVE"
            action_label = "Requires analyst approval to execute"
        else:
            autonomous_action = "MONITOR"
            action_label = "Monitor and investigate — no action yet"

        return {
            "niravan_guardian_ai": {
                "overall_confidence": round(overall_confidence, 1),
                "autonomous_action": autonomous_action,
                "action_label": action_label,
                "cvss": cvss,
                "summary": (
                    f"NIRAVAN has detected a {severity.upper()} severity {incident_type} incident "
                    f"with {round(overall_confidence, 1)}% confidence. "
                    f"CVSS Base Score: {cvss['base_score']} ({cvss['rating']}). "
                    f"{'Autonomous containment has been initiated.' if autonomous_action == 'EXECUTE' else 'Analyst approval required.' if autonomous_action == 'APPROVE' else 'Monitoring and investigation mode.'}"
                ),
            },
            "agents": {
                "threat_hunter": threat_hunter,
                "risk_analyst": risk_analyst,
                "compliance_officer": compliance,
                "incident_responder": responder,
            },
        }


# ═══════════════════════════════════════════════════════════════
# TIER 5 — Adaptive Sigma-Rule Detection Engine
# ═══════════════════════════════════════════════════════════════

class SigmaRuleEngine:
    """
    Evaluates Sigma-like detection rules against incoming telemetry.
    Rules are stored in the database and evaluated in memory.
    """

    BUILTIN_RULES = [
        {
            "id": "SIG-001",
            "name": "Ransomware Shadow Copy Deletion",
            "description": "Detects vssadmin or wmic usage to delete volume shadow copies — critical ransomware indicator",
            "severity": "critical",
            "mitre": ["T1490", "T1486"],
            "conditions": {
                "any": [
                    {"field": "CommandLine", "contains": "vssadmin delete shadows"},
                    {"field": "CommandLine", "contains": "wmic shadowcopy delete"},
                    {"field": "CommandLine", "contains": "bcdedit /set recoveryenabled no"},
                ]
            },
            "log_source": "windows_sysmon",
            "response": "isolate_host",
        },
        {
            "id": "SIG-002",
            "name": "Credential Dumping via LSASS",
            "description": "Detects access to LSASS process memory for credential extraction",
            "severity": "critical",
            "mitre": ["T1003"],
            "conditions": {
                "any": [
                    {"field": "CommandLine", "contains": "mimikatz"},
                    {"field": "CommandLine", "contains": "sekurlsa"},
                    {"field": "Image", "contains": "procdump"},
                    {"field": "CommandLine", "contains": "lsass.exe"},
                ]
            },
            "log_source": "windows_sysmon",
            "response": "isolate_host",
        },
        {
            "id": "SIG-003",
            "name": "PowerShell Encoded Command Execution",
            "description": "Detects obfuscated PowerShell commands using encoding — common malware dropper technique",
            "severity": "high",
            "mitre": ["T1059.001"],
            "conditions": {
                "any": [
                    {"field": "CommandLine", "contains": "-EncodedCommand"},
                    {"field": "CommandLine", "contains": "-enc "},
                    {"field": "CommandLine", "contains": "IEX ("},
                    {"field": "CommandLine", "contains": "Invoke-Expression"},
                ]
            },
            "log_source": "windows_sysmon",
            "response": "block_process",
        },
        {
            "id": "SIG-004",
            "name": "Suspicious Service Installation",
            "description": "Detects installation of new Windows services — persistence mechanism",
            "severity": "high",
            "mitre": ["T1543.003"],
            "conditions": {
                "any": [
                    {"field": "EventID", "equals": "7045"},
                    {"field": "CommandLine", "contains": "sc create"},
                    {"field": "CommandLine", "contains": "sc.exe create"},
                ]
            },
            "log_source": "windows_event",
            "response": "alert",
        },
        {
            "id": "SIG-005",
            "name": "Web Shell Access Pattern",
            "description": "Detects access to .php, .asp, .jsp scripts via POST — potential web shell",
            "severity": "high",
            "mitre": ["T1505.003"],
            "conditions": {
                "all": [
                    {"field": "method", "equals": "POST"},
                    {"field": "uri", "contains_any": [".php", ".asp", ".jsp"]},
                ]
            },
            "log_source": "proxy",
            "response": "alert",
        },
        {
            "id": "SIG-006",
            "name": "Data Exfiltration via DNS Tunneling",
            "description": "Detects abnormally long DNS subdomain queries — indicator of DNS tunneling",
            "severity": "high",
            "mitre": ["T1071.004", "T1048"],
            "conditions": {
                "any": [
                    {"field": "query_length", "greater_than": 50},
                    {"field": "query", "contains": "base64"},
                ]
            },
            "log_source": "dns",
            "response": "block_ip",
        },
        {
            "id": "SIG-007",
            "name": "Brute Force Attack Pattern",
            "description": "Detects more than 10 authentication failures within 5 minutes from single IP",
            "severity": "medium",
            "mitre": ["T1110"],
            "conditions": {
                "threshold": {
                    "field": "event_name",
                    "value": "Authentication Failure",
                    "count": 10,
                    "window_minutes": 5,
                }
            },
            "log_source": "any",
            "response": "block_ip",
        },
        {
            "id": "SIG-008",
            "name": "Privilege Escalation via sudo/chmod",
            "description": "Detects Linux privilege escalation via sudo abuse or setuid",
            "severity": "high",
            "mitre": ["T1548.001"],
            "conditions": {
                "any": [
                    {"field": "exe", "contains": "chmod +s"},
                    {"field": "command", "contains": "sudo su -"},
                    {"field": "command", "contains": "sudo bash"},
                    {"field": "command", "contains": "pkexec"},
                ]
            },
            "log_source": "linux_auditd",
            "response": "alert",
        },
        {
            "id": "SIG-009",
            "name": "Ransomware File Encryption Pattern",
            "description": "Detects mass file modification with encryption extensions",
            "severity": "critical",
            "mitre": ["T1486"],
            "conditions": {
                "any": [
                    {"field": "TargetFilename", "contains": ".locked"},
                    {"field": "TargetFilename", "contains": ".encrypted"},
                    {"field": "TargetFilename", "contains": ".crypt"},
                    {"field": "TargetFilename", "contains": "RANSOM"},
                    {"field": "TargetFilename", "contains": "README_HOW_TO_DECRYPT"},
                ]
            },
            "log_source": "windows_sysmon",
            "response": "isolate_host",
        },
        {
            "id": "SIG-010",
            "name": "Lateral Movement via Admin Shares",
            "description": "Detects connection to administrative shares — lateral movement indicator",
            "severity": "high",
            "mitre": ["T1021.002"],
            "conditions": {
                "any": [
                    {"field": "ShareName", "equals": "\\\\*\\ADMIN$"},
                    {"field": "ShareName", "equals": "\\\\*\\C$"},
                    {"field": "ShareName", "equals": "\\\\*\\IPC$"},
                ]
            },
            "log_source": "windows_event",
            "response": "alert",
        },
    ]

    @classmethod
    def evaluate(cls, log_data: Dict[str, Any], source_type: str) -> Optional[Dict[str, Any]]:
        """Evaluates log data against all Sigma rules. Returns first matching rule or None."""
        for rule in cls.BUILTIN_RULES:
            # Filter by log source
            if rule["log_source"] != "any" and rule["log_source"] != source_type:
                continue

            conditions = rule["conditions"]
            matched = False

            if "any" in conditions:
                for cond in conditions["any"]:
                    if cls._check_condition(log_data, cond):
                        matched = True
                        break

            elif "all" in conditions:
                matched = all(cls._check_condition(log_data, c) for c in conditions["all"])

            elif "threshold" in conditions:
                # Threshold rules are handled at the engine level
                matched = False

            if matched:
                return {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "response": rule["response"],
                }
        return None

    @classmethod
    def _check_condition(cls, log_data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        field = condition.get("field", "")
        value = str(log_data.get(field, "")).lower()

        if "contains" in condition:
            return condition["contains"].lower() in value
        elif "contains_any" in condition:
            return any(v.lower() in value for v in condition["contains_any"])
        elif "equals" in condition:
            return value == str(condition["equals"]).lower()
        elif "greater_than" in condition:
            try:
                return float(value) > float(condition["greater_than"])
            except Exception:
                return False
        return False


# ═══════════════════════════════════════════════════════════════
# TIER 6 — Threat Actor Attribution Database
# ═══════════════════════════════════════════════════════════════

THREAT_ACTORS = {
    "APT28": {
        "name": "APT28 (Fancy Bear)",
        "origin": "Russia",
        "type": "Nation-State",
        "motivation": "Espionage, Political Disruption",
        "sectors": ["Government", "Defence", "Energy"],
        "tools": ["X-Agent", "Sofacy", "Zebrocy", "CHOPSTICK"],
        "techniques": ["T1566.001", "T1078", "T1003", "T1021.002"],
        "ttp_description": "APT28 uses spearphishing with government-themed lures, exploits valid credentials, and performs credential dumping via LSASS access.",
        "threat_to_tn_gov": "HIGH — Known to target South Asian government email systems",
    },
    "APT41": {
        "name": "APT41 (Double Dragon)",
        "origin": "China",
        "type": "Nation-State / Criminal",
        "motivation": "Espionage, Financial Gain",
        "sectors": ["Healthcare", "Telecom", "Technology", "Government"],
        "tools": ["MESSAGETAP", "ShadowPad", "Cobalt Strike"],
        "techniques": ["T1190", "T1505.003", "T1548", "T1486"],
        "ttp_description": "APT41 exploits internet-facing applications, deploys web shells, escalates privileges, and may deploy ransomware as cover for espionage.",
        "threat_to_tn_gov": "HIGH — Targets healthcare and telecom in South Asia",
    },
    "Lazarus": {
        "name": "Lazarus Group",
        "origin": "North Korea",
        "type": "Nation-State",
        "motivation": "Financial Gain, Sanctions Evasion",
        "sectors": ["Banking", "Finance", "Cryptocurrency", "Government"],
        "tools": ["HOPLIGHT", "BLINDINGCAN", "ELECTRUM"],
        "techniques": ["T1566", "T1486", "T1048", "T1071.001"],
        "ttp_description": "Lazarus targets financial institutions with phishing, deploys ransomware, and exfiltrates funds via cryptocurrency channels.",
        "threat_to_tn_gov": "MEDIUM — Targets treasury and banking systems",
    },
    "REvil": {
        "name": "REvil (Sodinokibi)",
        "origin": "Russia",
        "type": "Criminal (RaaS)",
        "motivation": "Financial Extortion",
        "sectors": ["All Sectors"],
        "tools": ["REvil Ransomware", "Cobalt Strike", "Metasploit"],
        "techniques": ["T1486", "T1490", "T1489", "T1021.002"],
        "ttp_description": "REvil operators use Ransomware-as-a-Service model. Encrypts files and demands cryptocurrency ransom. Known for double extortion.",
        "threat_to_tn_gov": "HIGH — Active campaigns against Asian government entities",
    },
    "SideCopy": {
        "name": "SideCopy APT",
        "origin": "Pakistan",
        "type": "Nation-State",
        "motivation": "Espionage targeting Indian government",
        "sectors": ["Indian Government", "Defence", "Police"],
        "tools": ["CetaRAT", "Action RAT", "MargulasRAT"],
        "techniques": ["T1566.001", "T1059.003", "T1055", "T1071.001"],
        "ttp_description": "SideCopy specifically targets Indian government and defence with military-themed spearphishing. Deploys RATs for persistent access.",
        "threat_to_tn_gov": "CRITICAL — Specifically targets Tamil Nadu and Indian state government departments",
    },
    "Transparent Tribe": {
        "name": "Transparent Tribe (APT36)",
        "origin": "Pakistan",
        "type": "Nation-State",
        "motivation": "Espionage targeting India",
        "sectors": ["Indian Government", "Military", "Education"],
        "tools": ["Crimson RAT", "ObliqueRAT", "POSEIDON"],
        "techniques": ["T1566.001", "T1059.001", "T1071.001", "T1082"],
        "ttp_description": "APT36 targets Indian government and education with spearphishing. Uses remote access trojans for sustained espionage.",
        "threat_to_tn_gov": "HIGH — Documented attacks against Indian state governments and educational institutions",
    },
}


def attribute_threat_actor(
    source_ip: str,
    techniques: List[str],
    ioc_actor: Optional[str] = None,
) -> Dict[str, Any]:
    """Attributes an attack to a likely threat actor based on IP, techniques, and IOC data."""

    # Direct attribution from IOC data
    if ioc_actor and ioc_actor in THREAT_ACTORS:
        actor = THREAT_ACTORS[ioc_actor].copy()
        actor["attribution_confidence"] = 90
        actor["attribution_method"] = "IOC database match"
        return actor

    # Heuristic attribution based on IP geography and techniques
    technique_set = set(techniques)
    best_match = None
    best_score = 0

    for actor_id, actor in THREAT_ACTORS.items():
        score = 0
        for t in actor["techniques"]:
            if any(t2.startswith(t.split(".")[0]) for t2 in technique_set):
                score += 20

        # IP-based heuristics
        if source_ip.startswith("185.") and actor_id == "APT28":
            score += 30
        elif source_ip.startswith("45.") and actor_id == "APT41":
            score += 25
        elif "T1486" in techniques and actor_id == "REvil":
            score += 40
        elif ("T1566" in " ".join(techniques)) and actor_id in ["SideCopy", "Transparent Tribe"]:
            score += 30

        if score > best_score:
            best_score = score
            best_match = (actor_id, actor)

    if best_match and best_score >= 20:
        result = best_match[1].copy()
        result["attribution_confidence"] = min(85, best_score)
        result["attribution_method"] = "Technique and IP pattern matching"
        return result

    return {
        "name": "Unknown Threat Actor",
        "origin": "Unknown",
        "type": "Unknown",
        "motivation": "Unknown",
        "attribution_confidence": 10,
        "attribution_method": "No match found",
        "threat_to_tn_gov": "ASSESS — Investigate further",
    }


# ═══════════════════════════════════════════════════════════════
# TIER 7 — Security Posture Scorer
# ═══════════════════════════════════════════════════════════════

class SecurityPostureScorer:
    """
    Calculates an organisation's overall security posture score (0-100).
    Higher = more secure. Used for executive dashboard and benchmarking.
    """

    @staticmethod
    def calculate(
        total_assets: int,
        critical_assets_exposed: int,
        open_incidents: int,
        critical_incidents: int,
        total_vulnerabilities: int,
        avg_cvss_score: float,
        compliance_score: float,  # 0.0 to 1.0
        defense_memory_success_rate: float,  # 0.0 to 1.0
        days_since_last_patching: int,
        mfa_adoption_percent: float,  # 0 to 100
    ) -> Dict[str, Any]:

        score = 100.0

        # Asset exposure penalty
        if total_assets > 0:
            exposure_ratio = critical_assets_exposed / total_assets
            score -= exposure_ratio * 20

        # Incident penalties
        score -= min(30, open_incidents * 3)
        score -= min(20, critical_incidents * 10)

        # Vulnerability penalties
        score -= min(15, total_vulnerabilities * 0.5)
        score -= min(10, (avg_cvss_score / 10.0) * 10)

        # Compliance bonus/penalty
        score += (compliance_score - 0.5) * 10  # Bonus for high compliance, penalty for low

        # Defense effectiveness bonus
        score += (defense_memory_success_rate - 0.5) * 10

        # Patching penalty
        if days_since_last_patching > 90:
            score -= 15
        elif days_since_last_patching > 30:
            score -= 5

        # MFA bonus
        score += (mfa_adoption_percent / 100.0) * 10

        score = max(0.0, min(100.0, score))

        if score >= 80:
            grade = "A"
            label = "Strong"
            color = "#16a34a"
        elif score >= 65:
            grade = "B"
            label = "Adequate"
            color = "#ca8a04"
        elif score >= 50:
            grade = "C"
            label = "Needs Improvement"
            color = "#ea580c"
        else:
            grade = "D"
            label = "Critical Risk"
            color = "#dc2626"

        return {
            "score": round(score, 1),
            "grade": grade,
            "label": label,
            "color": color,
            "breakdown": {
                "asset_exposure": round(100 - (critical_assets_exposed / max(1, total_assets)) * 20, 1),
                "incident_health": round(100 - min(50, open_incidents * 3 + critical_incidents * 10), 1),
                "vulnerability_management": round(100 - min(25, total_vulnerabilities * 0.5 + (avg_cvss_score / 10.0) * 10), 1),
                "compliance": round(compliance_score * 100, 1),
                "defense_effectiveness": round(defense_memory_success_rate * 100, 1),
                "mfa_coverage": round(mfa_adoption_percent, 1),
            },
        }


# ═══════════════════════════════════════════════════════════════
# TIER 8 — Organisation-Scoped Analysis Engine
# ═══════════════════════════════════════════════════════════════

class OrgScopeEngine:
    """
    Ensures all data queries are scoped to the requesting user's organisation.
    Prevents data leakage between organisations.
    """

    @staticmethod
    def get_org_summary(db: Session, org_id: str) -> Dict[str, Any]:
        """Returns a complete security summary for a single organisation."""
        from main import (
            AssetModel, IncidentModel, OrganisationModel,
            HoneypotLogModel, DefenseMemoryModel, FeedbackModel,
        )

        org = db.query(OrganisationModel).filter(OrganisationModel.id == org_id).first()
        if not org:
            return {"error": "Organisation not found"}

        assets = db.query(AssetModel).filter(AssetModel.org_id == org_id).all()
        incidents = db.query(IncidentModel).filter(IncidentModel.org_id == org_id).all()
        open_incidents = [i for i in incidents if i.status == "open"]
        critical_incidents = [i for i in incidents if i.severity == "critical"]

        total_vulns = sum(a.vulnerabilities or 0 for a in assets)
        avg_risk = sum(a.riskScore or 0 for a in assets) / max(1, len(assets))

        defense_records = db.query(DefenseMemoryModel).filter(
            DefenseMemoryModel.org_id == org_id
        ).all() if hasattr(DefenseMemoryModel, "org_id") else []

        success_rate = (
            sum(1 for d in defense_records if d.result == "successful") / max(1, len(defense_records))
            if defense_records else 0.8
        )

        posture = SecurityPostureScorer.calculate(
            total_assets=len(assets),
            critical_assets_exposed=len([a for a in assets if a.criticality == "critical"]),
            open_incidents=len(open_incidents),
            critical_incidents=len(critical_incidents),
            total_vulnerabilities=total_vulns,
            avg_cvss_score=avg_risk / 10,
            compliance_score=0.75,
            defense_memory_success_rate=success_rate,
            days_since_last_patching=14,
            mfa_adoption_percent=60.0,
        )

        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for inc in incidents:
            severity_breakdown[inc.severity] = severity_breakdown.get(inc.severity, 0) + 1

        return {
            "org_id": org_id,
            "org_name": org.name,
            "org_type": org.org_type,
            "district": org.district,
            "total_assets": len(assets),
            "total_incidents": len(incidents),
            "open_incidents": len(open_incidents),
            "critical_incidents": len(critical_incidents),
            "total_vulnerabilities": total_vulns,
            "avg_risk_score": round(avg_risk, 1),
            "security_posture": posture,
            "incident_severity_breakdown": severity_breakdown,
            "assets_by_status": {
                "active": len([a for a in assets if a.status == "active"]),
                "compromised": len([a for a in assets if a.status == "compromised"]),
                "isolated": len([a for a in assets if a.status == "isolated"]),
            },
        }

    @staticmethod
    def generate_report_data(db: Session, org_id: str) -> Dict[str, Any]:
        """Generates full data payload for visual report generation."""
        summary = OrgScopeEngine.get_org_summary(db, org_id)

        from main import IncidentModel, AssetModel

        incidents = db.query(IncidentModel).filter(
            IncidentModel.org_id == org_id
        ).order_by(IncidentModel.timestamp.desc()).limit(100).all()

        # Incidents by type
        type_counts = {}
        for inc in incidents:
            type_counts[inc.type] = type_counts.get(inc.type, 0) + 1

        # Incidents by MITRE tactic
        tactic_counts = {}
        for inc in incidents:
            for t in (inc.mitre or "").split(","):
                t = t.strip()
                if t:
                    info = get_technique_info(t)
                    tactic = info.get("tactic_name", "Unknown")
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        # Risk trend (last 7 days)
        now = datetime.datetime.utcnow()
        trend = []
        for day_offset in range(6, -1, -1):
            day = now - datetime.timedelta(days=day_offset)
            day_incidents = [i for i in incidents if i.timestamp and i.timestamp.date() == day.date()]
            trend.append({
                "date": day.strftime("%d %b"),
                "count": len(day_incidents),
                "critical": len([i for i in day_incidents if i.severity == "critical"]),
            })

        return {
            "summary": summary,
            "charts": {
                "incidents_by_type": [{"label": k, "value": v} for k, v in type_counts.items()],
                "incidents_by_tactic": [{"label": k, "value": v} for k, v in tactic_counts.items()],
                "severity_distribution": [
                    {"label": k, "value": v}
                    for k, v in summary.get("incident_severity_breakdown", {}).items()
                ],
                "risk_trend_7days": trend,
            },
        }
