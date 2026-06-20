import logging
import datetime
import json
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.forensics_agent")

class ForensicsAgent:
    """
    Forensics Agent responsible for reconstructing incident timelines,
    correlating historical telemetry sequences, and preparing evidence logs.
    """

    def reconstruct_timeline(self, db, host: str, user: str, ip_address: str, time_window_hours: int = 1) -> Dict[str, Any]:
        """
        Reconstruct a forensics timeline of telemetry logs associated with the target host, user, or IP.
        """
        try:
            from main import TelemetryLogModel
            
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=time_window_hours)
            
            # Query all telemetry logs for this host, user, or IP within the time window
            filters = [TelemetryLogModel.timestamp >= cutoff]
            
            or_conditions = []
            if host:
                or_conditions.append(TelemetryLogModel.host == host)
            if user:
                or_conditions.append(TelemetryLogModel.user == user)
            if ip_address:
                or_conditions.append(TelemetryLogModel.ip_address == ip_address)
                
            if or_conditions:
                from sqlalchemy import or_
                filters.append(or_( *or_conditions ))
                
            logs = db.query(TelemetryLogModel).filter( *filters ).order_by(TelemetryLogModel.timestamp.asc()).all()
            
            timeline = []
            findings = []
            
            # Correlate logs to find patterns
            has_scan = False
            has_failed_auth = 0
            has_success_auth = False
            has_priv_esc = False
            has_malware = False
            
            for log in logs:
                payload_str = log.payload or ""
                payload_lower = payload_str.lower()
                
                event_desc = f"Observed telemetry from {log.source_type}"
                stage = "Collection"
                
                # Check for scan
                if any(x in payload_lower for x in ["nmap", "scan", "port"]):
                    event_desc = "Port scanning activity detected"
                    stage = "Reconnaissance"
                    has_scan = True
                    
                # Check for failed auth
                elif any(x in payload_lower for x in ["failed password", "failed logon", "eventid\": 4625"]):
                    has_failed_auth += 1
                    event_desc = f"Failed logon attempt (Total: {has_failed_auth})"
                    stage = "Credential Access"
                    
                # Check for success auth
                elif any(x in payload_lower for x in ["successful logon", "authentication successful", "eventid\": 4624"]):
                    event_desc = "Successful logon session initiated"
                    stage = "Lateral Movement"
                    has_success_auth = True
                    
                # Check for priv esc
                elif any(x in payload_lower for x in ["powershell.exe -executionpolicy", "privilege escalation", "bypass"]):
                    event_desc = "Suspicious PowerShell command execution"
                    stage = "Privilege Escalation"
                    has_priv_esc = True
                    
                # Check for ransomware/malware
                elif any(x in payload_lower for x in ["ransomware", "encrypt", "locked", "cryptor.exe"]):
                    event_desc = "Ransomware encryption/file modification behavior detected"
                    stage = "Actions on Objectives"
                    has_malware = True
                    
                timeline.append({
                    "timestamp": log.timestamp.isoformat(),
                    "source": log.source_type,
                    "event": event_desc,
                    "stage": stage,
                    "user": log.user,
                    "host": log.host
                })
                
            # Synthesize findings
            if has_scan:
                findings.append("Phase 1: Attacker executed port scans to map local open ports.")
            if has_failed_auth > 0:
                findings.append(f"Phase 2: Attacker performed brute-force authentication ({has_failed_auth} failed attempts).")
            if has_success_auth:
                findings.append("Phase 3: Attacker gained lateral access via successful credential reuse.")
            if has_priv_esc:
                findings.append("Phase 4: Attacker ran elevated commands to achieve privilege escalation.")
            if has_malware:
                findings.append("Phase 5: Attacker executed ransomware binary, initiating file encryption.")
                
            logger.info(f"Forensics timeline reconstructed. Steps: {len(timeline)}")
            return {
                "timeline": timeline,
                "forensic_findings": findings,
                "total_events_correlated": len(logs)
            }
        except Exception as e:
            logger.error(f"Error reconstructing timeline: {e}")
            return {
                "timeline": [],
                "forensic_findings": [f"Forensics timeline query error: {e}"],
                "total_events_correlated": 0
            }
