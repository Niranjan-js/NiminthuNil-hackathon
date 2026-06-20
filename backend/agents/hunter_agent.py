import logging
import datetime
import json
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.hunter_agent")

class HunterAgent:
    """
    Threat Hunting Agent that executes queries across telemetry and logs
    to discover hidden threats matching MITRE signatures or custom IOC patterns.
    """

    def run_hunt(self, db, hunt_query: str, technique_id: str = None, time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Run a threat hunt query against historical telemetry logs.
        """
        try:
            from main import TelemetryLogModel
            from niravan_engine import MITRE_TAXONOMY
            
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=time_window_hours)
            
            # Query telemetry logs in the time window
            logs = db.query(TelemetryLogModel).filter(
                TelemetryLogModel.timestamp >= cutoff_time
            ).all()
            
            matches = []
            
            # Fetch MITRE technique info if technique_id is given
            tech_info = None
            if technique_id and technique_id in MITRE_TAXONOMY:
                tech_info = MITRE_TAXONOMY[technique_id]
                
            query_lower = hunt_query.lower()
            
            for log in logs:
                similarity = 0.0
                matched_reasons = []
                
                payload_str = log.payload or ""
                payload_lower = payload_str.lower()
                
                # 1. Direct query matching
                if query_lower in payload_lower:
                    similarity += 0.6
                    matched_reasons.append("query_match_in_payload")
                if log.host and query_lower in log.host.lower():
                    similarity += 0.4
                    matched_reasons.append("query_match_in_host")
                if log.user and query_lower in log.user.lower():
                    similarity += 0.4
                    matched_reasons.append("query_match_in_user")
                if log.triggered_rule and query_lower in log.triggered_rule.lower():
                    similarity += 0.5
                    matched_reasons.append("query_match_in_triggered_rule")
                    
                # 2. MITRE signature matching
                if tech_info:
                    # Check if log triggered the specific rule or contains detection signature keywords
                    det_keywords = tech_info.get("detection", "").lower()
                    name_keywords = tech_info.get("name", "").lower()
                    
                    # Split keywords to check overlap
                    words = det_keywords.split() + name_keywords.split()
                    word_matches = sum(1 for w in words if len(w) > 3 and w in payload_lower)
                    
                    if word_matches > 0:
                        similarity += min(0.1 * word_matches, 0.4)
                        matched_reasons.append(f"mitre_sig_overlap_{technique_id}")
                        
                    if log.triggered_rule and technique_id.lower() in log.triggered_rule.lower():
                        similarity += 0.5
                        matched_reasons.append("mitre_rule_triggered")
                        
                if similarity > 0:
                    similarity = min(similarity, 1.0)
                    
                    # Snippet extraction
                    snippet = ""
                    try:
                        p_dict = json.loads(payload_str)
                        snippet = str(p_dict)[:150] + "..."
                    except Exception:
                        snippet = payload_str[:150] + "..."
                        
                    matches.append({
                        "event_id": log.id,
                        "host": log.host,
                        "user": log.user,
                        "ip_address": log.ip_address,
                        "timestamp": log.timestamp.isoformat(),
                        "similarity": round(similarity, 2),
                        "matched_reasons": matched_reasons,
                        "payload_snippet": snippet
                    })
                    
            # Sort by similarity descending
            matches.sort(key=lambda x: x["similarity"], reverse=True)
            
            # Risk Assessment
            total_matches = len(matches)
            assessment = "benign"
            investigation_recommendation = "No action required. Telemetry matches are clean."
            
            if total_matches > 0:
                highest_similarity = matches[0]["similarity"]
                if highest_similarity >= 0.8:
                    assessment = "confirmed_threat"
                    investigation_recommendation = (
                        f"CRITICAL: Confirmed match found for threat hunt '{hunt_query}'. "
                        f"Host '{matches[0]['host']}' shows highly correlated behavior matching {technique_id or 'IOC pattern'}. "
                        "Recommend immediate host isolation and credential rotation."
                    )
                elif total_matches >= 3 or highest_similarity >= 0.5:
                    assessment = "suspicious"
                    investigation_recommendation = (
                        f"WARNING: Suspicious activity matching hunt '{hunt_query}' detected across multiple hosts. "
                        "Recommend initiating a security incident case and carrying out further network traffic inspection."
                    )
                else:
                    assessment = "benign"
                    investigation_recommendation = "Minor low-confidence matches found. Keep monitoring."

            logger.info(f"HunterAgent executed. Found {total_matches} matches. Risk: {assessment}")
            return {
                "hunt_query": hunt_query,
                "technique_id": technique_id,
                "matches": matches[:10],
                "total_matches": total_matches,
                "risk_assessment": assessment,
                "recommended_investigation": investigation_recommendation
            }
        except Exception as e:
            logger.error(f"Error in HunterAgent run_hunt: {e}")
            return {
                "hunt_query": hunt_query,
                "technique_id": technique_id,
                "matches": [],
                "total_matches": 0,
                "risk_assessment": "benign",
                "recommended_investigation": f"Error executing threat hunt: {e}"
            }
