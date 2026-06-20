import logging
import datetime
import json
from typing import Dict, Any, List

logger = logging.getLogger("niravan.tools.hunt_tool")

TOOL_SPEC = {
    "name": "run_threat_hunt",
    "description": "Execute a threat hunt query across telemetry logs and assets to find hidden threats matching a specific ATT&CK technique or IOC pattern.",
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "description": "MITRE ATT&CK technique ID (e.g. T1110)"},
            "hunt_query": {"type": "string", "description": "Specific pattern, IOC, or behavior to hunt for"},
            "time_window_hours": {"type": "integer", "description": "Hours back to search. Default 24.", "default": 24}
        },
        "required": ["hunt_query"]
    }
}

class HuntTool:
    """Tool to query telemetry logs and incident models for active threat patterns."""

    @staticmethod
    def execute(db, hunt_query: str, technique_id: str = None, time_window_hours: int = 24) -> Dict[str, Any]:
        try:
            from main import TelemetryLogModel, IncidentModel
            
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=time_window_hours)
            
            # Query telemetry logs
            telemetry_matches = db.query(TelemetryLogModel).filter(
                TelemetryLogModel.timestamp >= cutoff_time
            ).all()
            
            matches = []
            
            # Search within telemetry payload, host, user, ip
            for log in telemetry_matches:
                match_score = 0.0
                matched_fields = []
                
                # Simple text search on payload
                payload_str = log.payload or ""
                if hunt_query.lower() in payload_str.lower():
                    match_score += 0.7
                    matched_fields.append("payload")
                    
                # Search user/host/ip
                if log.user and hunt_query.lower() in log.user.lower():
                    match_score += 0.5
                    matched_fields.append("user")
                if log.host and hunt_query.lower() in log.host.lower():
                    match_score += 0.5
                    matched_fields.append("host")
                if log.ip_address and hunt_query.lower() in log.ip_address.lower():
                    match_score += 0.6
                    matched_fields.append("ip_address")
                if log.triggered_rule and hunt_query.lower() in log.triggered_rule.lower():
                    match_score += 0.5
                    matched_fields.append("triggered_rule")
                    
                # technique matching
                if technique_id:
                    # Check if technique_id matches triggered rule or payload content
                    if technique_id.lower() in payload_str.lower() or (log.triggered_rule and technique_id.lower() in log.triggered_rule.lower()):
                        match_score += 0.3
                        matched_fields.append("technique")
                        
                if match_score > 0:
                    # Clip match score to maximum of 1.0
                    confidence = min(match_score, 1.0)
                    
                    # Snippet extraction
                    snippet = ""
                    try:
                        p_dict = json.loads(payload_str)
                        # extract a small portion
                        snippet = str(p_dict)[:150] + "..."
                    except Exception:
                        snippet = payload_str[:150] + "..."
                        
                    matches.append({
                        "event_id": log.id,
                        "type": "telemetry",
                        "host": log.host,
                        "user": log.user,
                        "ip_address": log.ip_address,
                        "timestamp": log.timestamp.isoformat(),
                        "confidence": confidence,
                        "matched_fields": matched_fields,
                        "payload_snippet": snippet
                    })
                    
            # Query incidents
            incident_matches = db.query(IncidentModel).filter(
                IncidentModel.timestamp >= cutoff_time
            ).all()
            
            for inc in incident_matches:
                match_score = 0.0
                matched_fields = []
                
                if hunt_query.lower() in inc.title.lower() or hunt_query.lower() in inc.description.lower():
                    match_score += 0.8
                    matched_fields.append("title/description")
                if inc.technique and hunt_query.lower() in inc.technique.lower():
                    match_score += 0.6
                    matched_fields.append("technique_name")
                if technique_id and (
                    (inc.technique and technique_id.lower() in inc.technique.lower()) or 
                    (inc.mitre and technique_id.lower() in inc.mitre.lower())
                ):
                    match_score += 0.9
                    matched_fields.append("mitre_id")
                    
                if match_score > 0:
                    confidence = min(match_score, 1.0)
                    matches.append({
                        "event_id": inc.id,
                        "type": "incident",
                        "host": inc.host,
                        "user": inc.user,
                        "timestamp": inc.timestamp.isoformat(),
                        "confidence": confidence,
                        "matched_fields": matched_fields,
                        "payload_snippet": f"Incident Title: {inc.title} - Description: {inc.description[:100]}..."
                    })
                    
            # Sort by confidence descending
            matches.sort(key=lambda x: x["confidence"], reverse=True)
            
            assessment = "benign"
            if matches:
                high_conf = sum(1 for m in matches if m["confidence"] >= 0.8)
                if high_conf > 0:
                    assessment = "confirmed_threat"
                elif len(matches) > 3:
                    assessment = "suspicious"
            
            logger.info(f"Threat hunt completed for query '{hunt_query}'. Found {len(matches)} matches.")
            return {
                "success": True,
                "hunt_query": hunt_query,
                "technique_id": technique_id,
                "total_matches": len(matches),
                "risk_assessment": assessment,
                "matches": matches[:10]  # Limit to top 10 matches
            }
        except Exception as e:
            logger.error(f"Error running threat hunt for '{hunt_query}': {e}")
            return {"success": False, "error": str(e)}
