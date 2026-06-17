import datetime
import json
import random
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session

# Import models from main
from main import (
    IncidentModel,
    AssetModel,
    IOCModel,
    TelemetryLogModel,
    GraphNodeModel,
    GraphEdgeModel,
    AuditLogModel,
    FeedbackModel,
    LoginLogModel,
    record_suspicious_activity
)
from wazuh_ingestor import WazuhIngestor
from intel_sync import IntelSync
from defense_memory import DefenseMemory
from identity_protection import IdentityProtection

class CorrelationEngine:
    @staticmethod
    def calculate_risk(exposure_score: float, criticality: int, likelihood: float) -> float:
        """Calculates Risk Score = Exposure Score * Asset Criticality * Threat Likelihood.
        Returns value scaled 0-100.
        """
        raw_score = exposure_score * (criticality / 5.0) * likelihood
        scaled = int(raw_score * 10)
        return min(100, max(0, scaled))

    @staticmethod
    def get_criticality_rating(criticality_str: str) -> int:
        """Maps asset criticality label to a 1-10 numeric scale."""
        c = (criticality_str or "medium").lower()
        if c == "critical":
            return 10
        elif c == "high":
            return 8
        elif c == "medium":
            return 5
        elif c == "low":
            return 2
        return 5

    @staticmethod
    def correlate_event(db: Session, source_type: str, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Central brain that ingests logs, executes IOC correlations, computes updated risk scores,
        checks multi-event time window rules, and triggers incidents with adaptive confidence and
        autonomous response control.
        """
        # 1. Normalize the log using WazuhIngestor
        normalized = WazuhIngestor.parse_log(source_type, log_data)
        
        # Save raw telemetry log to the DB
        telemetry_entry = TelemetryLogModel(
            source_type=source_type,
            host=normalized["host"],
            user=normalized["user"],
            ip_address=normalized["ip_address"],
            payload=json.dumps(normalized["raw_payload"])
        )
        db.add(telemetry_entry)
        db.commit()
        db.refresh(telemetry_entry)

        # 2. Threat Intelligence Correlation
        intel_match = None
        intel_hits = 0
        if normalized["ip_address"]:
            intel_match = IntelSync.match_ip_to_threat_intel(db, normalized["ip_address"])
            if intel_match:
                intel_hits = 1

        # 3. Fetch Asset Context & Calculate Risk Score
        asset = db.query(AssetModel).filter(
            (AssetModel.name == normalized["host"]) | (AssetModel.ip == normalized["ip_address"])
        ).first()
        
        risk_score = 30 # default
        if asset:
            is_internet_exposed = asset.status == "active"
            base_exposure = 3.5 if is_internet_exposed else 0.5
            vulns_factor = (asset.vulnerabilities or 0) * 0.8
            intel_factor = intel_hits * 1.5
            exposure_score = base_exposure + vulns_factor + intel_factor
            
            criticality_val = CorrelationEngine.get_criticality_rating(asset.criticality)
            likelihood = 1.0
            if normalized["severity"] == "critical":
                likelihood = 2.0
            elif normalized["severity"] == "high":
                likelihood = 1.5
            elif intel_hits > 0:
                likelihood = 1.8
                
            risk_score = CorrelationEngine.calculate_risk(exposure_score, criticality_val, likelihood)
            asset.riskScore = risk_score
            db.add(asset)
            db.commit()

        # 4. Multi-Event Time Window Rules Correlation (30-minute window)
        time_limit = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)
        
        recent_failed_logins = db.query(TelemetryLogModel).filter(
            TelemetryLogModel.timestamp >= time_limit,
            (TelemetryLogModel.host == normalized["host"]) | (TelemetryLogModel.user == normalized["user"]),
            TelemetryLogModel.payload.like("%Failed password%") | TelemetryLogModel.payload.like("%Failed Logon%") | TelemetryLogModel.payload.like("%EventID\": 4625%")
        ).all()
        
        failed_count = len(recent_failed_logins)
        
        has_powershell = False
        if normalized["severity"] in ["medium", "high", "critical"] and any(tag in normalized["mitre"] for tag in ["T1059.001", "T1003", "T1486"]):
            has_powershell = True
            
        if not has_powershell:
            recent_suspicious_cmds = db.query(TelemetryLogModel).filter(
                TelemetryLogModel.timestamp >= time_limit,
                TelemetryLogModel.host == normalized["host"],
                TelemetryLogModel.payload.like("%powershell%") | TelemetryLogModel.payload.like("%mimikatz%") | TelemetryLogModel.payload.like("%vssadmin%")
            ).first()
            if recent_suspicious_cmds:
                has_powershell = True

        # Rule Trigger evaluation
        rule_name = None
        base_confidence = 70.0
        planned_action = None
        target_ip = normalized["ip_address"]
        target_host = normalized["host"]
        
        is_success_login = normalized["event_name"] in ["Successful Logon (EventID 4624)", "Authentication Successful Logged"]
        is_failed_login = normalized["event_name"] in ["Failed Logon Attempt (EventID 4625)", "Authentication Failure Logged"]
        
        # 1. Check Deception Lures (Honeypots/Honeytokens)
        if normalized["user"] == "honey_admin":
            rule_name = "Deception Lure Triggered: Fake Admin Account Accessed"
            base_confidence = 100.0
            planned_action = "isolate_host"
            normalized["description"] = "CRITICAL: Deception honeypot user 'honey_admin' was accessed. Immediate autonomous host containment initiated."
            normalized["severity"] = "critical"
            normalized["technique"] = "Deception: Honeypot Trigger"
            normalized["mitre"] = ["T1078"]
            
        elif log_data.get("CommandLine") and "\\\\HONEY-SHARE\\backup" in log_data.get("CommandLine"):
            rule_name = "Deception Lure Triggered: Fake Share Accessed"
            base_confidence = 100.0
            planned_action = "isolate_host"
            normalized["description"] = "CRITICAL: Attempted access to decoy file share '\\\\HONEY-SHARE\\backup' detected. Immediate autonomous host containment initiated."
            normalized["severity"] = "critical"
            normalized["technique"] = "Deception: Honeytoken Trigger"
            normalized["mitre"] = ["T1021.002"]
            
        # 2. Check for Impossible Travel
        elif is_success_login and normalized["user"] and normalized["ip_address"]:
            # Record successful login to LoginLogModel so detect_impossible_travel can query it
            db.add(LoginLogModel(
                email=normalized["user"],
                ip_address=normalized["ip_address"],
                success=True
            ))
            db.commit()
            
            travel_detection = IdentityProtection.detect_impossible_travel(db, normalized["user"], normalized["ip_address"])
            if travel_detection:
                rule_name = "Impossible Travel Detected"
                base_confidence = 96.0
                planned_action = "isolate_host"
                normalized["description"] = travel_detection["description"]
                normalized["severity"] = "critical"
                normalized["technique"] = "Impossible Travel"
                normalized["mitre"] = ["T1078"]
                
        # 3. Check for Password Spray
        elif is_failed_login and normalized["ip_address"]:
            # Record failed login to LoginLogModel so detect_password_spray can query it
            db.add(LoginLogModel(
                email=normalized["user"] or "unknown",
                ip_address=normalized["ip_address"],
                success=False,
                reason="failed_telemetry_login"
            ))
            db.commit()
            
            spray_detection = IdentityProtection.detect_password_spray(db, normalized["ip_address"])
            if spray_detection:
                rule_name = "Password Spray Attack Detected"
                base_confidence = 92.0
                planned_action = "block_ip"
                normalized["description"] = spray_detection["description"]
                normalized["severity"] = "high"
                normalized["technique"] = "Password Spraying"
                normalized["mitre"] = ["T1110.003"]
                
        # 4. Check for Privilege Escalation
        if not rule_name and normalized["user"]:
            command = log_data.get("CommandLine") or log_data.get("exe") or log_data.get("command") or log_data.get("message") or ""
            if command:
                priv_detection = IdentityProtection.detect_privilege_escalation(db, normalized["user"], command)
                if priv_detection:
                    rule_name = "Privilege Escalation Attempt"
                    base_confidence = 94.0
                    planned_action = "isolate_host"
                    normalized["description"] = priv_detection["description"]
                    normalized["severity"] = "critical"
                    normalized["technique"] = "Privilege Escalation"
                    normalized["mitre"] = ["T1548"]
                    
        # 5. Fallback Rules
        if not rule_name:
            if failed_count >= 5 and has_powershell and intel_hits > 0:
                rule_name = "Potential Credential Attack (Correlated Multi-Vector)"
                base_confidence = 98.0
                planned_action = "block_ip"
            elif normalized["severity"] in ["high", "critical"]:
                rule_name = normalized["event_name"]
                base_confidence = 90.0 if normalized["severity"] == "critical" else 75.0
                # Ransomware or exploit targets -> Isolate Host
                if any(t in normalized["mitre"] for t in ["T1486", "T1190", "T1210"]):
                    planned_action = "isolate_host"
                else:
                    planned_action = "block_ip" if target_ip else None

        if rule_name:
            # 5. Adaptive Confidence Suppression (Change 1)
            # Query historical user feedback for this rule on this host
            feedbacks = db.query(FeedbackModel).filter(
                FeedbackModel.rule_triggered == rule_name,
                FeedbackModel.host == target_host
            ).all()
            
            fp_ratio = 0.0
            if feedbacks:
                fp_count = sum(1 for f in feedbacks if f.feedback_type == "false_positive")
                fp_ratio = float(fp_count) / len(feedbacks)
                
            confidence = base_confidence * (1.0 - fp_ratio)
            
            # Action selection and historical evaluation
            action_status = "none"
            final_severity = normalized.get("severity", "high")
            inc_status = "open"
            
            if planned_action:
                # Retrieve defense memory success rate (Change 3)
                success_rate = DefenseMemory.get_action_success_rate(db, pattern=rule_name, action=planned_action)
                
                # Check low success rate downgrade
                if success_rate < 0.6:
                    confidence = min(90.0, confidence) # Downgrades from Level 3 to Level 2
                    action_status = "downgraded_low_success"
                
                # Evaluate Confidence Levels
                if confidence > 95.0:
                    # Level 3: Autonomous Response Execution
                    action_status = f"executed_{planned_action}"
                    inc_status = "contained"
                    
                    try:
                        if planned_action == "block_ip" and target_ip:
                            # Execute IP blocking
                            existing_ioc = db.query(IOCModel).filter(IOCModel.type == "ip", IOCModel.indicator == target_ip).first()
                            if not existing_ioc:
                                db.add(IOCModel(
                                    type="ip",
                                    indicator=target_ip,
                                    actor="Autonomous Shield",
                                    confidence=100,
                                    lastSeen=datetime.datetime.utcnow().strftime("%Y-%m-%d"),
                                    threat=f"Containment Action: Autonomous Shield blocked IP due to {rule_name}"
                                ))
                            # Isolate associated assets
                            assets_to_isolate = db.query(AssetModel).filter(AssetModel.ip == target_ip).all()
                            for a in assets_to_isolate:
                                a.status = "isolated"
                                db.add(a)
                            # Log audit
                            db.add(AuditLogModel(
                                user_email="system",
                                action="BLOCK_IP",
                                detail=f"Autonomous Shield blocked IP {target_ip}. Reason: Correlated Threat {rule_name}.",
                                ip_address=target_ip
                            ))
                            # Save to defense memory
                            DefenseMemory.record_action(db, pattern=rule_name, action="block_ip", result="successful")
                            
                        elif planned_action == "isolate_host" and target_host:
                            # Execute host isolation
                            target_asset = db.query(AssetModel).filter(AssetModel.name == target_host).first()
                            if target_asset:
                                target_asset.status = "isolated"
                                db.add(target_asset)
                                # Log audit
                                db.add(AuditLogModel(
                                    user_email="system",
                                    action="ISOLATE_HOST",
                                    detail=f"Autonomous Shield isolated host {target_host}. Reason: Correlated Threat {rule_name}.",
                                    ip_address=target_asset.ip
                                ))
                                # Save to defense memory
                                DefenseMemory.record_action(db, pattern=rule_name, action="isolate_host", result="successful")
                    except Exception as ex:
                        action_status = "failed"
                        if planned_action:
                            DefenseMemory.record_action(db, pattern=rule_name, action=planned_action, result="failed")
                
                elif confidence >= 70.0:
                    # Level 2: Require Approval
                    action_status = "pending_approval"
                else:
                    # Level 1: Recommend Only
                    action_status = "recommended_only"
                    final_severity = "low" if final_severity == "high" else "medium"
            
            # Format description with confidence breakdown
            conf_details = f"[Confidence Level: {'Level 3 (Autonomous)' if confidence > 95 else 'Level 2 (Requires Approval)' if confidence >= 70 else 'Level 1 (Recommend Only)'}]"
            desc_text = (
                f"{normalized['description'] or 'Security alert escalated.'}\n"
                f"{conf_details} Confidence: {confidence:.1f}% (Base: {base_confidence}%, False Positive Ratio: {fp_ratio*100:.1f}%)."
            )
            
            # Calculate citizen and service impacts based on target host or department
            affected_citizens = 0
            affected_services = "None"
            affected_departments = "General"
            estimated_recovery_time = "1h"
            
            if target_host:
                host_lower = target_host.lower()
                if "web" in host_lower:
                    affected_citizens = 15000
                    affected_services = "EMIS School Registry"
                    affected_departments = "School Education Department"
                    estimated_recovery_time = "2 hours"
                elif "db" in host_lower or "dc" in host_lower:
                    affected_citizens = 120000
                    affected_services = "Finance Treasury DB"
                    affected_departments = "Finance Department"
                    estimated_recovery_time = "8 hours"
                elif "gw" in host_lower or "vpn" in host_lower:
                    affected_citizens = 50000
                    affected_services = "State Command API"
                    affected_departments = "IT Department"
                    estimated_recovery_time = "4 hours"

            inc_id = f"inc-{random.randint(9000, 9999)}"
            triggered_incident = IncidentModel(
                id=inc_id,
                title=f"Autonomous Response: {rule_name}" if confidence > 95 else rule_name,
                type=normalized["source_type"].upper(),
                severity=final_severity,
                description=desc_text,
                status=inc_status,
                user=normalized["user"] or "system",
                host=target_host,
                category=normalized["technique"],
                mitre=",".join(normalized["mitre"]),
                technique=normalized["technique"],
                timeStr="Just now",
                technical=json.dumps({
                    "confidence": confidence,
                    "action_status": action_status,
                    "planned_action": planned_action,
                    "success_rate": success_rate if planned_action else 1.0,
                    "details": f"[Correlation-Engine] Rule: {rule_name} | Events: {failed_count} failures | PowerShell: {has_powershell} | ThreatIntel: {intel_hits}"
                }),
                affected_citizens=affected_citizens,
                affected_services=affected_services,
                affected_departments=affected_departments,
                estimated_recovery_time=estimated_recovery_time
            )

            telemetry_entry.triggered_rule = rule_name
            db.add(triggered_incident)
            db.add(telemetry_entry)
            db.commit()
            db.refresh(triggered_incident)
            
            # Record suspicious activity
            record_suspicious_activity(
                db=db,
                who=triggered_incident.user,
                what=triggered_incident.title,
                where=triggered_incident.host or (normalized["ip_address"] or "UNKNOWN"),
                why=rule_name or "Correlation Engine Triggered",
                how=triggered_incident.description
            )
            
            # Update Knowledge Graph Nodes/Edges in DB
            CorrelationEngine.update_attack_graph(db, triggered_incident, asset)
            
            return {
                "status": "triggered",
                "rule": rule_name,
                "confidence": confidence,
                "action_status": action_status,
                "incident_id": triggered_incident.id,
                "message": f"Correlation Engine generated incident {triggered_incident.id} with action status: {action_status}."
            }

        return {
            "status": "ignored",
            "message": "Telemetry event correlated. No correlation rules triggered."
        }

    @staticmethod
    def update_attack_graph(db: Session, incident: IncidentModel, asset: Optional[AssetModel]):
        """Creates or updates graph representation inside database nodes and edges."""
        inc_node = db.query(GraphNodeModel).filter(
            GraphNodeModel.entity_type == "Incident",
            GraphNodeModel.entity_id == incident.id
        ).first()
        if not inc_node:
            inc_node = GraphNodeModel(
                entity_type="Incident",
                entity_id=incident.id,
                name=incident.title,
                risk_weight=95 if incident.severity == "critical" else 80,
                properties=json.dumps({"severity": incident.severity, "compromised": True})
            )
            db.add(inc_node)
            
        if asset:
            asset_node = db.query(GraphNodeModel).filter(
                GraphNodeModel.entity_type == "Asset",
                GraphNodeModel.entity_id == str(asset.id)
            ).first()
            if asset_node:
                asset_node.risk_weight = asset.riskScore
                props = json.loads(asset_node.properties or "{}")
                props["compromised"] = True
                props["last_incident"] = incident.id
                asset_node.properties = json.dumps(props)
                db.add(asset_node)
                
                edge = GraphEdgeModel(
                    source_type="Asset",
                    source_id=str(asset.id),
                    target_type="Incident",
                    target_id=str(incident.id),
                    relationship="compromised",
                    weight=1.0,
                    properties=json.dumps({"incident": incident.title})
                )
                db.add(edge)
                
        if incident.user and incident.user != "system":
            usr_node = db.query(GraphNodeModel).filter(
                GraphNodeModel.entity_type == "User",
                GraphNodeModel.entity_id == incident.user
            ).first()
            if usr_node:
                edge = GraphEdgeModel(
                    source_type="User",
                    source_id=incident.user,
                    target_type="Incident",
                    target_id=incident.id,
                    relationship="triggered",
                    weight=1.5,
                    properties=json.dumps({"action": incident.title})
                )
                db.add(edge)

        db.commit()

    @staticmethod
    def record_feedback_in_graph(db: Session, feedback: FeedbackModel):
        """
        Learns from user feedback by inserting Feedback nodes and edges (Change 2)
        representing false/true positive relationships into the Knowledge Graph.
        """
        # Create/Update Feedback node
        fb_node = db.query(GraphNodeModel).filter(
            GraphNodeModel.entity_type == "Feedback",
            GraphNodeModel.entity_id == str(feedback.id)
        ).first()
        if not fb_node:
            fb_node = GraphNodeModel(
                entity_type="Feedback",
                entity_id=str(feedback.id),
                name=f"Feedback: {feedback.feedback_type} on {feedback.rule_triggered}",
                risk_weight=0 if feedback.feedback_type == "false_positive" else 100,
                properties=json.dumps({
                    "feedback_type": feedback.feedback_type,
                    "rule": feedback.rule_triggered,
                    "host": feedback.host,
                    "comments": feedback.comments
                })
            )
            db.add(fb_node)
            db.commit()
            db.refresh(fb_node)

        # Link Asset node to Feedback node
        if feedback.host:
            asset = db.query(AssetModel).filter(AssetModel.name == feedback.host).first()
            if asset:
                existing_edge = db.query(GraphEdgeModel).filter(
                    GraphEdgeModel.source_type == "Asset",
                    GraphEdgeModel.source_id == str(asset.id),
                    GraphEdgeModel.target_type == "Feedback",
                    GraphEdgeModel.target_id == str(feedback.id)
                ).first()
                if not existing_edge:
                    edge = GraphEdgeModel(
                        source_type="Asset",
                        source_id=str(asset.id),
                        target_type="Feedback",
                        target_id=str(feedback.id),
                        relationship="has_feedback",
                        weight=1.0 if feedback.feedback_type == "true_positive" else -1.0,
                        properties=json.dumps({"feedback_type": feedback.feedback_type})
                    )
                    db.add(edge)
                    db.commit()
