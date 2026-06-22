"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — IoT Threat Hunter

Automates hunting playbooks to identify sophisticated IoT/OT threats, 
ranging from firmware implants to PLC manipulation and MQTT C2 channels.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger("niravan.ot_iot.threat_hunter")
logger.setLevel(logging.INFO)


class IoTThreatHunter:
    """
    Executes targeted threat hunting playbooks on OT/IoT network telemetry,
    correlating weak indicators into complex kill-chain alerts.
    """

    HUNT_PLAYBOOKS: List[Dict[str, Any]] = [
        {
            "name": "Telnet Default Creds",
            "description": "Identifies devices logging in with known industrial default credentials.",
            "tactic": "TA0001 - Initial Access",
            "required_logs": ["auth_logs"]
        },
        {
            "name": "Firmware Implant via HTTP",
            "description": "Detects anomalous firmware updates downloaded over insecure HTTP protocols.",
            "tactic": "TA0003 - Persistence",
            "required_logs": ["http_requests"]
        },
        {
            "name": "CCTV Botnet Activity",
            "description": "Checks for cameras participating in outbound flooding or scan behaviors.",
            "tactic": "TA0040 - Impact",
            "required_logs": ["connections", "device_inventory"]
        },
        {
            "name": "PLC Logic Manipulation",
            "description": "Flags unauthorized write/stop commands targeting critical controller registers.",
            "tactic": "TA0108 - Impair Process Control",
            "required_logs": ["plc_logs"]
        },
        {
            "name": "Smart Meter Data Exfiltration",
            "description": "Detects smart meters transmitting anomalous payload sizes to external destinations.",
            "tactic": "TA0009 - Collection",
            "required_logs": ["connections"]
        },
        {
            "name": "BLE Unauthorized Pairing",
            "description": "Identifies brute-forcing or unauthorized pairing attempts on BLE adapters.",
            "tactic": "TA0001 - Initial Access",
            "required_logs": ["ble_logs"]
        },
        {
            "name": "MQTT C2 Channel",
            "description": "Detects compromised IoT devices using MQTT brokers to receive shell commands.",
            "tactic": "TA0011 - Command and Control",
            "required_logs": ["mqtt_messages"]
        }
    ]

    @staticmethod
    def run_all_hunts(telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes all playbooks and correlates findings.

        Args:
            telemetry: Dictionary containing lists of events:
                       auth_logs, http_requests, connections, device_inventory, plc_logs, ble_logs, mqtt_messages

        Returns:
            Dict containing individual hunt results and aggregated correlation outputs.
        """
        hunt_results = []
        for playbook in IoTThreatHunter.HUNT_PLAYBOOKS:
            playbook_name = playbook["name"]
            try:
                res = IoTThreatHunter.run_hunt(playbook_name, telemetry)
                hunt_results.append(res)
            except Exception as e:
                logger.error("Error executing playbook %s: %s", playbook_name, str(e))
                hunt_results.append({
                    "playbook_name": playbook_name,
                    "triggered": False,
                    "severity": "INFO",
                    "matched_events": [],
                    "details": f"Execution error: {str(e)}"
                })

        correlated = IoTThreatHunter.correlate_findings(hunt_results)

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "playbooks_executed": len(IoTThreatHunter.HUNT_PLAYBOOKS),
            "results": hunt_results,
            "correlation_summary": correlated
        }

    @staticmethod
    def run_hunt(hunt_name: str, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a specific hunt scenario logic.
        """
        triggered = False
        severity = "INFO"
        matched_events = []
        details = "No matching threats identified."

        if hunt_name == "Telnet Default Creds":
            auth_logs = telemetry.get("auth_logs", [])
            # Standard Mirai/common defaults list
            default_creds = [
                ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), 
                ("admin", "admin"), ("root", "root"), ("support", "support")
            ]
            for log in auth_logs:
                port = log.get("port")
                user = log.get("username")
                passwd = log.get("password")
                status = log.get("status")

                if port in [23, 2323] and status == "success":
                    if (user, passwd) in default_creds:
                        matched_events.append(log)
            
            if matched_events:
                triggered = True
                severity = "CRITICAL"
                details = f"Detected {len(matched_events)} successful logins using known factory default credentials."

        elif hunt_name == "Firmware Implant via HTTP":
            http_requests = telemetry.get("http_requests", [])
            firmware_patterns = [r"\.bin$", r"\.hex$", r"\.fw$", r"/firmware/update", r"/upgrade", r"/ota/"]
            
            for req in http_requests:
                url = req.get("url", "")
                method = req.get("method", "GET")
                user_agent = req.get("user_agent", "")
                
                # Check for firmware file downloads or updates over HTTP
                matched_pat = [pat for pat in firmware_patterns if re.search(pat, url, re.IGNORECASE)]
                if matched_pat and method in ["GET", "POST"]:
                    # Flag suspicious user agents (curl, wget, empty, or scripts) or non-HTTPS
                    if any(agent in user_agent.lower() for agent in ["curl", "wget", "python", "go-http"]):
                        matched_events.append(req)
                    elif not user_agent:
                        matched_events.append(req)

            if matched_events:
                triggered = True
                severity = "HIGH"
                details = f"Detected {len(matched_events)} unencrypted HTTP requests downloading firmware binaries with scripted User-Agents."

        elif hunt_name == "CCTV Botnet Activity":
            connections = telemetry.get("connections", [])
            inventory = telemetry.get("device_inventory", {})
            
            # Identify camera IPs
            camera_ips = [ip for ip, info in inventory.items() if info.get("type") == "CCTV_Camera"]
            
            # Check camera outbound connections to public IPs or high rates
            cam_conn_counts = {}
            for conn in connections:
                src_ip = conn.get("src_ip")
                dst_ip = conn.get("dst_ip")
                
                if src_ip in camera_ips:
                    # Exclude typical RFC1918 internal addresses for local storage
                    is_public = False
                    if dst_ip and not (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or dst_ip.startswith("172.16.")):
                        is_public = True
                    
                    if is_public:
                        cam_conn_counts[src_ip] = cam_conn_counts.get(src_ip, 0) + 1
                        matched_events.append(conn)

            # Keep only devices exceeding thresholds (e.g. > 15 outbound connections to public space)
            active_suspects = [ip for ip, cnt in cam_conn_counts.items() if cnt > 15]
            matched_events = [c for c in matched_events if c["src_ip"] in active_suspects]

            if active_suspects:
                triggered = True
                severity = "HIGH"
                details = f"Identified CCTV cameras {active_suspects} generating excessive connections to external public targets."

        elif hunt_name == "PLC Logic Manipulation":
            plc_logs = telemetry.get("plc_logs", [])
            # Critical OT commands
            manipulation_commands = ["STOP_PLC", "FORCE_OUTPUT", "WRITE_REGISTER", "FIRMWARE_UPLOAD"]
            
            for log in plc_logs:
                command = log.get("command", "")
                src_ip = log.get("src_ip", "")
                auth_status = log.get("auth_status", "authorized")
                
                if command in manipulation_commands and (auth_status == "unauthorized" or not src_ip.startswith("10.0.10.")): 
                    # 10.0.10.x represents the authorized engineering workstations network
                    matched_events.append(log)

            if matched_events:
                triggered = True
                severity = "CRITICAL"
                details = f"Detected {len(matched_events)} unauthorized PLC manipulation commands originating outside engineering subnets."

        elif hunt_name == "Smart Meter Data Exfiltration":
            connections = telemetry.get("connections", [])
            inventory = telemetry.get("device_inventory", {})
            
            meter_ips = [ip for ip, info in inventory.items() if info.get("type") == "Smart_Meter"]
            
            for conn in connections:
                src_ip = conn.get("src_ip")
                bytes_sent = conn.get("bytes_out", 0)
                # Smart meters sending more than 2MB in a single connection is highly anomalous
                if src_ip in meter_ips and bytes_sent > 2000000:
                    matched_events.append(conn)

            if matched_events:
                triggered = True
                severity = "MEDIUM"
                details = f"Smart meter exfiltration suspect: {len(matched_events)} connections sent anomalously large files (>2MB)."

        elif hunt_name == "BLE Unauthorized Pairing":
            ble_logs = telemetry.get("ble_logs", [])
            
            for log in ble_logs:
                event_type = log.get("event")
                status = log.get("status")
                attempts = log.get("attempts", 1)
                
                if event_type == "pairing_request" and (status == "rejected" or attempts > 3):
                    matched_events.append(log)

            if matched_events:
                triggered = True
                severity = "LOW"
                details = f"BLE pairing failures or sweeps detected: {len(matched_events)} events matched."

        elif hunt_name == "MQTT C2 Channel":
            mqtt_messages = telemetry.get("mqtt_messages", [])
            suspicious_topics = ["/cmd", "/c2", "/shell", "/exec", "/admin"]
            
            for msg in mqtt_messages:
                topic = msg.get("topic", "")
                payload = msg.get("payload", "")
                
                # Check for commands or base64 patterns in payloads
                is_suspicious_topic = any(top in topic for top in suspicious_topics)
                is_base64_cmd = False
                if isinstance(payload, str):
                    if payload.startswith("eyJ") or (len(payload) > 12 and payload.endswith("==")): # base64 indicators
                        is_base64_cmd = True
                    if any(term in payload.lower() for term in ["wget", "curl", "chmod", "sh", "busybox"]):
                        is_base64_cmd = True

                if is_suspicious_topic or is_base64_cmd:
                    matched_events.append(msg)

            if matched_events:
                triggered = True
                severity = "HIGH"
                details = f"MQTT communication matches C2 characteristics: {len(matched_events)} messages on execution topics."

        return {
            "playbook_name": hunt_name,
            "triggered": triggered,
            "severity": severity,
            "matched_events": matched_events,
            "details": details
        }

    @staticmethod
    def correlate_findings(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Cross-correlates triggered playbook findings to expose complex attack steps.
        """
        triggered_playbooks = [res for res in results if res["triggered"]]
        
        correlated_events = []
        overall_risk_score = 0.0
        
        # Build index of affected IPs per playbook
        affected_ips = {}
        for res in triggered_playbooks:
            p_name = res["playbook_name"]
            ips = set()
            for evt in res["matched_events"]:
                for key in ["src_ip", "device_ip", "ip"]:
                    if key in evt:
                        ips.add(evt[key])
            affected_ips[p_name] = ips

        # Correlation 1: Telnet Default Creds + CCTV Botnet Activity on same IP
        # Indicates active botnet enrollment of camera
        cam_botnet_ips = affected_ips.get("CCTV_Camera", set()) | affected_ips.get("CCTV Botnet Activity", set())
        telnet_ips = affected_ips.get("Telnet Default Creds", set())
        shared_cam_ips = cam_botnet_ips & telnet_ips
        if shared_cam_ips:
            correlated_events.append({
                "correlation_id": "CORR_CCTV_BOTNET_ENROLLMENT",
                "name": "CCTV Camera Botnet Compromise",
                "description": f"IPs {list(shared_cam_ips)} matched both Telnet default credential logins and high-rate outbound botnet connections.",
                "severity": "CRITICAL"
            })
            overall_risk_score = max(overall_risk_score, 95.0)

        # Correlation 2: Firmware Implant via HTTP + PLC Logic Manipulation on same network segment
        # Represents an ICS attack chain (APT)
        fw_ips = affected_ips.get("Firmware Implant via HTTP", set())
        plc_ips = affected_ips.get("PLC Logic Manipulation", set())
        
        # Check subnet match (e.g. 10.0.10.x / 24)
        subnet_overlap = False
        for fw_ip in fw_ips:
            for plc_ip in plc_ips:
                if fw_ip.split(".")[:3] == plc_ip.split(".")[:3]:
                    subnet_overlap = True
                    break

        if subnet_overlap:
            correlated_events.append({
                "correlation_id": "CORR_ICS_KILL_CHAIN",
                "name": "Industrial Control System Compromise Chain",
                "description": f"Subnet overlap detected between firmware implants ({list(fw_ips)}) and unauthorized PLC modifications ({list(plc_ips)}). Likely targeted attack.",
                "severity": "CRITICAL"
            })
            overall_risk_score = max(overall_risk_score, 99.0)

        # Correlation 3: MQTT C2 + Smart Meter Exfiltration
        mqtt_ips = affected_ips.get("MQTT C2 Channel", set())
        meter_ips = affected_ips.get("Smart Meter Data Exfiltration", set())
        shared_meter_ips = mqtt_ips & meter_ips
        if shared_meter_ips:
            correlated_events.append({
                "correlation_id": "CORR_SMART_METER_C2_EXFIL",
                "name": "Smart Grid Data Exfiltration via MQTT C2",
                "description": f"Smart meter(s) {list(shared_meter_ips)} exhibited MQTT C2 commands alongside anomalous high-bandwidth data transfers.",
                "severity": "HIGH"
            })
            overall_risk_score = max(overall_risk_score, 85.0)

        # General score scaling based on total triggered plays
        if not overall_risk_score:
            active_count = len(triggered_playbooks)
            if active_count >= 3:
                overall_risk_score = 75.0
            elif active_count == 2:
                overall_risk_score = 50.0
            elif active_count == 1:
                severity_scores = {"CRITICAL": 80.0, "HIGH": 65.0, "MEDIUM": 45.0, "LOW": 20.0, "INFO": 5.0}
                overall_risk_score = severity_scores.get(triggered_playbooks[0]["severity"], 5.0)

        # Aggregated threat level classification
        if overall_risk_score >= 80.0:
            agg_threat = "CRITICAL"
        elif overall_risk_score >= 60.0:
            agg_threat = "HIGH"
        elif overall_risk_score >= 35.0:
            agg_threat = "MEDIUM"
        elif overall_risk_score > 0.0:
            agg_threat = "LOW"
        else:
            agg_threat = "INFO"

        return {
            "triggered_playbook_count": len(triggered_playbooks),
            "correlations_found": correlated_events,
            "overall_risk_score": round(overall_risk_score, 2),
            "aggregated_threat_level": agg_threat
        }
