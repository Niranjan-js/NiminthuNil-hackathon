"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — IoT Behavior Analyzer

Analyzes device traffic and telemetry logs to detect behavioral deviations,
port scans, lateral movement, beaconing activity, and bandwidth anomalies.
"""

import logging
import math
from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("niravan.ot_iot.behavior_analyzer")
logger.setLevel(logging.INFO)


class IoTBehaviorAnalyzer:
    """
    Analyzes IoT/OT device telemetry for abnormal behavior patterns.
    """

    # Normal behavioral profiles per device type
    BEHAVIORAL_PROFILES: Dict[str, Dict[str, Any]] = {
        "PLC": {
            "max_bytes_out_per_min": 100000,         # PLCs usually send small control commands/telemetry
            "max_connections_per_min": 15,
            "allowed_ports": [502, 102, 44818, 20000, 22],
            "max_unique_destinations": 5,
        },
        "CCTV_Camera": {
            "max_bytes_out_per_min": 10000000,      # Cameras stream video (high bandwidth)
            "max_connections_per_min": 10,
            "allowed_ports": [80, 443, 554, 8554, 1935],
            "max_unique_destinations": 4,
        },
        "IP_Phone": {
            "max_bytes_out_per_min": 2000000,
            "max_connections_per_min": 30,
            "allowed_ports": [5060, 5061, 80, 443, 16384],
            "max_unique_destinations": 10,
        },
        "Smart_Meter": {
            "max_bytes_out_per_min": 50000,
            "max_connections_per_min": 5,
            "allowed_ports": [4059, 1153, 80, 443],
            "max_unique_destinations": 2,
        },
        "HVAC_Controller": {
            "max_bytes_out_per_min": 80000,
            "max_connections_per_min": 10,
            "allowed_ports": [47808, 502, 80, 443],
            "max_unique_destinations": 3,
        },
        "Industrial_Gateway": {
            "max_bytes_out_per_min": 5000000,
            "max_connections_per_min": 100,
            "allowed_ports": [22, 80, 443, 1883, 8883, 502, 44818],
            "max_unique_destinations": 20,
        },
        "default": {
            "max_bytes_out_per_min": 500000,
            "max_connections_per_min": 25,
            "allowed_ports": [80, 443, 8080],
            "max_unique_destinations": 10,
        }
    }

    @staticmethod
    def analyze(device_info: Dict[str, Any], traffic_sample: Dict[str, Any] = None) -> Dict[str, Any]:
        if traffic_sample is None:
            traffic_sample = {}
        """
        Runs baseline checks against the behavioral profile of the device's type.
        Detects anomalies, computes threat scores, and lists botnet indicators.

        Args:
            device_info: Metadata of the device (type, ip, mac, etc.)
            traffic_sample: Traffic observations (bytes_out, connection_count, ports, destinations, etc.)

        Returns:
            Dictionary with evaluation results.
        """
        device_type = device_info.get("type", "default")
        device_ip = device_info.get("ip", "unknown")
        
        profile = IoTBehaviorAnalyzer.BEHAVIORAL_PROFILES.get(device_type, IoTBehaviorAnalyzer.BEHAVIORAL_PROFILES["default"])

        anomalies_detected = []
        botnet_indicators = []
        anomaly_score = 0.0

        # 1. Bandwidth check
        bytes_out = traffic_sample.get("bytes_out", 0)
        max_bytes_out = profile["max_bytes_out_per_min"]
        if bytes_out > max_bytes_out:
            anomalies_detected.append("high_bandwidth_usage")
            ratio = bytes_out / max_bytes_out
            anomaly_score += min(30.0, ratio * 5)
            if ratio > 10:
                botnet_indicators.append("data_exfiltration_or_ddos_staging")

        # 2. Connection frequency check
        conn_count = traffic_sample.get("connection_count", 0)
        max_conn = profile["max_connections_per_min"]
        if conn_count > max_conn:
            anomalies_detected.append("excessive_connections")
            anomaly_score += min(25.0, (conn_count / max_conn) * 5)
            if conn_count > max_conn * 5:
                botnet_indicators.append("rapid_connection_rate_scanner_like")

        # 3. Ports check
        ports = traffic_sample.get("ports_used", [])
        allowed_ports = profile["allowed_ports"]
        unauthorized_ports = [p for p in ports if p not in allowed_ports]
        if unauthorized_ports:
            anomalies_detected.append("unauthorized_ports_accessed")
            anomaly_score += min(20.0, len(unauthorized_ports) * 5)
            # Common botnet setup ports or shell access
            critical_botnet_ports = {23, 2323, 80, 8080, 5555, 9527, 37215}
            matched_bad_ports = [p for p in unauthorized_ports if p in critical_botnet_ports]
            if matched_bad_ports:
                botnet_indicators.append(f"malicious_port_usage_{matched_bad_ports}")
                anomaly_score += 15.0

        # 4. Destination diversity check
        destinations = traffic_sample.get("unique_destinations", [])
        max_dests = profile["max_unique_destinations"]
        if len(destinations) > max_dests:
            anomalies_detected.append("unusual_destination_diversity")
            anomaly_score += min(25.0, (len(destinations) - max_dests) * 5)
            if len(destinations) > max_dests * 3:
                botnet_indicators.append("horizontal_ip_sweeping")

        # Cap score at 100
        anomaly_score = min(100.0, anomaly_score)

        # Threat level classification
        if anomaly_score >= 75.0:
            threat_level = "CRITICAL"
        elif anomaly_score >= 50.0:
            threat_level = "HIGH"
        elif anomaly_score >= 25.0:
            threat_level = "MEDIUM"
        elif anomaly_score > 0.0:
            threat_level = "LOW"
        else:
            threat_level = "INFO"

        return {
            "device_ip": device_ip,
            "device_type": device_type,
            "anomalies_detected": anomalies_detected,
            "anomaly_score": round(anomaly_score, 2),
            "threat_level": threat_level,
            "botnet_indicators": botnet_indicators,
            "baseline_limits": {
                "max_bytes_out": max_bytes_out,
                "max_connections": max_conn,
                "allowed_ports": allowed_ports,
                "max_destinations": max_dests
            }
        }

    @staticmethod
    def detect_port_scan_from_device(device_ip: str, log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes traffic logs/connection attempts from a single device to identify port scanning activity.

        Args:
            device_ip: IP address of the source device
            log: List of connection dicts, each with keys like:
                 'src_ip', 'dst_ip', 'dst_port', 'timestamp', 'status' (e.g. 'failed' or 'success')

        Returns:
            Dictionary detailing detected port scan properties.
        """
        device_logs = [entry for entry in log if entry.get("src_ip") == device_ip]
        if not device_logs:
            return {
                "port_scan_detected": False,
                "scanned_ports": [],
                "target_ips": [],
                "scan_type": "none",
                "confidence": 0.0,
                "details": "No logs found for device IP."
            }

        # Track targets
        # Horizontal: same port, many different IPs
        # Vertical: same IP, many different ports
        target_ports_per_ip = defaultdict(set)
        ips_per_port = defaultdict(set)
        failed_count = 0
        total_count = len(device_logs)

        for entry in device_logs:
            dst_ip = entry.get("dst_ip")
            dst_port = entry.get("dst_port")
            status = entry.get("status", "success")

            if dst_ip and dst_port is not None:
                target_ports_per_ip[dst_ip].add(dst_port)
                ips_per_port[dst_port].add(dst_ip)
            
            if status == "failed":
                failed_count += 1

        # Check for scanning patterns
        max_ports_on_single_ip = max([len(ports) for ports in target_ports_per_ip.values()]) if target_ports_per_ip else 0
        max_ips_on_single_port = max([len(ips) for ips in ips_per_port.values()]) if ips_per_port else 0
        unique_targets = list(target_ports_per_ip.keys())
        all_ports = set()
        for ports in target_ports_per_ip.values():
            all_ports.update(ports)

        scan_detected = False
        scan_type = "none"
        confidence = 0.0

        # Define thresholds
        VERT_THRESHOLD = 15     # 15+ ports on a single IP
        HORIZ_THRESHOLD = 10    # 10+ IPs scanned on a single port

        if max_ports_on_single_ip >= VERT_THRESHOLD and max_ips_on_single_port >= HORIZ_THRESHOLD:
            scan_detected = True
            scan_type = "mixed"
            confidence = min(0.99, 0.5 + (max_ports_on_single_ip / 50.0) + (max_ips_on_single_port / 50.0))
        elif max_ports_on_single_ip >= VERT_THRESHOLD:
            scan_detected = True
            scan_type = "vertical"
            confidence = min(0.95, 0.4 + (max_ports_on_single_ip / 40.0))
        elif max_ips_on_single_port >= HORIZ_THRESHOLD:
            scan_detected = True
            scan_type = "horizontal"
            confidence = min(0.95, 0.4 + (max_ips_on_single_port / 30.0))

        # Boost confidence if failure rate is high
        if scan_detected and total_count > 5:
            fail_rate = failed_count / total_count
            confidence = min(0.99, confidence + (fail_rate * 0.15))

        details = "No port scanning patterns detected."
        if scan_detected:
            details = (
                f"Detected {scan_type} scanning activity from {device_ip}. "
                f"Max ports scanned on single IP: {max_ports_on_single_ip}. "
                f"Max IPs scanned on single port: {max_ips_on_single_port}. "
                f"Failure rate: {failed_count}/{total_count} ({failed_count/total_count:.1%})."
            )

        return {
            "port_scan_detected": scan_detected,
            "scanned_ports": sorted(list(all_ports)),
            "target_ips": unique_targets,
            "scan_type": scan_type,
            "confidence": round(confidence, 2) if scan_detected else 0.0,
            "details": details
        }

    @staticmethod
    def detect_lateral_movement(device_ip: str, arp_table: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes ARP table states or transition logs to detect lateral movement,
        including ARP spoofing (Man-in-the-Middle) or ARP-based network scanning.

        Args:
            device_ip: IP of the device to inspect
            arp_table: List of dictionaries detailing ARP mapping observations:
                       [{'ip': str, 'mac': str, 'timestamp': datetime/str, 'src_mac': Optional[str], 'type': Optional[str]}]

        Returns:
            Detection results.
        """
        mac_to_ips = defaultdict(set)
        ip_to_macs = defaultdict(set)
        
        # Check for rapid ARP requesting: one MAC requesting many IPs in a short period (ARP Sweep)
        arp_requests_by_mac = defaultdict(list)
        
        for entry in arp_table:
            ip = entry.get("ip")
            mac = entry.get("mac")
            entry_type = entry.get("type", "reply")
            src_mac = entry.get("src_mac")
            
            if ip and mac:
                mac_to_ips[mac].add(ip)
                ip_to_macs[ip].add(mac)

            if entry_type == "request" and src_mac:
                arp_requests_by_mac[src_mac].append(ip)

        detected = False
        anomaly_type = "none"
        description = "No anomalous ARP activity or lateral movement detected."
        spoofed_ips = []
        swept_ips = []
        risk_score = 0.0

        # Detect ARP Spoofing / MITM
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                detected = True
                anomaly_type = "arp_spoofing"
                spoofed_ips.append(ip)
                risk_score = max(risk_score, 85.0)
                description = f"ARP Spoofing detected! IP {ip} is mapped to multiple MAC addresses: {list(macs)}."

        # Detect ARP Sweep (Lateral Scanning)
        for mac, ips in arp_requests_by_mac.items():
            # If a single MAC requests more than 10 distinct IPs, suspect ARP Sweep
            unique_ips = set(ips)
            if len(unique_ips) >= 10:
                detected = True
                if anomaly_type == "arp_spoofing":
                    anomaly_type = "multiple_anomalies"
                else:
                    anomaly_type = "arp_sweep"
                swept_ips.extend(list(unique_ips))
                risk_score = max(risk_score, 70.0)
                description = f"ARP Sweep detected! MAC {mac} is sweeping the network, requesting {len(unique_ips)} IPs."

        return {
            "lateral_movement_detected": detected,
            "anomaly_type": anomaly_type,
            "spoofed_ips": spoofed_ips,
            "swept_ips": swept_ips,
            "risk_score": risk_score,
            "description": description
        }

    @staticmethod
    def detect_beaconing(device_ip: str, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes connection logs for highly regular, repetitive traffic intervals (beaconing).
        Beaconing indicates persistent connection attempts to a C2 server.

        Args:
            device_ip: IP of the device under test
            history: List of connection records: [{'dst_ip': str, 'timestamp': datetime/str}]

        Returns:
            Beaconing report.
        """
        device_history = [h for h in history if h.get("src_ip", device_ip) == device_ip]
        if len(device_history) < 5:
            return {
                "beaconing_detected": False,
                "destinations": {},
                "max_confidence": 0.0,
                "details": "Insufficient connections to perform beaconing analysis (minimum 5 required)."
            }

        # Group timestamps by destination
        dest_times = defaultdict(list)
        for h in device_history:
            dst = h.get("dst_ip")
            ts = h.get("timestamp")
            if not dst or not ts:
                continue
            if isinstance(ts, str):
                try:
                    if "T" in ts:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
            dest_times[dst].append(ts)

        beaconing_destinations = {}
        max_confidence = 0.0

        for dst, t_list in dest_times.items():
            if len(t_list) < 5:
                continue
            t_list.sort()
            deltas = []
            for i in range(len(t_list) - 1):
                delta = (t_list[i+1] - t_list[i]).total_seconds()
                deltas.append(delta)

            mean_delta = sum(deltas) / len(deltas)
            if mean_delta < 1.0:
                continue

            variance = sum((x - mean_delta) ** 2 for x in deltas) / len(deltas)
            std_dev = math.sqrt(variance)

            coef_of_variation = std_dev / mean_delta if mean_delta > 0 else 999.0

            if coef_of_variation < 0.15 and len(t_list) >= 5:
                confidence = max(0.0, 1.0 - (coef_of_variation * 4.0))
                confidence = min(0.99, confidence + (min(len(t_list), 50) / 200.0))
                
                beaconing_destinations[dst] = {
                    "connection_count": len(t_list),
                    "mean_interval_sec": round(mean_delta, 2),
                    "std_dev_sec": round(std_dev, 2),
                    "coef_of_variation": round(coef_of_variation, 4),
                    "confidence": round(confidence, 2)
                }
                max_confidence = max(max_confidence, confidence)

        detected = len(beaconing_destinations) > 0
        details = "No beaconing activity detected."
        if detected:
            details = f"Beaconing detected to {len(beaconing_destinations)} destination(s)."

        return {
            "beaconing_detected": detected,
            "destinations": beaconing_destinations,
            "max_confidence": round(max_confidence, 2),
            "details": details
        }

    @staticmethod
    def detect_bandwidth_spike(device_info: Dict[str, Any], traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates if the bytes sent by the device exceed standard profile parameters.

        Args:
            device_info: Dictionary detailing device type
            traffic: Dictionary with current traffic information (bytes_out, bytes_in)

        Returns:
            Bandwidth evaluation report.
        """
        device_type = device_info.get("type", "default")
        profile = IoTBehaviorAnalyzer.BEHAVIORAL_PROFILES.get(device_type, IoTBehaviorAnalyzer.BEHAVIORAL_PROFILES["default"])

        bytes_out = traffic.get("bytes_out", 0)
        baseline_max = profile["max_bytes_out_per_min"]

        ratio = bytes_out / baseline_max if baseline_max > 0 else 0.0
        detected = ratio > 2.0

        severity = "none"
        if detected:
            if ratio > 10.0:
                severity = "critical"
            elif ratio > 5.0:
                severity = "high"
            elif ratio > 3.0:
                severity = "medium"
            else:
                severity = "low"

        return {
            "bandwidth_spike_detected": detected,
            "bytes_out": bytes_out,
            "baseline_max": baseline_max,
            "ratio": round(ratio, 2),
            "severity": severity
        }
