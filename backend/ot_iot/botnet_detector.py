"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — Botnet Detector

Detects signatures of prominent IoT botnets (Mirai, Mozi, Gafgyt, VPNFilter, 
BrickerBot, FritzFrog, Kaiten) in traffic characteristics and command history.
"""

import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger("niravan.ot_iot.botnet_detector")
logger.setLevel(logging.INFO)


class BotnetDetector:
    """
    Identifies IoT/OT botnet activity based on traffic signatures, payload inspection, 
    and shell command histories.
    """

    BOTNET_SIGNATURES: Dict[str, Dict[str, Any]] = {
        "Mirai": {
            "ports": [23, 2323, 48101],
            "protocols": ["TCP", "UDP"],
            "payload_regex": [
                r"dvrHelper", 
                r"\x54\x54\x59\x55\x53\x45\x52",  # TTYUSER
                r"\x4d\x49\x52\x41\x49",          # MIRAI ASCII/HEX
                r"Host:.*update\.freebsd-update\.com"
            ],
            "commands": ["busybox", "cat /proc/mounts", "enable", "system", "shellcheck", "/bin/busybox MIRAI"]
        },
        "Mozi": {
            "ports": [3478, 7547, 37215, 80, 8080],
            "protocols": ["UDP", "TCP"],
            "payload_regex": [
                r"d1:ad2:id20:",                  # DHT node id query
                r"mozi\.m", 
                r"mozi\.a", 
                r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/mozi"
            ],
            "commands": ["/bin/busybox mozi", "wget http://.*/mozi.*", "chmod 777 mozi", "./mozi"]
        },
        "Gafgyt": {
            "ports": [22, 23, 80, 8080],
            "protocols": ["TCP"],
            "payload_regex": [
                r"BASHLITE", 
                r"Gafgyt", 
                r"HTTPFLOOD", 
                r"TCPFLOOD", 
                r"UDPFLOOD"
            ],
            "commands": ["cd /tmp", "chmod 777 *", "chmod +x *", "tftp -g", "wget http://.*/sh", "rc.local"]
        },
        "VPNFilter": {
            "ports": [80, 443, 8080],
            "protocols": ["TCP"],
            "payload_regex": [
                r"photobucket\.com/albums/o214", 
                r"imageshack\.us", 
                r"vpnfilter",
                r"vpnfilter\.stage1",
                r"vpnfilter\.stage2"
            ],
            "commands": ["vpnfilter", "mkdir -p /var/run/vpnfilter", "vpnfilter/stage1", "sh -c /var/run/vpnfilter"]
        },
        "BrickerBot": {
            "ports": [22, 23],
            "protocols": ["TCP"],
            "payload_regex": [
                r"mtdblock", 
                r"sysctl -w net\.ipv4\.ip_forward=0",
                r"flash_eraseall"
            ],
            "commands": [
                "rm -rf /", 
                "dd if=/dev/zero of=/dev/mtdblock", 
                "flash_eraseall", 
                "ip link set eth0 down", 
                "reboot",
                "echo 1 > /proc/sys/kernel/sysrq"
            ]
        },
        "FritzFrog": {
            "ports": [22, 55555, 2862],
            "protocols": ["TCP"],
            "payload_regex": [
                r"fritzfrog",
                r"P2P_PORT",
                r"f_frog"
            ],
            "commands": [
                "./libexec", 
                "cp /bin/sh /dev/shm", 
                "/dev/shm/ifconfig", 
                "/dev/shm/libexec"
            ]
        },
        "Kaiten": {
            "ports": [6667, 6668, 6669],  # IRC ports
            "protocols": ["TCP"],
            "payload_regex": [
                r"NICK ", 
                r"JOIN #", 
                r"TSUNAMI", 
                r"PANIC",
                r"IRC_C2"
            ],
            "commands": ["./tsunami", "./kaiten", "chmod +x tsunami", "chmod +x kaiten"]
        }
    }

    @staticmethod
    def detect(device_ip: str, traffic: Dict[str, Any], cmd_history: List[str]) -> Dict[str, Any]:
        """
        Orchestrates botnet detection by analyzing traffic characteristics, 
        payload markers, and shell command logs.

        Args:
            device_ip: IP of the target device.
            traffic: Traffic details (ports_used, protocols, payloads, connections_rate).
            cmd_history: List of shell commands run by the device.

        Returns:
            Dictionary containing detected threats, severity, matches, and recommendations.
        """
        # Guard against None inputs
        if traffic is None:
            traffic = {}
        if cmd_history is None:
            cmd_history = []

        matches = []
        highest_severity = "INFO"
        threat_detected = "None"
        recommendations = []
        overall_confidence = 0.0

        # Evaluate individual botnets
        mirai_res = BotnetDetector.detect_mirai(traffic)
        mozi_res = BotnetDetector.detect_mozi(traffic)
        gafgyt_res = BotnetDetector.detect_gafgyt(traffic)
        vpnfilter_res = BotnetDetector.detect_vpnfilter(traffic)
        brickerbot_res = BotnetDetector.detect_brickerbot(traffic)

        res_map = {
            "Mirai": mirai_res,
            "Mozi": mozi_res,
            "Gafgyt": gafgyt_res,
            "VPNFilter": vpnfilter_res,
            "BrickerBot": brickerbot_res
        }

        # Check command history against signatures
        cmd_matches = []
        for botnet_name, sig in BotnetDetector.BOTNET_SIGNATURES.items():
            matched_cmds = []
            for cmd in cmd_history:
                for target_cmd in sig["commands"]:
                    if target_cmd in cmd:
                        matched_cmds.append(cmd)
            
            if matched_cmds:
                cmd_matches.append({
                    "botnet": botnet_name,
                    "matched_commands": matched_cmds
                })
                # If command history matches, it greatly increases confidence
                if botnet_name in res_map:
                    res_map[botnet_name]["detected"] = True
                    res_map[botnet_name]["confidence"] = max(res_map[botnet_name]["confidence"], 0.85)
                else:
                    # For FritzFrog, Kaiten which don't have dedicated methods, we build dynamic result
                    res_map[botnet_name] = {
                        "detected": True,
                        "confidence": 0.80,
                        "details": f"Command match: {matched_cmds}"
                    }

        # Traffic payload/port regex check for FritzFrog/Kaiten
        for botnet_name in ["FritzFrog", "Kaiten"]:
            sig = BotnetDetector.BOTNET_SIGNATURES[botnet_name]
            # Port check
            ports_used = traffic.get("ports_used", [])
            matched_ports = [p for p in ports_used if p in sig["ports"]]
            
            # Payload check
            payloads = traffic.get("payloads", [])
            matched_payloads = []
            for payload in payloads:
                for regex in sig["payload_regex"]:
                    if re.search(regex, payload, re.IGNORECASE):
                        matched_payloads.append(payload)

            if matched_ports or matched_payloads:
                confidence = 0.4
                if matched_ports and matched_payloads:
                    confidence = 0.8
                elif matched_payloads:
                    confidence = 0.65
                
                if botnet_name not in res_map:
                    res_map[botnet_name] = {
                        "detected": True,
                        "confidence": confidence,
                        "details": f"Matched ports {matched_ports} or payloads {matched_payloads}"
                    }
                else:
                    res_map[botnet_name]["detected"] = True
                    res_map[botnet_name]["confidence"] = max(res_map[botnet_name]["confidence"], confidence)

        # Gather matches and determine the most likely threat
        for botnet_name, res in res_map.items():
            if res.get("detected"):
                matches.append({
                    "botnet": botnet_name,
                    "confidence": res["confidence"],
                    "details": res.get("details", "")
                })
                if res["confidence"] > overall_confidence:
                    overall_confidence = res["confidence"]
                    threat_detected = botnet_name

        # Map severities
        severity_map = {
            "Mirai": "CRITICAL",
            "Mozi": "CRITICAL",
            "Gafgyt": "HIGH",
            "VPNFilter": "HIGH",
            "BrickerBot": "CRITICAL",
            "FritzFrog": "MEDIUM",
            "Kaiten": "HIGH",
            "None": "INFO"
        }
        highest_severity = severity_map.get(threat_detected, "INFO")

        # Compile recommendations
        if threat_detected == "Mirai":
            recommendations = [
                "Isolate device immediately to prevent scan spreading.",
                "Reboot the device to clear memory-resident malware.",
                "Change default Telnet/SSH passwords immediately.",
                "Block outbound TCP connections to ports 23, 2323, and 48101."
            ]
        elif threat_detected == "Mozi":
            recommendations = [
                "Block incoming and outgoing UDP traffic on DHT port 3478.",
                "Disable TR-069 port 7547 on external interfaces.",
                "Flash device firmware to a verified, clean image.",
                "Isolate the device from local OT assets."
            ]
        elif threat_detected == "Gafgyt":
            recommendations = [
                "Terminate unauthorized active SSH/Telnet sessions.",
                "Inspect /tmp and /var directories for malicious binary downloads.",
                "Apply firewalls restricting local commands or shell updates."
            ]
        elif threat_detected == "VPNFilter":
            recommendations = [
                "Perform factory reset of the router/NAS.",
                "Reboot the device (clears Stage 1 transient malware).",
                "Apply manufacturer firmware updates immediately.",
                "Disable remote administration UI."
            ]
        elif threat_detected == "BrickerBot":
            recommendations = [
                "IMMEDIATELY cut off all network connections to prevent device permanent bricking.",
                "Disable WAN-side Telnet and SSH interfaces.",
                "Restore storage configs and verify hardware watchdog parameters.",
                "Inspect device flash partition for block-erasure indicators."
            ]
        elif threat_detected == "FritzFrog":
            recommendations = [
                "Inspect memory and /dev/shm for libexec or f_frog payloads.",
                "Block port 55555 and 2862 traffic.",
                "Implement strict SSH key rotation and restrict SSH ingress."
            ]
        elif threat_detected == "Kaiten":
            recommendations = [
                "Block IRC ports (6667-6669) outbound.",
                "Inspect processes running tsunami/kaiten binaries.",
                "Reboot the hardware to clear volatile memory footprints."
            ]
        else:
            if matches:
                recommendations = ["Analyze device telemetry logs.", "Audit open ports and authentication passwords."]
            else:
                recommendations = ["No action required. Continue routine monitoring."]

        return {
            "device_ip": device_ip,
            "threat_detected": threat_detected,
            "severity": highest_severity,
            "confidence": round(overall_confidence, 2),
            "matches": matches,
            "command_matches": cmd_matches,
            "recommendations": recommendations
        }

    @staticmethod
    def detect_mirai(traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects Mirai traffic characteristics (telnet sweeps, high SYN packet volume).
        """
        ports_used = traffic.get("ports_used", [])
        payloads = traffic.get("payloads", [])
        conn_rate = traffic.get("connection_rate", 0)  # connections per sec
        syn_ratio = traffic.get("syn_packet_ratio", 0.0)

        confidence = 0.0
        details = []

        # Check ports
        mirai_ports = [p for p in ports_used if p in [23, 2323, 48101]]
        if mirai_ports:
            confidence += 0.25
            details.append(f"Accessed common Mirai ports: {mirai_ports}")

        # Check payloads
        matched_payloads = []
        for p in payloads:
            for regex in BotnetDetector.BOTNET_SIGNATURES["Mirai"]["payload_regex"]:
                if re.search(regex, p, re.IGNORECASE):
                    matched_payloads.append(p)
        
        if matched_payloads:
            confidence += 0.45
            details.append(f"Payload signature matches: {matched_payloads}")

        # Check rate and TCP SYN ratio
        if conn_rate > 50:
            confidence += 0.15
            details.append(f"High connection rate: {conn_rate} conns/sec")
        if syn_ratio > 0.85:
            confidence += 0.15
            details.append(f"High TCP SYN ratio: {syn_ratio:.1%}")

        confidence = min(0.99, confidence)
        detected = confidence >= 0.50

        return {
            "detected": detected,
            "confidence": round(confidence, 2),
            "details": "; ".join(details) if details else "No Mirai characteristics identified."
        }

    @staticmethod
    def detect_mozi(traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects Mozi botnet using DHT signatures, high UDP packets, TR-069 port access.
        """
        ports_used = traffic.get("ports_used", [])
        protocols = traffic.get("protocols", [])
        payloads = traffic.get("payloads", [])
        udp_ratio = traffic.get("udp_packet_ratio", 0.0)

        confidence = 0.0
        details = []

        # DHT Port check or TR-069 ports
        mozi_ports = [p for p in ports_used if p in [3478, 7547, 37215]]
        if mozi_ports:
            confidence += 0.3
            details.append(f"Accessed Mozi/DHT ports: {mozi_ports}")

        # UDP protocol dominance
        if "UDP" in protocols and udp_ratio > 0.70:
            confidence += 0.2
            details.append(f"High UDP traffic ratio: {udp_ratio:.1%}")

        # Payload patterns
        matched_payloads = []
        for p in payloads:
            for regex in BotnetDetector.BOTNET_SIGNATURES["Mozi"]["payload_regex"]:
                if re.search(regex, p, re.IGNORECASE):
                    matched_payloads.append(p)

        if matched_payloads:
            confidence += 0.45
            details.append(f"DHT or Mozi URL payload signatures matched: {matched_payloads}")

        confidence = min(0.99, confidence)
        detected = confidence >= 0.50

        return {
            "detected": detected,
            "confidence": round(confidence, 2),
            "details": "; ".join(details) if details else "No Mozi characteristics identified."
        }

    @staticmethod
    def detect_gafgyt(traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects Gafgyt payload markers (e.g. BASHLITE) and custom floods.
        """
        payloads = traffic.get("payloads", [])
        ports_used = traffic.get("ports_used", [])

        confidence = 0.0
        details = []

        # Port checks
        gafgyt_ports = [p for p in ports_used if p in [22, 23]]
        if gafgyt_ports:
            confidence += 0.2
            details.append(f"Targeted common SSH/Telnet ports: {gafgyt_ports}")

        # Payloads
        matched_payloads = []
        for p in payloads:
            for regex in BotnetDetector.BOTNET_SIGNATURES["Gafgyt"]["payload_regex"]:
                if re.search(regex, p, re.IGNORECASE):
                    matched_payloads.append(p)

        if matched_payloads:
            confidence += 0.65
            details.append(f"Gafgyt/BASHLITE control string matches: {matched_payloads}")

        confidence = min(0.99, confidence)
        detected = confidence >= 0.50

        return {
            "detected": detected,
            "confidence": round(confidence, 2),
            "details": "; ".join(details) if details else "No Gafgyt characteristics identified."
        }

    @staticmethod
    def detect_vpnfilter(traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects VPNFilter payload patterns targeting known SOHO networks or downloading firmware images.
        """
        payloads = traffic.get("payloads", [])
        urls = traffic.get("requested_urls", [])

        confidence = 0.0
        details = []

        # Check requested URLs
        matched_urls = []
        for url in urls:
            if "photobucket.com/albums/o214" in url or "imageshack.us" in url:
                matched_urls.append(url)
        
        if matched_urls:
            confidence += 0.6
            details.append(f"C2 photobucket/imageshack URL requests matched: {matched_urls}")

        # Check payload regex
        matched_payloads = []
        for p in payloads:
            for regex in BotnetDetector.BOTNET_SIGNATURES["VPNFilter"]["payload_regex"]:
                if re.search(regex, p, re.IGNORECASE):
                    matched_payloads.append(p)
        
        if matched_payloads:
            confidence += 0.35
            details.append(f"VPNFilter string matches in packet data: {matched_payloads}")

        confidence = min(0.99, confidence)
        detected = confidence >= 0.45

        return {
            "detected": detected,
            "confidence": round(confidence, 2),
            "details": "; ".join(details) if details else "No VPNFilter characteristics identified."
        }

    @staticmethod
    def detect_brickerbot(traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects BrickerBot characteristics (destructive command transmission, port disables).
        """
        payloads = traffic.get("payloads", [])
        ports_used = traffic.get("ports_used", [])

        confidence = 0.0
        details = []

        # Checking for SSH/Telnet ports
        if any(p in ports_used for p in [22, 23]):
            confidence += 0.2
            details.append("Accessed SSH/Telnet ports")

        # Destructive payloads
        matched_payloads = []
        for p in payloads:
            for regex in BotnetDetector.BOTNET_SIGNATURES["BrickerBot"]["payload_regex"]:
                if re.search(regex, p, re.IGNORECASE):
                    matched_payloads.append(p)

        if matched_payloads:
            confidence += 0.7
            details.append(f"Destructive commands found in payload: {matched_payloads}")

        confidence = min(0.99, confidence)
        detected = confidence >= 0.50

        return {
            "detected": detected,
            "confidence": round(confidence, 2),
            "details": "; ".join(details) if details else "No BrickerBot characteristics identified."
        }

    @staticmethod
    def check_telnet_brute_force(log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Inspects authentication and session logs to detect active Telnet brute forcing.

        Args:
            log: List of connection/auth events:
                 [{'src_ip': str, 'dst_ip': str, 'port': int, 'username': str, 'password': str, 'status': str, 'timestamp': datetime/str}]

        Returns:
            Dictionary containing brute force analysis.
        """
        attempts = 0
        failures = 0
        successes = 0
        usernames_tried = set()
        ip_attempts = {}

        for entry in log:
            port = entry.get("port")
            # Telnet ports are 23 or 2323
            if port not in [23, 2323]:
                continue
            
            src_ip = entry.get("src_ip")
            status = entry.get("status")
            user = entry.get("username", "")

            attempts += 1
            if status == "failed":
                failures += 1
            elif status == "success":
                successes += 1

            if user:
                usernames_tried.add(user)

            if src_ip:
                ip_attempts[src_ip] = ip_attempts.get(src_ip, 0) + 1

        detected = False
        confidence = 0.0
        details = "No significant Telnet brute forcing detected."

        # High attempts rate or high failure rate (e.g. 5+ failed attempts from a single source)
        max_attempts_from_single_source = max(ip_attempts.values()) if ip_attempts else 0
        
        if max_attempts_from_single_source >= 5:
            detected = True
            # Confidence scales with number of failures and unique usernames tried
            confidence = min(0.99, 0.4 + (failures / 20.0) + (len(usernames_tried) / 15.0))
            details = (
                f"Telnet brute force detected! Total attempts: {attempts}. "
                f"Failures: {failures}. Successes: {successes}. "
                f"Max attempts from single IP: {max_attempts_from_single_source}. "
                f"Unique usernames tried: {list(usernames_tried)}."
            )

        return {
            "brute_force_detected": detected,
            "attack_attempts": attempts,
            "failed_logins": failures,
            "unique_usernames": sorted(list(usernames_tried)),
            "confidence": round(confidence, 2) if detected else 0.0,
            "details": details
        }
