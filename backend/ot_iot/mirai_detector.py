"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — Mirai Detector

Specialized detection module for the Mirai botnet, its variants (Satori, Okiru, Masuta, 
Echobot), scanning behavior, C2 communication, and infection stages.
"""

import logging
import re
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger("niravan.ot_iot.mirai_detector")
logger.setLevel(logging.INFO)


class MiraiDetector:
    """
    Detects and analyzes Mirai botnet infections, scanning profiles, 
    and C2 patterns.
    """

    SCANNER_PORTS: List[int] = [23, 2323, 7547, 5555, 37215, 80, 8080, 9000, 48101]

    DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
        {"username": "root", "password": "xc3511"},
        {"username": "root", "password": "vizxv"},
        {"username": "root", "password": "admin"},
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": "root"},
        {"username": "support", "password": "support"},
        {"username": "admin", "password": "password"},
        {"username": "root", "password": "default"},
        {"username": "telecomadmin", "password": "admintelecom"},
        {"username": "user", "password": "user"}
    ]

    C2_INDICATORS: List[str] = [
        "cnc.w00t.club",
        "mirai.c2.domain",
        "darkness.net",
        "bot.mirai.net",
        "satori.c2.net",
        "masuta.c2.org",
        "185.112.146.50",
        "109.248.9.15",
        "210.22.4.110"
    ]

    MIRAI_VARIANTS: Dict[str, Dict[str, Any]] = {
        "Satori": {
            "signature_ports": [37215, 52869],
            "c2_domains": ["satori.c2.net", "satori.ot.io"],
            "payload_markers": ["Satori", "satori.x86", "satori.mips"],
            "description": "Mirai variant targeting UPnP ports and Huawei home routers."
        },
        "Okiru": {
            "signature_ports": [23, 2323],
            "c2_domains": ["okiru.c2.org"],
            "payload_markers": ["okiru.mips", "okiru.arm"],
            "description": "Mirai variant optimized to target ARC (Argonaut RISC Core) processors."
        },
        "Masuta": {
            "signature_ports": [23, 80, 8080],
            "c2_domains": ["masuta.c2.org"],
            "payload_markers": ["masuta.sh4", "masuta.arm"],
            "description": "Uses ADB (Android Debug Bridge) exploits for propagation."
        },
        "Echobot": {
            "signature_ports": [80, 8080, 32764, 49152],
            "c2_domains": ["echobot.c2.info"],
            "payload_markers": ["echobot", "echo.mips"],
            "description": "Expands on Mirai by exploiting dozens of distinct enterprise/SOHO vulnerabilities."
        },
        "Moobot": {
            "signature_ports": [2323, 80],
            "c2_domains": ["moo.botnet.cc"],
            "payload_markers": ["moobot", "moo.arm"],
            "description": "Targets specific DVR/IP camera endpoints."
        }
    }

    ARCHITECTURE_TARGETS: List[str] = [
        "x86", "mips", "mipsel", "arm", "arm7", "sh4", "powerpc", "sparc", "m68k", "arc"
    ]

    @staticmethod
    def detect(device_ip: str, traffic: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs Mirai variant checks, resolves infection stage, and evaluates risks.

        Args:
            device_ip: IP of the device being evaluated.
            traffic: Dict containing:
                     'ports_used', 'payloads', 'connections', 'requested_urls', 'dns_queries'

        Returns:
            Dictionary with detection outputs (detected, variant, infection_stage, risk_details).
        """
        payloads = traffic.get("payloads", [])
        ports = traffic.get("ports_used", [])
        dns_queries = traffic.get("dns_queries", [])
        urls = traffic.get("requested_urls", [])

        detected = False
        detected_variant = "None"
        max_variant_confidence = 0.0

        # Check for specific variant matches
        for variant_name, properties in MiraiDetector.MIRAI_VARIANTS.items():
            port_match = any(p in ports for p in properties["signature_ports"])
            payload_match = any(
                any(marker.lower() in p.lower() for marker in properties["payload_markers"])
                for p in payloads
            )
            dns_match = any(
                any(domain.lower() in q.lower() for domain in properties["c2_domains"])
                for q in dns_queries
            )

            confidence = 0.0
            if port_match:
                confidence += 0.25
            if dns_match:
                confidence += 0.50
            if payload_match:
                confidence += 0.65

            confidence = min(0.99, confidence)
            if confidence >= 0.50 and confidence > max_variant_confidence:
                max_variant_confidence = confidence
                detected_variant = variant_name
                detected = True

        # Fallback to standard Mirai detection if no variant matches but payloads suggest generic Mirai
        if not detected:
            generic_markers = ["mirai", "dvrhelper", "busybox mirai", "telnet brute"]
            for p in payloads:
                if any(m in p.lower() for m in generic_markers):
                    detected = True
                    detected_variant = "Standard Mirai"
                    max_variant_confidence = 0.70

        infection_stage = MiraiDetector.detect_infection_stage(device_ip, traffic)
        
        # Calculate risk scores
        risk_score = 0.0
        if detected:
            risk_score = 50.0 + (max_variant_confidence * 50.0)
        elif infection_stage != "NONE":
            detected = True
            detected_variant = "Standard Mirai (Inferred)"
            risk_score = 45.0
            if infection_stage in ["C2_ESTABLISHED", "PROPAGATING_ATTACK"]:
                risk_score = 80.0

        return {
            "device_ip": device_ip,
            "detected": detected,
            "variant": detected_variant,
            "infection_stage": infection_stage,
            "risk_details": {
                "risk_score": round(risk_score, 2),
                "confidence": round(max_variant_confidence, 2) if detected else 0.0,
                "targets_architecture": any(arch in "".join(payloads).lower() for arch in MiraiDetector.ARCHITECTURE_TARGETS),
                "description": f"Mirai botnet signature matched. Variant: {detected_variant}. Stage: {infection_stage}."
            }
        }

    @staticmethod
    def detect_scanning_activity(src_ip: str, log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes connection attempts to identify typical Mirai SYN scanning.

        Args:
            src_ip: Target source IP
            log: List of connection events:
                 [{'src_ip': str, 'dst_ip': str, 'dst_port': int, 'timestamp': datetime/str, 'status': str}]

        Returns:
            Scanning report
        """
        device_conns = [c for c in log if c.get("src_ip") == src_ip]
        if not device_conns:
            return {
                "scanning_detected": False,
                "scan_rate_per_min": 0.0,
                "scanned_ips": [],
                "scanned_ports": [],
                "confidence": 0.0
            }

        scanned_ips = set()
        scanned_ports = set()
        mirai_port_hits = 0
        total_attempts = len(device_conns)

        for conn in device_conns:
            dst_ip = conn.get("dst_ip")
            dst_port = conn.get("dst_port")
            if dst_ip:
                scanned_ips.add(dst_ip)
            if dst_port:
                scanned_ports.add(dst_port)
                if dst_port in MiraiDetector.SCANNER_PORTS:
                    mirai_port_hits += 1

        # Calculate scan rate: let's assume log spans 1 minute if timestamps aren't detailed,
        # or calculate differences between timestamps
        scan_rate = len(device_conns)  # default

        # Logic: hitting many different IPs on ports 23/2323
        detected = False
        confidence = 0.0

        unique_ips_count = len(scanned_ips)
        mirai_port_ratio = mirai_port_hits / total_attempts if total_attempts > 0 else 0.0

        if unique_ips_count >= 5 and mirai_port_ratio >= 0.5:
            detected = True
            confidence = min(0.99, 0.4 + (unique_ips_count / 30.0) + (mirai_port_ratio * 0.3))

        return {
            "scanning_detected": detected,
            "scan_rate_per_min": round(scan_rate, 2),
            "scanned_ips": sorted(list(scanned_ips)),
            "scanned_ports": sorted(list(scanned_ports)),
            "confidence": round(confidence, 2) if detected else 0.0
        }

    @staticmethod
    def detect_c2_communication(device_ip: str, dns_log: List[Dict[str, Any]], conn_log: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes connection log and DNS lookups to find active C2 interactions.

        Args:
            device_ip: Target source device IP
            dns_log: [{device_ip, query, timestamp}]
            conn_log: [{src_ip, dst_ip, dst_port, timestamp}]
        """
        resolved_domains = []
        c2_conns = []
        confidence = 0.0

        # Check DNS logs
        for entry in dns_log:
            if entry.get("device_ip") == device_ip:
                query = entry.get("query", "")
                # Check against standard indicators
                for indicator in MiraiDetector.C2_INDICATORS:
                    if indicator in query.lower():
                        resolved_domains.append(query)
                        confidence = max(confidence, 0.70)

        # Check Connection logs
        for entry in conn_log:
            if entry.get("src_ip") == device_ip:
                dst_ip = entry.get("dst_ip")
                dst_port = entry.get("dst_port")

                # Connections to port 101 or 48101 (common Mirai C2/Report receiver ports)
                if dst_port in [101, 48101]:
                    c2_conns.append(entry)
                    confidence = max(confidence, 0.85)

                # Connections to known C2 IPs
                if dst_ip in MiraiDetector.C2_INDICATORS:
                    c2_conns.append(entry)
                    confidence = max(confidence, 0.90)

        c2_detected = len(resolved_domains) > 0 or len(c2_conns) > 0

        return {
            "c2_detected": c2_detected,
            "resolved_c2_domains": list(set(resolved_domains)),
            "active_c2_connections": c2_conns,
            "confidence": round(confidence, 2) if c2_detected else 0.0
        }

    @staticmethod
    def detect_infection_stage(device_ip: str, traffic: Dict[str, Any]) -> str:
        """
        Identifies the current progression of a Mirai lifecycle infection.
        Stages: RECON, EXPLOITATION, C2_ESTABLISHED, PROPAGATING_ATTACK, NONE
        """
        ports_used = traffic.get("ports_used", [])
        payloads = traffic.get("payloads", [])
        dns_queries = traffic.get("dns_queries", [])
        conn_rate = traffic.get("connection_rate", 0)

        # 1. PROPAGATING_ATTACK: Massive scans + SSH/Telnet default cred payloads
        is_scanning = any(p in ports_used for p in [23, 2323])
        has_cred_payloads = any("root" in p.lower() or "admin" in p.lower() for p in payloads)
        if is_scanning and conn_rate > 30:
            return "PROPAGATING_ATTACK"

        # 2. C2_ESTABLISHED: Resolved domain or connected to report ports
        has_c2_dns = any(any(ind in q.lower() for ind in MiraiDetector.C2_INDICATORS) for q in dns_queries)
        has_c2_ports = any(p in [101, 48101] for p in ports_used)
        if has_c2_dns or has_c2_ports:
            return "C2_ESTABLISHED"

        # 3. EXPLOITATION: heavy payload downloading targeting local system shell commands
        tftp_wget_markers = ["wget ", "tftp ", "chmod +x", "elf", ".arm", ".mips", ".x86"]
        payloads_str = "".join(payloads).lower()
        if any(m in payloads_str for m in tftp_wget_markers):
            return "EXPLOITATION"

        # 4. RECON: Port scan targeting typical Telnet or exploit ports without login payloads
        if any(p in ports_used for p in MiraiDetector.SCANNER_PORTS):
            return "RECON"

        return "NONE"

    @staticmethod
    def estimate_botnet_size(c2_conns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Correlates global connections to evaluate the extent of the active Mirai network.

        Args:
            c2_conns: List of active connections matching C2 markers from ALL monitored devices:
                      [{'src_ip': str, 'dst_ip': str, 'dst_port': int}]

        Returns:
            Dictionary containing estimated botnet size metrics.
        """
        c2_to_bots = defaultdict(set)
        
        for conn in c2_conns:
            src = conn.get("src_ip")
            dst = conn.get("dst_ip")
            if src and dst:
                c2_to_bots[dst].add(src)

        bots_per_c2 = {}
        total_unique_bots = set()
        active_c2_servers = []

        for c2, bots in c2_to_bots.items():
            bots_per_c2[c2] = len(bots)
            total_unique_bots.update(bots)
            active_c2_servers.append(c2)

        estimated_size = len(total_unique_bots)
        
        # We can extrapolate the size. If we see N bots in our localized network segment,
        # we can estimate standard global subnet sizes (e.g. multiplied by scaling factors),
        # but in a localized context, we report the local botnet count.
        confidence = 0.5
        if estimated_size > 0:
            confidence = min(0.95, 0.5 + (estimated_size * 0.05))

        return {
            "estimated_size": estimated_size,
            "active_c2_servers": active_c2_servers,
            "bots_per_c2": bots_per_c2,
            "confidence": round(confidence, 2),
            "explanation": f"Detected {estimated_size} local bots communicating with {len(active_c2_servers)} C2 servers."
        }
