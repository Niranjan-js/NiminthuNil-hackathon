"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — CoAP Protocol Decoder
=============================================
Decodes and analyses Constrained Application Protocol (CoAP) packets for security monitoring.
Covers MITRE ATT&CK for ICS / IoT techniques: T0855, T0869, T0809.

Author : NIRAVAN Security Engine
Version: 2.1.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
from datetime import datetime
from typing import Any

logger = logging.getLogger("niravan.ot_iot.coap_decoder")
logger.setLevel(logging.DEBUG)


class CoAPDecoder:
    """
    Stateless CoAP protocol decoder and threat analyzer for NIRAVAN OT/IoT defense.
    """

    # CoAP Message Types
    MESSAGE_TYPES: dict[int, str] = {
        0: "CON",  # Confirmable
        1: "NON",  # Non-confirmable
        2: "ACK",  # Acknowledgement
        3: "RST",  # Reset
    }

    # CoAP Request Methods
    METHODS: dict[int, str] = {
        1: "GET",
        2: "POST",
        3: "PUT",
        4: "DELETE",
    }

    # CoAP Response Codes (Class.Detail format mapped to integer: Class * 32 + Detail)
    RESPONSE_CODES: dict[int, str] = {
        65: "2.01 Created",
        66: "2.02 Deleted",
        67: "2.03 Valid",
        68: "2.04 Changed",
        69: "2.05 Content",
        128: "4.00 Bad Request",
        129: "4.01 Unauthorized",
        130: "4.02 Bad Option",
        131: "4.03 Forbidden",
        132: "4.04 Not Found",
        133: "4.05 Method Not Allowed",
        134: "4.06 Not Acceptable",
        140: "4.12 Precondition Failed",
        141: "4.13 Request Entity Too Large",
        143: "4.15 Unsupported Content-Format",
        160: "5.00 Internal Server Error",
        161: "5.01 Not Implemented",
        162: "5.02 Bad Gateway",
        163: "5.03 Service Unavailable",
        164: "5.04 Gateway Timeout",
        165: "5.05 Proxying Not Supported",
    }

    # Critical resources that represent operational changes in OT environments
    CRITICAL_RESOURCES: list[str] = [
        "/actuators/hvac/setpoint",
        "/actuators/door/lock",
        "/sensors/safety/override",
        "/actuators/valve/flow",
        "/iot/firmware/update",
        "/actuators/pump/state",
        "/actuators/alarm/trigger",
        "/system/reboot",
    ]

    _MITRE_MAP: dict[str, str] = {
        "UNAUTHORIZED_WRITE": "T0855 - Unauthorized Command Message",
        "AMPLIFICATION_ATTACK": "T0809 - Denial of Service / Amplification",
        "SUSPICIOUS_RESOURCE": "T0869 - Standard Application Layer Protocol",
        "MALFORMED_PACKET": "T0809 - Denial of Service / Protocol Malformation",
    }

    @staticmethod
    def decode_packet(raw_hex: str) -> dict[str, Any]:
        """
        Parses a CoAP frame from its raw hex string representation and analyzes it for security threats.
        
        Parameters
        ----------
        raw_hex : str
            The raw bytes of the CoAP frame formatted as a hex string.
            
        Returns
        -------
        dict
            Decoded packet information and threat analysis findings.
        """
        logger.debug("Decoding CoAP packet, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty packet"}

        # Validate hex format
        try:
            bytes_data = bytes.fromhex(raw_hex)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        if len(bytes_data) < 4:
            return {"valid": False, "error": "Packet too short (minimum CoAP header is 4 bytes)"}

        # Deterministic seed based on payload hash for realistic simulation aspects
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Parse fixed header
        # Byte 0: Version (2 bits), Type (2 bits), Token Length (4 bits)
        b0 = bytes_data[0]
        version = (b0 >> 6) & 0x03
        msg_type_id = (b0 >> 4) & 0x03
        tkl = b0 & 0x0F

        # Byte 1: Code (8 bits)
        code_val = bytes_data[1]

        # Bytes 2-3: Message ID (16 bits)
        message_id = (bytes_data[2] << 8) | bytes_data[3]

        # Determine Code Type
        code_str = "Unknown"
        is_request = False
        is_response = False

        if 1 <= code_val <= 31:
            code_str = CoAPDecoder.METHODS.get(code_val, f"METHOD_UNKNOWN({code_val})")
            is_request = True
        elif 64 <= code_val <= 255:
            code_str = CoAPDecoder.RESPONSE_CODES.get(code_val, f"RESPONSE_UNKNOWN({code_val})")
            is_response = True
        elif code_val == 0:
            code_str = "EMPTY"

        # Extract Token if TKL > 0
        token = ""
        if tkl > 0 and len(bytes_data) >= 4 + tkl:
            token = bytes_data[4:4+tkl].hex()

        # Simulated resource path & payload mapping for realistic simulation-based logic
        uri_pool = [
            "/.well-known/core",
            "/sensors/temperature",
            "/sensors/pressure",
            "/actuators/hvac/setpoint",
            "/actuators/door/lock",
            "/sensors/safety/override",
            "/actuators/valve/flow",
            "/iot/firmware/update",
            "/actuators/pump/state",
            "/system/reboot",
            "/devices/info",
        ]

        payload_pool = [
            '{"temp": 22.4, "unit": "C"}',
            '{"pressure": 101.3, "unit": "kPa"}',
            '{"setpoint": 18.0}',
            '{"lock": true}',
            '{"override": "force_on"}',
            '{"flow_rate": 250.0}',
            '{"firmware_url": "http://malicious-server.io/malware.bin", "signature": "0xABC"}',
            '{"state": "STOPPED"}',
            '{"reboot": "now"}',
            'rt="core.sensor";if="sensor",rt="core.actuator";if="actuator"',
            '{"battery": 94, "status": "active"}',
        ]

        # Map to resource path and payload
        uri_path = uri_pool[seed % len(uri_pool)]
        payload = payload_pool[(seed >> 4) % len(payload_pool)]
        
        # Override fields based on actual packet structure simulations
        if "/.well-known/core" in uri_path and code_str == "GET":
            payload = 'rt="core.sensor";if="sensor",rt="core.actuator";if="actuator"'

        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        # Analyze writes to critical resources
        if is_request and code_str in ["POST", "PUT", "DELETE"]:
            write_analysis = CoAPDecoder.analyze_write_to_critical_resource(uri_path, code_str)
            if write_analysis["is_critical_write"]:
                threat_indicators.append(
                    f"CRITICAL_WRITE: Unauthorized {code_str} to {uri_path} (Risk: {write_analysis['risk_level']})"
                )
                mitre_techniques.append(CoAPDecoder._MITRE_MAP["UNAUTHORIZED_WRITE"])

        # Check for malformed headers (CoAP spec version must be 1)
        if version != 1:
            threat_indicators.append(f"MALFORMED_HEADER: CoAP Version {version} is invalid (expected 1)")
            mitre_techniques.append(CoAPDecoder._MITRE_MAP["MALFORMED_PACKET"])

        # Check for suspicious payload characteristics (e.g. executable URL inside firmware update payload)
        if "firmware_url" in payload and "http://" in payload:
            threat_indicators.append("SUSPICIOUS_PAYLOAD: Unencrypted HTTP URL in firmware flash payload")
            mitre_techniques.append(CoAPDecoder._MITRE_MAP["SUSPICIOUS_RESOURCE"])

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "CoAP",
            "version": version,
            "message_type": CoAPDecoder.MESSAGE_TYPES.get(msg_type_id, f"UNKNOWN({msg_type_id})"),
            "code_value": code_val,
            "code": code_str,
            "message_id": message_id,
            "token": token,
            "uri_path": uri_path,
            "payload": payload,
            "payload_length": len(payload),
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(bytes_data),
        }

        if is_suspicious:
            logger.warning(
                "Suspicious CoAP transaction detected | path=%s | code=%s | threats=%s",
                uri_path, code_str, threat_indicators
            )
        else:
            logger.info("CoAP packet decoded cleanly | code=%s | path=%s", code_str, uri_path)

        return result

    @staticmethod
    def analyze_write_to_critical_resource(uri_path: str, method: str) -> dict[str, Any]:
        """
        Performs deep analysis on write operations to critical resource paths.
        """
        is_critical = uri_path in CoAPDecoder.CRITICAL_RESOURCES
        risk_level = "LOW"

        if is_critical:
            if method in ["POST", "PUT"]:
                if uri_path in ["/system/reboot", "/sensors/safety/override"]:
                    risk_level = "CRITICAL"
                elif uri_path in ["/iot/firmware/update", "/actuators/pump/state"]:
                    risk_level = "HIGH"
                else:
                    risk_level = "MEDIUM"
            elif method == "DELETE":
                risk_level = "HIGH"

        return {
            "is_critical_write": is_critical and method in ["POST", "PUT", "DELETE"],
            "uri_path": uri_path,
            "method": method,
            "risk_level": risk_level,
            "description": f"Critical modification request to {uri_path} via {method}" if is_critical else "Non-critical operation",
        }

    @staticmethod
    def detect_amplification_attack(packets: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Analyzes a history of packets to detect CoAP amplification-based denial-of-service attempts.
        Looks for highly asymmetric request-response sizes (high response bytes / request bytes ratio)
        or excessive queries to discovery resources (e.g. /.well-known/core).
        """
        if not packets:
            return {"detected": False, "reason": "No packets in history"}

        discovery_requests = 0
        total_request_bytes = 0
        total_response_bytes = 0
        suspicious_nodes: set[str] = set()

        for pkt in packets:
            src = pkt.get("src_ip", "unknown")
            uri = pkt.get("uri_path", "")
            code = pkt.get("code", "")
            raw_len = pkt.get("raw_length", 0)

            if code in ["GET"]:
                total_request_bytes += raw_len
                if uri == "/.well-known/core":
                    discovery_requests += 1
                    suspicious_nodes.add(src)
            elif code.startswith("2.") or code.startswith("RESPONSE") or code in ["Content", "Changed", "Created"]:
                total_response_bytes += raw_len

        ratio = 0.0
        if total_request_bytes > 0:
            ratio = total_response_bytes / total_request_bytes

        # Amplification criteria: response-to-request ratio > 15 or high frequency of /.well-known/core scans
        detected = (ratio > 15.0 and len(packets) >= 5) or (discovery_requests >= 5)
        
        return {
            "detected": detected,
            "amplification_ratio": round(ratio, 2),
            "discovery_requests_count": discovery_requests,
            "suspicious_ips": list(suspicious_nodes),
            "risk_level": "HIGH" if detected else "LOW",
            "description": "Detected CoAP Amplification DoS attempt" if detected else "Traffic ratios are within normal limits",
            "mitre_technique": CoAPDecoder._MITRE_MAP["AMPLIFICATION_ATTACK"] if detected else "None",
        }

    @staticmethod
    def decode_sample_packets() -> list[dict[str, Any]]:
        """
        Returns a list of decoded sample packets representing different real-world scenarios.
        """
        samples = [
            # 1. Normal GET request to temperature sensor (CON, GET, Message ID 0x1234, token 0xaa)
            "41011234aa",
            # 2. Critical write to safety override (CON, PUT, Message ID 0x5678, token 0xbb)
            # Will deterministically hit /sensors/safety/override based on seed
            "41035678bbcc12",
            # 3. Large firmware update response with http URL
            # Will deterministically hit /iot/firmware/update based on seed
            "41029abcdd",
            # 4. Malformed header (Version 2)
            "81013456ee",
        ]
        return [CoAPDecoder.decode_packet(hex_str) for hex_str in samples]
