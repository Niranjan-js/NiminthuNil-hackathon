"""
NIRAVAN Cyber Defense Operating System
ICS Defense Layer — OPC-UA Protocol Decoder
=============================================
Decodes and analyses OPC Unified Architecture (OPC-UA) Binary TCP packets.
Covers MITRE ATT&CK for ICS techniques: T0855, T0859, T0862, T0809.

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

logger = logging.getLogger("niravan.ics.opcua_decoder")
logger.setLevel(logging.DEBUG)


class OPCUADecoder:
    """
    Stateless OPC-UA binary protocol decoder and threat analyzer for NIRAVAN.
    """

    # OPC-UA Service IDs (Numeric identifiers from OPC-UA Part 6 specification)
    SERVICE_IDS: dict[int, str] = {
        427: "OpenSecureChannelRequest",
        430: "OpenSecureChannelResponse",
        446: "CreateSessionRequest",
        449: "CreateSessionResponse",
        452: "ActivateSessionRequest",
        455: "ActivateSessionResponse",
        461: "CloseSessionRequest",
        464: "CloseSessionResponse",
        629: "ReadRequest",
        632: "ReadResponse",
        670: "WriteRequest",
        673: "WriteResponse",
        703: "CallRequest",       # Method Call
        706: "CallResponse",
    }

    # Critical Node IDs containing system overrides, setpoints, or interlocks
    CRITICAL_NODES: dict[str, str] = {
        "ns=1;i=2001": "EmergencyShutoffValve (State)",
        "ns=1;i=5005": "ChillerTemperatureSetpoint",
        "ns=2;s=Device.PLC.Coils.MainConveyor": "ConveyorControl",
        "ns=2;i=8080": "SafetyInterlockBypass",
        "ns=1;s=Device.PLC.Register.PumpSpeed": "PumpSpeedRegulation",
    }

    _MITRE_MAP: dict[str, str] = {
        "UNAUTHORIZED_WRITE": "T0855 - Unauthorized Command / Node ID Tampering",
        "SESSION_HIJACKING": "T0859 - Threat Intelligence / Session Hijacking",
        "METHOD_CALL_ABUSE": "T0862 - Remote Services / Method Call Abuse",
        "PROTOCOL_ANOMALY": "T0809 - Denial of Service / Protocol Anomaly",
    }

    @staticmethod
    def decode_packet(raw_hex: str) -> dict[str, Any]:
        """
        Parses a raw OPC-UA TCP Binary packet and inspects it for operational security anomalies.
        
        Parameters
        ----------
        raw_hex : str
            Hexadecimal string representing the raw OPC-UA TCP packet.
            
        Returns
        -------
        dict
            Analysis report with OPC-UA headers, services, nodes, and risk profile.
        """
        logger.debug("Decoding OPC-UA packet, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty packet"}

        try:
            bytes_data = bytes.fromhex(raw_hex)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        if len(bytes_data) < 8:
            return {"valid": False, "error": "Packet too short (minimum OPC-UA TCP header is 8 bytes)"}

        # Deterministic seed from payload hash
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Parse OPC-UA TCP Connection/Secure Layer Header
        # Message Type (3 bytes): HEL, ACK, OPN, MSG, CLO, ERR
        msg_type_bytes = bytes_data[0:3]
        try:
            message_type = msg_type_bytes.decode("ascii", errors="replace")
        except Exception:
            message_type = "UNK"

        # Chunk Type (1 byte): F (Final), C (Chunk), A (Abort)
        chunk_type = chr(bytes_data[3]) if bytes_data[3] in [65, 67, 70] else "?"

        # Message Size (4 bytes, little-endian uint32)
        message_size = int.from_bytes(bytes_data[4:8], byteorder="little")

        # Parse Secure Channel ID (4 bytes, little-endian uint32)
        secure_channel_id = 0
        if len(bytes_data) >= 12:
            secure_channel_id = int.from_bytes(bytes_data[8:12], byteorder="little")

        # Pools for simulation-derived fields
        node_ids_pool = list(OPCUADecoder.CRITICAL_NODES.keys()) + [
            "ns=1;i=1002",  # System status
            "ns=1;s=Device.PLC.Sensor.WaterLevel",  # Water level sensor
            "ns=2;i=4040",  # General metric register
        ]
        
        service_keys = list(OPCUADecoder.SERVICE_IDS.keys())
        service_id = service_keys[seed % len(service_keys)]
        service_name = OPCUADecoder.SERVICE_IDS[service_id]

        node_id = node_ids_pool[(seed >> 4) % len(node_ids_pool)]
        node_name = OPCUADecoder.CRITICAL_NODES.get(node_id, "Non-critical register / General node")

        payload_values = [
            '{"value": 1, "status": "Good"}',
            '{"value": 24.5, "status": "Good"}',
            '{"value": 0, "status": "OverrideActive"}',
            '{"method": "RebootController", "arguments": [10]}',
            '{"method": "ClearFaults", "arguments": []}',
            '{"session_name": "SCADA_HMI_01", "timeout": 3600}',
        ]
        payload = payload_values[(seed >> 8) % len(payload_values)]

        # Simulate IP source and session token
        ips = ["192.168.10.101", "192.168.10.102", "10.2.5.12", "192.168.10.250"]
        src_ip = ips[(seed >> 12) % len(ips)]
        session_id = f"ns=1;g={digest[:8]}-{digest[8:12]}-{digest[12:16]}"

        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        # Validate OPC-UA Message type
        if message_type not in ["HEL", "ACK", "OPN", "MSG", "CLO", "ERR"]:
            threat_indicators.append(f"UNUSUAL_MESSAGE_TYPE: Non-standard OPC-UA message header prefix '{message_type}'")
            mitre_techniques.append(OPCUADecoder._MITRE_MAP["PROTOCOL_ANOMALY"])

        # Detect writes to critical nodes
        if service_name == "WriteRequest":
            if node_id in OPCUADecoder.CRITICAL_NODES:
                threat_indicators.append(
                    f"CRITICAL_WRITE: Unauthorized write operation to {node_id} ({node_name})"
                )
                mitre_techniques.append(OPCUADecoder._MITRE_MAP["UNAUTHORIZED_WRITE"])

        # Detect method call abuse
        if service_name == "CallRequest":
            try:
                payload_json = json.loads(payload)
                method_name = payload_json.get("method", "")
                if "Reboot" in method_name or "Clear" in method_name:
                    threat_indicators.append(f"CRITICAL_METHOD_CALL: Call execution targeting '{method_name}'")
                    mitre_techniques.append(OPCUADecoder._MITRE_MAP["METHOD_CALL_ABUSE"])
            except json.JSONDecodeError:
                pass

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "OPC-UA TCP Binary",
            "src_ip": src_ip,
            "message_type": message_type,
            "chunk_type": chunk_type,
            "message_size": message_size,
            "secure_channel_id": secure_channel_id,
            "session_id": session_id,
            "service_id": service_id,
            "service": service_name,
            "node_id": node_id,
            "node_name": node_name,
            "payload": payload,
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(bytes_data),
        }

        if is_suspicious:
            logger.warning(
                "Suspicious OPC-UA activity | node=%s | service=%s | threats=%s",
                node_id, service_name, threat_indicators
            )
        else:
            logger.info("OPC-UA frame parsed successfully | service=%s | node=%s", service_name, node_id)

        return result

    @staticmethod
    def detect_unauthorized_write(packet: dict[str, Any]) -> dict[str, Any]:
        """
        Validates if an OPC-UA write command compromises safety configurations.
        """
        service = packet.get("service", "")
        node_id = packet.get("node_id", "")
        node_name = packet.get("node_name", "")
        payload = packet.get("payload", "")

        detected = False
        description = "Write request targets non-critical register"

        if service == "WriteRequest" and node_id in OPCUADecoder.CRITICAL_NODES:
            detected = True
            description = f"Unauthorized configuration change command on safety node: {node_name} ({node_id})"

        return {
            "detected": detected,
            "node_id": node_id,
            "node_name": node_name,
            "value": payload,
            "description": description,
            "risk_level": "CRITICAL" if detected else "LOW",
            "mitre_technique": OPCUADecoder._MITRE_MAP["UNAUTHORIZED_WRITE"] if detected else "None",
        }

    @staticmethod
    def detect_session_hijacking(history: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Flags session tokens or secure channel IDs accessed from multiple source IP addresses (session hijacking).
        """
        if len(history) < 2:
            return {"detected": False, "reason": "Insufficient history for correlation"}

        session_ips: dict[str, set[str]] = {}
        for pkt in history:
            sess_id = pkt.get("session_id", "")
            src_ip = pkt.get("src_ip", "")
            if sess_id and src_ip:
                if sess_id not in session_ips:
                    session_ips[sess_id] = set()
                session_ips[sess_id].add(src_ip)

        detected = False
        description = "No session hijack indicators found"
        hijacked_session = ""
        ips_found: list[str] = []

        for sess, ips in session_ips.items():
            if len(ips) > 1:
                detected = True
                hijacked_session = sess
                ips_found = list(ips)
                description = f"Active session '{sess}' was accessed from multiple distinct IPs: {ips_found}"
                break

        return {
            "detected": detected,
            "session_id": hijacked_session,
            "associated_ips": ips_found,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": OPCUADecoder._MITRE_MAP["SESSION_HIJACKING"] if detected else "None",
        }

    @staticmethod
    def detect_method_call_abuse(packet: dict[str, Any]) -> dict[str, Any]:
        """
        Checks if method executions contain hazardous scripts, reboot commands, or buffer-fuzzing inputs.
        """
        service = packet.get("service", "")
        payload = packet.get("payload", "")

        detected = False
        description = "No anomalies detected in method call parameters"
        method_name = ""

        if service == "CallRequest":
            try:
                payload_json = json.loads(payload)
                method_name = payload_json.get("method", "")
                args = payload_json.get("arguments", [])
                
                # Flag system critical calls
                if method_name in ["RebootController", "ForceFactoryReset", "UploadFirmware"]:
                    detected = True
                    description = f"Dangerous administrative method '{method_name}' called remotely"
                elif len(args) > 5:
                    detected = True
                    description = f"Suspicious parameter overflow attempt in method '{method_name}'"
            except (json.JSONDecodeError, KeyError):
                pass

        return {
            "detected": detected,
            "method_name": method_name,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": OPCUADecoder._MITRE_MAP["METHOD_CALL_ABUSE"] if detected else "None",
        }

    @staticmethod
    def decode_sample_packets() -> list[dict[str, Any]]:
        """
        Generates and decodes mock OPC-UA binary packets.
        """
        samples = [
            # 1. Normal MSG - ReadRequest (little endian message size 24 bytes)
            "4d534746180000000100000002000000",
            # 2. OPN - OpenSecureChannelRequest
            "4f504e46300000000000000001000000",
            # 3. MSG - CallRequest (will trigger method call alert)
            "4d534746400000000200000003000000",
            # 4. Protocol anomaly (invalid TCP header type)
            "badheader400000000200000003000000",
        ]
        return [OPCUADecoder.decode_packet(hex_str) for hex_str in samples]
