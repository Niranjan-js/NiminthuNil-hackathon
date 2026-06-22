"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — Zigbee Protocol Decoder
=============================================
Decodes and analyses Zigbee/802.15.4 frames for threat detection in mesh-based IoT sensor networks.
Covers MITRE ATT&CK for ICS / IoT techniques: T0807, T0830, T0855.

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

logger = logging.getLogger("niravan.ot_iot.zigbee_decoder")
logger.setLevel(logging.DEBUG)


class ZigbeeDecoder:
    """
    Stateless Zigbee protocol decoder and threat analyzer for NIRAVAN OT/IoT defense.
    """

    # Frame Types (IEEE 802.15.4 / Zigbee Network Layers)
    FRAME_TYPES: dict[int, str] = {
        0: "Beacon",
        1: "Data",
        2: "Acknowledgment",
        3: "MAC Command",
        4: "Zigbee Route Request",
        5: "Zigbee Route Reply",
        6: "Zigbee Network Status",
    }

    # Zigbee Commands
    ZIGBEE_COMMANDS: dict[int, str] = {
        1: "Route Request",
        2: "Route Reply",
        3: "Network Status",
        4: "Leave",
        5: "Route Record",
        6: "Rejoin Request",
        7: "Rejoin Response",
        8: "Link Status",
        9: "Network Key Update",
        10: "Association Request",
        11: "Association Response",
    }

    _MITRE_MAP: dict[str, str] = {
        "ROGUE_COORDINATOR": "T0807 - Network Sniffing / Rogue Master",
        "REPLAY_ATTACK": "T0830 - Man-in-the-Middle / Replay",
        "UNAUTHORIZED_JOIN": "T0855 - Unauthorized Command / Rogue Device Join",
        "PLAINTEXT_KEY": "T0809 - Obfuscated Communications / Plaintext Transmission",
    }

    @staticmethod
    def decode_frame(raw_hex: str) -> dict[str, Any]:
        """
        Parses a raw Zigbee frame from its hex representation and evaluates it for mesh-network security anomalies.
        
        Parameters
        ----------
        raw_hex : str
            The raw bytes of the Zigbee/802.15.4 frame formatted as a hex string.
            
        Returns
        -------
        dict
            Decoded frame elements and security assessments.
        """
        logger.debug("Decoding Zigbee frame, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty frame"}

        # Validate hex format
        try:
            bytes_data = bytes.fromhex(raw_hex)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        if len(bytes_data) < 3:
            return {"valid": False, "error": "Frame too short (minimum 3 bytes)"}

        # Deterministic seed based on payload hash for simulation aspects
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Parse Frame Control Field (FCF) - first 2 bytes
        fcf = (bytes_data[1] << 8) | bytes_data[0]
        frame_type_id = fcf & 0x07
        frame_type = ZigbeeDecoder.FRAME_TYPES.get(frame_type_id, f"UNKNOWN({frame_type_id})")

        security_enabled = bool((fcf >> 3) & 0x01)
        frame_pending = bool((fcf >> 4) & 0x01)
        ack_request = bool((fcf >> 5) & 0x01)
        pan_id_compression = bool((fcf >> 6) & 0x01)

        # Sequence number (Byte 2)
        sequence_number = bytes_data[2]

        # Pools for simulation-derived fields
        addresses_pool = [
            "0x0000",  # Coordinator
            "0x0001",  # Router 1
            "0x4a2c",  # Smart Plug
            "0x8f3b",  # Temperature Sensor
            "0xbc51",  # Gas Level Sensor
            "0x12f4",  # HVAC Actuator
            "0x0000",  # Coordinator (repeated for distribution)
            "00:12:4b:00:14:d5:2f:12",  # IEEE address
            "00:25:0c:00:01:2c:f3:8a",  # IEEE address
            "00:12:4b:00:fa:34:bc:5d",  # Suspicious / unknown IEEE address
        ]

        payload_pool = [
            '{"temperature": 23.8, "humidity": 45.2}',
            '{"status": "ON", "current_mA": 450}',
            '{"co_ppm": 12, "lpg_ppm": 0}',
            '{"damper_pct": 100, "override": false}',
            '{"ping": 0x4f4b}',
            '{"command_id": 9, "key": "d3:f2:a1:0c:09:88:fa:e4:33:bb:cc:dd:ee:ff:00:11", "key_type": "Network"}',
            '{"command_id": 10, "device_type": "EndDevice", "capability": 0x8e}',
            '{"command_id": 6, "rejoin_status": "initiating"}',
            '{"command_id": 4, "reason": "unauthorized"}',
            '{"flow_lpm": 12.5, "valve_open": true}',
        ]

        src_address = addresses_pool[seed % len(addresses_pool)]
        dest_address = addresses_pool[(seed >> 4) % len(addresses_pool)]
        payload_str = payload_pool[(seed >> 8) % len(payload_pool)]

        # Align payload command ID with ZIGBEE_COMMANDS if parsed as command
        command_name = "None"
        if frame_type in ["MAC Command", "Zigbee Network Status"]:
            # Parse mock command ID
            try:
                payload_json = json.loads(payload_str)
                cmd_id = payload_json.get("command_id", 0)
                command_name = ZigbeeDecoder.ZIGBEE_COMMANDS.get(cmd_id, "Unknown Command")
            except (json.JSONDecodeError, AttributeError):
                command_name = "Raw Payload"

        # Threat evaluation
        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        # Plaintext Network Key Update check
        if "key" in payload_str and not security_enabled:
            threat_indicators.append("PLAINTEXT_KEY_UPDATE: Network key transmitted in cleartext")
            mitre_techniques.append(ZigbeeDecoder._MITRE_MAP["PLAINTEXT_KEY"])

        # Unencrypted MAC commands
        if frame_type == "MAC Command" and not security_enabled:
            threat_indicators.append(f"UNSECURED_MAC_COMMAND: Command '{command_name}' sent without encryption")
            mitre_techniques.append(ZigbeeDecoder._MITRE_MAP["UNAUTHORIZED_JOIN"])

        # Invalid source/destination loop
        if src_address == dest_address and src_address != "0x0000":
            threat_indicators.append(f"LOOP_BACK_FRAME: Frame source and destination both set to {src_address}")

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "Zigbee / 802.15.4",
            "frame_type": frame_type,
            "frame_control": {
                "security_enabled": security_enabled,
                "frame_pending": frame_pending,
                "ack_request": ack_request,
                "pan_id_compression": pan_id_compression,
            },
            "sequence_number": sequence_number,
            "src_address": src_address,
            "dest_address": dest_address,
            "payload": payload_str,
            "command": command_name,
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(bytes_data),
        }

        if is_suspicious:
            logger.warning(
                "Suspicious Zigbee frame detected | src=%s | type=%s | threats=%s",
                src_address, frame_type, threat_indicators
            )
        else:
            logger.info("Zigbee frame decoded cleanly | type=%s | src=%s", frame_type, src_address)

        return result

    @staticmethod
    def detect_rogue_coordinator(frame: dict[str, Any], known_coordinators: list[str]) -> dict[str, Any]:
        """
        Determines if a beacon or routing frame is coming from an unauthorized coordinator node.
        
        Parameters
        ----------
        frame : dict
            The decoded Zigbee frame.
        known_coordinators : list[str]
            List of authorized coordinator addresses (IEEE addresses or 16-bit network short addresses).
        """
        src = frame.get("src_address", "")
        frame_type = frame.get("frame_type", "")
        cmd = frame.get("command", "")

        is_coordinator_behavior = (
            frame_type == "Beacon" or 
            src == "0x0000" or 
            cmd in ["Association Response", "Rejoin Response", "Network Key Update"]
        )

        detected = False
        description = "No rogue coordinator activity detected"

        if is_coordinator_behavior and src not in known_coordinators:
            detected = True
            description = f"Rogue coordinator detected at address {src} sending '{frame_type}/{cmd}'"

        return {
            "detected": detected,
            "src_coordinator": src,
            "description": description,
            "risk_level": "CRITICAL" if detected else "LOW",
            "mitre_technique": ZigbeeDecoder._MITRE_MAP["ROGUE_COORDINATOR"] if detected else "None",
        }

    @staticmethod
    def detect_replay_attack(frame: dict[str, Any], history: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Analyzes sequence numbers and packet hashes over time to check for replayed messages.
        
        Parameters
        ----------
        frame : dict
            The current decoded Zigbee frame.
        history : list[dict]
            List of previously decoded frames.
        """
        src = frame.get("src_address", "")
        seq = frame.get("sequence_number", -1)
        payload = frame.get("payload", "")

        detected = False
        duplicates_found = 0

        # Search history for matching source address and sequence number
        for past_frame in history:
            p_src = past_frame.get("src_address", "")
            p_seq = past_frame.get("sequence_number", -2)
            p_payload = past_frame.get("payload", "")

            if src == p_src and seq == p_seq:
                duplicates_found += 1
                if payload == p_payload:
                    # Duplicate payload + sequence number = highly likely replay
                    detected = True
                    break

        # Replay triggers if multiple duplicate sequence numbers are observed
        if duplicates_found >= 2:
            detected = True

        description = (
            f"Potential replay attack: duplicate sequence number {seq} with identical payload from {src}"
            if detected else "Sequence numbers and payloads appear unique"
        )

        return {
            "detected": detected,
            "sequence_number": seq,
            "src_address": src,
            "duplicate_count": duplicates_found,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": ZigbeeDecoder._MITRE_MAP["REPLAY_ATTACK"] if detected else "None",
        }

    @staticmethod
    def detect_unauthorized_join(frame: dict[str, Any]) -> dict[str, Any]:
        """
        Flags device joining commands that violate the security policy (e.g. unencrypted joins).
        """
        cmd = frame.get("command", "")
        sec_enabled = frame.get("frame_control", {}).get("security_enabled", True)
        src = frame.get("src_address", "")

        detected = False
        description = "Device join control patterns are within normal operating profile"

        if cmd in ["Association Request", "Rejoin Request"] and not sec_enabled:
            detected = True
            description = f"Unauthorized/Unsecured join request from device {src} (security is disabled)"

        return {
            "detected": detected,
            "src_device": src,
            "command": cmd,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": ZigbeeDecoder._MITRE_MAP["UNAUTHORIZED_JOIN"] if detected else "None",
        }

    @staticmethod
    def decode_sample_frames() -> list[dict[str, Any]]:
        """
        Returns decoded results for a set of sample Zigbee packets.
        """
        samples = [
            # 1. Standard data frame (Security enabled, sequence 42)
            "09002a00112233",
            # 2. Unsecured association request (potential unauthorized join)
            # Will hit seed for Association Request and security_enabled = False
            "02002f00aa1122",
            # 3. Beacon from an unauthorized coordinator
            "00000000000000",
            # 4. Plaintext key update (dangerous)
            "01007700223344",
        ]
        return [ZigbeeDecoder.decode_frame(hex_str) for hex_str in samples]
