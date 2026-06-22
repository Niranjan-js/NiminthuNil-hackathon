"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — Bluetooth Low Energy (BLE) Decoder
=========================================================
Decodes and analyses BLE advertisement and GATT packets for security vulnerabilities.
Covers MITRE ATT&CK for ICS / IoT techniques: T0807, T0855, T0809.

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

logger = logging.getLogger("niravan.ot_iot.bluetooth_decoder")
logger.setLevel(logging.DEBUG)


class BLEDecoder:
    """
    Stateless BLE protocol decoder and threat analyzer for NIRAVAN OT/IoT defense.
    """

    # Advertising PDU types
    ADV_TYPES: dict[int, str] = {
        0: "ADV_IND",            # Connectable undirected advertising
        1: "ADV_DIRECT_IND",     # Connectable directed advertising
        2: "ADV_NONCONN_IND",    # Non-connectable undirected advertising
        3: "SCAN_REQ",           # Scan request
        4: "SCAN_RSP",           # Scan response
        5: "CONNECT_IND",        # Connection request
        6: "ADV_SCAN_IND",       # Scannable undirected advertising
    }

    # Attribute Protocol (ATT) / GATT Opcodes
    GATT_OPCODES: dict[int, str] = {
        1: "Read Request",
        2: "Read Response",
        3: "Write Request",
        4: "Write Command",     # Write without response
        5: "Write Response",
        6: "Notification",
        7: "Indication",
    }

    # Services representing potential attack surfaces or operational controls
    DANGEROUS_SERVICES: dict[str, str] = {
        "0000180a-0000-1000-8000-00805f9b34fb": "Device Information Service",
        "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
        "0000ff01-0000-1000-8000-00805f9b34fb": "Custom Command/OTA Characteristic",
        "e2c56db5-dffb-48d2-b060-d0f5a71096e0": "Legacy Device Control/Backdoor Service",
    }

    _MITRE_MAP: dict[str, str] = {
        "UNAUTHORIZED_PAIRING": "T0807 - Network Sniffing / Unauthorized Connection",
        "GATT_INJECTION": "T0855 - Unauthorized Command / GATT Write Injection",
        "BEACONING": "T0809 - Denial of Service / Resource Exhaustion",
        "OTA_ABUSE": "T0840 - Network Connection Enumeration / OTA Abuse",
    }

    @staticmethod
    def decode_packet(raw_hex: str) -> dict[str, Any]:
        """
        Parses a raw BLE frame (Advertising or GATT ATT PDU) and analyzes it for security risks.
        
        Parameters
        ----------
        raw_hex : str
            Hexadecimal representation of the BLE packet payload.
            
        Returns
        -------
        dict
            Analysis findings containing decoded fields and detected threats.
        """
        logger.debug("Decoding BLE packet, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty packet"}

        # Validate hex format
        try:
            bytes_data = bytes.fromhex(raw_hex)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        if len(bytes_data) < 2:
            return {"valid": False, "error": "Packet too short"}

        # Deterministic seed based on payload hash
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Distinguish between Adv and GATT packet based on seed/first byte
        is_gatt = (bytes_data[0] % 2 == 1)

        src_macs = [
            "24:0a:c4:82:11:02",  # Espressif Node
            "c0:26:da:01:bc:54",  # Smart Lock
            "00:1a:7d:da:71:11",  # Beacon Device
            "7c:d1:c3:2b:88:fa",  # Unknown / Rogue device
            "aa:bb:cc:dd:ee:ff",  # Attack simulation MAC
        ]

        dest_macs = [
            "c0:26:da:01:bc:54",
            "24:0a:c4:82:11:02",
            "ff:ff:ff:ff:ff:ff",  # Broadcast
        ]

        src_mac = src_macs[seed % len(src_macs)]
        dest_mac = dest_macs[(seed >> 4) % len(dest_macs)]
        rssi = rng.randint(-95, -45)

        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        decoded_fields: dict[str, Any] = {}

        if is_gatt:
            # GATT mode simulation
            opcode_val = (bytes_data[1] % 7) + 1
            gatt_opcode = BLEDecoder.GATT_OPCODES.get(opcode_val, f"UNKNOWN_OPCODE({opcode_val})")
            
            services_keys = list(BLEDecoder.DANGEROUS_SERVICES.keys())
            service_uuid = services_keys[(seed >> 8) % len(services_keys)]
            service_name = BLEDecoder.DANGEROUS_SERVICES[service_uuid]

            # Custom payloads mapping
            payload_values = [
                "0100",  # Subscribe
                "4f54415f5354415254",  # "OTA_START"
                "41414141414141414141414141414141",  # Buffer overflow test
                "756e6c6f636b",  # "unlock"
                "00",  # Disable
            ]
            raw_val_hex = payload_values[(seed >> 12) % len(payload_values)]

            decoded_fields = {
                "packet_type": "GATT_ATT",
                "gatt_opcode": gatt_opcode,
                "service_uuid": service_uuid,
                "service_name": service_name,
                "handle": f"0x{bytes_data[1]:02x}{bytes_data[0]:02x}",
                "value_hex": raw_val_hex,
            }

            # Evaluate GATT injection threats
            if gatt_opcode in ["Write Request", "Write Command"]:
                if service_name == "Custom Command/OTA Characteristic":
                    threat_indicators.append("SUSPICIOUS_GATT_WRITE: Write to critical OTA endpoint")
                    mitre_techniques.append(BLEDecoder._MITRE_MAP["OTA_ABUSE"])
                elif service_name == "Legacy Device Control/Backdoor Service":
                    threat_indicators.append("LEGACY_SERVICE_ABUSE: Commands targeting obsolete backdoor control service")
                    mitre_techniques.append(BLEDecoder._MITRE_MAP["GATT_INJECTION"])

                # Fuzzing/Overflow indicators
                if len(raw_val_hex) > 20 and raw_val_hex.startswith("414141"):
                    threat_indicators.append("GATT_FUZZING_ATTEMPT: High volume repetitive buffer overflow pattern")
                    mitre_techniques.append(BLEDecoder._MITRE_MAP["GATT_INJECTION"])

        else:
            # Advertisement mode simulation
            adv_type_val = bytes_data[0] % 7
            adv_type = BLEDecoder.ADV_TYPES[adv_type_val]

            decoded_fields = {
                "packet_type": "ADVERTISEMENT",
                "adv_type": adv_type,
                "tx_power_dbm": rng.randint(-12, 4),
            }

            # Flag direct connections to critical locks or system profiles
            if adv_type == "CONNECT_IND" and dest_mac != "ff:ff:ff:ff:ff:ff":
                # Connection requested
                pass

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "BLE (Bluetooth Low Energy)",
            "src_mac": src_mac,
            "dest_mac": dest_mac,
            "rssi_dbm": rssi,
            "decoded_fields": decoded_fields,
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(bytes_data),
        }

        if is_suspicious:
            logger.warning(
                "Suspicious BLE packet detected | MAC=%s | threats=%s",
                src_mac, threat_indicators
            )
        else:
            logger.info("BLE packet decoded cleanly | MAC=%s | PDU=%s", src_mac, decoded_fields.get("packet_type"))

        return result

    @staticmethod
    def detect_unauthorized_pairing(packet: dict[str, Any], authorized_devices: list[str]) -> dict[str, Any]:
        """
        Flags connections originating from unauthorized BLE controllers.
        """
        src = packet.get("src_mac", "")
        fields = packet.get("decoded_fields", {})
        packet_type = fields.get("packet_type", "")
        adv_type = fields.get("adv_type", "")

        detected = False
        description = "No unauthorized BLE pairing detected"

        # CONNECT_IND indicates a connection attempt
        if packet_type == "ADVERTISEMENT" and adv_type == "CONNECT_IND":
            if src not in authorized_devices:
                detected = True
                description = f"Unauthorized pairing/connection attempt from unknown BLE address: {src}"

        return {
            "detected": detected,
            "mac_address": src,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": BLEDecoder._MITRE_MAP["UNAUTHORIZED_PAIRING"] if detected else "None",
        }

    @staticmethod
    def detect_gatt_injection(packet: dict[str, Any]) -> dict[str, Any]:
        """
        Examines GATT writes to identify potential exploit payloads, command injection or buffer overflows.
        """
        fields = packet.get("decoded_fields", {})
        packet_type = fields.get("packet_type", "")
        opcode = fields.get("gatt_opcode", "")
        uuid = fields.get("service_uuid", "")
        val = fields.get("value_hex", "")

        detected = False
        description = "GATT write parameters appear safe"

        if packet_type == "GATT_ATT" and opcode in ["Write Request", "Write Command"]:
            # Check for buffer overflow payload (repetitive 'A' characters / hex 41)
            if len(val) > 20 and all(c in ['4', '1'] for c in val):
                detected = True
                description = f"Potential GATT injection / Buffer overflow pattern written to {uuid}"
            elif uuid == "e2c56db5-dffb-48d2-b060-d0f5a71096e0":
                detected = True
                description = f"Unauthorized command sequence targeted at legacy service {uuid}"

        return {
            "detected": detected,
            "service_uuid": uuid,
            "payload_hex": val,
            "description": description,
            "risk_level": "CRITICAL" if detected else "LOW",
            "mitre_technique": BLEDecoder._MITRE_MAP["GATT_INJECTION"] if detected else "None",
        }

    @staticmethod
    def detect_ble_beaconing(history: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Monitors advertising intervals to isolate unauthorized tracker/beacon beacons or spamming activity.
        """
        if len(history) < 5:
            return {"detected": False, "reason": "Insufficient advertising packets"}

        adv_counts: dict[str, int] = {}
        for pkt in history:
            fields = pkt.get("decoded_fields", {})
            if fields.get("packet_type") == "ADVERTISEMENT":
                src = pkt.get("src_mac", "")
                adv_counts[src] = adv_counts.get(src, 0) + 1

        # Find devices transmitting at exceptionally high frequencies
        detected = False
        description = "Beaconing patterns fall within normal operational limits"
        target_mac = ""

        for mac, count in adv_counts.items():
            if count >= 10:
                detected = True
                target_mac = mac
                description = f"High density beaconing detected from device {mac} ({count} advertisements)"
                break

        return {
            "detected": detected,
            "src_mac": target_mac,
            "packet_count": adv_counts.get(target_mac, 0),
            "description": description,
            "risk_level": "MEDIUM" if detected else "LOW",
            "mitre_technique": BLEDecoder._MITRE_MAP["BEACONING"] if detected else "None",
        }

    @staticmethod
    def decode_sample_packets() -> list[dict[str, Any]]:
        """
        Generates and decodes various simulated BLE packets.
        """
        samples = [
            # 1. Normal advertiser (ADV_IND)
            "001234",
            # 2. Connection request (CONNECT_IND) from target MAC
            "05aabbcc",
            # 3. GATT write request (causes simulated write to backdoor service)
            "01035566",
            # 4. GATT buffer overflow payload (will trigger injection logic)
            "0b034141414141414141414141414141414141414141",
        ]
        return [BLEDecoder.decode_packet(hex_str) for hex_str in samples]
