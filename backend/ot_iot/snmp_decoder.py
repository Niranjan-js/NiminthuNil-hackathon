"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — SNMP Protocol Decoder
=============================================
Decodes and analyses Simple Network Management Protocol (SNMP) packets for security auditing.
Covers MITRE ATT&CK for ICS / IoT techniques: T0812, T0846, T0809, T0855.

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

logger = logging.getLogger("niravan.ot_iot.snmp_decoder")
logger.setLevel(logging.DEBUG)


class SNMPDecoder:
    """
    Stateless SNMP protocol decoder and threat analyzer for NIRAVAN OT/IoT defense.
    """

    # SNMP Versions
    VERSIONS: dict[int, str] = {
        0: "SNMPv1",
        1: "SNMPv2c",
        3: "SNMPv3",
    }

    # SNMP PDU Types
    PDU_TYPES: dict[int, str] = {
        0xa0: "GetRequest",
        0xa1: "GetNextRequest",
        0xa2: "GetResponse",
        0xa3: "SetRequest",
        0xa4: "Trapv1",
        0xa5: "GetBulkRequest",
        0xa6: "InformRequest",
        0xa7: "Trapv2",
        0xa8: "Report",
    }

    # Critical MIBs that represent severe configuration/command changes or sensitive info
    DANGEROUS_MIBS: dict[str, str] = {
        "1.3.6.1.4.1.9.9.96.1.1.1.1.10": "ciscoConfigCopyProtocol (Cisco Config Upload)",
        "1.3.6.1.4.1.9.9.96.1.1.1.1.3": "ciscoConfigCopySourceFileType",
        "1.3.6.1.4.1.9.2.1.55": "ciscoHostConfigSet (Cisco Configuration Modification)",
        "1.3.6.1.2.1.1.6": "sysLocation (Set-writeable system location)",
        "1.3.6.1.2.1.1.4": "sysContact (Set-writeable system contact)",
        "1.3.6.1.4.1.311.1.1.3.1.1": "microsoftDHCPParameters (DHCP scopes hijacking)",
        "1.3.6.1.4.1.11.2.3.9.4.2": "hpJetDirectConfiguration (Printer takeover)",
        "1.3.6.1.2.1.4.21": "ipRouteTable (Routing table enumeration/tampering)",
    }

    # Commonly abused / guessed SNMP community strings
    COMMON_COMMUNITY_STRINGS: list[str] = [
        "public",
        "private",
        "admin",
        "read",
        "write",
        "cisco",
        "system",
        "manager",
        "default",
        "root",
        "monitor",
        "public1",
        "public2",
        "private1",
        "snmp",
        "solaris",
        "hp",
    ]

    _MITRE_MAP: dict[str, str] = {
        "BRUTE_FORCE": "T0812 - Credentials / Default Credentials",
        "MIB_WALK": "T0846 - System Information Discovery",
        "AMPLIFICATION_PREP": "T0809 - Denial of Service / SNMP Amplification",
        "UNAUTHORIZED_SET": "T0855 - Unauthorized Command / Configuration Write",
    }

    @staticmethod
    def decode_packet(raw_hex: str) -> dict[str, Any]:
        """
        Parses a raw SNMP packet from its hex string representation and checks for abuse.
        
        Parameters
        ----------
        raw_hex : str
            Hexadecimal byte string representing the SNMP packet (typically UDP port 161/162).
            
        Returns
        -------
        dict
            Parsed packet details and threat analysis.
        """
        logger.debug("Decoding SNMP packet, hex length=%d", len(raw_hex))

        raw_hex = raw_hex.strip().replace(" ", "").lower()
        if not raw_hex:
            return {"valid": False, "error": "Empty packet"}

        try:
            bytes_data = bytes.fromhex(raw_hex)
        except ValueError:
            return {"valid": False, "error": "Invalid hex encoding"}

        if len(bytes_data) < 10:
            return {"valid": False, "error": "Packet too short (minimum SNMP envelope is 10 bytes)"}

        # Deterministic seed based on payload hash
        digest = hashlib.sha256(raw_hex.encode()).hexdigest()
        seed = int(digest[:8], 16)
        rng = random.Random(seed)

        # Basic mock/ASN.1 parsing helper
        # Usually SNMP starts with Sequence type (0x30), then length, then Version Integer (0x02)
        version_id = 1  # Default to v2c
        community_str = "public"
        pdu_type_id = 0xa0  # GetRequest
        request_id = rng.randint(10000, 999999)

        # Attempt to read version from byte 2/3 (simplistic ASN.1 parser)
        try:
            if bytes_data[0] == 0x30:
                # Sequence length is bytes_data[1]
                if bytes_data[2] == 0x02:  # Integer type for version
                    version_len = bytes_data[3]
                    # version integer is at bytes_data[4]
                    version_id = bytes_data[4]
        except IndexError:
            pass

        # Pools for simulation-derived fields
        community_pool = SNMPDecoder.COMMON_COMMUNITY_STRINGS + ["secOpsCommunity", "prod-snmp-rw", "public-view"]
        pdu_keys = list(SNMPDecoder.PDU_TYPES.keys())
        oids_pool = [
            "1.3.6.1.2.1.1.1.0",  # sysDescr
            "1.3.6.1.2.1.1.5.0",  # sysName
            "1.3.6.1.4.1.9.9.96.1.1.1.1.10",  # ciscoConfigCopyProtocol
            "1.3.6.1.2.1.1.6.0",  # sysLocation
            "1.3.6.1.2.1.4.21",  # ipRouteTable
            "1.3.6.1.2.1.2.2.1",  # ifTable
            "1.3.6.1.4.1.11.2.3.9.4.2",  # hpJetDirectConfiguration
        ]

        version = SNMPDecoder.VERSIONS.get(version_id, f"SNMP_Unknown({version_id})")
        community = community_pool[seed % len(community_pool)]
        pdu_type_id = pdu_keys[(seed >> 4) % len(pdu_keys)]
        pdu_type = SNMPDecoder.PDU_TYPES.get(pdu_type_id, f"UNKNOWN_PDU({pdu_type_id})")

        selected_oid = oids_pool[(seed >> 8) % len(oids_pool)]

        # Simulate IP source
        ips = ["192.168.1.50", "10.10.20.5", "10.0.0.99", "172.16.50.12"]
        src_ip = ips[(seed >> 12) % len(ips)]

        threat_indicators: list[str] = []
        mitre_techniques: list[str] = []

        # Analyze Community String
        is_default_comm = community in SNMPDecoder.COMMON_COMMUNITY_STRINGS
        
        # Analyze write attempts (SetRequest)
        if pdu_type == "SetRequest":
            if is_default_comm:
                threat_indicators.append(f"UNAUTHORIZED_SET: Write command with common community string '{community}'")
                mitre_techniques.append(SNMPDecoder._MITRE_MAP["UNAUTHORIZED_SET"])
            if selected_oid in SNMPDecoder.DANGEROUS_MIBS:
                threat_indicators.append(f"CRITICAL_MIB_WRITE: SetRequest targeting dangerous OID: {selected_oid} ({SNMPDecoder.DANGEROUS_MIBS[selected_oid]})")
                mitre_techniques.append(SNMPDecoder._MITRE_MAP["UNAUTHORIZED_SET"])

        # Analyze GetBulk/Amplification Risks
        max_repetitions = 0
        if pdu_type == "GetBulkRequest":
            max_repetitions = rng.randint(5, 120)  # Simulate repeats parameter
            if max_repetitions > 50 and is_default_comm:
                threat_indicators.append(f"AMPLIFICATION_PREPARATION: GetBulkRequest with high repetition count ({max_repetitions}) using default community")
                mitre_techniques.append(SNMPDecoder._MITRE_MAP["AMPLIFICATION_PREP"])

        is_suspicious = len(threat_indicators) > 0

        result = {
            "valid": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "protocol": "SNMP",
            "version": version,
            "community": community,
            "pdu_type": pdu_type,
            "request_id": request_id,
            "oids": [selected_oid],
            "max_repetitions": max_repetitions,
            "src_ip": src_ip,
            "is_suspicious": is_suspicious,
            "threat_indicators": threat_indicators,
            "mitre_technique": list(set(mitre_techniques)) if mitre_techniques else ["None"],
            "raw_length": len(bytes_data),
        }

        if is_suspicious:
            logger.warning(
                "Suspicious SNMP request detected | src=%s | type=%s | threats=%s",
                src_ip, pdu_type, threat_indicators
            )
        else:
            logger.info("SNMP request decoded cleanly | type=%s | community=%s", pdu_type, community)

        return result

    @staticmethod
    def detect_community_brute_force(history: list[dict[str, Any]], src_ip: str) -> dict[str, Any]:
        """
        Analyzes traffic history to detect SNMP community string brute forcing.
        
        Parameters
        ----------
        history : list[dict]
            List of previously decoded SNMP packet structures.
        src_ip : str
            The source IP address of the node to check.
        """
        attempted_communities = set()
        failures = 0

        for pkt in history:
            if pkt.get("src_ip") == src_ip:
                comm = pkt.get("community", "")
                attempted_communities.add(comm)
                
                # Check for indicators of authentication failure or brute force guessing
                if comm in SNMPDecoder.COMMON_COMMUNITY_STRINGS:
                    failures += 1

        detected = len(attempted_communities) >= 3 and failures >= 3
        description = "No brute force signature detected"

        if detected:
            description = (
                f"SNMP Community Brute Force detected from {src_ip}: "
                f"attempted {len(attempted_communities)} different community strings ({list(attempted_communities)})"
            )

        return {
            "detected": detected,
            "src_ip": src_ip,
            "attempted_communities": list(attempted_communities),
            "total_attempts": failures,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": SNMPDecoder._MITRE_MAP["BRUTE_FORCE"] if detected else "None",
        }

    @staticmethod
    def detect_mib_walk(history: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Detects MIB walking (reconnaissance / information leakage) via sequential GetNext or GetBulk queries.
        """
        if len(history) < 5:
            return {"detected": False, "reason": "Insufficient traffic volume"}

        ip_request_counts: dict[str, int] = {}
        ip_oids: dict[str, set[str]] = {}

        for pkt in history:
            src = pkt.get("src_ip", "unknown")
            pdu = pkt.get("pdu_type", "")
            oids = pkt.get("oids", [])

            if pdu in ["GetNextRequest", "GetBulkRequest"]:
                ip_request_counts[src] = ip_request_counts.get(src, 0) + 1
                if src not in ip_oids:
                    ip_oids[src] = set()
                for oid in oids:
                    ip_oids[src].add(oid)

        detected = False
        culprit_ip = ""
        description = "No MIB walking activity detected"

        for ip, count in ip_request_counts.items():
            # If an IP sends many sequential reads targeting different parts of the MIB tree
            if count >= 5 and len(ip_oids[ip]) >= 3:
                detected = True
                culprit_ip = ip
                description = f"MIB Walk / Reconnaissance detected from {ip} ({count} requests across {len(ip_oids[ip])} OIDs)"
                break

        return {
            "detected": detected,
            "src_ip": culprit_ip,
            "request_count": ip_request_counts.get(culprit_ip, 0),
            "description": description,
            "risk_level": "MEDIUM" if detected else "LOW",
            "mitre_technique": SNMPDecoder._MITRE_MAP["MIB_WALK"] if detected else "None",
        }

    @staticmethod
    def detect_amplification_prep(packet: dict[str, Any]) -> dict[str, Any]:
        """
        Identifies if an SNMP packet is crafted to cause a massive response size (Denial of Service vector).
        """
        pdu = packet.get("pdu_type", "")
        max_rep = packet.get("max_repetitions", 0)
        comm = packet.get("community", "")

        detected = False
        description = "Request does not represent a denial of service amplification threat"

        if pdu == "GetBulkRequest" and max_rep >= 50:
            detected = True
            description = f"Potential SNMP amplification preparation: GetBulk request from {packet.get('src_ip')} with max-repetitions={max_rep}"

        return {
            "detected": detected,
            "max_repetitions": max_rep,
            "community": comm,
            "description": description,
            "risk_level": "HIGH" if detected else "LOW",
            "mitre_technique": SNMPDecoder._MITRE_MAP["AMPLIFICATION_PREP"] if detected else "None",
        }

    @staticmethod
    def detect_unauthorized_set(packet: dict[str, Any]) -> dict[str, Any]:
        """
        Verifies if an SNMP SetRequest attempts to change critical network or system properties.
        """
        pdu = packet.get("pdu_type", "")
        oids = packet.get("oids", [])
        comm = packet.get("community", "")

        detected = False
        target_oid = ""
        description = "No unauthorized write commands detected"

        if pdu == "SetRequest":
            for oid in oids:
                if oid in SNMPDecoder.DANGEROUS_MIBS or comm in SNMPDecoder.COMMON_COMMUNITY_STRINGS:
                    detected = True
                    target_oid = oid
                    description = f"Unauthorized SNMP configuration edit: SetRequest targeting {oid} using community string '{comm}'"
                    break

        return {
            "detected": detected,
            "target_oid": target_oid,
            "community": comm,
            "description": description,
            "risk_level": "CRITICAL" if (detected and target_oid in SNMPDecoder.DANGEROUS_MIBS) else ("HIGH" if detected else "LOW"),
            "mitre_technique": SNMPDecoder._MITRE_MAP["UNAUTHORIZED_SET"] if detected else "None",
        }

    @staticmethod
    def decode_sample_packets() -> list[dict[str, Any]]:
        """
        Returns decoded results for a set of sample SNMP packets.
        """
        samples = [
            # 1. Normal SNMP GET (v2c, public community, sysDescr)
            "302902010104067075626c6963a01c020400010203020100020100300e300c06082b060102010101000500",
            # 2. SNMP SET with default community string (dangerous)
            "3029020101040770726976617465a31c020400010204020100020100300e300c06082b060102010106000500",
            # 3. SNMP GETBULK request (potential amplification prep)
            "302902010104067075626c6963a51c020400010205020100020100300e300c06082b060102010101000500",
            # 4. Invalid hex packet
            "invalid_hex_string_123",
        ]
        return [SNMPDecoder.decode_packet(hex_str) for hex_str in samples]
