import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.agents.director_agent")

class DirectorAgent:
    """
    Director Agent acts as the swarm commander, decomposing cases into sub-tasks
    and delegating them to appropriate specialist agents.

    Swarm 3.0 — Extended with IoT/OT specialist agents:
      - IoTAgent: IoT device botnet/compromise/firmware incidents
      - FirmwareAgent: Firmware CVE analysis and patch management
      - ProtocolAgent: OT/IoT protocol decoding (MQTT, Modbus, S7Comm, IEC104, OPC-UA, Zigbee, BLE)
    """

    IOT_KEYWORDS = [
        "iot", "cctv", "camera", "nvr", "dvr", "biometric", "printer", "ip phone",
        "smart meter", "mirai", "gafgyt", "mozi", "vpnfilter", "brickerbot", "botnet",
        "mqtt", "coap", "zigbee", "bluetooth", "ble", "snmp", "raspberry pi",
        "shadow iot", "firmware", "default credentials", "telnet brute"
    ]

    OT_KEYWORDS = [
        "modbus", "ics", "bacnet", "plc", "rtu", "hmi", "scada", "s7comm", "siemens",
        "schneider", "iec104", "opc-ua", "opcua", "dnp3", "industrial", "water plant",
        "power grid", "traffic signal", "railway signaling", "ot anomaly"
    ]

    FIRMWARE_KEYWORDS = [
        "firmware", "cve", "patch", "vulnerability", "exploit", "cisa kev",
        "hikvision", "dahua", "axis", "zyxel", "default password"
    ]

    PROTOCOL_KEYWORDS = [
        "modbus frame", "mqtt packet", "s7comm", "iec104", "coap", "zigbee frame",
        "ble packet", "snmp trap", "opc-ua", "protocol decode", "protocol anomaly"
    ]

    def delegate_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intelligently routes incidents to specialist agents based on title, type, and context.
        Returns a delegation plan with ordered agent execution sequence.
        """
        title = incident_data.get("title", "").lower()
        incident_type = incident_data.get("type", "").lower()
        description = incident_data.get("description", "").lower()
        combined = f"{title} {incident_type} {description}"

        delegation_plan = []
        routing_reason = []

        # IoT device incidents
        if any(kw in combined for kw in self.IOT_KEYWORDS):
            delegation_plan.extend(["IoTAgent", "FirmwareAgent"])
            routing_reason.append("IoT/botnet indicators detected")

        # OT/ICS protocol incidents
        if any(kw in combined for kw in self.OT_KEYWORDS):
            delegation_plan.extend(["OTAgent", "ProtocolAgent", "NetworkAgent"])
            routing_reason.append("OT/ICS protocol anomaly detected")

        # Firmware-specific incidents
        if any(kw in combined for kw in self.FIRMWARE_KEYWORDS) and "FirmwareAgent" not in delegation_plan:
            delegation_plan.append("FirmwareAgent")
            routing_reason.append("Firmware vulnerability indicated")

        # Protocol decode requests
        if any(kw in combined for kw in self.PROTOCOL_KEYWORDS) and "ProtocolAgent" not in delegation_plan:
            delegation_plan.append("ProtocolAgent")
            routing_reason.append("Protocol decoding required")

        # Traditional IT incident routing
        if not delegation_plan:
            if "malware" in combined or "trojan" in combined or "mimikatz" in combined or "ransomware" in combined:
                delegation_plan.extend(["MalwareAgent", "ForensicsAgent"])
                routing_reason.append("Malware/ransomware indicators")
            elif "cloud" in combined or "s3" in combined or "azure" in combined or "gcp" in combined:
                delegation_plan.extend(["CloudAgent", "IdentityAgent"])
                routing_reason.append("Cloud infrastructure incident")
            elif "lateral" in combined or "privilege" in combined or "kerberos" in combined:
                delegation_plan.extend(["HunterAgent", "ForensicsAgent", "PrivilegeAgent"])
                routing_reason.append("Lateral movement/privilege escalation")
            elif "exfil" in combined or "data loss" in combined:
                delegation_plan.extend(["HunterAgent", "ForensicsAgent", "NetworkAgent"])
                routing_reason.append("Data exfiltration suspected")
            else:
                delegation_plan.extend(["HunterAgent", "ForensicsAgent"])
                routing_reason.append("General security incident — default routing")

        # Always add consensus for multi-agent coordination
        if len(delegation_plan) > 1:
            delegation_plan.append("ConsensusAgent")

        return {
            "status": "success",
            "delegation_plan": list(dict.fromkeys(delegation_plan)),  # deduplicate preserving order
            "routing_reasons": routing_reason,
            "orchestrated_by": "DirectorAgent 3.0",
            "swarm_size": len(delegation_plan),
            "priority": self._determine_priority(incident_data),
        }

    def _determine_priority(self, incident_data: Dict[str, Any]) -> str:
        severity = incident_data.get("severity", "medium").lower()
        incident_type = incident_data.get("type", "").lower()
        ot_types = ["plc_manipulation", "ics_anomaly", "scada_attack", "grid_attack", "water_plant"]
        if any(t in incident_type for t in ot_types) or severity == "critical":
            return "P0_IMMEDIATE"
        elif severity == "high":
            return "P1_HIGH"
        elif severity == "medium":
            return "P2_MEDIUM"
        return "P3_LOW"
