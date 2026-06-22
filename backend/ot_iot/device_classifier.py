import logging
from typing import Dict, Any, List

logger = logging.getLogger("niravan.ot_iot.device_classifier")


class DeviceClassifier:
    """
    Device Classification Engine for NIRAVAN OT/IoT Defense Layer.
    Assigns OT/IoT devices to security categories, risk tiers, MITRE contexts,
    recommends secure protocols, and outlines isolation policies for each risk tier.
    """

    # Primary mappings of device types to metadata
    DEVICE_TYPES: Dict[str, Dict[str, Any]] = {
        "PLC": {
            "category": "OT_Critical",
            "risk_tier": 1,
            "mitre_context": ["T0800", "T0801", "T0806", "T0855"],
            "monitoring_priority": "CRITICAL"
        },
        "RTU": {
            "category": "OT_Critical",
            "risk_tier": 1,
            "mitre_context": ["T0800", "T0801"],
            "monitoring_priority": "CRITICAL"
        },
        "DCS": {
            "category": "OT_Critical",
            "risk_tier": 1,
            "mitre_context": ["T0800"],
            "monitoring_priority": "CRITICAL"
        },
        "Smart_Meter": {
            "category": "OT_Critical",
            "risk_tier": 1,
            "mitre_context": ["T0802"],
            "monitoring_priority": "HIGH"
        },
        "HMI": {
            "category": "OT_Critical",
            "risk_tier": 1,
            "mitre_context": ["T0813", "T0806"],
            "monitoring_priority": "CRITICAL"
        },
        "CCTV_Camera": {
            "category": "IoT_Physical",
            "risk_tier": 2,
            "mitre_context": ["T0887"],
            "monitoring_priority": "HIGH"
        },
        "NVR": {
            "category": "IoT_Physical",
            "risk_tier": 2,
            "mitre_context": ["T0887"],
            "monitoring_priority": "HIGH"
        },
        "DVR": {
            "category": "IoT_Physical",
            "risk_tier": 2,
            "mitre_context": ["T0887"],
            "monitoring_priority": "HIGH"
        },
        "Biometric": {
            "category": "IoT_Physical",
            "risk_tier": 2,
            "mitre_context": ["T0806"],
            "monitoring_priority": "HIGH"
        },
        "Access_Control": {
            "category": "IoT_Physical",
            "risk_tier": 2,
            "mitre_context": ["T0806"],
            "monitoring_priority": "HIGH"
        },
        "IP_Phone": {
            "category": "IoT_Consumer",
            "risk_tier": 3,
            "mitre_context": [],
            "monitoring_priority": "MEDIUM"
        },
        "Printer": {
            "category": "IoT_Consumer",
            "risk_tier": 3,
            "mitre_context": [],
            "monitoring_priority": "MEDIUM"
        },
        "Smart_TV": {
            "category": "IoT_Consumer",
            "risk_tier": 4,
            "mitre_context": [],
            "monitoring_priority": "LOW"
        },
        "HVAC_Controller": {
            "category": "OT_Critical",
            "risk_tier": 2,
            "mitre_context": ["T0806"],
            "monitoring_priority": "HIGH"
        },
        "Industrial_Switch": {
            "category": "Network_Infrastructure",
            "risk_tier": 2,
            "mitre_context": ["T0814"],
            "monitoring_priority": "CRITICAL"
        },
        "Switch": {
            "category": "Network_Infrastructure",
            "risk_tier": 2,
            "mitre_context": ["T0814"],
            "monitoring_priority": "CRITICAL"
        },
        "Router": {
            "category": "Network_Infrastructure",
            "risk_tier": 1,
            "mitre_context": ["T0814"],
            "monitoring_priority": "CRITICAL"
        },
        "Firewall": {
            "category": "Network_Infrastructure",
            "risk_tier": 1,
            "mitre_context": ["T0814"],
            "monitoring_priority": "CRITICAL"
        }
    }

    def classify(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies a device based on its attributes.
        Returns category, risk tier, MITRE context, and monitoring priority.
        """
        dt = device_info.get("device_type")
        if dt and dt in self.DEVICE_TYPES:
            meta = self.DEVICE_TYPES[dt]
            return {
                "device_type": dt,
                "category": meta["category"],
                "risk_tier": meta["risk_tier"],
                "mitre_context": meta["mitre_context"],
                "monitoring_priority": meta["monitoring_priority"]
            }

        # Try heuristic matching against model, vendor, and device type fields
        model_str = (device_info.get("model") or "").lower()
        vendor_str = (device_info.get("vendor") or "").lower()
        dev_type_str = (device_info.get("device_type") or "").lower()

        # Keyword substring check
        for key, meta in self.DEVICE_TYPES.items():
            key_lower = key.lower()
            if key_lower in dev_type_str or key_lower in model_str:
                return {
                    "device_type": key,
                    "category": meta["category"],
                    "risk_tier": meta["risk_tier"],
                    "mitre_context": meta["mitre_context"],
                    "monitoring_priority": meta["monitoring_priority"]
                }

        # Specific heuristics
        if "camera" in model_str or "ipc" in model_str or "camera" in dev_type_str:
            meta = self.DEVICE_TYPES["CCTV_Camera"]
            return {
                "device_type": "CCTV_Camera",
                "category": meta["category"],
                "risk_tier": meta["risk_tier"],
                "mitre_context": meta["mitre_context"],
                "monitoring_priority": meta["monitoring_priority"]
            }
        if "controller" in model_str or "plc" in model_str or "simatic" in model_str or "modicon" in model_str or "s7" in model_str or "siemens" in vendor_str or any(p.lower() in ["s7comm", "modbus", "opcua", "iec104"] for p in device_info.get("protocols", [])):
            meta = self.DEVICE_TYPES["PLC"]
            return {
                "device_type": "PLC",
                "category": meta["category"],
                "risk_tier": meta["risk_tier"],
                "mitre_context": meta["mitre_context"],
                "monitoring_priority": meta["monitoring_priority"]
            }
        if "switch" in model_str or "switch" in dev_type_str:
            meta = self.DEVICE_TYPES["Industrial_Switch"]
            return {
                "device_type": "Industrial_Switch",
                "category": meta["category"],
                "risk_tier": meta["risk_tier"],
                "mitre_context": meta["mitre_context"],
                "monitoring_priority": meta["monitoring_priority"]
            }
        if "phone" in model_str or "phone" in dev_type_str:
            meta = self.DEVICE_TYPES["IP_Phone"]
            return {
                "device_type": "IP_Phone",
                "category": meta["category"],
                "risk_tier": meta["risk_tier"],
                "mitre_context": meta["mitre_context"],
                "monitoring_priority": meta["monitoring_priority"]
            }

        # Fallback default values
        logger.warning(f"Device classification fall back for device {device_info}")
        return {
            "device_type": device_info.get("device_type") or "Unknown",
            "category": "IoT_Consumer",
            "risk_tier": 3,
            "mitre_context": [],
            "monitoring_priority": "MEDIUM"
        }

    @staticmethod
    def get_recommended_protocols(device_type: str) -> List[str]:
        """Returns recommended secure protocols for a given device type."""
        protocols = {
            "PLC": ["OPC-UA Secure", "PROFINET", "Modbus TCP/Secure", "HTTPS"],
            "RTU": ["DNP3 Secure", "IEC 104 Secure", "Modbus TCP/Secure"],
            "Smart_Meter": ["DLMS/COSEM", "MQTTS", "HTTPS"],
            "CCTV_Camera": ["HTTPS", "SRTSP", "ONVIF Secure"],
            "NVR": ["HTTPS", "SRTSP"],
            "DVR": ["HTTPS", "SRTSP"],
            "Biometric": ["HTTPS", "ZKNET Secure"],
            "IP_Phone": ["SIPS", "SRTP", "HTTPS"],
            "Printer": ["IPPS", "HTTPS", "SNMPv3"],
            "Smart_TV": ["HTTPS"],
            "Industrial_Switch": ["SSH", "HTTPS", "SNMPv3"],
            "Switch": ["SSH", "HTTPS", "SNMPv3"],
            "Router": ["SSH", "HTTPS", "SNMPv3"],
            "Firewall": ["SSH", "HTTPS", "SNMPv3"]
        }
        for k, v in protocols.items():
            if k.lower() == device_type.lower():
                return v
        return ["HTTPS", "SSH"]

    @staticmethod
    def get_isolation_policy(risk_tier: int) -> Dict[str, Any]:
        """
        Determines the VLAN segmentation and network port security configuration
        for a device based on its risk tier.
        """
        if risk_tier == 1:
            return {
                "vlan_id": 10,
                "description": "Critical Industrial Control System Network (OT)",
                "port_security": {
                    "mac_limit": 1,
                    "action": "shutdown",
                    "sticky_mac": True,
                    "dot1x_enabled": True,
                    "traffic_filtering": "strict_industrial_only"
                }
            }
        elif risk_tier == 2:
            return {
                "vlan_id": 20,
                "description": "IoT Infrastructure and Security System Network",
                "port_security": {
                    "mac_limit": 2,
                    "action": "restrict",
                    "sticky_mac": True,
                    "dot1x_enabled": True,
                    "traffic_filtering": "restricted_access_only"
                }
            }
        elif risk_tier == 3:
            return {
                "vlan_id": 30,
                "description": "Office Automation Support IoT Network",
                "port_security": {
                    "mac_limit": 3,
                    "action": "protect",
                    "sticky_mac": False,
                    "dot1x_enabled": False,
                    "traffic_filtering": "standard_office_traffic"
                }
            }
        elif risk_tier == 4:
            return {
                "vlan_id": 40,
                "description": "Untrusted / Guest IoT System Network",
                "port_security": {
                    "mac_limit": 5,
                    "action": "protect",
                    "sticky_mac": False,
                    "dot1x_enabled": False,
                    "traffic_filtering": "internet_egress_only"
                }
            }
        else:
            return {
                "vlan_id": 99,
                "description": "Quarantine / Isolated Network",
                "port_security": {
                    "mac_limit": 1,
                    "action": "shutdown",
                    "sticky_mac": False,
                    "dot1x_enabled": False,
                    "traffic_filtering": "deny_all"
                }
            }

