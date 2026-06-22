import logging
import random
import hashlib
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.mac_vendor_lookup")

class MacVendorLookup:
    """OUI MAC prefix to vendor name and risk category lookup."""

    MAC_OUI_DB: Dict[str, Dict[str, Any]] = {
        "00:40:48": {"vendor": "Hikvision", "device_types": ["IP Camera", "NVR", "DVR"], "risk_category": "iot_critical"},
        "E4:24:6C": {"vendor": "Hikvision", "device_types": ["IP Camera"], "risk_category": "iot_critical"},
        "BC:AD:28": {"vendor": "Hikvision", "device_types": ["IP Camera", "NVR"], "risk_category": "iot_critical"},
        "E4:24:6C": {"vendor": "Dahua", "device_types": ["IP Camera", "NVR"], "risk_category": "iot_critical"},
        "90:02:A9": {"vendor": "Dahua", "device_types": ["IP Camera"], "risk_category": "iot_critical"},
        "00:40:8C": {"vendor": "Axis Communications", "device_types": ["IP Camera", "Video Encoder"], "risk_category": "iot_critical"},
        "AC:CC:8E": {"vendor": "Axis Communications", "device_types": ["IP Camera"], "risk_category": "iot_critical"},
        "00:0A:B0": {"vendor": "Cisco", "device_types": ["Router", "Switch", "IP Phone"], "risk_category": "it_standard"},
        "00:1A:A2": {"vendor": "Cisco", "device_types": ["IP Phone", "Router"], "risk_category": "it_standard"},
        "00:0E:8C": {"vendor": "Siemens", "device_types": ["PLC", "HMI", "Industrial Switch"], "risk_category": "ot_critical"},
        "00:1B:1B": {"vendor": "Siemens", "device_types": ["S7-300", "S7-1200", "S7-1500"], "risk_category": "ot_critical"},
        "00:80:F4": {"vendor": "Schneider Electric", "device_types": ["Modicon PLC", "RTU", "HMI"], "risk_category": "ot_critical"},
        "00:00:54": {"vendor": "Schneider Electric", "device_types": ["Modicon M340", "Modicon M580"], "risk_category": "ot_critical"},
        "00:04:A3": {"vendor": "Honeywell", "device_types": ["HVAC Controller", "Building Management"], "risk_category": "ot_critical"},
        "00:09:9A": {"vendor": "Bosch Security Systems", "device_types": ["CCTV", "NVR", "Access Control"], "risk_category": "iot_critical"},
        "00:07:AB": {"vendor": "Samsung", "device_types": ["Smart TV", "NVR", "IP Camera"], "risk_category": "iot_standard"},
        "B8:27:EB": {"vendor": "Raspberry Pi Foundation", "device_types": ["Raspberry Pi", "IoT Gateway"], "risk_category": "iot_critical"},
        "DC:A6:32": {"vendor": "Raspberry Pi Foundation", "device_types": ["Raspberry Pi 4"], "risk_category": "iot_critical"},
        "E4:5F:01": {"vendor": "Raspberry Pi Foundation", "device_types": ["Raspberry Pi Zero 2W"], "risk_category": "iot_critical"},
        "00:1D:0F": {"vendor": "TP-Link", "device_types": ["Router", "Switch", "WiFi AP"], "risk_category": "it_standard"},
        "50:C7:BF": {"vendor": "TP-Link", "device_types": ["WiFi Router", "AP"], "risk_category": "it_standard"},
        "00:09:5B": {"vendor": "Netgear", "device_types": ["Router", "Switch", "NAS"], "risk_category": "it_standard"},
        "00:1B:11": {"vendor": "D-Link", "device_types": ["Router", "IP Camera", "NAS"], "risk_category": "iot_standard"},
        "00:30:DE": {"vendor": "ABB", "device_types": ["PLC", "RTU", "Drive"], "risk_category": "ot_critical"},
        "00:00:BC": {"vendor": "Rockwell Automation", "device_types": ["Allen Bradley PLC", "HMI"], "risk_category": "ot_critical"},
        "00:0B:B1": {"vendor": "Yokogawa", "device_types": ["DCS", "RTU", "Transmitter"], "risk_category": "ot_critical"},
        "00:30:48": {"vendor": "Emerson", "device_types": ["DeltaV DCS", "RTU", "Analyzer"], "risk_category": "ot_critical"},
        "00:90:27": {"vendor": "GE Digital", "device_types": ["SCADA", "HMI", "Historian"], "risk_category": "ot_critical"},
        "00:00:78": {"vendor": "Mitsubishi Electric", "device_types": ["MELSEC PLC", "GOT HMI"], "risk_category": "ot_critical"},
        "00:00:53": {"vendor": "Omron", "device_types": ["CJ-series PLC", "NS HMI"], "risk_category": "ot_critical"},
        "00:A0:45": {"vendor": "Phoenix Contact", "device_types": ["ILC PLC", "Industrial Switch", "Gateway"], "risk_category": "ot_critical"},
        "00:01:05": {"vendor": "Beckhoff Automation", "device_types": ["CX IPC", "EtherCAT Master"], "risk_category": "ot_critical"},
        "C8:D3:A3": {"vendor": "Hanwha Vision", "device_types": ["IP Camera", "NVR"], "risk_category": "iot_critical"},
        "00:80:45": {"vendor": "Panasonic", "device_types": ["IP Camera", "CCTV", "Intercom"], "risk_category": "iot_standard"},
        "00:A0:C6": {"vendor": "ZKTeco", "device_types": ["Biometric Reader", "Access Control", "Attendance"], "risk_category": "iot_critical"},
        "00:1F:9E": {"vendor": "Cisco", "device_types": ["Catalyst Switch", "ASR Router"], "risk_category": "it_standard"},
        "00:1E:58": {"vendor": "D-Link", "device_types": ["IP Camera", "DVR"], "risk_category": "iot_standard"},
        "00:26:B9": {"vendor": "Dell", "device_types": ["Server", "Workstation"], "risk_category": "it_standard"},
        "00:50:56": {"vendor": "VMware", "device_types": ["Virtual Machine NIC"], "risk_category": "it_standard"},
        "08:00:27": {"vendor": "VirtualBox", "device_types": ["Virtual Machine"], "risk_category": "unknown"},
    }

    @classmethod
    def _normalize_mac(cls, mac: str) -> str:
        mac = mac.upper().replace("-", ":").replace(".", ":")
        parts = mac.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3])
        return mac[:8]

    @classmethod
    def lookup(cls, mac: str) -> Dict[str, Any]:
        prefix = cls._normalize_mac(mac)
        info = cls.MAC_OUI_DB.get(prefix)
        if info:
            return {"mac_prefix": prefix, "found": True, **info}
        return {"mac_prefix": prefix, "found": False, "vendor": "Unknown", "device_types": ["Unknown"], "risk_category": "unknown"}

    @classmethod
    def is_ot_device(cls, mac: str) -> bool:
        result = cls.lookup(mac)
        return result.get("risk_category") == "ot_critical"

    @classmethod
    def is_iot_camera(cls, mac: str) -> bool:
        result = cls.lookup(mac)
        return any("Camera" in dt or "CCTV" in dt or "NVR" in dt for dt in result.get("device_types", []))

    @classmethod
    def get_risk_category(cls, mac: str) -> str:
        return cls.lookup(mac).get("risk_category", "unknown")

    @classmethod
    def get_all_ot_prefixes(cls) -> List[str]:
        return [prefix for prefix, info in cls.MAC_OUI_DB.items() if info["risk_category"] == "ot_critical"]

    @classmethod
    def get_vendor_stats(cls) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        vendors: Dict[str, int] = {}
        for info in cls.MAC_OUI_DB.values():
            cats[info["risk_category"]] = cats.get(info["risk_category"], 0) + 1
            vendors[info["vendor"]] = vendors.get(info["vendor"], 0) + 1
        return {"total_oui_entries": len(cls.MAC_OUI_DB), "by_risk_category": cats, "top_vendors": vendors}
