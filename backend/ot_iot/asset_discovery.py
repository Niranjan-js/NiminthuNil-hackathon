import logging
import random
import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.asset_discovery")


class IoTAssetDiscovery:
    """
    IoT/OT Asset Discovery Engine.
    Simulates ARP, SNMP, mDNS, SSDP, and UPnP protocol-based
    discovery for a Tamil Nadu government network environment.
    Supports both active and passive discovery modes.
    """

    DEVICE_TEMPLATES = [
        {"vendor": "Hikvision", "model": "DS-2CD2043G0-I", "device_type": "CCTV_Camera", "category": "IoT_Physical",
         "open_ports": [80, 443, 554, 8000], "protocols": ["RTSP", "HTTP", "ONVIF"], "firmware": "V5.7.3 build 210319",
         "risk_tier": 2, "mac_prefix": "00:40:48", "subnet": "192.168.10"},
        {"vendor": "Hikvision", "model": "DS-7616NXI-I2", "device_type": "NVR", "category": "IoT_Physical",
         "open_ports": [80, 443, 8000, 554], "protocols": ["HTTP", "RTSP", "ONVIF"], "firmware": "V4.30.210 build 210625",
         "risk_tier": 2, "mac_prefix": "BC:AD:28", "subnet": "192.168.10"},
        {"vendor": "Dahua", "model": "IPC-HDW2831T-AS", "device_type": "CCTV_Camera", "category": "IoT_Physical",
         "open_ports": [80, 443, 554, 37777], "protocols": ["RTSP", "HTTP", "ONVIF"], "firmware": "V2.820.0000000.2.R",
         "risk_tier": 2, "mac_prefix": "90:02:A9", "subnet": "192.168.10"},
        {"vendor": "Axis Communications", "model": "P3245-V", "device_type": "CCTV_Camera", "category": "IoT_Physical",
         "open_ports": [80, 443, 554], "protocols": ["RTSP", "HTTP", "ONVIF", "VAPIX"], "firmware": "10.9.1",
         "risk_tier": 2, "mac_prefix": "00:40:8C", "subnet": "192.168.10"},
        {"vendor": "Bosch Security Systems", "model": "DIVAR IP 3000", "device_type": "NVR", "category": "IoT_Physical",
         "open_ports": [80, 443, 4444], "protocols": ["HTTP", "RTSP"], "firmware": "3.83.0025",
         "risk_tier": 2, "mac_prefix": "00:09:9A", "subnet": "192.168.10"},
        {"vendor": "Cisco", "model": "CP-8865", "device_type": "IP_Phone", "category": "IoT_Consumer",
         "open_ports": [80, 443, 5060, 5061], "protocols": ["SIP", "SCCP", "HTTP"], "firmware": "12.8.1",
         "risk_tier": 3, "mac_prefix": "00:1A:A2", "subnet": "192.168.20"},
        {"vendor": "Epson", "model": "WF-3820", "device_type": "Printer", "category": "IoT_Consumer",
         "open_ports": [80, 443, 9100, 631], "protocols": ["IPP", "HTTP", "SNMP"], "firmware": "FL20I4",
         "risk_tier": 3, "mac_prefix": "00:26:AB", "subnet": "192.168.30"},
        {"vendor": "HP", "model": "LaserJet M428fdw", "device_type": "Printer", "category": "IoT_Consumer",
         "open_ports": [80, 443, 9100, 161], "protocols": ["IPP", "HTTP", "SNMP"], "firmware": "20210809",
         "risk_tier": 3, "mac_prefix": "3C:D9:2B", "subnet": "192.168.30"},
        {"vendor": "ZKTeco", "model": "SpeedFace-V5L", "device_type": "Biometric", "category": "IoT_Physical",
         "open_ports": [80, 4370, 5005], "protocols": ["HTTP", "ZKNET"], "firmware": "6.0.12",
         "risk_tier": 2, "mac_prefix": "00:A0:C6", "subnet": "192.168.40"},
        {"vendor": "Raspberry Pi Foundation", "model": "Raspberry Pi 4 Model B", "device_type": "Raspberry_Pi",
         "category": "IoT_Physical", "open_ports": [22, 80, 8080], "protocols": ["SSH", "HTTP"],
         "firmware": "Raspbian 11 (bullseye)", "risk_tier": 1, "mac_prefix": "DC:A6:32", "subnet": "192.168.50"},
        {"vendor": "TP-Link", "model": "TL-SG1024D", "device_type": "Industrial_Switch", "category": "Network_Infrastructure",
         "open_ports": [80, 443, 23, 161], "protocols": ["HTTP", "TELNET", "SNMP"], "firmware": "1.0.0 Build 20210115",
         "risk_tier": 2, "mac_prefix": "50:C7:BF", "subnet": "192.168.1"},
        {"vendor": "Siemens", "model": "SIMATIC S7-1200", "device_type": "PLC", "category": "OT_Critical",
         "open_ports": [102, 80, 443, 44818], "protocols": ["S7Comm", "Modbus", "PROFINET", "HTTP"],
         "firmware": "V4.5.0", "risk_tier": 1, "mac_prefix": "00:1B:1B", "subnet": "10.10.1"},
        {"vendor": "Schneider Electric", "model": "Modicon M221", "device_type": "PLC", "category": "OT_Critical",
         "open_ports": [502, 80, 1025], "protocols": ["Modbus", "HTTP", "EtherNet/IP"], "firmware": "SV1.13.0.0",
         "risk_tier": 1, "mac_prefix": "00:80:F4", "subnet": "10.10.1"},
        {"vendor": "ABB", "model": "AC500 PM591", "device_type": "PLC", "category": "OT_Critical",
         "open_ports": [502, 102, 80], "protocols": ["Modbus", "S7Comm", "HTTP"], "firmware": "V3.4.5.127",
         "risk_tier": 1, "mac_prefix": "00:30:DE", "subnet": "10.10.1"},
        {"vendor": "Yokogawa", "model": "STARDOM FCN-100", "device_type": "RTU", "category": "OT_Critical",
         "open_ports": [502, 80, 443, 2222], "protocols": ["Modbus", "OPC-UA", "HTTP"], "firmware": "R10.04",
         "risk_tier": 1, "mac_prefix": "00:0B:B1", "subnet": "10.10.2"},
        {"vendor": "Honeywell", "model": "T6 Pro Smart Thermostat", "device_type": "HVAC_Controller",
         "category": "OT_Critical", "open_ports": [80, 443, 1883], "protocols": ["HTTP", "MQTT"],
         "firmware": "1.8.48", "risk_tier": 2, "mac_prefix": "00:04:A3", "subnet": "192.168.60"},
        {"vendor": "Samsung", "model": "QN65Q80B Smart TV", "device_type": "Smart_TV", "category": "IoT_Consumer",
         "open_ports": [8080, 8443, 9197], "protocols": ["HTTP", "DLNA", "UPnP"], "firmware": "T-HKMFDEUC-1352.3",
         "risk_tier": 4, "mac_prefix": "00:07:AB", "subnet": "192.168.70"},
        {"vendor": "Phoenix Contact", "model": "FL SWITCH 1008", "device_type": "Industrial_Switch",
         "category": "OT_Critical", "open_ports": [80, 443, 23, 161, 162], "protocols": ["HTTP", "SNMP", "TELNET"],
         "firmware": "3.60 H", "risk_tier": 1, "mac_prefix": "00:A0:45", "subnet": "10.10.1"},
        {"vendor": "Landis+Gyr", "model": "E350 Smart Meter", "device_type": "Smart_Meter", "category": "OT_Critical",
         "open_ports": [1883, 8883, 4059], "protocols": ["MQTT", "DLMS/COSEM", "IEC104"], "firmware": "L8.5.2",
         "risk_tier": 1, "mac_prefix": "00:1B:CE", "subnet": "10.20.1"},
        {"vendor": "Netgear", "model": "GS308E", "device_type": "Industrial_Switch", "category": "Network_Infrastructure",
         "open_ports": [80, 443, 23], "protocols": ["HTTP", "TELNET"], "firmware": "V1.00.10ENB",
         "risk_tier": 3, "mac_prefix": "00:09:5B", "subnet": "192.168.1"},
    ]

    @classmethod
    def discover(cls, subnet: str = "192.168.10.0/24",
                 protocols: List[str] = None,
                 passive: bool = False) -> Dict[str, Any]:
        """
        Simulate IoT asset discovery across a subnet.
        Returns a rich discovery result with all detected devices.
        """
        if protocols is None:
            protocols = ["ARP"] if passive else ["ARP", "SNMP", "mDNS", "SSDP", "UPnP"]

        discovered_devices = []
        base_subnet = subnet.split("/")[0].rsplit(".", 1)[0]

        templates_to_use = [t for t in cls.DEVICE_TEMPLATES
                            if t["subnet"] in base_subnet or not passive]
        if len(templates_to_use) == 0:
            templates_to_use = cls.DEVICE_TEMPLATES

        num_devices = random.randint(8, min(len(templates_to_use), 18))
        selected = random.sample(templates_to_use, num_devices)

        ip_counter = 10
        for tmpl in selected:
            ip = f"{tmpl['subnet']}.{ip_counter}"
            ip_counter += random.randint(1, 5)
            mac_suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
            mac = f"{tmpl['mac_prefix']}:{mac_suffix}"
            device_id = f"iot-{hashlib.md5(ip.encode()).hexdigest()[:8]}"

            discovered_devices.append({
                "id": device_id,
                "ip": ip,
                "mac": mac,
                "hostname": cls._generate_hostname(tmpl["device_type"], ip_counter),
                "vendor": tmpl["vendor"],
                "model": tmpl["model"],
                "device_type": tmpl["device_type"],
                "category": tmpl["category"],
                "open_ports": tmpl["open_ports"],
                "protocols_detected": tmpl["protocols"],
                "firmware_version": tmpl["firmware"],
                "discovery_method": random.choice(protocols),
                "risk_tier": tmpl["risk_tier"],
                "last_seen": datetime.datetime.utcnow().isoformat(),
                "network_segment": f"VLAN-{tmpl['subnet'].split('.')[2] if len(tmpl['subnet'].split('.')) > 2 else '10'}",
                "is_on_asset_register": random.choice([True, True, True, False]),
                "management_interface": f"http://{ip}" if 80 in tmpl["open_ports"] else None,
            })

        by_category: Dict[str, int] = {}
        for d in discovered_devices:
            by_category[d["category"]] = by_category.get(d["category"], 0) + 1

        shadow_count = sum(1 for d in discovered_devices if not d["is_on_asset_register"])
        ot_critical = sum(1 for d in discovered_devices if d["category"] == "OT_Critical")

        return {
            "subnet": subnet,
            "scan_time": datetime.datetime.utcnow().isoformat(),
            "scan_mode": "passive" if passive else "active",
            "discovery_protocols_used": protocols,
            "total_discovered": len(discovered_devices),
            "devices": discovered_devices,
            "by_category": by_category,
            "ot_critical_count": ot_critical,
            "shadow_iot_count": shadow_count,
            "risk_summary": cls.get_summary_stats(discovered_devices),
        }

    @classmethod
    def passive_discovery(cls, netflow_data: List[dict] = None) -> Dict[str, Any]:
        """Passive discovery via ARP monitoring and NetFlow analysis."""
        return cls.discover(protocols=["ARP", "mDNS", "NetFlow"], passive=True)

    @classmethod
    def get_summary_stats(cls, devices: List[Dict]) -> Dict[str, Any]:
        risk_counts = {1: 0, 2: 0, 3: 0, 4: 0}
        for d in devices:
            risk_counts[d.get("risk_tier", 4)] += 1
        return {
            "tier1_critical": risk_counts[1],
            "tier2_high": risk_counts[2],
            "tier3_medium": risk_counts[3],
            "tier4_low": risk_counts[4],
            "internet_facing": sum(1 for d in devices if 443 in d.get("open_ports", [])),
            "telnet_exposed": sum(1 for d in devices if 23 in d.get("open_ports", [])),
            "snmp_exposed": sum(1 for d in devices if 161 in d.get("open_ports", [])),
        }

    @staticmethod
    def _generate_hostname(device_type: str, counter: int) -> str:
        prefixes = {"CCTV_Camera": "CCTV", "PLC": "PLC", "RTU": "RTU", "Printer": "PRN",
                    "IP_Phone": "PHONE", "Biometric": "BIO", "Smart_Meter": "METER",
                    "Industrial_Switch": "SW", "Raspberry_Pi": "RPI", "NVR": "NVR"}
        prefix = prefixes.get(device_type, "IOT")
        return f"{prefix}-{counter:03d}"


import hashlib
