import logging
from typing import Dict, Any, List, Optional
import datetime
import hashlib

logger = logging.getLogger("niravan.ot_iot.digital_twin")


class DigitalTwin:
    """
    Virtual representation of 7 critical environments for OT/IoT Cyber Defense.
    Provides inventory tracking, risk profiling, and compromise simulations.
    """

    ENVIRONMENTS: Dict[str, Dict[str, Any]] = {
        "Hospital": {
            "name": "Hospital",
            "departments": ["Emergency Room", "ICU", "Oncology", "Radiology", "Pharmacy", "Admin"],
            "network_config": {
                "ip_range": "192.168.10.0/21",
                "vlans": {
                    "VLAN-10": {"name": "Medical Devices", "subnet": "192.168.10.0/24"},
                    "VLAN-20": {"name": "Admin & Staff", "subnet": "192.168.11.0/24"},
                    "VLAN-30": {"name": "HVAC & Building Automation", "subnet": "192.168.12.0/24"},
                    "VLAN-40": {"name": "Guest Network", "subnet": "192.168.13.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-40", "destination": "VLAN-10", "action": "DROP"},
                    {"source": "VLAN-20", "destination": "VLAN-10", "action": "ALLOW", "ports": [443, 80]},
                    {"source": "VLAN-30", "destination": "Internet", "action": "ALLOW", "ports": [443, 8883]},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-hosp-01",
                    "vendor": "Becton Dickinson",
                    "model": "Alaris Infusion Pump 8015",
                    "device_type": "Infusion_Pump",
                    "category": "OT_Critical",
                    "department": "ICU",
                    "ip": "192.168.10.15",
                    "mac": "00:1E:C9:AB:45:11",
                    "firmware_version": "V12.1.2",
                    "open_ports": [23, 80, 5000],
                    "protocols": ["TELNET", "HTTP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-hosp-02",
                    "vendor": "Philips",
                    "model": "IntelliVue MX550",
                    "device_type": "Patient_Monitor",
                    "category": "OT_Critical",
                    "department": "Emergency Room",
                    "ip": "192.168.10.22",
                    "mac": "00:09:FB:56:88:C1",
                    "firmware_version": "N.02.01",
                    "open_ports": [443, 8000, 9100],
                    "protocols": ["HTTPS", "HL7"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-hosp-03",
                    "vendor": "Honeywell",
                    "model": "T6 Pro Smart Thermostat",
                    "device_type": "HVAC_Controller",
                    "category": "OT_Critical",
                    "department": "Pharmacy",
                    "ip": "192.168.12.10",
                    "mac": "00:04:A3:EF:BC:88",
                    "firmware_version": "1.8.48",
                    "open_ports": [80, 443, 1883],
                    "protocols": ["HTTP", "MQTT"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-hosp-04",
                    "vendor": "Hikvision",
                    "model": "DS-2CD2043G0-I",
                    "device_type": "CCTV_Camera",
                    "category": "IoT_Physical",
                    "department": "Admin",
                    "ip": "192.168.11.35",
                    "mac": "00:40:48:9A:BC:33",
                    "firmware_version": "V5.7.3 build 210319",
                    "open_ports": [80, 443, 554, 8000],
                    "protocols": ["RTSP", "HTTP", "ONVIF"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-hosp-05",
                    "vendor": "ZKTeco",
                    "model": "SpeedFace-V5L",
                    "device_type": "Biometric",
                    "category": "IoT_Physical",
                    "department": "Pharmacy",
                    "ip": "192.168.11.45",
                    "mac": "00:A0:C6:12:34:56",
                    "firmware_version": "6.0.12",
                    "open_ports": [80, 4370, 5005],
                    "protocols": ["HTTP", "ZKNET"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "PACS Imaging Server", "ip": "192.168.10.5", "status": "Online"},
                {"name": "Electronic Medical Records (EMR) DB", "ip": "192.168.10.10", "status": "Online"},
                {"name": "ICU Ventilator Central Monitor", "ip": "192.168.10.20", "status": "Online"},
            ],
            "citizen_impact_multiplier": 9.5,
            "description": "Simulated Regional Government Hospital providing ICU and critical care services.",
        },
        "School": {
            "name": "School",
            "departments": ["Classrooms", "Computer Lab", "Library", "Administration"],
            "network_config": {
                "ip_range": "192.168.40.0/22",
                "vlans": {
                    "VLAN-40": {"name": "Admin & Staff", "subnet": "192.168.40.0/24"},
                    "VLAN-50": {"name": "Student Lab", "subnet": "192.168.41.0/24"},
                    "VLAN-60": {"name": "IoT & Facilities", "subnet": "192.168.42.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-50", "destination": "VLAN-40", "action": "DROP"},
                    {"source": "VLAN-60", "destination": "VLAN-40", "action": "DROP"},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-sch-01",
                    "vendor": "Samsung",
                    "model": "QN65Q80B Smart TV",
                    "device_type": "Smart_TV",
                    "category": "IoT_Consumer",
                    "department": "Library",
                    "ip": "192.168.42.50",
                    "mac": "00:07:AB:33:44:55",
                    "firmware_version": "T-HKMFDEUC-1352.3",
                    "open_ports": [8080, 8443, 9197],
                    "protocols": ["HTTP", "DLNA", "UPnP"],
                    "risk_tier": 4,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-sch-02",
                    "vendor": "D-Link",
                    "model": "DIR-842",
                    "device_type": "Wireless_Router",
                    "category": "Network_Infrastructure",
                    "department": "Computer Lab",
                    "ip": "192.168.41.1",
                    "mac": "B8:62:1F:C1:22:A9",
                    "firmware_version": "v1.04",
                    "open_ports": [80, 1900],
                    "protocols": ["HTTP", "UPnP"],
                    "risk_tier": 3,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-sch-03",
                    "vendor": "Epson",
                    "model": "WF-3820",
                    "device_type": "Printer",
                    "category": "IoT_Consumer",
                    "department": "Administration",
                    "ip": "192.168.40.21",
                    "mac": "00:26:AB:DC:12:34",
                    "firmware_version": "FL20I4",
                    "open_ports": [80, 443, 9100, 631],
                    "protocols": ["IPP", "HTTP", "SNMP"],
                    "risk_tier": 3,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-sch-04",
                    "vendor": "Netgear",
                    "model": "GS308E",
                    "device_type": "Industrial_Switch",
                    "category": "Network_Infrastructure",
                    "department": "Computer Lab",
                    "ip": "192.168.41.10",
                    "mac": "00:09:5B:E1:E2:E3",
                    "firmware_version": "V1.00.10ENB",
                    "open_ports": [80, 443, 23],
                    "protocols": ["HTTP", "TELNET"],
                    "risk_tier": 3,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "Student Information System", "ip": "192.168.40.5", "status": "Online"},
                {"name": "Active Directory Controller", "ip": "192.168.40.10", "status": "Online"},
            ],
            "citizen_impact_multiplier": 4.5,
            "description": "Government Model Higher Secondary School with computerized classrooms and student lab.",
        },
        "WaterPlant": {
            "name": "WaterPlant",
            "departments": ["Intake Pump Station", "Filtration Unit", "Chemical Treatment", "Distribution Grid", "SCADA Room"],
            "network_config": {
                "ip_range": "10.10.1.0/22",
                "vlans": {
                    "VLAN-101": {"name": "SCADA DMZ", "subnet": "10.10.1.0/24"},
                    "VLAN-102": {"name": "OT Process Network", "subnet": "10.10.2.0/24"},
                    "VLAN-103": {"name": "Corporate Office", "subnet": "10.10.3.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-103", "destination": "VLAN-102", "action": "DROP"},
                    {"source": "VLAN-101", "destination": "VLAN-102", "action": "ALLOW", "ports": [502, 102, 44818]},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-water-01",
                    "vendor": "Schneider Electric",
                    "model": "Modicon M221",
                    "device_type": "PLC",
                    "category": "OT_Critical",
                    "department": "Chemical Treatment",
                    "ip": "10.10.2.15",
                    "mac": "00:80:F4:7D:BC:90",
                    "firmware_version": "SV1.13.0.0",
                    "open_ports": [502, 80, 1025],
                    "protocols": ["Modbus", "HTTP", "EtherNet/IP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-water-02",
                    "vendor": "Siemens",
                    "model": "SIMATIC S7-1200",
                    "device_type": "PLC",
                    "category": "OT_Critical",
                    "department": "Filtration Unit",
                    "ip": "10.10.2.20",
                    "mac": "00:1B:1B:3E:4F:5A",
                    "firmware_version": "V4.5.0",
                    "open_ports": [102, 80, 443, 44818],
                    "protocols": ["S7Comm", "Modbus", "PROFINET", "HTTP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-water-03",
                    "vendor": "Yokogawa",
                    "model": "STARDOM FCN-100",
                    "device_type": "RTU",
                    "category": "OT_Critical",
                    "department": "Intake Pump Station",
                    "ip": "10.10.2.35",
                    "mac": "00:0B:B1:AC:DF:22",
                    "firmware_version": "R10.04",
                    "open_ports": [502, 80, 443, 2222],
                    "protocols": ["Modbus", "OPC-UA", "HTTP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-water-04",
                    "vendor": "Phoenix Contact",
                    "model": "FL SWITCH 1008",
                    "device_type": "Industrial_Switch",
                    "category": "OT_Critical",
                    "department": "SCADA Room",
                    "ip": "10.10.2.2",
                    "mac": "00:A0:45:90:88:11",
                    "firmware_version": "3.60 H",
                    "open_ports": [80, 443, 23, 161, 162],
                    "protocols": ["HTTP", "SNMP", "TELNET"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-water-05",
                    "vendor": "Axis Communications",
                    "model": "P3245-V",
                    "device_type": "CCTV_Camera",
                    "category": "IoT_Physical",
                    "department": "Intake Pump Station",
                    "ip": "10.10.1.55",
                    "mac": "00:40:8C:F9:A1:B2",
                    "firmware_version": "10.9.1",
                    "open_ports": [80, 443, 554],
                    "protocols": ["RTSP", "HTTP", "ONVIF", "VAPIX"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "SCADA Host HMI", "ip": "10.10.1.10", "status": "Online"},
                {"name": "Chlorine Dosing Loop", "ip": "10.10.2.15", "status": "Online"},
                {"name": "Clear Water Reservoir Level Control", "ip": "10.10.2.20", "status": "Online"},
            ],
            "citizen_impact_multiplier": 10.0,
            "description": "Metropolitan Municipal Water Treatment and Distribution Plant.",
        },
        "PowerStation": {
            "name": "PowerStation",
            "departments": ["Generation Hall", "Turbine Control Room", "Substation Automation", "Security Gateway"],
            "network_config": {
                "ip_range": "10.20.1.0/22",
                "vlans": {
                    "VLAN-201": {"name": "Process Control", "subnet": "10.20.1.0/24"},
                    "VLAN-202": {"name": "Substation Control", "subnet": "10.20.2.0/24"},
                    "VLAN-203": {"name": "Admin Network", "subnet": "10.20.3.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-203", "destination": "VLAN-201", "action": "DROP"},
                    {"source": "VLAN-202", "destination": "VLAN-201", "action": "ALLOW", "ports": [2404, 102]},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-power-01",
                    "vendor": "Siemens",
                    "model": "SIMATIC S7-1500",
                    "device_type": "PLC",
                    "category": "OT_Critical",
                    "department": "Generation Hall",
                    "ip": "10.20.1.12",
                    "mac": "00:1B:1B:4F:9A:90",
                    "firmware_version": "V2.9.2",
                    "open_ports": [102, 80, 443],
                    "protocols": ["S7Comm", "PROFINET", "HTTP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-power-02",
                    "vendor": "Landis+Gyr",
                    "model": "E350 Smart Meter",
                    "device_type": "Smart_Meter",
                    "category": "OT_Critical",
                    "department": "Substation Automation",
                    "ip": "10.20.2.45",
                    "mac": "00:1B:CE:22:D8:EF",
                    "firmware_version": "L8.5.2",
                    "open_ports": [1883, 8883, 4059, 2404],
                    "protocols": ["MQTT", "DLMS/COSEM", "IEC104"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-power-03",
                    "vendor": "ABB",
                    "model": "REF615",
                    "device_type": "Protection_Relay",
                    "category": "OT_Critical",
                    "department": "Substation Automation",
                    "ip": "10.20.2.30",
                    "mac": "00:30:DE:5B:6A:77",
                    "firmware_version": "V5.1",
                    "open_ports": [102, 502, 2404],
                    "protocols": ["IEC61850", "Modbus", "IEC104"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-power-04",
                    "vendor": "Moxa",
                    "model": "NPort 5150",
                    "device_type": "Serial_Server",
                    "category": "OT_Critical",
                    "department": "Turbine Control Room",
                    "ip": "10.20.1.25",
                    "mac": "00:90:E8:4A:5D:6C",
                    "firmware_version": "v2.10",
                    "open_ports": [23, 80, 950, 4800],
                    "protocols": ["TELNET", "HTTP", "RFC2217"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "Steam Turbine Controller HMI", "ip": "10.20.1.100", "status": "Online"},
                {"name": "Substation RTU Gateway", "ip": "10.20.2.5", "status": "Online"},
                {"name": "Grid Synchronization System", "ip": "10.20.1.12", "status": "Online"},
            ],
            "citizen_impact_multiplier": 10.0,
            "description": "Thermal Power Plant and Substation feeding industrial grids.",
        },
        "TrafficSignals": {
            "name": "TrafficSignals",
            "departments": ["City Center Command", "North Junctions", "South Junctions"],
            "network_config": {
                "ip_range": "172.16.10.0/24",
                "vlans": {
                    "VLAN-301": {"name": "ATC Traffic Controllers", "subnet": "172.16.10.0/24"},
                    "VLAN-302": {"name": "Surveillance CCTV", "subnet": "172.16.20.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-302", "destination": "VLAN-301", "action": "DROP"},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-traffic-01",
                    "vendor": "Intelight",
                    "model": "MaxTime Signal Controller",
                    "device_type": "Traffic_Controller",
                    "category": "OT_Critical",
                    "department": "North Junctions",
                    "ip": "172.16.10.10",
                    "mac": "00:1E:1D:A9:E8:77",
                    "firmware_version": "v2.5.4",
                    "open_ports": [80, 161, 5005],
                    "protocols": ["HTTP", "SNMP", "NTCIP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-traffic-02",
                    "vendor": "Dahua",
                    "model": "IPC-HDW2831T-AS",
                    "device_type": "CCTV_Camera",
                    "category": "IoT_Physical",
                    "department": "South Junctions",
                    "ip": "172.16.20.25",
                    "mac": "90:02:A9:AB:CD:E5",
                    "firmware_version": "V2.820.0000000.2.R",
                    "open_ports": [80, 443, 554, 37777],
                    "protocols": ["RTSP", "HTTP", "ONVIF"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-traffic-03",
                    "vendor": "Netgear",
                    "model": "GS308E",
                    "device_type": "Industrial_Switch",
                    "category": "Network_Infrastructure",
                    "department": "North Junctions",
                    "ip": "172.16.10.1",
                    "mac": "00:09:5B:C2:C3:C4",
                    "firmware_version": "V1.00.10ENB",
                    "open_ports": [80, 443, 23],
                    "protocols": ["HTTP", "TELNET"],
                    "risk_tier": 3,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "Central Traffic Management HMI", "ip": "172.16.10.5", "status": "Online"},
                {"name": "Emergency Preemption System", "ip": "172.16.10.8", "status": "Online"},
            ],
            "citizen_impact_multiplier": 7.0,
            "description": "Smart City Intelligent Traffic Light Control System.",
        },
        "Treasury": {
            "name": "Treasury",
            "departments": ["Main Vault", "IT & Server Room", "Pension Dispensation", "Public Desk"],
            "network_config": {
                "ip_range": "192.168.60.0/22",
                "vlans": {
                    "VLAN-60": {"name": "Finance Network", "subnet": "192.168.60.0/24"},
                    "VLAN-70": {"name": "Physical Security Network", "subnet": "192.168.61.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-60", "destination": "VLAN-70", "action": "ALLOW", "ports": [443]},
                    {"source": "VLAN-70", "destination": "VLAN-60", "action": "DROP"},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-treas-01",
                    "vendor": "ZKTeco",
                    "model": "SpeedFace-V5L",
                    "device_type": "Biometric",
                    "category": "IoT_Physical",
                    "department": "Main Vault",
                    "ip": "192.168.61.22",
                    "mac": "00:A0:C6:BB:AA:33",
                    "firmware_version": "6.0.12",
                    "open_ports": [80, 4370, 5005],
                    "protocols": ["HTTP", "ZKNET"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-treas-02",
                    "vendor": "Hikvision",
                    "model": "DS-7616NXI-I2",
                    "device_type": "NVR",
                    "category": "IoT_Physical",
                    "department": "IT & Server Room",
                    "ip": "192.168.61.10",
                    "mac": "BC:AD:28:FE:89:12",
                    "firmware_version": "V4.30.210 build 210625",
                    "open_ports": [80, 443, 8000, 554],
                    "protocols": ["HTTP", "RTSP", "ONVIF"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-treas-03",
                    "vendor": "HP",
                    "model": "LaserJet M428fdw",
                    "device_type": "Printer",
                    "category": "IoT_Consumer",
                    "department": "Pension Dispensation",
                    "ip": "192.168.60.40",
                    "mac": "3C:D9:2B:A1:B2:C3",
                    "firmware_version": "20210809",
                    "open_ports": [80, 443, 9100, 161],
                    "protocols": ["IPP", "HTTP", "SNMP"],
                    "risk_tier": 3,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "IFHRMS Core Ledger", "ip": "192.168.60.100", "status": "Online"},
                {"name": "CCTV Vault Surveillance Host", "ip": "192.168.61.10", "status": "Online"},
                {"name": "Biometric Access Control DB", "ip": "192.168.61.5", "status": "Online"},
            ],
            "citizen_impact_multiplier": 8.5,
            "description": "District Treasury Department handling pension deposits and state funds.",
        },
        "Railway": {
            "name": "Railway",
            "departments": ["Signalling Interlocking", "Station Control", "Public Platforms", "Power Feed Room"],
            "network_config": {
                "ip_range": "10.30.1.0/22",
                "vlans": {
                    "VLAN-401": {"name": "Signalling Interlocking", "subnet": "10.30.1.0/24"},
                    "VLAN-402": {"name": "Passenger Information & Ops", "subnet": "10.30.2.0/24"},
                    "VLAN-403": {"name": "Admin Network", "subnet": "10.30.3.0/24"},
                },
                "firewall_rules": [
                    {"source": "VLAN-402", "destination": "VLAN-401", "action": "DROP"},
                    {"source": "VLAN-403", "destination": "VLAN-401", "action": "DROP"},
                ],
            },
            "iot_devices": [
                {
                    "id": "dev-rail-01",
                    "vendor": "Siemens",
                    "model": "SIMATIC S7-300",
                    "device_type": "PLC",
                    "category": "OT_Critical",
                    "department": "Signalling Interlocking",
                    "ip": "10.30.1.15",
                    "mac": "00:1B:1B:E8:D2:12",
                    "firmware_version": "V3.3.1",
                    "open_ports": [102, 80],
                    "protocols": ["S7Comm", "PROFINET"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-rail-02",
                    "vendor": "Moxa",
                    "model": "EDS-408A",
                    "device_type": "Industrial_Switch",
                    "category": "OT_Critical",
                    "department": "Signalling Interlocking",
                    "ip": "10.30.1.5",
                    "mac": "00:90:E8:33:F2:1A",
                    "firmware_version": "V3.8",
                    "open_ports": [80, 443, 23, 161],
                    "protocols": ["HTTP", "HTTPS", "TELNET", "SNMP"],
                    "risk_tier": 1,
                    "is_on_asset_register": True,
                },
                {
                    "id": "dev-rail-03",
                    "vendor": "Axis Communications",
                    "model": "P3245-V",
                    "device_type": "CCTV_Camera",
                    "category": "IoT_Physical",
                    "department": "Public Platforms",
                    "ip": "10.30.2.50",
                    "mac": "00:40:8C:AA:BB:CC",
                    "firmware_version": "10.9.1",
                    "open_ports": [80, 443, 554],
                    "protocols": ["RTSP", "HTTP", "ONVIF"],
                    "risk_tier": 2,
                    "is_on_asset_register": True,
                },
            ],
            "critical_systems": [
                {"name": "Solid State Interlocking (SSI)", "ip": "10.30.1.15", "status": "Online"},
                {"name": "Train Collision Avoidance System (TCAS)", "ip": "10.30.1.20", "status": "Online"},
                {"name": "Passenger Information System Controller", "ip": "10.30.2.10", "status": "Online"},
            ],
            "citizen_impact_multiplier": 9.8,
            "description": "Central Signaling and Interlocking System for Regional Railways.",
        },
    }

    @classmethod
    def get_environment(cls, name: str) -> Optional[Dict[str, Any]]:
        """
        Get the configuration dictionary of a specific environment.
        """
        env = cls.ENVIRONMENTS.get(name)
        if not env:
            logger.warning(f"Environment '{name}' not found in DigitalTwin catalog.")
            return None
        return env

    @classmethod
    def get_device_inventory(cls, name: str) -> List[Dict[str, Any]]:
        """
        Get the list of IoT/OT devices in a specified environment.
        """
        env = cls.get_environment(name)
        if not env:
            return []
        return env.get("iot_devices", [])

    @classmethod
    def assess_risk(cls, name: str) -> Dict[str, Any]:
        """
        Performs a virtual risk assessment on the environment using configuration metrics.
        """
        env = cls.get_environment(name)
        if not env:
            return {"error": f"Environment {name} not found"}

        devices = env.get("iot_devices", [])
        critical_systems = env.get("critical_systems", [])
        multiplier = env.get("citizen_impact_multiplier", 1.0)

        # Base scoring calculation
        risk_score = 0.0
        vulnerabilities_identified = 0
        insecure_protocols_count = 0
        unsegmented_hosts = 0

        # Assess security of network rules
        rules = env.get("network_config", {}).get("firewall_rules", [])
        has_broad_allow = any(r.get("action") == "ALLOW" and r.get("source") == "VLAN-40" for r in rules)
        
        for dev in devices:
            # High risk tier, open ports (especially unencrypted like telnet/http)
            ports = dev.get("open_ports", [])
            protocols = dev.get("protocols", [])
            
            score_contrib = 5.0
            if dev.get("risk_tier") == 1:
                score_contrib += 15.0  # Critical OT tier gets weighed heavily if exposed
            
            # Protocols check
            unencrypted = {"HTTP", "TELNET", "RTSP", "ZKNET", "SNMP", "Modbus", "S7Comm"}
            dev_unencrypted = [p for p in protocols if p in unencrypted]
            insecure_protocols_count += len(dev_unencrypted)
            score_contrib += len(dev_unencrypted) * 8.0

            # Default interfaces open
            if 23 in ports or 80 in ports:
                vulnerabilities_identified += 1
                score_contrib += 10.0
                
            risk_score += score_contrib

        # Normalization and weighting
        base_risk = (risk_score / max(len(devices), 1)) + (len(critical_systems) * 5.0)
        if has_broad_allow:
            base_risk += 15.0
            
        final_score = min(max(base_risk, 10.0) * multiplier / 10.0, 100.0)

        if final_score >= 80.0:
            level = "CRITICAL"
        elif final_score >= 60.0:
            level = "HIGH"
        elif final_score >= 40.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "environment": name,
            "overall_score": round(final_score, 2),
            "risk_level": level,
            "vulnerabilities_count": vulnerabilities_identified,
            "insecure_protocols_detected": insecure_protocols_count,
            "critical_systems_exposed": len(critical_systems),
            "citizen_impact_multiplier": multiplier,
            "assessment_timestamp": datetime.datetime.utcnow().isoformat(),
            "recommendations": cls._generate_env_recommendations(name, level)
        }

    @classmethod
    def simulate_compromise(cls, name: str, device_type: str) -> Dict[str, Any]:
        """
        Simulate the impact of a compromise of a specific device type in the environment.
        """
        env = cls.get_environment(name)
        if not env:
            return {"error": f"Environment {name} not found"}

        devices = [d for d in env.get("iot_devices", []) if d["device_type"] == device_type]
        if not devices:
            return {
                "success": False,
                "message": f"No devices of type '{device_type}' found in {name} to simulate compromise."
            }

        target_device = devices[0]
        multiplier = env.get("citizen_impact_multiplier", 1.0)
        
        # Calculate lateral movement paths based on environment network config
        lateral_movement = []
        affected_critical_systems = []
        severity = "MEDIUM"
        impact_score = 30.0

        if target_device["category"] == "OT_Critical":
            severity = "CRITICAL"
            impact_score = 90.0
            # Compromising critical OT devices easily affects all critical systems
            affected_critical_systems = [s["name"] for s in env.get("critical_systems", [])]
            lateral_movement.append("Pivot from process controller directly to physical actuators / valves")
            lateral_movement.append("Hijack HMI operator communications via protocol injection")
        else:
            # Pivot potential
            vlans = env.get("network_config", {}).get("vlans", {})
            rules = env.get("network_config", {}).get("firewall_rules", [])
            
            # Simple simulation logic for lateral pivots
            lateral_movement.append("Obtain local network credentials from device memory dump")
            if any(r.get("action") == "ALLOW" and r.get("source") != r.get("destination") for r in rules):
                lateral_movement.append("Pivot across VLAN segments via allowed firewall exception ports")
                affected_critical_systems.append(env.get("critical_systems", [{}])[0].get("name", "Gateway Admin"))
                severity = "HIGH"
                impact_score = 65.0
            else:
                lateral_movement.append("Perform subnet ARP poisoning and passive traffic monitoring")
                severity = "MEDIUM"
                impact_score = 45.0

        final_citizen_impact = min(impact_score * multiplier / 10.0, 100.0)

        # Generate simulation timeline
        timeline = [
            {"time_offset": "0m", "event": f"Initial access gained on {target_device['vendor']} {target_device['model']} ({target_device['ip']}) via firmware vulnerability."},
            {"time_offset": "5m", "event": "Established persistent command-and-control connection from internal node."},
            {"time_offset": "15m", "event": "Local network scanning initiated; scanned open ports on active VLAN segment."},
            {"time_offset": "30m", "event": f"Lateral movement attempted to target critical components. Affected: {', '.join(affected_critical_systems) if affected_critical_systems else 'None'}."},
        ]

        return {
            "success": True,
            "environment": name,
            "compromised_device": {
                "id": target_device["id"],
                "vendor": target_device["vendor"],
                "model": target_device["model"],
                "ip": target_device["ip"],
                "category": target_device["category"]
            },
            "severity": severity,
            "citizen_impact_score": round(final_citizen_impact, 2),
            "lateral_movement_paths": lateral_movement,
            "affected_critical_systems": affected_critical_systems,
            "timeline": timeline,
            "remediation_actions": [
                f"Isolate IP {target_device['ip']} on the network switch level.",
                "Verify and update firmware to plug known exploit vectors.",
                "Revoke and rotate credentials used or stored on this device.",
                "Deploy strict access-control lists on transit firewall interfaces."
            ]
        }

    @classmethod
    def get_all_environments(cls) -> List[Dict[str, Any]]:
        """
        Retrieve basic metadata for all configured environments.
        """
        all_envs = []
        for name, config in cls.ENVIRONMENTS.items():
            all_envs.append({
                "name": name,
                "description": config.get("description"),
                "device_count": len(config.get("iot_devices", [])),
                "critical_systems_count": len(config.get("critical_systems", [])),
                "citizen_impact_multiplier": config.get("citizen_impact_multiplier"),
                "ip_range": config.get("network_config", {}).get("ip_range")
            })
        return all_envs

    @staticmethod
    def _generate_env_recommendations(name: str, level: str) -> List[str]:
        """
        Helper to return contextual recommendations based on environment risk profile.
        """
        recs = [
            "Implement multi-factor authentication on all administrative gateways.",
            "Enable network-level protocol filtering for standard OT protocols."
        ]
        if level in ["CRITICAL", "HIGH"]:
            recs.insert(0, f"Critical risk detected: Isolate the {name} process control segment immediately.")
            recs.append("Configure strict egress filtering; block arbitrary internet access from field instrumentation.")
        if name in ["WaterPlant", "PowerStation", "Railway"]:
            recs.append("Review PLC configuration safety interlocks to prevent physical over-pressure/voltage scenarios.")
        elif name == "Hospital":
            recs.append("Verify PACS imaging traffic encryption and EMR DB firewall isolation rules.")
        return recs
