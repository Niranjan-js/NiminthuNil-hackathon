import logging
from typing import Dict, Any, List, Optional
import re

logger = logging.getLogger("niravan.ot_iot.ics_attack_mapper")


class ICSAttackMapper:
    """
    Maps ICS security alerts, protocol behaviors, and threat logs
    to the MITRE ATT&CK for ICS framework (35+ techniques, T0800 - T0891).
    """

    MITRE_ICS_TECHNIQUES: Dict[str, Dict[str, Any]] = {
        "T0801": {"name": "Alarm Suppression", "tactic": "Inhibit Response Function", "description": "Preventing alarm notifications from reaching operators or SCADA HMI."},
        "T0802": {"name": "Automated Compromise", "tactic": "Execution", "description": "Using automated scripts or worms to compromise multiple OT targets."},
        "T0803": {"name": "Block Command Transmission", "tactic": "Inhibit Response Function", "description": "Interfering with the transmission of control commands to devices."},
        "T0804": {"name": "Block Reporting Message", "tactic": "Inhibit Response Function", "description": "Blocking feedback updates or status reports from field controllers."},
        "T0805": {"name": "Brute Force", "tactic": "Credential Access", "description": "Attempting multiple password combinations to gain access to control interfaces."},
        "T0806": {"name": "Change Operating Mode", "tactic": "Impair Process Control", "description": "Forcing controllers into Halt, Program, or Safe state to disrupt operations."},
        "T0807": {"name": "Command Injection", "tactic": "Execution", "description": "Injecting unauthorized control commands (e.g. Modbus write) directly into field networks."},
        "T0808": {"name": "Common Application Port Bypass", "tactic": "Evasion", "description": "Wrapping unauthorized traffic in standard protocols to bypass firewalls."},
        "T0809": {"name": "Data Destruction", "tactic": "Impact", "description": "Permanently deleting operational, config, or safety database parameters."},
        "T0810": {"name": "Default Credentials", "tactic": "Credential Access", "description": "Exploiting factory-default passwords left unchanged on devices."},
        "T0811": {"name": "Detect Operating Mode", "tactic": "Discovery", "description": "Querying controllers to determine if they are in Run or Program mode."},
        "T0812": {"name": "Device Configuration Discovery", "tactic": "Discovery", "description": "Retrieving controller configurations, I/O maps, and serial numbers."},
        "T0813": {"name": "Execution Flow Modulation", "tactic": "Execution", "description": "Altering program execution sequences on PLCs."},
        "T0814": {"name": "Exploitation for Evasion", "tactic": "Evasion", "description": "Using software defects to disable or bypass security logs or intrusion detection."},
        "T0815": {"name": "Exploitation of Remote Services", "tactic": "Initial Access", "description": "Exploiting network vulnerabilities in services like SSH, HTTP, or VPN."},
        "T0816": {"name": "Hardcoded Credentials", "tactic": "Credential Access", "description": "Leveraging vendor backdoors or hardcoded passwords in firmware binary."},
        "T0817": {"name": "I/O Image Manipulation", "tactic": "Impair Process Control", "description": "Directly changing input/output registers in PLC memory layout."},
        "T0818": {"name": "Impair Process Control", "tactic": "Impair Process Control", "description": "Sending multiple commands to force physical equipment past safety ranges."},
        "T0819": {"name": "Insecure Industrial Protocols", "tactic": "Initial Access", "description": "Exploiting lack of authentication in legacy protocols (Modbus, S7, DNP3)."},
        "T0820": {"name": "Lateral Movement", "tactic": "Lateral Movement", "description": "Moving between devices on the control network (VLAN routing bypass)."},
        "T0821": {"name": "Loss of Control", "tactic": "Impact", "description": "Disabling operators' ability to issue commands or control physical processes."},
        "T0822": {"name": "Loss of Safety", "tactic": "Impact", "description": "Disabling safety Instrumented Systems (SIS) leading to unsafe operating conditions."},
        "T0823": {"name": "Man-in-the-Middle", "tactic": "Lateral Movement", "description": "Intercepting and modifying traffic on transit switches or gateways."},
        "T0824": {"name": "Masquerading", "tactic": "Evasion", "description": "Spoofing IP/MAC addresses of valid HMIs or engineering workstations."},
        "T0825": {"name": "Modify Control Logic", "tactic": "Impair Process Control", "description": "Overwriting program control blocks or ladder logic blocks in PLC memory."},
        "T0826": {"name": "Modify Parameter", "tactic": "Impair Process Control", "description": "Changing variable values, setpoints, or calibration values on field devices."},
        "T0827": {"name": "Monitor Process State", "tactic": "Discovery", "description": "Sniffing telemetry or poll replies to understand physical workflows."},
        "T0828": {"name": "Network Connection Discovery", "tactic": "Discovery", "description": "Scanning ports to find active connections and listening services."},
        "T0829": {"name": "Network Sniffing", "tactic": "Collection", "description": "Capturing cleartext protocol frames to steal commands or configurations."},
        "T0830": {"name": "Point-to-Point Serial Links", "tactic": "Lateral Movement", "description": "Exploiting connected serial networks (RS-232/485) to pivot across links."},
        "T0831": {"name": "Program Upload", "tactic": "Collection", "description": "Uploading ladder logic code from the PLC to reverse-engineer process flow."},
        "T0832": {"name": "Program Download", "tactic": "Execution", "description": "Downloading malicious control logic blocks to overwrite PLC runtime state."},
        "T0833": {"name": "Project File Infection", "tactic": "Persistence", "description": "Injecting scripts/macro code inside engineering project design files."},
        "T0834": {"name": "Remote System Discovery", "tactic": "Discovery", "description": "Discovering active IP addresses and hostname lists on secondary subnets."},
        "T0835": {"name": "Replication Across Removable Media", "tactic": "Lateral Movement", "description": "Using USB storage devices to cross air-gapped network boundaries."},
        "T0836": {"name": "Rogue Master", "tactic": "Command and Control", "description": "Deploying a rogue HMI or master terminal emulator to poll and control slaves."},
        "T0837": {"name": "Rootkit", "tactic": "Persistence", "description": "Installing low-level kernel or firmware modules to hide malicious components."},
        "T0839": {"name": "Scripting", "tactic": "Execution", "description": "Running python, bash, or PowerShell scripts on gateway OS hosts."},
        "T0840": {"name": "Service Stop", "tactic": "Inhibit Response Function", "description": "Stopping essential system services, safety services, or syslog agents."},
        "T0841": {"name": "Spoof Reporting Message", "tactic": "Inhibit Response Function", "description": "Sending falsified feedback data to SCADA to mask physical malfunctions."},
        "T0842": {"name": "System Firmware", "tactic": "Persistence", "description": "Flashing malicious firmware onto device microcontrollers."},
        "T0843": {"name": "Unauthorized Command Message", "tactic": "Command and Control", "description": "Sending raw frames directly to devices to perform unscheduled operations."},
        "T0844": {"name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Using legitimate operator credentials acquired via social engineering or dumps."},
        "T0846": {"name": "Wireless Sniffing", "tactic": "Discovery", "description": "Intercepting cleartext 802.11, Zigbee, or WirelessHART frames in proximity."},
        "T0891": {"name": "Ransomware Execution", "tactic": "Impact", "description": "Encrypting process data databases and holding access keys for ransom."}
    }

    TACTIC_MAP: Dict[str, List[str]] = {
        "Initial Access": ["T0815", "T0819"],
        "Execution": ["T0802", "T0807", "T0813", "T0832", "T0839"],
        "Persistence": ["T0833", "T0837", "T0842"],
        "Credential Access": ["T0805", "T0810", "T0816"],
        "Discovery": ["T0811", "T0812", "T0827", "T0828", "T0834", "T0846"],
        "Lateral Movement": ["T0820", "T0823", "T0830", "T0835"],
        "Collection": ["T0829", "T0831"],
        "Command and Control": ["T0836", "T0843"],
        "Defense Evasion": ["T0808", "T0814", "T0824", "T0844"],
        "Inhibit Response Function": ["T0801", "T0803", "T0804", "T0840", "T0841"],
        "Impair Process Control": ["T0806", "T0817", "T0818", "T0825", "T0826"],
        "Impact": ["T0809", "T0821", "T0822", "T0891"]
    }

    PROTOCOL_TECHNIQUE_MAP: Dict[str, List[str]] = {
        "MODBUS": ["T0807", "T0812", "T0817", "T0819", "T0826", "T0827", "T0843"],
        "S7COMM": ["T0806", "T0807", "T0811", "T0819", "T0825", "T0831", "T0832", "T0843"],
        "IEC104": ["T0803", "T0804", "T0807", "T0819", "T0841", "T0843"],
        "DNP3": ["T0804", "T0807", "T0819", "T0826", "T0843"],
        "SNMP": ["T0812", "T0826", "T0828", "T0843"],
        "HTTP": ["T0805", "T0810", "T0815", "T0828"],
        "RTSP": ["T0829", "T0843"],
        "ZKNET": ["T0807", "T0843"]
    }

    @classmethod
    def map_to_techniques(cls, description: str, protocol: str) -> List[Dict[str, Any]]:
        """
        Map a threat description text and active network protocol to matching MITRE ICS technique definitions.
        """
        matched_ids = set()
        desc_lower = description.lower()
        proto_upper = protocol.upper().strip()

        # Keyword mapping rules
        rules = {
            "alarm": "T0801",
            "block command": "T0803",
            "block report": "T0804",
            "brute-force": "T0805",
            "brute force": "T0805",
            "operating mode": "T0806",
            "inject": "T0807",
            "write register": "T0807",
            "destruction": "T0809",
            "default password": "T0810",
            "default credentials": "T0810",
            "config discovery": "T0812",
            "lateral": "T0820",
            "pivot": "T0820",
            "spoof": "T0824",
            "ladder logic": "T0825",
            "modify control logic": "T0825",
            "parameter": "T0826",
            "setpoint": "T0826",
            "sniff": "T0829",
            "download": "T0832",
            "firmware": "T0842",
            "ransomware": "T0891",
            "locked": "T0891"
        }

        for keyword, tech_id in rules.items():
            if keyword in desc_lower:
                matched_ids.add(tech_id)

        # Intersect with protocol mapping recommendations
        if proto_upper in cls.PROTOCOL_TECHNIQUE_MAP:
            # If the description contains generic indicator keywords, cross check with typical protocol techniques
            for tech_id in cls.PROTOCOL_TECHNIQUE_MAP[proto_upper]:
                # Add if description contains general trigger words like "command", "unauthenticated", "write"
                if "command" in desc_lower or "write" in desc_lower or "read" in desc_lower:
                    matched_ids.add(tech_id)

        # Build detailed results
        results = []
        for tech_id in sorted(matched_ids):
            tech = cls.get_technique(tech_id)
            if tech:
                results.append(tech)

        return results

    @classmethod
    def get_technique(cls, tech_id: str) -> Optional[Dict[str, Any]]:
        """
        Get name, tactic, and description for a specific technique ID.
        """
        tech = cls.MITRE_ICS_TECHNIQUES.get(tech_id)
        if not tech:
            return None
        return {
            "technique_id": tech_id,
            "name": tech["name"],
            "tactic": tech["tactic"],
            "description": tech["description"]
        }

    @classmethod
    def get_techniques_by_tactic(cls, tactic: str) -> List[Dict[str, Any]]:
        """
        Get all technique definitions that belong to the specified tactic.
        """
        tactic_clean = tactic.strip()
        matched = []
        for tech_id, details in cls.MITRE_ICS_TECHNIQUES.items():
            if details["tactic"].lower() == tactic_clean.lower():
                matched.append({
                    "technique_id": tech_id,
                    "name": details["name"],
                    "tactic": details["tactic"],
                    "description": details["description"]
                })
        return matched

    @classmethod
    def generate_attack_matrix(cls, attacks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a MITRE ICS Attack Matrix representation based on a list of executed attacks.
        Categorizes occurrences by tactic groups.
        """
        matrix = {tactic: [] for tactic in cls.TACTIC_MAP.keys()}
        triggered_techniques = set()

        for attack in attacks:
            # Attack item can have 'mitre_id', 'technique_id', or description and protocol to map
            tech_id = attack.get("mitre_id", attack.get("technique_id"))
            
            if not tech_id and "description" in attack:
                mapped = cls.map_to_techniques(attack["description"], attack.get("protocol", "TCP"))
                if mapped:
                    tech_id = mapped[0]["technique_id"]

            if tech_id:
                tech_details = cls.get_technique(tech_id)
                if tech_details:
                    triggered_techniques.add((tech_id, tech_details["name"], tech_details["tactic"]))

        # Populate matrix cells
        for tech_id, name, tactic in triggered_techniques:
            if tactic in matrix:
                matrix[tactic].append({
                    "technique_id": tech_id,
                    "name": name
                })
            else:
                # Tactic might not be in standard map (dynamic fallback)
                matrix.setdefault(tactic, []).append({
                    "technique_id": tech_id,
                    "name": name
                })

        return {
            "matrix": {k: v for k, v in matrix.items() if v},  # filter out empty tactics
            "summary": {
                "total_tactics_triggered": sum(1 for v in matrix.values() if v),
                "total_techniques_triggered": len(triggered_techniques),
                "triggered_ids": sorted([t[0] for t in triggered_techniques])
            }
        }
