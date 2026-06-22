import logging
import datetime
import random
from typing import Dict, Any, List, Optional

try:
    from backend.ot_iot.digital_twin import DigitalTwin
except ImportError:
    from digital_twin import DigitalTwin

logger = logging.getLogger("niravan.ot_iot.attack_emulator")


class OTIoTAttackEmulator:
    """
    Emulates advanced cyber-attacks targeting OT/IoT critical infrastructures.
    Simulates stages, logs, damage, citizen impact, and recommends defenses.
    """

    ATTACK_SCENARIOS: Dict[str, Dict[str, Any]] = {
        "CCTV Botnet": {
            "name": "CCTV Botnet",
            "description": "Exploitation of weak/default credentials on security cameras to enrol them into a DDoS botnet.",
            "target_device_type": "CCTV_Camera",
            "base_financial_damage": 12000.0,
            "base_citizen_impact": 35.0,
            "mitre_tactic": "TA0107 - Command and Control",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Reconnaissance",
                    "description": "Mass scanning of subnet for open HTTP port 80 and RTSP port 554.",
                    "mitre_id": "T0843",
                    "log_pattern": "Security camera web interface scanned by external IP."
                },
                {
                    "stage_id": 2,
                    "name": "Initial Access",
                    "description": "Brute-forcing admin credentials using common default passwords (admin/admin, admin/12345).",
                    "mitre_id": "T0812",
                    "log_pattern": "Authentication failed multiple times followed by successful login for user 'admin' from anomalous IP."
                },
                {
                    "stage_id": 3,
                    "name": "Persistence",
                    "description": "Downloading malicious binary (Mirai variant) via unencrypted HTTP and executing shell command.",
                    "mitre_id": "T0868",
                    "log_pattern": "Unusual outbound connection to remote IP downloading shell script 'cam_infect.sh'."
                },
                {
                    "stage_id": 4,
                    "name": "Impact (DDoS)",
                    "description": "Launching volumetric UDP/TCP floods from the camera towards external state servers.",
                    "mitre_id": "T0819",
                    "log_pattern": "High volume UDP flood detected originating from CCTV camera interface. Bandwidth saturated."
                }
            ]
        },
        "Hospital Ransomware": {
            "name": "Hospital Ransomware",
            "description": "Intrusion targeting medical networks, leading to lateral movement and ransomware execution on EMR database.",
            "target_device_type": "Patient_Monitor",
            "base_financial_damage": 180000.0,
            "base_citizen_impact": 95.0,
            "mitre_tactic": "TA0109 - Impact",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Initial Access",
                    "description": "Exploiting legacy operating system software on medical monitoring stations or remote gateways.",
                    "mitre_id": "T0820",
                    "log_pattern": "Exploitation attempt of CVE-2019-11812 (URGENT/11) detected on patient monitor segment."
                },
                {
                    "stage_id": 2,
                    "name": "Lateral Movement",
                    "description": "Using SMB protocol vulnerabilities to pivot from guest devices to EMR servers.",
                    "mitre_id": "T0808",
                    "log_pattern": "Anomalous SMBv1 traffic detected between Patient Monitor segment and EMR Database Server."
                },
                {
                    "stage_id": 3,
                    "name": "Inhibit Response Function",
                    "description": "Disabling anti-virus services and security event logging on host systems.",
                    "mitre_id": "T0849",
                    "log_pattern": "Windows Event Log service terminated unexpectedly on EMR Database Server."
                },
                {
                    "stage_id": 4,
                    "name": "Ransomware Execution",
                    "description": "Symmetric encryption of medical databases and display of extortion instructions.",
                    "mitre_id": "T0891",
                    "log_pattern": "Rapid file modification activity. Extension changed to '.niravan_locked' on EMR files."
                }
            ]
        },
        "Water Plant PLC Sabotage": {
            "name": "Water Plant PLC Sabotage",
            "description": "Unauthenticated Modbus command injection to alter chlorine dosing levels and pump rates, threatening water safety.",
            "target_device_type": "PLC",
            "base_financial_damage": 75000.0,
            "base_citizen_impact": 100.0,
            "mitre_tactic": "TA0108 - Impair Process Control",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Reconnaissance",
                    "description": "Passive sniffing of SCADA Modbus TCP communications to map register addresses.",
                    "mitre_id": "T0842",
                    "log_pattern": "Continuous Modbus TCP query requests for holding registers (40001 - 40100) from unexpected IP."
                },
                {
                    "stage_id": 2,
                    "name": "Impair Process Control",
                    "description": "Injecting forged write commands (Modbus Function Code 16) to overwrite chemical pump limits.",
                    "mitre_id": "T0855",
                    "log_pattern": "Modbus FC16 (Write Multiple Registers) issued to PLC on Register 40045 (Chlorine Dosing Rate) by non-HMI node."
                },
                {
                    "stage_id": 3,
                    "name": "Modify Parameter",
                    "description": "Altering safety parameters to prevent emergency alarm triggers.",
                    "mitre_id": "T0836",
                    "log_pattern": "PLC Safety Interlock values modified. Alarm threshold for high chlorine increased from 2.0 ppm to 15.0 ppm."
                },
                {
                    "stage_id": 4,
                    "name": "Damage to Property",
                    "description": "Forcing chemical dosing pumps to run continuously while masking status on the SCADA HMI.",
                    "mitre_id": "T0879",
                    "log_pattern": "Chlorine concentration levels exceeds critical limits. Sensor reported 10.5 ppm. SCADA display manipulation active."
                }
            ]
        },
        "Power Grid IEC104 Attack": {
            "name": "Power Grid IEC104 Attack",
            "description": "Interception and manipulation of IEC 60870-5-104 commands to open protective relays, causing local blackout.",
            "target_device_type": "Protection_Relay",
            "base_financial_damage": 250000.0,
            "base_citizen_impact": 98.0,
            "mitre_tactic": "TA0108 - Impair Process Control",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Initial Access",
                    "description": "Compromising external cellular RTUs or VPN connection to obtain SCADA transit access.",
                    "mitre_id": "T0822",
                    "log_pattern": "VPN connection established for engineer account 'guest_op' outside normal working hours."
                },
                {
                    "stage_id": 2,
                    "name": "Spoof Reporting Message",
                    "description": "Manipulating status responses to make the grid appear stable.",
                    "mitre_id": "T0856",
                    "log_pattern": "IEC-104 APDU sequence mismatch detected. Out-of-order ASDU status reports received from Substation RTU."
                },
                {
                    "stage_id": 3,
                    "name": "Command Injection",
                    "description": "Injecting single command (ASDU Type 45) to trip circuit breakers on Substation Relay.",
                    "mitre_id": "T0807",
                    "log_pattern": "IEC-104 Command Code 45 (Single Command) execution: OPEN breaker for Feeder Line 3."
                },
                {
                    "stage_id": 4,
                    "name": "Loss of Power",
                    "description": "Tripping feeder circuits leading to blackout in residential grid and cascading infrastructure failure.",
                    "mitre_id": "T0809",
                    "log_pattern": "Critical Alarm: Loss of Power on Feeder 3. Current drops to 0A. Citizen blackout initiated."
                }
            ]
        },
        "Traffic Signal Override": {
            "name": "Traffic Signal Override",
            "description": "Exploiting unencrypted NTCIP commands over SNMP to force traffic signals at an intersection into a permanent green conflict state.",
            "target_device_type": "Traffic_Controller",
            "base_financial_damage": 40000.0,
            "base_citizen_impact": 70.0,
            "mitre_tactic": "TA0109 - Impact",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Discovery",
                    "description": "Scanning network segment for SNMP traffic and reading MIB parameters.",
                    "mitre_id": "T0846",
                    "log_pattern": "SNMP GET requests mapping OID 1.3.6.1.4.1.1206 (NTCIP device parameters) from unauthorized node."
                },
                {
                    "stage_id": 2,
                    "name": "Initial Access",
                    "description": "Exploiting cleartext community strings ('public' / 'private') to authenticate.",
                    "mitre_id": "T0812",
                    "log_pattern": "Successful SNMP write session opened using default community string 'private'."
                },
                {
                    "stage_id": 3,
                    "name": "Impair Process Control",
                    "description": "Sending SNMP SET commands to alter timing configuration and bypass collision safety interlocks.",
                    "mitre_id": "T0855",
                    "log_pattern": "SNMP SET issued to OID 1.3.6.1.4.1.1206.4.2.1 (Phase Control): Set North-South and East-West to GREEN."
                },
                {
                    "stage_id": 4,
                    "name": "Loss of Control",
                    "description": "Forcing intersection controllers into conflict mode, causing signals to blink yellow or green in all directions.",
                    "mitre_id": "T0827",
                    "log_pattern": "Hardware Conflict Monitor triggered: Signal Controller entered FAILSAFE FLASHING mode due to conflicting green signals."
                }
            ]
        },
        "Treasury ATM Jackpotting": {
            "name": "Treasury ATM Jackpotting",
            "description": "Physical or network bypass of ATM/Safe access controllers to trigger cash dispensation or lock bypass.",
            "target_device_type": "Biometric",
            "base_financial_damage": 110000.0,
            "base_citizen_impact": 65.0,
            "mitre_tactic": "TA0109 - Impact",
            "stages": [
                {
                    "stage_id": 1,
                    "name": "Initial Access",
                    "description": "Locally connecting to physical controller ports or access points by breaking physical casing.",
                    "mitre_id": "T0812",
                    "log_pattern": "Tamper sensor alert: Device enclosure opened on biometric safe terminal."
                },
                {
                    "stage_id": 2,
                    "name": "Privilege Escalation",
                    "description": "Exploiting API buffer overflow on biometric controllers to gain root shell.",
                    "mitre_id": "T0890",
                    "log_pattern": "Heap overflow pattern detected on terminal TCP Port 4370. Root shell spawned."
                },
                {
                    "stage_id": 3,
                    "name": "Command Injection",
                    "description": "Sending unlock signals or raw command packets directly to lock actuators.",
                    "mitre_id": "T0855",
                    "log_pattern": "Unauthenticated ZKNET command packet injected: Release Lock Solenoid (Duration: 300s)."
                },
                {
                    "stage_id": 4,
                    "name": "Loss of Containment",
                    "description": "Uncontrolled opening of physical asset vaults, resulting in cash theft and service disruption.",
                    "mitre_id": "T0811",
                    "log_pattern": "Physical vault open alert. High-value safe access recorded without authorized biometric verification."
                }
            ]
        }
    }

    @classmethod
    def emulate(cls, scenario_name: str, environment: str) -> Dict[str, Any]:
        """
        Simulates the execution of the specified attack scenario against an environment.
        """
        scenario = cls.ATTACK_SCENARIOS.get(scenario_name)
        if not scenario:
            logger.error(f"Scenario '{scenario_name}' not found.")
            return {"error": f"Scenario '{scenario_name}' not found."}

        env_config = DigitalTwin.get_environment(environment)
        if not env_config:
            logger.error(f"Environment '{environment}' not found in DigitalTwin.")
            return {"error": f"Environment '{environment}' not found."}

        # Check if environment contains the target device type
        target_dev_type = scenario["target_device_type"]
        matching_devices = [d for d in env_config.get("iot_devices", []) if d["device_type"] == target_dev_type]
        device_compromised = None
        
        if matching_devices:
            device_compromised = matching_devices[0]
            status = "COMPLETED"
        else:
            status = "PARTIAL_COMPATIBILITY_EXECUTED"
            logger.warning(f"Target device '{target_dev_type}' not present in '{environment}'. Simulating default execution.")

        logs = []
        timeline = []
        base_time = datetime.datetime.utcnow()

        # Execute stages
        for stage in scenario["stages"]:
            offset_sec = (stage["stage_id"] - 1) * 300 + random.randint(15, 60)
            timestamp = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
            
            # Populate log message
            target_ip = device_compromised["ip"] if device_compromised else "10.99.99.99"
            log_entry = f"[{timestamp}] [CRITICAL] [NIRAVAN-EMU] - MITRE: {stage['mitre_id']} - {stage['log_pattern']} (Target: {target_ip})"
            
            logs.append(log_entry)
            timeline.append({
                "stage": stage["name"],
                "mitre_id": stage["mitre_id"],
                "timestamp": timestamp,
                "description": stage["description"],
                "activity_log": log_entry
            })

        # Calculate damages
        damage_estimates = cls.calculate_damage_estimate(scenario, env_config)

        # Generate detection recommendations
        recommendations = cls.generate_detection_recommendations(scenario)

        return {
            "scenario_name": scenario_name,
            "environment": environment,
            "status": status,
            "target_device_compromised": {
                "vendor": device_compromised["vendor"] if device_compromised else "Unknown",
                "model": device_compromised["model"] if device_compromised else "Generic OT Host",
                "ip": device_compromised["ip"] if device_compromised else "Unknown"
            } if device_compromised else None,
            "mitre_tactic": scenario["mitre_tactic"],
            "logs": logs,
            "timeline": timeline,
            "damage_estimates": damage_estimates,
            "citizen_impact_score": damage_estimates["citizen_impact_score"],
            "detection_recommendations": recommendations
        }

    @classmethod
    def calculate_damage_estimate(cls, scenario: Dict[str, Any], env_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates financial and citizen impact estimates based on the scenario and environment.
        """
        base_financial = scenario.get("base_financial_damage", 10000.0)
        base_citizen = scenario.get("base_citizen_impact", 50.0)
        multiplier = env_config.get("citizen_impact_multiplier", 1.0)
        critical_systems = len(env_config.get("critical_systems", []))

        # Formula logic
        escalation_factor = 1.0 + (critical_systems * 0.15)
        
        financial_damage = base_financial * multiplier * escalation_factor
        citizen_impact = min(base_citizen * multiplier, 100.0)

        # Randomize slightly for realistic simulation variance
        financial_damage = round(financial_damage * random.uniform(0.9, 1.1), 2)
        citizen_impact = round(citizen_impact, 2)

        if citizen_impact >= 80.0:
            severity = "CRITICAL"
        elif citizen_impact >= 60.0:
            severity = "HIGH"
        elif citizen_impact >= 35.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "base_financial_damage": base_financial,
            "estimated_financial_loss_inr": financial_damage,
            "citizen_impact_score": citizen_impact,
            "impact_severity": severity,
            "affected_critical_nodes_count": critical_systems,
            "calculation_metadata": {
                "impact_multiplier": multiplier,
                "escalation_factor": round(escalation_factor, 2)
            }
        }

    @classmethod
    def generate_detection_recommendations(cls, scenario: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations to detect the stages of the scenario.
        """
        scenario_name = scenario.get("name", "")
        recs = [
            "Implement anomalous login threshold alerts (brute force detection).",
            "Monitor outbound connections to non-whitelisted external IPs."
        ]

        if "PLC" in scenario_name or "Water" in scenario_name:
            recs.extend([
                "Deploy Modbus TCP Deep Packet Inspection (DPI) to monitor unauthorized function codes.",
                "Enforce multi-engineer authentication keys on HMI for PLC register changes.",
                "Establish network baselining for PLC polling intervals."
            ])
        elif "IEC104" in scenario_name or "Grid" in scenario_name:
            recs.extend([
                "Enable IDS signatures for out-of-order IEC-104 ASDU transmissions.",
                "Alert on all VPN operations initiated outside of operator scheduled shifts.",
                "Verify integrity of RTU firmware images regularly against vendor hashes."
            ])
        elif "Ransomware" in scenario_name or "Hospital" in scenario_name:
            recs.extend([
                "Block SMBv1 protocol usage across internal segments completely.",
                "Monitor for high rates of directory/file traversal and write actions.",
                "Implement isolated air-gapped daily backups of PACS and EMR systems."
            ])
        elif "CCTV" in scenario_name or "Botnet" in scenario_name:
            recs.extend([
                "Block default credentials at first boot stage via mandatory configuration policies.",
                "Restrict CCTV camera VLAN egress only to NVR systems and update servers.",
                "Monitor camera memory usage for spikes indicating active user-space daemon execution."
            ])
        elif "Traffic" in scenario_name:
            recs.extend([
                "Migrate traffic controller management protocols from SNMPv1/v2c (cleartext) to SNMPv3.",
                "Enforce network layer authentication on ATC switches.",
                "Conduct quarterly physical cabinet audit checks for hardware tampering."
            ])
        elif "Jackpotting" in scenario_name or "ATM" in scenario_name or "Biometric" in scenario_name:
            recs.extend([
                "Configure physical chassis opening sensors to instantly flush crypto keys.",
                "Inspect device logs for TCP socket floods on vendor ports.",
                "Deploy encrypted local bus lines between biometric reader and electric lock actuators."
            ])

        return recs
