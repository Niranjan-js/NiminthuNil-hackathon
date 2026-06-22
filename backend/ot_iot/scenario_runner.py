import logging
import datetime
from typing import Dict, Any, List, Optional

try:
    from backend.ot_iot.digital_twin import DigitalTwin
    from backend.ot_iot.attack_emulator import OTIoTAttackEmulator
    from backend.ot_iot.iot_response_engine import IoTResponseEngine
except ImportError:
    from digital_twin import DigitalTwin
    from attack_emulator import OTIoTAttackEmulator
    from iot_response_engine import IoTResponseEngine

logger = logging.getLogger("niravan.ot_iot.scenario_runner")


class OTIoTScenarioRunner:
    """
    Orchestrates the end-to-end execution of attack scenarios,
    linking attack emulation, threat detection alerts, and response engine containment.
    """

    @classmethod
    def run_scenario(cls, scenario_name: str, environment: str, include_response: bool = True) -> Dict[str, Any]:
        """
        Runs an attack scenario end-to-end, generating attack logs, detection triggers, and containment plans.
        """
        logger.info(f"Running scenario '{scenario_name}' on environment '{environment}' (Include response: {include_response})")
        
        # 1. Attack Emulation
        attack_result = OTIoTAttackEmulator.emulate(scenario_name, environment)
        if "error" in attack_result:
            return attack_result

        # Extract targeted device info from Digital Twin for the response engine
        env_config = DigitalTwin.get_environment(environment)
        target_device_type = OTIoTAttackEmulator.ATTACK_SCENARIOS[scenario_name]["target_device_type"]
        
        target_device = None
        if env_config:
            matching = [d for d in env_config.get("iot_devices", []) if d["device_type"] == target_device_type]
            if matching:
                target_device = matching[0]

        # Fallback device config if none matches
        device_info = {
            "device_id": target_device["id"] if target_device else f"dev-mock-{environment.lower()[:4]}",
            "ip": target_device["ip"] if target_device else "192.168.99.99",
            "mac": target_device["mac"] if target_device else "00:11:22:33:44:55",
            "vendor": target_device["vendor"] if target_device else "Generic",
            "model": target_device["model"] if target_device else "Generic Model",
            "device_type": target_device_type,
            "switch_ip": "10.99.1.1",
            "port_id": "GigabitEthernet1/0/1",
            "category": target_device["category"] if target_device else "OT_Critical"
        }

        # Translate scenario name to threat type keyword recognized by IoTResponseEngine
        threat_keyword = "unknown"
        sc_lower = scenario_name.lower()
        if "ransomware" in sc_lower:
            threat_keyword = "ransomware"
        elif "botnet" in sc_lower or "cctv" in sc_lower:
            threat_keyword = "botnet"
        elif "plc" in sc_lower or "sabotage" in sc_lower:
            threat_keyword = "plc_manipulation"
        elif "iec104" in sc_lower or "grid" in sc_lower:
            threat_keyword = "modbus_abuse"  # maps to OT containment
        elif "override" in sc_lower or "traffic" in sc_lower:
            threat_keyword = "lateral_movement"
        elif "jackpotting" in sc_lower or "atm" in sc_lower:
            threat_keyword = "default_creds"

        threat_context = {
            "threat_type": threat_keyword,
            "confidence": 0.95,
            "source": "NIRAVAN-EMU",
            "indicators": [stage["log_pattern"] for stage in OTIoTAttackEmulator.ATTACK_SCENARIOS[scenario_name]["stages"]]
        }

        # 2. Simulated Detection Alerts
        detection_alerts = []
        for stage in attack_result.get("timeline", []):
            detection_alerts.append({
                "alert_id": f"alert-{datetime.datetime.utcnow().timestamp()}-{stage['mitre_id']}",
                "timestamp": stage["timestamp"],
                "mitre_technique": stage["mitre_id"],
                "message": f"Detection trigger: {stage['description']}",
                "severity": "CRITICAL" if stage["stage"] == "Impact" or stage["stage"].startswith("Damage") else "MEDIUM"
            })

        # 3. Response Execution
        response_result = {}
        if include_response:
            try:
                engine = IoTResponseEngine()
                # Run the actual response action
                response_result = engine.respond(device_info, threat_context)
            except Exception as e:
                logger.warning(f"Failed to invoke IoTResponseEngine directly: {e}. Simulating response fallback.")
                response_result = cls._simulate_fallback_response(device_info, threat_context)
        else:
            response_result = {
                "status": "SKIPPED",
                "message": "Response execution disabled for this run."
            }

        # 4. Lessons Learned and Risk Reduction
        lessons_learned = cls._generate_lessons_learned(scenario_name, target_device)
        risk_reduction = cls._calculate_risk_reduction(scenario_name, env_config)

        return {
            "scenario_name": scenario_name,
            "environment": environment,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attack_details": {
                "target_device": device_info,
                "mitre_tactic": attack_result["mitre_tactic"],
                "citizen_impact_score": attack_result["citizen_impact_score"],
                "damage_estimates": attack_result["damage_estimates"]
            },
            "attack_logs": attack_result["logs"],
            "detection_alerts": detection_alerts,
            "response_actions": response_result,
            "lessons_learned": lessons_learned,
            "risk_reduction_percentage": risk_reduction,
            "status": "SUCCESS"
        }

    @classmethod
    def run_red_team_exercise(cls, environment: str) -> Dict[str, Any]:
        """
        Simulates a multi-stage Red Team exercise on the specified environment.
        Executes multiple relevant scenarios sequentially, producing combined metrics.
        """
        env_config = DigitalTwin.get_environment(environment)
        if not env_config:
            return {"error": f"Environment '{environment}' not found"}

        # Select relevant scenarios based on what device types exist in the environment
        env_device_types = {d["device_type"] for d in env_config.get("iot_devices", [])}
        scenarios_to_run = []
        for name, details in OTIoTAttackEmulator.ATTACK_SCENARIOS.items():
            if details["target_device_type"] in env_device_types:
                scenarios_to_run.append(name)
        
        # Fallback to run at least two generic scenarios if no match
        if len(scenarios_to_run) < 2:
            scenarios_to_run = list(OTIoTAttackEmulator.ATTACK_SCENARIOS.keys())[:2]

        results = []
        total_financial_loss = 0.0
        max_citizen_impact = 0.0
        stages_executed = 0

        for sc_name in scenarios_to_run:
            run_res = cls.run_scenario(sc_name, environment, include_response=True)
            if "error" in run_res:
                continue
            
            results.append(run_res)
            dmg_est = run_res["attack_details"]["damage_estimates"]
            total_financial_loss += dmg_est.get("estimated_financial_loss_inr", 0.0)
            max_citizen_impact = max(max_citizen_impact, dmg_est.get("citizen_impact_score", 0.0))
            stages_executed += len(run_res["attack_logs"])

        return {
            "exercise_type": "OT/IoT Red Team Simulation",
            "environment": environment,
            "scenarios_executed": scenarios_to_run,
            "total_scenarios": len(scenarios_to_run),
            "stages_executed_count": stages_executed,
            "aggregated_metrics": {
                "total_estimated_financial_loss_inr": round(total_financial_loss, 2),
                "max_citizen_impact_score": max_citizen_impact,
                "overall_breach_level": "CRITICAL" if max_citizen_impact >= 85.0 else "HIGH" if max_citizen_impact >= 60.0 else "MEDIUM"
            },
            "scenario_runs": results,
            "hardening_roadmap": [
                "De-authorize non-essential administrative protocols across all network segments.",
                "Enforce network virtualization/VLAN micro-segmentation to break lateral movement chains.",
                "Integrate IoT/OT telemetry logs directly into a centralized Security Operations Center (SOC)."
            ]
        }

    @classmethod
    def run_all_scenarios(cls, environment: str) -> List[Dict[str, Any]]:
        """
        Runs all defined attack scenarios for the environment.
        """
        results = []
        for name in OTIoTAttackEmulator.ATTACK_SCENARIOS.keys():
            res = cls.run_scenario(name, environment, include_response=True)
            if "error" not in res:
                results.append(res)
        return results

    @staticmethod
    def _simulate_fallback_response(device_info: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback simulation in case the physical response engine fails or is modified.
        """
        vlan = "VLAN999-Quarantine" if threat["threat_type"] in ["ransomware", "botnet"] else "VLAN200-OT-Isolated"
        return {
            "status": "CONTAINED",
            "actions_taken": [
                f"Isolated IP {device_info.get('ip')} by dynamically switching VLAN to {vlan}.",
                f"Injected firewall rule blocking egress access on port {device_info.get('switch_ip')}.",
                f"Logged security containment event to SIEM for device ID {device_info.get('device_id')}."
            ],
            "containment_duration_seconds": 180,
            "rollback_plan_generated": True
        }

    @staticmethod
    def _generate_lessons_learned(scenario_name: str, device: Optional[Dict[str, Any]]) -> List[str]:
        """
        Generate contextual security takeaways.
        """
        vendor = device["vendor"] if device else "Generic Vendor"
        model = device["model"] if device else "Generic IoT"
        
        lessons = [
            f"Vulnerability remediation is critical. {vendor} {model} should not run legacy/outdated firmware.",
            "Network monitoring interfaces must flag spikes in raw TCP/UDP outbound traffic immediately."
        ]

        if "PLC" in scenario_name:
            lessons.extend([
                "Modbus does not verify authentication. SCADA networks must rely on physical network layer isolation.",
                "Verify alarm thresholds regularly on physical devices, not just HMI panels."
            ])
        elif "Ransomware" in scenario_name:
            lessons.extend([
                "Segregate medical databases from device VLANs. Implement read-only database connections where possible.",
                "Educate administration staff against phishing emails to cut down initial access vectors."
            ])
        elif "IEC104" in scenario_name:
            lessons.extend([
                "IEC-104 requires strict network level firewall rules. Limit connections to authenticated HMI/RTU IPs only.",
                "Enforce secondary confirmation for control commands (e.g. Dual control switches)."
            ])

        return lessons

    @staticmethod
    def _calculate_risk_reduction(scenario_name: str, env_config: Optional[Dict[str, Any]]) -> float:
        """
        Calculates how much risk would be mitigated if recommendations are put in place.
        """
        base_reduction = 35.0
        if not env_config:
            return base_reduction

        # Hospital or Grid scenarios have complex mitigations, hence higher risk reduction potential
        if "Ransomware" in scenario_name or "IEC104" in scenario_name:
            base_reduction += 15.0
        elif "PLC" in scenario_name:
            base_reduction += 20.0
            
        # Adjust based on the impact multiplier
        multiplier = env_config.get("citizen_impact_multiplier", 1.0)
        reduction = min(base_reduction * (1.2 if multiplier > 8.0 else 1.0), 95.0)
        return round(reduction, 2)
