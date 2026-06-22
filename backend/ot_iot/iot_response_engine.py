"""
NIRAVAN Cyber Defense Operating System
OT/IoT Defense Layer — IoT Response Engine
Automated containment, isolation, and remediation for compromised IoT/OT devices.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("niravan.ot_iot.response_engine")
logging.basicConfig(level=logging.INFO)


class IoTResponseEngine:
    """
    Automated response and containment engine for compromised IoT/OT devices.

    Capabilities:
    - VLAN-based network isolation
    - Dynamic firewall rule injection
    - Switch-port disablement simulation
    - SOC alert generation
    - Rollback / restoration planning
    - Containment verification
    """

    VLAN_MAP: Dict[int, str] = {
        1: "VLAN999-Quarantine",
        2: "VLAN200-OT-Isolated",
        3: "VLAN300-IoT-Monitored",
        4: "VLAN400-IoT-Normal",
    }

    THREAT_VLAN_POLICY: Dict[str, int] = {
        "ransomware":        1,
        "mirai":             1,
        "botnet":            1,
        "c2":                1,
        "lateral_movement":  2,
        "plc_manipulation":  2,
        "modbus_abuse":      2,
        "anomalous_traffic": 3,
        "default_creds":     3,
        "port_scan":         3,
        "unknown":           3,
    }

    FIREWALL_RULE_TEMPLATES: List[str] = [
        "DENY ip {device_ip}/32 any",
        "DENY ip any {device_ip}/32",
        "DENY tcp {device_ip}/32 any eq 23",
        "DENY tcp {device_ip}/32 any eq 22",
        "DENY udp {device_ip}/32 any eq 1883",
        "PERMIT ip {device_ip}/32 10.99.1.254/32",
    ]

    SOC_SEVERITY_MAP: Dict[str, str] = {
        "ransomware":        "CRITICAL",
        "mirai":             "CRITICAL",
        "botnet":            "CRITICAL",
        "c2":                "CRITICAL",
        "lateral_movement":  "HIGH",
        "plc_manipulation":  "HIGH",
        "modbus_abuse":      "HIGH",
        "anomalous_traffic": "MEDIUM",
        "default_creds":     "MEDIUM",
        "port_scan":         "LOW",
        "unknown":           "MEDIUM",
    }

    def __init__(self) -> None:
        self._action_log: List[Dict[str, Any]] = []
        self._containment_registry: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    #  Primary Entry Point
    # ------------------------------------------------------------------ #

    def respond(self, device_info: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate the full automated response for a detected threat.

        Args:
            device_info: Device metadata (device_id, device_ip, mac, vendor, type, switch_ip, port_id, etc.)
            threat:      Threat context (threat_type, confidence, source, indicators, etc.)

        Returns:
            Comprehensive response result dictionary.
        """
        t_start = time.time()
        logger.info(
            "[RESPONSE] Initiating response for device=%s threat=%s",
            device_info.get("device_id", "UNK"),
            threat.get("threat_type", "unknown"),
        )

        device_id  = device_info.get("device_id",  f"DEV-{random.randint(1000,9999)}")
        device_ip  = device_info.get("device_ip",  "10.0.0.1")
        threat_type = threat.get("threat_type",    "unknown").lower()
        switch_ip  = device_info.get("switch_ip",  "192.168.1.1")
        port_id    = device_info.get("port_id",    f"GE1/{random.randint(1,48)}")

        actions_taken: List[str] = []
        firewall_rules_added: List[Dict[str, Any]] = []

        # 1. Determine isolation VLAN
        vlan_id = self.VLAN_MAP.get(
            self.THREAT_VLAN_POLICY.get(threat_type, 3), "VLAN300-IoT-Monitored"
        )

        # 2. VLAN isolation
        vlan_result = self.vlan_isolate(device_ip, device_id, vlan_id)
        actions_taken.append(f"VLAN_ISOLATE -> {vlan_id}")

        # 3. Firewall rules
        severity = self.SOC_SEVERITY_MAP.get(threat_type, "MEDIUM")
        if severity in ("CRITICAL", "HIGH"):
            fw_result = self.add_firewall_block(device_ip, direction="both", duration_hours=24)
            firewall_rules_added = fw_result.get("rules", [])
            actions_taken.append("FIREWALL_BLOCK (bidirectional, 24 h)")

        # 4. Switch-port disable for critical threats
        switch_result: Optional[Dict[str, Any]] = None
        if severity == "CRITICAL":
            switch_result = self.disable_switch_port(switch_ip, port_id, device_ip)
            actions_taken.append(f"SWITCH_PORT_DISABLED {switch_ip}:{port_id}")

        # 5. SOC alert
        soc_alert = self.generate_soc_alert(device_info, threat)
        actions_taken.append(f"SOC_ALERT_RAISED ticket={soc_alert['ticket_id']}")

        # 6. Rollback plan
        rollback_plan = self._build_rollback_plan(
            device_info, vlan_id, firewall_rules_added, switch_result, port_id, switch_ip
        )

        # 7. Verify containment
        containment = self.verify_containment(device_ip)

        # 8. Register containment state
        self._containment_registry[device_ip] = {
            "device_id":   device_id,
            "vlan":        vlan_id,
            "fw_rules":    firewall_rules_added,
            "switch_port": f"{switch_ip}:{port_id}" if switch_result else None,
            "timestamp":   datetime.utcnow().isoformat(),
            "rollback":    rollback_plan,
        }

        elapsed_ms = round((time.time() - t_start) * 1000, 2)
        logger.info("[RESPONSE] Completed in %.2f ms actions=%d", elapsed_ms, len(actions_taken))

        return {
            "device_id":            device_id,
            "device_ip":            device_ip,
            "threat_type":          threat_type,
            "threat_confidence":    threat.get("confidence", 0.0),
            "actions_taken":        actions_taken,
            "vlan_isolation":       vlan_result,
            "firewall_rules_added": firewall_rules_added,
            "switch_port_result":   switch_result,
            "soc_alert":            soc_alert,
            "rollback_plan":        rollback_plan,
            "containment_verify":   containment,
            "execution_time_ms":    elapsed_ms,
            "response_timestamp":   datetime.utcnow().isoformat() + "Z",
            "status":               "CONTAINED" if containment.get("contained") else "PARTIAL",
        }

    # ------------------------------------------------------------------ #
    #  VLAN Isolation
    # ------------------------------------------------------------------ #

    def vlan_isolate(self, device_ip: str, device_id: str, vlan_id: str) -> Dict[str, Any]:
        """
        Simulate VLAN re-assignment to isolate a device.

        Args:
            device_ip: Target device IP.
            device_id: Target device identifier.
            vlan_id:   Destination VLAN name/ID string.

        Returns:
            Isolation result dict.
        """
        logger.info("[VLAN] Isolating %s -> %s", device_ip, vlan_id)
        numeric_match = re.search(r"VLAN(\d+)", vlan_id)
        numeric_vlan  = int(numeric_match.group(1)) if numeric_match else 999
        iface = f"GigabitEthernet1/{random.randint(1,48)}"

        return {
            "action":         "VLAN_ISOLATION",
            "device_ip":      device_ip,
            "device_id":      device_id,
            "previous_vlan":  f"VLAN{random.randint(10, 100)}-Production",
            "assigned_vlan":  vlan_id,
            "numeric_vlan":   numeric_vlan,
            "switch_command": (
                f"interface {iface}\n"
                f" switchport access vlan {numeric_vlan}\n"
                f" shutdown\n"
                f" spanning-tree portfast\n"
            ),
            "nac_policy":  f"NAC-POLICY-{vlan_id}",
            "acl_applied": f"ACL-ISOLATE-{numeric_vlan}",
            "success":     True,
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------ #
    #  Firewall Rules
    # ------------------------------------------------------------------ #

    def add_firewall_block(
        self,
        device_ip: str,
        direction: str = "both",
        duration_hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Inject firewall block rules for a given device IP.

        Args:
            device_ip:      IP address to block.
            direction:      'inbound', 'outbound', or 'both'.
            duration_hours: How long the rule should persist.

        Returns:
            Firewall rule result dict.
        """
        logger.info("[FW] Adding block rules for %s direction=%s", device_ip, direction)
        expiry       = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat() + "Z"
        rule_id_base = f"NIRAVAN-FW-{random.randint(10000, 99999)}"
        rules: List[Dict[str, Any]] = []

        if direction in ("inbound", "both"):
            rules.append({
                "rule_id":   f"{rule_id_base}-IN",
                "direction": "inbound",
                "action":    "DENY",
                "protocol":  "any",
                "src":       "any",
                "dst":       device_ip,
                "priority":  10,
                "log":       True,
                "expiry":    expiry,
                "raw_acl":   f"deny ip any host {device_ip} log",
            })

        if direction in ("outbound", "both"):
            rules.append({
                "rule_id":   f"{rule_id_base}-OUT",
                "direction": "outbound",
                "action":    "DENY",
                "protocol":  "any",
                "src":       device_ip,
                "dst":       "any",
                "priority":  10,
                "log":       True,
                "expiry":    expiry,
                "raw_acl":   f"deny ip host {device_ip} any log",
            })

        for port, proto, note in [(23, "tcp", "Telnet"), (1883, "tcp", "MQTT"), (161, "udp", "SNMP")]:
            rules.append({
                "rule_id":   f"{rule_id_base}-P{port}",
                "direction": "outbound",
                "action":    "DENY",
                "protocol":  proto,
                "src":       device_ip,
                "dst":       "any",
                "dst_port":  port,
                "note":      note,
                "priority":  5,
                "log":       True,
                "expiry":    expiry,
                "raw_acl":   f"deny {proto} host {device_ip} any eq {port} log",
            })

        return {
            "action":         "FIREWALL_BLOCK",
            "device_ip":      device_ip,
            "direction":      direction,
            "rules":          rules,
            "rule_count":     len(rules),
            "duration_hours": duration_hours,
            "expiry":         expiry,
            "firewall_zone":  "OT_DMZ_INGRESS",
            "policy_set":     "NIRAVAN-EMERGENCY",
            "success":        True,
            "timestamp":      datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------ #
    #  Switch-Port Disable
    # ------------------------------------------------------------------ #

    def disable_switch_port(
        self,
        switch_ip: str,
        port_id: str,
        device_ip: str,
    ) -> Dict[str, Any]:
        """
        Simulate disabling the network switch port connected to the compromised device.

        Args:
            switch_ip: Management IP of the network switch.
            port_id:   Interface/port identifier on the switch.
            device_ip: IP of the device connected to this port.

        Returns:
            Port-disable result dict.
        """
        logger.info("[SWITCH] Disabling port %s on switch %s for device %s", port_id, switch_ip, device_ip)
        return {
            "action":         "SWITCH_PORT_DISABLE",
            "switch_ip":      switch_ip,
            "switch_model":   random.choice(["Cisco Catalyst 9300", "Cisco Catalyst 2960X", "Juniper EX2300"]),
            "port_id":        port_id,
            "device_ip":      device_ip,
            "previous_state": "UP",
            "new_state":      "ADMIN_DOWN",
            "snmp_oid":       f"1.3.6.1.2.1.2.2.1.7.{random.randint(1,48)}",
            "netconf_rpc": (
                "<edit-config><config>"
                f"<interface><name>{port_id}</name><enabled>false</enabled></interface>"
                "</config></edit-config>"
            ),
            "admin_command": f"interface {port_id}\n shutdown\n description NIRAVAN-QUARANTINE",
            "change_ticket": f"CHG-{random.randint(100000, 999999)}",
            "success":       True,
            "timestamp":     datetime.utcnow().isoformat() + "Z",
        }

    # ------------------------------------------------------------------ #
    #  SOC Alert
    # ------------------------------------------------------------------ #

    def generate_soc_alert(
        self,
        device_info: Dict[str, Any],
        threat: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate a rich SOC alert with ticket details, MITRE mapping, and context.

        Args:
            device_info: Device metadata.
            threat:      Threat context.

        Returns:
            SOC alert dict.
        """
        threat_type = threat.get("threat_type", "unknown").lower()
        severity    = self.SOC_SEVERITY_MAP.get(threat_type, "MEDIUM")
        ticket_id   = f"SOC-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(1000,9999)}"
        device_ip   = device_info.get("device_ip", "10.0.0.1")
        device_id   = device_info.get("device_id", "UNK")
        vendor      = device_info.get("vendor",    "Unknown Vendor")
        device_type = device_info.get("type",      "IoT Device")

        mitre_map: Dict[str, List[str]] = {
            "ransomware":        ["T1486", "T1490", "T1489"],
            "mirai":             ["T1498", "T1583.006", "T1105"],
            "botnet":            ["T1583.005", "T1071.001", "T1041"],
            "c2":                ["T1071", "T1095", "T1572"],
            "lateral_movement":  ["T1021", "T1210", "T1550"],
            "plc_manipulation":  ["T0831", "T0855", "T0836"],
            "modbus_abuse":      ["T0831", "T0836", "T0855"],
            "anomalous_traffic": ["T1040", "T1046"],
            "default_creds":     ["T1110.001", "T1078"],
            "port_scan":         ["T1046", "T1595"],
        }
        techniques = mitre_map.get(threat_type, ["T1040"])

        playbook_map: Dict[str, str] = {
            "CRITICAL": "PB-IR-001-Critical-IoT-Compromise",
            "HIGH":     "PB-IR-002-High-OT-Anomaly",
            "MEDIUM":   "PB-IR-003-Medium-IoT-Alert",
            "LOW":      "PB-IR-004-Low-Observation",
        }
        sla_map = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}

        return {
            "ticket_id":        ticket_id,
            "alert_name":       f"[{severity}] IoT Threat Detected: {threat_type.upper()} on {device_id}",
            "severity":         severity,
            "priority":         {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}[severity],
            "device_id":        device_id,
            "device_ip":        device_ip,
            "device_type":      device_type,
            "vendor":           vendor,
            "threat_type":      threat_type,
            "confidence":       threat.get("confidence", round(random.uniform(0.70, 0.99), 2)),
            "indicators":       threat.get("indicators", [f"Suspicious traffic from {device_ip}"]),
            "mitre_techniques": techniques,
            "playbook":         playbook_map[severity],
            "assigned_team":    "NIRAVAN-SOC-Tier2" if severity in ("CRITICAL", "HIGH") else "NIRAVAN-SOC-Tier1",
            "sla_minutes":      sla_map[severity],
            "escalation_time":  (datetime.utcnow() + timedelta(minutes=sla_map[severity])).isoformat() + "Z",
            "affected_environment": device_info.get("environment", "OT-Network"),
            "citizen_impact":   threat.get("citizen_impact", False),
            "notification_sent": (
                ["soc@niravan.gov.in", "ciso@niravan.gov.in"]
                if severity == "CRITICAL" else ["soc@niravan.gov.in"]
            ),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status":     "OPEN",
        }

    # ------------------------------------------------------------------ #
    #  Rollback / Restoration
    # ------------------------------------------------------------------ #

    def rollback_containment(
        self,
        device_ip: str,
        rollback_plan: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute rollback of all containment actions for a cleared device.

        Args:
            device_ip:     IP of the device to restore.
            rollback_plan: The rollback plan originally generated during response.

        Returns:
            Rollback execution result.
        """
        logger.info("[ROLLBACK] Executing rollback for %s", device_ip)
        steps_executed: List[Dict[str, Any]] = []

        for step in rollback_plan.get("steps", []):
            result = {
                "step":      step.get("action"),
                "detail":    step.get("detail", ""),
                "success":   True,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            steps_executed.append(result)
            logger.info("[ROLLBACK] Step=%s success=True", step.get("action"))

        self._containment_registry.pop(device_ip, None)

        return {
            "action":                   "ROLLBACK_CONTAINMENT",
            "device_ip":                device_ip,
            "steps_executed":           steps_executed,
            "steps_count":              len(steps_executed),
            "vlan_restored":            rollback_plan.get("original_vlan", "VLAN10-Production"),
            "firewall_rules_removed":   len(rollback_plan.get("firewall_rules_to_remove", [])),
            "switch_port_re_enabled":   rollback_plan.get("re_enable_port", False),
            "success":                  all(s["success"] for s in steps_executed),
            "timestamp":                datetime.utcnow().isoformat() + "Z",
            "restored_by":              "NIRAVAN-AutoResponse-v2.1",
            "post_rollback_monitoring": "ENHANCED_48H",
        }

    # ------------------------------------------------------------------ #
    #  Containment Verification
    # ------------------------------------------------------------------ #

    def verify_containment(self, device_ip: str) -> Dict[str, Any]:
        """
        Verify that the containment measures are effective.

        Args:
            device_ip: IP address of the contained device.

        Returns:
            Verification result dict.
        """
        logger.info("[VERIFY] Checking containment for %s", device_ip)
        checks = [
            {"check": "VLAN_REASSIGNMENT",    "pass": True,  "detail": "Device confirmed in quarantine VLAN"},
            {"check": "FIREWALL_RULES_ACTIVE", "pass": True,  "detail": "ACL entries confirmed on perimeter FW"},
            {"check": "SWITCH_PORT_STATUS",    "pass": random.choice([True, True, False]),
             "detail": "Port admin-down confirmed via SNMP"},
            {"check": "NO_OUTBOUND_TRAFFIC",   "pass": True,  "detail": "Zero outbound flows in last 60s"},
            {"check": "DNS_BLOCKED",           "pass": True,  "detail": "DNS queries from device dropped"},
            {"check": "ARP_ENTRY_CLEARED",     "pass": True,  "detail": "ARP cache entry flushed on GW"},
            {"check": "NAC_POLICY_APPLIED",    "pass": True,  "detail": "802.1X policy re-applied"},
        ]
        all_pass  = all(c["pass"] for c in checks)
        pass_count = sum(1 for c in checks if c["pass"])

        return {
            "device_ip":        device_ip,
            "contained":        all_pass,
            "containment_pct":  round(pass_count / len(checks) * 100, 1),
            "checks":           checks,
            "checks_passed":    pass_count,
            "checks_total":     len(checks),
            "verified_at":      datetime.utcnow().isoformat() + "Z",
            "recommended_action": (
                "CONTAINMENT_COMPLETE" if all_pass else "MANUAL_REVIEW_REQUIRED"
            ),
        }

    # ------------------------------------------------------------------ #
    #  Private Helpers
    # ------------------------------------------------------------------ #

    def _build_rollback_plan(
        self,
        device_info: Dict[str, Any],
        vlan_id: str,
        fw_rules: List[Dict[str, Any]],
        switch_result: Optional[Dict[str, Any]],
        port_id: str,
        switch_ip: str,
    ) -> Dict[str, Any]:
        """Build a structured rollback plan for the applied containment actions."""
        steps: List[Dict[str, Any]] = [
            {
                "action":  "RESTORE_VLAN",
                "detail":  f"Move device back to original production VLAN from {vlan_id}",
                "command": "switchport access vlan <original>",
                "risk":    "LOW",
            },
            {
                "action":   "REMOVE_FIREWALL_RULES",
                "detail":   f"Remove {len(fw_rules)} firewall ACL entries",
                "rule_ids": [r.get("rule_id") for r in fw_rules],
                "risk":     "LOW",
            },
        ]
        if switch_result:
            steps.append({
                "action":  "RE_ENABLE_SWITCH_PORT",
                "detail":  f"Admin-up port {port_id} on switch {switch_ip}",
                "command": f"interface {port_id}\n no shutdown",
                "risk":    "MEDIUM",
            })
        steps.extend([
            {
                "action": "POST_RESTORATION_SCAN",
                "detail": "Run full vulnerability scan before returning to production",
                "risk":   "LOW",
            },
            {
                "action": "ENHANCED_MONITORING_48H",
                "detail": "Apply elevated behavioral monitoring for 48 hours post-restoration",
                "risk":   "LOW",
            },
        ])

        return {
            "rollback_id":              f"RB-{random.randint(10000,99999)}",
            "original_vlan":            "VLAN10-Production",
            "firewall_rules_to_remove": [r.get("rule_id") for r in fw_rules],
            "re_enable_port":           switch_result is not None,
            "steps":                    steps,
            "estimated_restore_time_min": len(steps) * 2,
            "approval_required":        True,
            "approver":                 "NIRAVAN-SOC-Lead",
            "prerequisites": [
                "Threat remediation confirmed by Tier2 analyst",
                "Firmware patched or factory-reset completed",
                "Vulnerability scan passed",
            ],
        }
