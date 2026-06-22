import logging
import datetime
import hashlib
import random
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.forensics")


class IoTForensics:
    """
    IoT/OT Forensic Analysis and Evidence Collection Engine.
    Simulates memory dumping, firmware hash verification, log collection,
    and constructs incident timeline reports with chain of custody validation.
    """

    EVIDENCE_TYPES = {
        "device_logs": "Syslog and authentication log extractions.",
        "memory_snapshot": "Volatile RAM process registry dump.",
        "firmware_hash": "Verifiable hash of the active flash firmware partition.",
        "config_backup": "Configuration parameters and routing tables.",
        "traffic_capture": "PCAP file of active interface communication."
    }

    @classmethod
    def collect_evidence(cls, device_info: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
        """
        Orchestrates evidence collection across all forensic types for a compromised device.
        Establishes verification hashes and chain of custody.
        """
        device_id = device_info.get("id", f"dev-{random.randint(100, 999)}")
        logger.info(f"Initiating forensic evidence collection for device ID {device_id} on Incident {incident_id}")

        timestamp = datetime.datetime.utcnow().isoformat()
        
        # Collect individual evidence elements
        logs = cls.collect_device_logs(device_info)
        firmware = cls.capture_firmware_hash(device_info)
        config = cls.backup_configuration(device_info)
        memory = cls.memory_snapshot(device_info)
        network = cls.capture_network_state(device_info)

        # Build raw string for collective checksum
        raw_manifest_data = f"{incident_id}-{device_id}-{timestamp}-{logs['sha256']}-{firmware['current_hash']}-{config['sha256']}"
        manifest_md5 = hashlib.md5(raw_manifest_data.encode()).hexdigest()
        manifest_sha256 = hashlib.sha256(raw_manifest_data.encode()).hexdigest()

        evidence_payload = {
            "incident_id": incident_id,
            "collection_time": timestamp,
            "device_metadata": {
                "id": device_id,
                "ip": device_info.get("ip", "Unknown"),
                "mac": device_info.get("mac", "Unknown"),
                "vendor": device_info.get("vendor", "Generic"),
                "model": device_info.get("model", "Generic Model")
            },
            "evidence_artifacts": {
                "device_logs": logs,
                "firmware_hash": firmware,
                "config_backup": config,
                "memory_snapshot": memory,
                "network_state": network
            },
            "chain_of_custody": {
                "collecting_officer": "NIRAVAN Forensic Agent v2.0",
                "acquisition_method": "API Secure Remote Dump",
                "storage_location": f"/var/niravan/forensics/{incident_id}_{device_id}/",
                "manifest_checksums": {
                    "md5": manifest_md5,
                    "sha256": manifest_sha256
                },
                "custody_history": [
                    {
                        "action": "Acquisition",
                        "timestamp": timestamp,
                        "handler": "NIRAVAN Automated System",
                        "notes": "Acquired directly from switch interface and device diagnostic APIs."
                    }
                ]
            }
        }
        return evidence_payload

    @classmethod
    def collect_device_logs(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate extracting device logs, including authentication events.
        """
        vendor = device_info.get("vendor", "Generic")
        base_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        
        simulated_logs = [
            f"[{ (base_time + datetime.timedelta(minutes=5)).isoformat() }] sshd[1202]: Connection from 192.168.10.99 port 48991",
            f"[{ (base_time + datetime.timedelta(minutes=15)).isoformat() }] sshd[1202]: Invalid user admin from 192.168.10.99",
            f"[{ (base_time + datetime.timedelta(minutes=20)).isoformat() }] sshd[1202]: Failed password for invalid user admin",
            f"[{ (base_time + datetime.timedelta(minutes=30)).isoformat() }] sshd[1202]: Accepted publickey for operator from 192.168.10.10",
            f"[{ (base_time + datetime.timedelta(minutes=45)).isoformat() }] systemd[1]: Service 'niravan-agent' stopped by root user"
        ]
        
        log_content = "\n".join(simulated_logs)
        sha256 = hashlib.sha256(log_content.encode()).hexdigest()
        
        return {
            "artifact_type": "device_logs",
            "content": log_content,
            "size_bytes": len(log_content),
            "sha256": sha256,
            "verified": True
        }

    @classmethod
    def capture_firmware_hash(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate reading firmware flash partition and hashing it.
        Checks for malicious modifications against vendor database.
        """
        vendor = device_info.get("vendor", "Generic")
        model = device_info.get("model", "Generic Model")
        
        # Reference vendor hash
        seed = f"{vendor}-{model}-firmware-stable-v1.0"
        ref_hash = hashlib.sha256(seed.encode()).hexdigest()
        
        # Simulate potential compromise (1 in 3 chance during incident simulation)
        is_compromised = random.choice([True, False, False])
        if is_compromised:
            current_hash = hashlib.sha256((seed + "-backdoor").encode()).hexdigest()
        else:
            current_hash = ref_hash

        status = "INTEGRITY_MATCH" if current_hash == ref_hash else "COMPROMISED_FIRMWARE_DETECTED"

        return {
            "artifact_type": "firmware_hash",
            "reference_hash": ref_hash,
            "current_hash": current_hash,
            "status": status,
            "tamper_detected": is_compromised
        }

    @classmethod
    def backup_configuration(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate backing up configuration files.
        """
        ip = device_info.get("ip", "192.168.1.1")
        config_data = f"""
        ! NIRAVAN Device Config Dump
        hostname {device_info.get('vendor','')}_{device_info.get('model','')}
        interface fastethernet0
         ip address {ip} 255.255.255.0
         no shutdown
        !
        line vty 0 4
         login local
         transport input telnet ssh
        !
        end
        """
        sha256 = hashlib.sha256(config_data.encode()).hexdigest()
        return {
            "artifact_type": "config_backup",
            "content": config_data,
            "sha256": sha256
        }

    @classmethod
    def memory_snapshot(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate dumping volatile RAM process registry.
        """
        processes = [
            {"pid": 1, "name": "init", "user": "root", "mem_kb": 1024},
            {"pid": 20, "name": "kthreadd", "user": "root", "mem_kb": 0},
            {"pid": 110, "name": "sshd", "user": "root", "mem_kb": 4500},
            {"pid": 1205, "name": "web_controller", "user": "admin", "mem_kb": 32000},
            {"pid": 9999, "name": "nc", "user": "nobody", "mem_kb": 1200}  # Netcat reverse shell indicator
        ]
        
        raw_repr = str(processes)
        sha256 = hashlib.sha256(raw_repr.encode()).hexdigest()
        
        return {
            "artifact_type": "memory_snapshot",
            "active_processes": processes,
            "total_process_count": len(processes),
            "sha256": sha256
        }

    @classmethod
    def capture_network_state(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate collecting active network socket connections.
        """
        sockets = [
            {"protocol": "TCP", "local": f"{device_info.get('ip')}:80", "remote": "0.0.0.0:*", "state": "LISTEN"},
            {"protocol": "TCP", "local": f"{device_info.get('ip')}:22", "remote": "192.168.10.10:48992", "state": "ESTABLISHED"},
            {"protocol": "TCP", "local": f"{device_info.get('ip')}:4444", "remote": "185.190.140.5:443", "state": "ESTABLISHED"}, # Anomalous outbound C2 socket
        ]
        return {
            "artifact_type": "network_state",
            "sockets": sockets,
            "active_connections_count": len(sockets)
        }

    @classmethod
    def build_timeline(cls, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes evidence logs and active connection timestamps to reconstruct incident timeline.
        """
        timeline = []
        artifacts = evidence.get("evidence_artifacts", {})
        
        # 1. Parse raw log lines if present
        log_data = artifacts.get("device_logs", {}).get("content", "")
        if log_data:
            lines = log_data.split("\n")
            for line in lines:
                if not line.strip():
                    continue
                # Simple extraction of timestamp and message: e.g. [2026-06-21T...] msg
                parts = line.split("] ", 1)
                if len(parts) == 2:
                    ts = parts[0].replace("[", "").strip()
                    msg = parts[1].strip()
                    timeline.append({
                        "timestamp": ts,
                        "source": "Device Logs",
                        "description": msg,
                        "indicator_level": "HIGH" if "Failed" in msg or "stopped" in msg else "INFO"
                    })

        # 2. Add structural artifacts info
        fw_status = artifacts.get("firmware_hash", {})
        if fw_status.get("tamper_detected"):
            # Add dynamic timestamp close to the log session
            timeline.append({
                "timestamp": evidence.get("collection_time"),
                "source": "Firmware Analysis",
                "description": f"ALERT: Firmware integrity violation detected. Current SHA256: {fw_status['current_hash']}",
                "indicator_level": "CRITICAL"
            })

        net_state = artifacts.get("network_state", {})
        for sock in net_state.get("sockets", []):
            if sock["remote"].startswith("185.190.140.5"): # Simulated C2 IP
                timeline.append({
                    "timestamp": evidence.get("collection_time"),
                    "source": "Network Socket State",
                    "description": f"ALERT: Rogue C2 connection active to external IP {sock['remote']} on port 4444",
                    "indicator_level": "CRITICAL"
                })

        # Sort timeline by timestamp ascending
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline

    @classmethod
    def generate_forensics_report(cls, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile findings, evidence metrics, and incident timeline into a comprehensive forensic report.
        """
        timeline = cls.build_timeline(evidence)
        artifacts = evidence.get("evidence_artifacts", {})
        dev = evidence.get("device_metadata", {})
        
        # Determine root cause
        root_cause = "Unauthorized credentials usage via SSH."
        if artifacts.get("firmware_hash", {}).get("tamper_detected"):
            root_cause = "Firmware compromise. Unauthorized binary injected in flash partition."
        
        active_sockets = artifacts.get("network_state", {}).get("sockets", [])
        if any(s["local"].endswith(":4444") or s["remote"].startswith("185.190.140.5") for s in active_sockets):
            root_cause += " Outbound remote shell backdoor (Netcat reverse shell) established."

        report = {
            "forensics_report_id": f"REP-{evidence.get('incident_id')}-{dev.get('id')}",
            "device_profile": dev,
            "root_cause_analysis": root_cause,
            "evidence_integrity_status": "VALIDATED" if evidence.get("chain_of_custody", {}).get("manifest_checksums") else "INVALID",
            "tamper_detected": artifacts.get("firmware_hash", {}).get("tamper_detected", False),
            "timeline_events": timeline,
            "investigation_summary": f"Remote forensics analysis confirms {dev.get('vendor')} {dev.get('model')} suffered initial access exploitation followed by malicious process execution.",
            "defense_action_plan": [
                "Isolate target IP at layer 2 immediately.",
                "Force flash official vendor firmware to overwrite potential bootkits.",
                "Conduct audit on password registry keys.",
                "Deploy network IDS rules targeting rogue IP subnets detected in sockets."
            ]
        }
        return report
