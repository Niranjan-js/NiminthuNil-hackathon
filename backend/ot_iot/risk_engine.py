import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.risk_engine")


class IoTRiskEngine:
    """
    IoT/OT Compliance and Risk Assessment Engine.
    Evaluates vulnerabilities, configurations, protocols, and exposures to compute risk ratings.
    """

    RISK_FACTORS = {
        "firmware_cves": 0.35,
        "default_credentials": 0.25,
        "internet_exposure": 0.15,
        "unencrypted_protocols": 0.10,
        "unsupported_firmware": 0.10,
        "management_ports": 0.05
    }

    @classmethod
    def score_device(cls, device_info: Dict[str, Any], firmware_scan: Dict[str, Any], behavior: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate full risk profile of a device and output compliance levels and remediation actions.
        """
        # Score each vector (each returns 0.0 to 100.0)
        firmware_score = cls.score_firmware_risk(firmware_scan)
        credential_score = cls.score_credential_risk(device_info)
        exposure_score = cls.score_exposure_risk(device_info)
        protocol_score = cls.score_protocol_risk(device_info)

        # Unsupported firmware subscore
        unsupported_score = 100.0 if firmware_scan.get("is_unsupported_eol", False) else 0.0

        # Management ports risk
        mgt_ports = {22, 23, 80, 443, 8000, 37777, 4370}
        open_ports = set(device_info.get("open_ports", []))
        active_mgt_ports = open_ports.intersection(mgt_ports)
        management_port_score = min(len(active_mgt_ports) * 20.0, 100.0)

        # Weighted calculation
        overall_risk = (
            (firmware_score * cls.RISK_FACTORS["firmware_cves"]) +
            (credential_score * cls.RISK_FACTORS["default_credentials"]) +
            (exposure_score * cls.RISK_FACTORS["internet_exposure"]) +
            (protocol_score * cls.RISK_FACTORS["unencrypted_protocols"]) +
            (unsupported_score * cls.RISK_FACTORS["unsupported_firmware"]) +
            (management_port_score * cls.RISK_FACTORS["management_ports"])
        )

        overall_risk = round(min(max(overall_risk, 0.0), 100.0), 2)
        compliance_score = round(100.0 - overall_risk, 2)

        # Risk tier assignment
        if overall_risk >= 80.0:
            level = "CRITICAL"
        elif overall_risk >= 60.0:
            level = "HIGH"
        elif overall_risk >= 35.0:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Generate remedial actions
        remediations = []
        if credential_score > 0.0:
            remediations.append("Rotate administrative passwords; disable default credentials.")
        if firmware_score > 50.0 or unsupported_score > 0.0:
            remediations.append("Apply vendor-published patch updates or isolate EOL firmware node.")
        if exposure_score > 50.0:
            remediations.append("Update firewall policy to restrict public WAN exposure.")
        if protocol_score > 40.0:
            remediations.append("Disable legacy unencrypted protocols (e.g. TELNET, HTTP) and configure SSH/HTTPS.")
        if len(active_mgt_ports) > 2:
            remediations.append("Close unnecessary listening ports on management endpoints.")

        return {
            "device_id": device_info.get("id"),
            "vendor": device_info.get("vendor"),
            "model": device_info.get("model"),
            "device_type": device_info.get("device_type"),
            "overall_risk_score": overall_risk,
            "risk_level": level,
            "compliance_score": compliance_score,
            "vector_scores": {
                "firmware_cves": round(firmware_score, 2),
                "credentials": round(credential_score, 2),
                "internet_exposure": round(exposure_score, 2),
                "protocols": round(protocol_score, 2),
                "firmware_support": round(unsupported_score, 2),
                "management_ports": round(management_port_score, 2)
            },
            "remediation_actions": remediations
        }

    @classmethod
    def score_firmware_risk(cls, scan: Dict[str, Any]) -> float:
        """
        Evaluate CVSS values from a firmware vulnerability scan to assign score (0.0 to 100.0).
        """
        cves = scan.get("cves", [])
        if not cves:
            return 0.0

        max_cvss = 0.0
        sum_cvss = 0.0

        for cve in cves:
            cvss = float(cve.get("cvss", 0.0))
            sum_cvss += cvss
            if cvss > max_cvss:
                max_cvss = cvss

        # Formula: Combine maximum CVSS with average CVSS
        avg_cvss = sum_cvss / len(cves)
        calculated_score = (max_cvss * 6.0) + (avg_cvss * 4.0)
        return min(max(calculated_score, 0.0), 100.0)

    @classmethod
    def score_credential_risk(cls, device: Dict[str, Any]) -> float:
        """
        Scores credential configurations based on presence of default/weak login keys.
        """
        status = device.get("credentials_status", "unknown").lower()
        has_defaults = device.get("has_default_credentials", False)

        if has_defaults or status == "default":
            return 100.0
        elif status == "weak" or device.get("credentials_strength", 10) < 4:
            return 60.0
        elif status == "configured_safe":
            return 0.0
        
        # Default fallback: check ports like telnet (often indicator of default config)
        if 23 in device.get("open_ports", []):
            return 80.0
        return 30.0

    @classmethod
    def score_exposure_risk(cls, device: Dict[str, Any]) -> float:
        """
        Scores public internet exposure configuration.
        """
        exposed = device.get("internet_exposed", device.get("exposed_to_internet", False))
        ip = device.get("ip", "")

        # Score based on public IP allocation or flag
        if exposed:
            return 100.0

        # Check if IP starts with public ranges (simple simulation)
        is_private = ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.")
        if ip and not is_private:
            return 90.0

        # Check if segment config is public or guest
        vlan = device.get("network_segment", "")
        if "Guest" in vlan or "VLAN-40" in vlan:
            return 40.0

        return 0.0

    @classmethod
    def score_protocol_risk(cls, device: Dict[str, Any]) -> float:
        """
        Scores protocol risk based on transmission encryption and protocol type.
        """
        protocols = [p.upper() for p in device.get("protocols_detected", device.get("protocols", []))]
        if not protocols:
            return 0.0

        risk_score = 0.0
        # Insecure or raw OT protocols
        insecure_map = {
            "TELNET": 45.0,
            "HTTP": 25.0,
            "RTSP": 20.0,
            "SNMP": 15.0,
            "MODBUS": 35.0,
            "S7COMM": 35.0,
            "IEC104": 40.0,
            "FTP": 20.0,
            "ZKNET": 30.0
        }

        for proto, weight in insecure_map.items():
            if proto in protocols:
                risk_score += weight

        # Cap the protocol risk at 100
        return min(risk_score, 100.0)

    @classmethod
    def rank_devices_by_risk(cls, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates a list of devices and returns them sorted by overall risk score in descending order.
        """
        scored_devices = []
        for dev in devices:
            # Generate mock firmware and behavior inputs if missing
            fw_scan = dev.get("firmware_scan", {
                "cves": [{"id": "CVE-2021-3618", "cvss": 7.5}] if dev.get("risk_tier", 3) <= 2 else [],
                "is_unsupported_eol": dev.get("risk_tier") == 4
            })
            behavior = dev.get("behavior", {"anomalous_connections": 0})
            
            scored = cls.score_device(dev, fw_scan, behavior)
            scored_devices.append(scored)

        # Sort descending by overall_risk_score
        scored_devices.sort(key=lambda x: x["overall_risk_score"], reverse=True)
        return scored_devices

    @classmethod
    def generate_risk_dashboard(cls, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregates device risk evaluations to build a compliance executive dashboard.
        """
        if not devices:
            return {"message": "No devices to evaluate"}

        ranked = cls.rank_devices_by_risk(devices)
        
        total = len(ranked)
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        sum_risk = 0.0
        sum_compliance = 0.0

        for r in ranked:
            score = r["overall_risk_score"]
            sum_risk += score
            sum_compliance += r["compliance_score"]
            
            level = r["risk_level"]
            if level == "CRITICAL":
                critical_count += 1
            elif level == "HIGH":
                high_count += 1
            elif level == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1

        avg_risk = round(sum_risk / total, 2)
        avg_compliance = round(sum_compliance / total, 2)

        return {
            "total_assets_evaluated": total,
            "average_risk_score": avg_risk,
            "average_compliance_score": avg_compliance,
            "distribution": {
                "CRITICAL": critical_count,
                "HIGH": high_count,
                "MEDIUM": medium_count,
                "LOW": low_count
            },
            "posture_status": "POOR" if avg_risk >= 65.0 else "FAIR" if avg_risk >= 40.0 else "GOOD",
            "top_high_risk_devices": ranked[:3],  # Return top 3 highest risk
            "general_recommendations": [
                "Implement patch management cycles targeting Critical vulnerabilities.",
                "Enforce network separation using VLAN access policies.",
                "Conduct audit assessments on accounts matching 'default' credentials."
            ]
        }
