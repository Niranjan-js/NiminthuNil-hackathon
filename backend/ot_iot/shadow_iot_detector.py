import logging
from typing import Dict, Any, List, Optional
import re

logger = logging.getLogger("niravan.ot_iot.shadow_iot_detector")


class ShadowIoTDetector:
    """
    Detector engine for identifying Shadow IoT and rogue hardware assets.
    Cross-references discovery results against authorized asset registers and scans for rogue patterns.
    """

    SHADOW_INDICATORS = {
        "rogue_wifi_ap": "Unauthorized wireless access points providing backdoors into secure VLANs.",
        "personal_device": "Employee-owned smartphones, tablets, or laptops connected to enterprise networks.",
        "unauthorized_camera": "IP surveillance cameras installed without security registration.",
        "network_implant": "Compact single-board computers (like Raspberry Pis) plugged directly into network switchports."
    }

    KNOWN_ROGUE_PATTERNS = [
        "AndroidAP", "iPhone", "iPad", "TP-LINK", "TL-WR", "Linksys", "Netgear-Guest", 
        "D-Link-Guest", "MyWiFi", "PortableHotspot", "Raspberry", "Pi-Implant"
    ]

    @classmethod
    def scan_for_shadow_devices(cls, discovery_result: Dict[str, Any], asset_register: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Cross-references discovery results with the asset register to identify unregistered (shadow) devices.
        Rates the risk level of each detected shadow device.
        """
        discovered_devices = discovery_result.get("devices", [])
        
        # Build lookups for authorized assets using MAC and IP addresses
        auth_macs = {a.get("mac", "").upper().strip() for a in asset_register}
        auth_ips = {a.get("ip", "").strip() for a in asset_register}
        auth_ids = {a.get("id", "").strip() for a in asset_register}

        shadow_devices = []
        overall_risk_score = 0.0

        for dev in discovered_devices:
            dev_mac = dev.get("mac", "").upper().strip()
            dev_ip = dev.get("ip", "").strip()
            dev_id = dev.get("id", "").strip()

            # A device is shadow if it is not in the official asset register
            is_authorized = (dev_mac in auth_macs) or (dev_ip in auth_ips) or (dev_id in auth_ids) or dev.get("is_on_asset_register", True)
            
            if not is_authorized:
                # Rate risk of this specific shadow device
                risk_factors = []
                device_risk = 20.0  # Base shadow risk
                
                # Check for critical open ports
                ports = dev.get("open_ports", [])
                if 23 in ports:
                    device_risk += 25.0
                    risk_factors.append("TELNET port 23 open (Unencrypted admin access)")
                if 80 in ports:
                    device_risk += 10.0
                    risk_factors.append("HTTP port 80 open (Unencrypted web interface)")
                if 22 in ports:
                    device_risk += 15.0
                    risk_factors.append("SSH port 22 open (Terminal shell access)")
                
                # Check for protocols
                protocols = dev.get("protocols_detected", dev.get("protocols", []))
                if any(p in ["Modbus", "S7Comm", "IEC104"] for p in protocols):
                    device_risk += 30.0
                    risk_factors.append("Exposing raw Industrial Control protocols (OT exposure)")

                # Model name checks
                model = dev.get("model", "")
                vendor = dev.get("vendor", "")
                full_name = f"{vendor} {model}"
                if any(pattern.lower() in full_name.lower() for pattern in ["Raspberry", "Pi"]):
                    device_risk += 25.0
                    risk_factors.append("Identified as Raspberry Pi (Possible network implant)")

                final_device_risk = min(device_risk, 100.0)
                overall_risk_score += final_device_risk

                shadow_devices.append({
                    "id": dev.get("id"),
                    "ip": dev_ip,
                    "mac": dev_mac,
                    "hostname": dev.get("hostname", "unknown"),
                    "vendor": vendor,
                    "model": model,
                    "device_type": dev.get("device_type", "Unknown"),
                    "category": dev.get("category", "IoT_Consumer"),
                    "risk_score": final_device_risk,
                    "risk_level": "CRITICAL" if final_device_risk >= 75.0 else "HIGH" if final_device_risk >= 50.0 else "MEDIUM" if final_device_risk >= 30.0 else "LOW",
                    "risk_factors": risk_factors
                })

        num_shadow = len(shadow_devices)
        avg_risk = round(overall_risk_score / max(num_shadow, 1), 2)

        return {
            "total_shadow_detected": num_shadow,
            "scan_timestamp": discovery_result.get("scan_time"),
            "shadow_devices": shadow_devices,
            "risk_summary": {
                "average_risk_score": avg_risk,
                "overall_severity_level": "CRITICAL" if avg_risk >= 70.0 else "HIGH" if avg_risk >= 50.0 else "MEDIUM" if avg_risk >= 25.0 else "LOW",
                "risk_description": f"Detected {num_shadow} unauthorized devices interacting with network resources."
            }
        }

    @classmethod
    def detect_rogue_access_points(cls, wifi_scan: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Scans a list of detected WiFi networks to locate rogue access points or hotspots.
        """
        rogue_aps = []
        overall_threat_score = 0.0

        for ap in wifi_scan:
            ssid = ap.get("ssid", "")
            bssid = ap.get("bssid", "").upper().strip()
            signal_dbm = ap.get("signal_strength", -70)
            security = ap.get("security", "WPA2")

            is_rogue = False
            rogue_reason = []
            ap_risk = 15.0

            # Match SSID patterns
            for pattern in cls.KNOWN_ROGUE_PATTERNS:
                if pattern.lower() in ssid.lower():
                    is_rogue = True
                    ap_risk += 35.0
                    rogue_reason.append(f"SSID matches rogue signature pattern '{pattern}'")

            # Check for unencrypted APs in corporate bounds
            if security.upper() in ["OPEN", "NONE"]:
                is_rogue = True
                ap_risk += 30.0
                rogue_reason.append("Open (unencrypted) security standard in use")

            # MAC address checks (e.g. if the vendor belongs to consumer router chips on a enterprise floor)
            # Simulated check
            if "GUEST" in ssid.upper() and security.upper() != "WPA2-ENTERPRISE":
                is_rogue = True
                ap_risk += 20.0
                rogue_reason.append("Unsecured guest AP mimicking enterprise SSID")

            if is_rogue:
                final_risk = min(ap_risk, 100.0)
                overall_threat_score += final_risk
                rogue_aps.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_strength_dbm": signal_dbm,
                    "security_type": security,
                    "channel": ap.get("channel", 6),
                    "estimated_distance_m": round(10 ** ((27.55 - (20 * 2.4) - abs(signal_dbm)) / 20), 2),
                    "risk_score": final_risk,
                    "risk_reasons": rogue_reason
                })

        num_rogues = len(rogue_aps)
        avg_threat = round(overall_threat_score / max(num_rogues, 1), 2)

        return {
            "rogue_aps_found": rogue_aps,
            "total_rogues": num_rogues,
            "average_threat_score": avg_threat,
            "mitigation_advice": [
                "Locate physical device using RF signal triangulation.",
                "Verify switch port MAC tables for associated wireless bridge devices.",
                "Deploy wireless intrusion prevention system (WIPS) to broadcast deauthentication frames."
            ]
        }

    @classmethod
    def detect_raspberry_pi_implants(cls, discovery_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes discovered assets to locate hidden Raspberry Pi implants acting as lateral access points.
        """
        devices = discovery_result.get("devices", [])
        implants = []
        
        # Official OUI prefixes associated with Raspberry Pi foundation
        pi_mac_prefixes = ["DC:A6:32", "B8:27:EB", "D8:3A:DD", "E4:5F:01"]

        for dev in devices:
            mac = dev.get("mac", "").upper()
            vendor = dev.get("vendor", "")
            model = dev.get("model", "")
            
            is_pi = False
            reasons = []

            # Check MAC prefix
            if any(mac.startswith(prefix) for prefix in pi_mac_prefixes):
                is_pi = True
                reasons.append(f"MAC prefix matches Raspberry Pi Foundation OUI.")

            # Check Vendor / Model fields
            if "raspberry" in vendor.lower() or "raspberry" in model.lower():
                is_pi = True
                reasons.append("Device vendor details contain 'Raspberry Pi'.")

            if is_pi:
                # Assess implant threat level based on active network behavior
                open_ports = dev.get("open_ports", [])
                threat_level = "MEDIUM"
                risk_score = 40.0
                
                # Pi with SSH/HTTP is likely a manual implant interface
                if 22 in open_ports or 23 in open_ports:
                    threat_level = "HIGH"
                    risk_score += 30.0
                    reasons.append("Administrative port (SSH/Telnet) is active.")
                if 8080 in open_ports or 80 in open_ports:
                    threat_level = "HIGH"
                    risk_score += 15.0
                    reasons.append("Web proxy or staging server active (Port 80/8080).")

                implants.append({
                    "id": dev.get("id"),
                    "ip": dev.get("ip"),
                    "mac": mac,
                    "hostname": dev.get("hostname"),
                    "open_ports": open_ports,
                    "threat_level": threat_level,
                    "risk_score": risk_score,
                    "reasons_flagged": reasons
                })

        return {
            "implant_count": len(implants),
            "implants": implants,
            "alert_triggered": len(implants) > 0,
            "recommended_action": "Immediately disable physical switchport matching the implant MAC address."
        }

    @classmethod
    def detect_unauthorized_cameras(cls, discovery_result: Dict[str, Any], auth_cameras: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Cross-references discovered CCTV cameras against the authorized surveillance camera registry.
        """
        devices = discovery_result.get("devices", [])
        
        # Build lookup from authorized cameras list
        auth_ips = {c.get("ip", "").strip() for c in auth_cameras}
        auth_macs = {c.get("mac", "").upper().strip() for c in auth_cameras}

        unauthorized_cameras = []

        for dev in devices:
            # We target device category or specific camera models
            is_camera = (dev.get("device_type") in ["CCTV_Camera", "NVR"]) or ("camera" in dev.get("device_type", "").lower())
            
            if is_camera:
                ip = dev.get("ip", "").strip()
                mac = dev.get("mac", "").upper().strip()

                is_authorized = (ip in auth_ips) or (mac in auth_macs)
                if not is_authorized:
                    # Capture unlisted camera details
                    unauthorized_cameras.append({
                        "id": dev.get("id"),
                        "ip": ip,
                        "mac": mac,
                        "vendor": dev.get("vendor"),
                        "model": dev.get("model"),
                        "open_ports": dev.get("open_ports"),
                        "risk_score": 65.0,  # Unauthorized cameras present high threat of espionage / leakage
                        "mitre_technique": "T0809 - Espionage / Rogue Camera Implant"
                    })

        return {
            "unauthorized_camera_count": len(unauthorized_cameras),
            "unauthorized_cameras": unauthorized_cameras,
            "risk_level": "HIGH" if len(unauthorized_cameras) > 0 else "LOW",
            "action_items": [
                "De-authenticate rogue IP from CCTV VLAN.",
                "Review physical access security of the deployment area.",
                "Check for RTSP feed credentials compromise."
            ]
        }
