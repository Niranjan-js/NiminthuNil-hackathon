import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger("niravan.ot_iot.firmware_scanner")


class FirmwareScanner:
    """
    Firmware Vulnerability and Risk Scanning Engine for NIRAVAN OT/IoT Defense Layer.
    Audits firmware against known CVEs, checks CISA KEV (Known Exploited Vulnerabilities),
    lists default vendor passwords, and computes risk scores.
    """

    # Simulated CVE database mapping vendor:model:version to CVE details
    CVE_DATABASE: Dict[str, List[Dict[str, Any]]] = {
        "Hikvision:DS-2CD2043G0-I:V5.7.3": [
            {
                "cve_id": "CVE-2021-36260",
                "cvss": 9.8,
                "description": "Command injection vulnerability in web server due to lack of input validation",
                "severity": "CRITICAL"
            },
            {
                "cve_id": "CVE-2017-7921",
                "cvss": 8.1,
                "description": "Backdoor privilege escalation vulnerability allowing unauthenticated access",
                "severity": "HIGH"
            }
        ],
        "Dahua:IPC-HDW2831T-AS:V2.820.0000000.2.R": [
            {
                "cve_id": "CVE-2021-33044",
                "cvss": 9.8,
                "description": "Authentication bypass vulnerability during device login process",
                "severity": "CRITICAL"
            },
            {
                "cve_id": "CVE-2021-33045",
                "cvss": 9.8,
                "description": "Connection authentication bypass vulnerability in video stream interface",
                "severity": "CRITICAL"
            }
        ],
        "Cisco:CP-8865:12.8.1": [
            {
                "cve_id": "CVE-2020-3161",
                "cvss": 9.8,
                "description": "Cisco IP Phone web server remote code execution / denial of service",
                "severity": "CRITICAL"
            }
        ],
        "Siemens:SIMATIC S7-1200:V4.5.0": [
            {
                "cve_id": "CVE-2022-38773",
                "cvss": 7.5,
                "description": "Denial of service vulnerability via malformed PROFINET packets",
                "severity": "HIGH"
            }
        ],
        "Schneider Electric:Modicon M221:SV1.13.0.0": [
            {
                "cve_id": "CVE-2020-7537",
                "cvss": 7.5,
                "description": "Modbus protocol lack of authentication allowing firmware configuration modification",
                "severity": "HIGH"
            },
            {
                "cve_id": "CVE-2020-7538",
                "cvss": 9.8,
                "description": "Command execution via engineering port and diagnostic commands",
                "severity": "CRITICAL"
            }
        ],
        "Yokogawa:STARDOM FCN-100:R10.04": [
            {
                "cve_id": "CVE-2018-16194",
                "cvss": 8.3,
                "description": "Yokogawa STARDOM CPU module memory corruption leading to code execution",
                "severity": "HIGH"
            }
        ]
    }

    # Vendor default credential lists
    DEFAULT_PASSWORDS: Dict[str, List[Dict[str, str]]] = {
        "Hikvision": [
            {"username": "admin", "password": "12345"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin"}
        ],
        "Dahua": [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "admin123"},
            {"username": "admin", "password": "123456"}
        ],
        "Cisco": [
            {"username": "admin", "password": "admin"},
            {"username": "cisco", "password": "cisco"},
            {"username": "admin", "password": "cisco"}
        ],
        "Siemens": [
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"}
        ],
        "Schneider Electric": [
            {"username": "admin", "password": "admin"},
            {"username": "User", "password": "User"},
            {"username": "Administrator", "password": "Password"}
        ],
        "ABB": [
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"}
        ],
        "Yokogawa": [
            {"username": "yokogawa", "password": "stardom"},
            {"username": "admin", "password": "admin"}
        ],
        "HP": [
            {"username": "admin", "password": ""},
            {"username": "admin", "password": "admin"}
        ],
        "TP-Link": [
            {"username": "admin", "password": "admin"}
        ],
        "Epson": [
            {"username": "admin", "password": "access"},
            {"username": "admin", "password": "admin"}
        ]
    }

    # CISA Known Exploited Vulnerabilities list
    CISA_KEV_IDS: Set[str] = {
        "CVE-2021-36260",  # Hikvision Command Injection
        "CVE-2017-7921",   # Hikvision Backdoor
        "CVE-2023-20198",  # Cisco IOS XE Web UI Privilege Escalation
        "CVE-2021-33044",  # Dahua Auth Bypass
        "CVE-2021-33045",  # Dahua Auth Bypass
        "CVE-2020-3161"    # Cisco IP Phone RCE
    }

    @classmethod
    def check_default_passwords(cls, vendor: str) -> List[Dict[str, str]]:
        """Returns the simulated default passwords for the given vendor."""
        for v, credentials in cls.DEFAULT_PASSWORDS.items():
            if v.lower() == vendor.lower():
                return credentials
        return [{"username": "admin", "password": "admin"}]

    @classmethod
    def calculate_risk_score(cls, cve_list: List[Any]) -> float:
        """
        Calculates a normalized risk score from 0.0 to 10.0 based on CVEs.
        Computes compound risk by weighting auxiliary CVEs.
        """
        if not cve_list:
            return 0.0

        cvss_scores = []
        for cve in cve_list:
            if isinstance(cve, dict):
                cvss_scores.append(cve.get("cvss", 5.0))
            elif isinstance(cve, str):
                cvss_scores.append(cls._find_cvss_for_cve_id(cve))

        if not cvss_scores:
            return 0.0

        max_cvss = max(cvss_scores)
        # Add 10% of other vulnerability scores as compound risk, cap at 10.0
        extra_risk = sum(score * 0.1 for score in cvss_scores if score != max_cvss)
        final_score = min(max_cvss + extra_risk, 10.0)
        return round(final_score, 2)

    @classmethod
    def _find_cvss_for_cve_id(cls, cve_id: str) -> float:
        """Helper to lookup CVSS score of a CVE ID within the local database."""
        for cve_list in cls.CVE_DATABASE.values():
            for cve in cve_list:
                if cve["cve_id"] == cve_id:
                    return cve["cvss"]
        # Standard values for fallback
        if "CVE-2023-20198" in cve_id:
            return 10.0
        return 5.0

    @classmethod
    def scan(cls, vendor: str, model: str, firmware_version: str) -> Dict[str, Any]:
        """
        Scans a specific device's firmware for CVEs, CISA KEV flags,
        and retrieves default passwords to inspect.
        """
        cve_entries = []
        exact_key = f"{vendor}:{model}:{firmware_version}"

        # Try exact search
        if exact_key in cls.CVE_DATABASE:
            cve_entries = [dict(c) for c in cls.CVE_DATABASE[exact_key]]
        else:
            # Fallback search by vendor/model prefix
            fuzzy_pattern = f"{vendor}:{model}:".lower()
            for key, val in cls.CVE_DATABASE.items():
                if key.lower().startswith(fuzzy_pattern):
                    cve_entries = [dict(c) for c in val]
                    break

        # Check if CVEs are in CISA KEV list
        cisa_kev_active = False
        for cve in cve_entries:
            cve_id = cve["cve_id"]
            if cve_id in cls.CISA_KEV_IDS:
                cisa_kev_active = True
                cve["cisa_kev"] = True
            else:
                cve["cisa_kev"] = False

        passwords = cls.check_default_passwords(vendor)
        risk_score = cls.calculate_risk_score(cve_entries)

        # Set suggested mitigation response
        if risk_score >= 9.0:
            recommended_action = "CRITICAL: Urgent firmware upgrade required. Isolate device in Quarantine VLAN immediately."
        elif risk_score >= 7.0:
            recommended_action = "HIGH: Firmware upgrade advised. Restrict network access and monitor protocols."
        elif risk_score >= 4.0:
            recommended_action = "MEDIUM: Change default credentials and apply subnet isolation policies."
        else:
            recommended_action = "LOW: Ensure default credentials are changed. Keep monitoring baseline traffic."

        if cisa_kev_active:
            recommended_action = f"CISA KEV ALERT: {recommended_action} Exploited in the wild!"

        logger.info(f"Finished vulnerability scan on {vendor} {model} (version: {firmware_version}). Risk Score: {risk_score}")
        return {
            "cves": cve_entries,
            "default_passwords_checked": passwords,
            "risk_score": risk_score,
            "recommended_action": recommended_action,
            "cisa_kev_active": cisa_kev_active
        }
