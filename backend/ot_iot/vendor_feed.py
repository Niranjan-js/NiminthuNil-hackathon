import logging
import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.vendor_feed")


class VendorFeedAggregator:
    """
    Simulated Threat Intelligence Feed Aggregator for IoT/OT vendors.
    Retrieves and caches CVE security advisories and syncs with CISA/ICS-CERT catalogs.
    """

    VENDOR_FEEDS: Dict[str, Dict[str, str]] = {
        "Hikvision": {
            "url": "https://www.hikvision.com/en/support/cybersecurity/security-advisory/",
            "name": "Hikvision Security Advisory RSS Feed",
            "format": "XML/RSS"
        },
        "Dahua": {
            "url": "https://www.dahuasecurity.com/support/cybersecurity/advisory/",
            "name": "Dahua Cybersecurity Advisory Bulletin",
            "format": "JSON"
        },
        "Siemens CERT": {
            "url": "https://cert-portal.siemens.com/productcert/txt/advisories.txt",
            "name": "Siemens ProductCERT Advisory Portal",
            "format": "Text/TXT"
        },
        "Schneider": {
            "url": "https://www.se.com/ww/en/download/document/Schneider-Electric-Security-Advisory-Feed/",
            "name": "Schneider Electric Security Advisory Portal",
            "format": "XML/RSS"
        },
        "Axis": {
            "url": "https://www.axis.com/support/product-security/security-advisories",
            "name": "Axis Security Advisory Bulletins",
            "format": "HTML"
        },
        "Cisco": {
            "url": "https://tools.cisco.com/security/center/publicationTemp.x",
            "name": "Cisco Security Advisories and Alerts Feed",
            "format": "JSON"
        },
        "ICS-CERT": {
            "url": "https://www.cisa.gov/uscert/ics/advisories",
            "name": "CISA Industrial Control Systems Advisory Feed",
            "format": "XML/RSS"
        },
        "CISA KEV": {
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "name": "CISA Known Exploited Vulnerabilities Catalog",
            "format": "JSON"
        }
    }

    # 15+ Simulated recent advisories around current date (2026-06-21)
    RECENT_ADVISORIES: List[Dict[str, Any]] = [
        {
            "advisory_id": "HCSA-2026-095",
            "cve_id": "CVE-2021-36260",
            "vendor": "Hikvision",
            "title": "Hikvision IP Camera Unauthenticated Command Injection",
            "description": "Critical vulnerability in the web server module of Hikvision cameras allows injection of malicious command arguments.",
            "published_date": "2026-06-18",
            "severity": "CRITICAL",
            "remediation_actions": "Apply Hikvision firmware patch released on June 18."
        },
        {
            "advisory_id": "DASA-2026-112",
            "cve_id": "CVE-2021-33044",
            "vendor": "Dahua",
            "title": "Dahua Network Camera Authentication Bypass Advisory",
            "description": "Flaw in authorization mechanism allows remote attackers to bypass login credentials and hijack stream control.",
            "published_date": "2026-06-15",
            "severity": "CRITICAL",
            "remediation_actions": "Disable HTTP management port 80 or upgrade to latest camera firmware."
        },
        {
            "advisory_id": "SSA-781290",
            "cve_id": "CVE-2022-38465",
            "vendor": "Siemens CERT",
            "title": "Siemens SIMATIC S7 PLC Cryptographic Key Leakage",
            "description": "Hardcoded keying material extracted from SIMATIC S7-1200/1500 firmware exposes control logic downloads to replay attacks.",
            "published_date": "2026-06-14",
            "severity": "HIGH",
            "remediation_actions": "Configure secure PG/PC communications with TLS in Siemens TIA Portal."
        },
        {
            "advisory_id": "SEVD-2026-152",
            "cve_id": "CVE-2021-22779",
            "vendor": "Schneider",
            "title": "Schneider Modicon PLC Modbus Authentication Failure",
            "description": "Lack of verification in Modbus command routines allows injection of arbitrary coils/registers changes.",
            "published_date": "2026-06-10",
            "severity": "CRITICAL",
            "remediation_actions": "Restrict port 502 to authorized engineering workstation subnet."
        },
        {
            "advisory_id": "AXSA-2026-003",
            "cve_id": "CVE-2018-19035",
            "vendor": "Axis",
            "title": "Axis Communications VAPIX API Buffer Overflow",
            "description": "Unauthenticated buffer overflow vulnerability in parameter parsing API allows remote script execution.",
            "published_date": "2026-06-20",
            "severity": "CRITICAL",
            "remediation_actions": "Apply AXIS OS firmware update released on June 20."
        },
        {
            "advisory_id": "CISCO-SA-202606-08",
            "cve_id": "CVE-2026-9912",
            "vendor": "Cisco",
            "title": "Cisco IOS-XE Wireless Controller DoS Vulnerability",
            "description": "An issue in CAPWAP protocol processing allows remote attackers to force system reload.",
            "published_date": "2026-06-19",
            "severity": "HIGH",
            "remediation_actions": "Upgrade IOS-XE to patch release v17.9.4a."
        },
        {
            "advisory_id": "ICSA-26-160-01",
            "cve_id": "CVE-2022-2068",
            "vendor": "ICS-CERT",
            "title": "Moxa NPort Device Server Injection Advisory",
            "description": "Moxa NPort serial device servers contain OS command injection vulnerabilities in their web interface.",
            "published_date": "2026-06-11",
            "severity": "HIGH",
            "remediation_actions": "Update Moxa NPort firmware to patch SV2.10."
        },
        {
            "advisory_id": "HCSA-2026-092",
            "cve_id": "CVE-2020-9512",
            "vendor": "Hikvision",
            "title": "Hikvision Setup Data Leakage Vulnerability",
            "description": "Vulnerability allows reading local configuration files from the device web controller interface.",
            "published_date": "2026-06-08",
            "severity": "MEDIUM",
            "remediation_actions": "Enable secure account lockouts and change administrative setup credentials."
        },
        {
            "advisory_id": "DASA-2026-105",
            "cve_id": "CVE-2021-33045",
            "vendor": "Dahua",
            "title": "Dahua Connection Parser RCE Vulnerability",
            "description": "Memory overflow in Dahua network configuration API parses data parameters causing execution hijacking.",
            "published_date": "2026-06-05",
            "severity": "CRITICAL",
            "remediation_actions": "Apply latest firmware revisions from Dahua security advisory board."
        },
        {
            "advisory_id": "SSA-993801",
            "cve_id": "CVE-2019-19281",
            "vendor": "Siemens CERT",
            "title": "Siemens SIMATIC S7-300 Access Protection Bypass",
            "description": "A design flow flaw permits reading program logic blocks directly over S7 network protocols.",
            "published_date": "2026-06-02",
            "severity": "MEDIUM",
            "remediation_actions": "Deploy Siemens CPU protection level passwords."
        },
        {
            "advisory_id": "SEVD-2026-140",
            "cve_id": "CVE-2022-45788",
            "vendor": "Schneider",
            "title": "Schneider Modicon CoP Protocol Unauthenticated Execution",
            "description": "Command routines in Schneider Modicon CoP protocol allows sending executable blocks without login.",
            "published_date": "2026-05-28",
            "severity": "HIGH",
            "remediation_actions": "Enable secure modbus protocols and implement switch port ACLs."
        },
        {
            "advisory_id": "ICSA-26-150-02",
            "cve_id": "CVE-2021-22681",
            "vendor": "ICS-CERT",
            "title": "Rockwell Logix5000 Authentication Bypass Advisory",
            "description": "Rockwell Automation Logix5000 controllers contain authentication bypass vulnerability through pre-shared keys leak.",
            "published_date": "2026-06-01",
            "severity": "CRITICAL",
            "remediation_actions": "Activate CIP Security configs in Rockwell software configuration suite."
        },
        {
            "advisory_id": "AXSA-2026-002",
            "cve_id": "CVE-2023-21406",
            "vendor": "Axis",
            "title": "Axis Device Telemetry API Memory Leak",
            "description": "Resource leak in Axis Communications VAPIX API causes network subsystem failure under high load.",
            "published_date": "2026-05-20",
            "severity": "MEDIUM",
            "remediation_actions": "Limit access to Axis VAPIX ports on transit interfaces."
        },
        {
            "advisory_id": "HONY-2026-001",
            "cve_id": "CVE-2021-38395",
            "vendor": "Honeywell",
            "title": "Honeywell T6 Pro Thermostat Directory Traversal",
            "description": "Flaw allows reading system configuration parameter files from Honeywell T6 series controllers.",
            "published_date": "2026-06-17",
            "severity": "HIGH",
            "remediation_actions": "Isolate Honeywell thermostat segment using dynamic firewall rules."
        },
        {
            "advisory_id": "ABBA-2026-005",
            "cve_id": "CVE-2020-8481",
            "vendor": "ABB",
            "title": "ABB PM591 PLC Software Buffer Overflow",
            "description": "Vulnerability in ABB Panel Builder utility software allows execution of arbitrary payloads.",
            "published_date": "2026-06-12",
            "severity": "HIGH",
            "remediation_actions": "Apply ABB PB610 software update patches."
        }
    ]

    @classmethod
    def get_feed(cls, vendor: str) -> Optional[Dict[str, str]]:
        """
        Retrieves configuration and endpoint details of a specific vendor feed.
        """
        vendor_clean = vendor.strip().lower()
        for name, feed in cls.VENDOR_FEEDS.items():
            if vendor_clean in name.lower() or name.lower() in vendor_clean:
                return feed
        logger.warning(f"Vendor feed config for '{vendor}' not found.")
        return None

    @classmethod
    def get_all_recent_advisories(cls, days: int = 15) -> List[Dict[str, Any]]:
        """
        Fetch all simulated advisories released within the specified window of days.
        Current time reference: 2026-06-21.
        """
        current_ref_date = datetime.date(2026, 6, 21)
        matched = []

        for adv in cls.RECENT_ADVISORIES:
            try:
                pub_date = datetime.datetime.strptime(adv["published_date"], "%Y-%m-%d").date()
                delta_days = (current_ref_date - pub_date).days
                if 0 <= delta_days <= days:
                    matched.append(adv)
            except ValueError as e:
                logger.error(f"Failed to parse advisory date for {adv['advisory_id']}: {e}")

        return matched

    @classmethod
    def check_vendor_advisory(cls, vendor: str, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Looks up the advisory cache to check if a specific CVE ID has been registered by a vendor.
        """
        vendor_clean = vendor.strip().lower()
        cve_clean = cve_id.strip().upper()

        for adv in cls.RECENT_ADVISORIES:
            adv_vendor = adv["vendor"].lower()
            if (vendor_clean in adv_vendor or adv_vendor in vendor_clean) and adv["cve_id"].upper() == cve_clean:
                return adv
        return None

    @classmethod
    def sync_feeds(cls) -> Dict[str, Any]:
        """
        Simulates an active connection and synchronization with all vendor advisories, CISA and ICS feeds.
        """
        timestamp = datetime.datetime.utcnow().isoformat()
        synced_vendors = list(cls.VENDOR_FEEDS.keys())
        
        logger.info(f"Threat Intel Feed sync triggered at {timestamp}.")

        return {
            "status": "SUCCESS",
            "last_synced_time": timestamp,
            "total_feeds_synced": len(synced_vendors),
            "synced_feeds": synced_vendors,
            "new_advisories_synced_count": len(cls.RECENT_ADVISORIES),
            "threat_intel_notes": "CISA KEV mapping updated. 13 active KEV items synchronized into local cache."
        }
