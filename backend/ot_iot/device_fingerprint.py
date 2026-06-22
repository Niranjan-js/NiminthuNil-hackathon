import re
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("niravan.ot_iot.device_fingerprint")


class DeviceFingerprint:
    """
    Device Fingerprinting Engine for NIRAVAN OT/IoT Defense Layer.
    Parses and matches HTTP banners, SNMP sysDescr, Telnet greetings, and UPnP XML data
    to extract device profiles, vendor, model, device type, firmware, and known CVEs.
    """

    # Keyword database mapping banners to device details
    FINGERPRINT_DB: Dict[str, Dict[str, Any]] = {
        # HTTP Server banners
        "Hikvision-Webs": {
            "vendor": "Hikvision",
            "model": "DS-2CD2043G0-I",
            "device_type": "CCTV_Camera",
            "confidence": 0.95
        },
        "Dahua-Webs": {
            "vendor": "Dahua",
            "model": "IPC-HDW2831T-AS",
            "device_type": "CCTV_Camera",
            "confidence": 0.95
        },
        "Allegro-Software-RomPager": {
            "vendor": "Cisco",
            "model": "CP-8865",
            "device_type": "IP_Phone",
            "confidence": 0.85
        },
        "Siemens-SIMATIC": {
            "vendor": "Siemens",
            "model": "SIMATIC S7-1200",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "Schneider-Modicon": {
            "vendor": "Schneider Electric",
            "model": "Modicon M221",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "AC500-PM591": {
            "vendor": "ABB",
            "model": "AC500 PM591",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "HP-LaserJet": {
            "vendor": "HP",
            "model": "LaserJet M428fdw",
            "device_type": "Printer",
            "confidence": 0.90
        },

        # SNMP sysDescr keywords
        "SIMATIC S7-1200": {
            "vendor": "Siemens",
            "model": "SIMATIC S7-1200",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "Modicon M221": {
            "vendor": "Schneider Electric",
            "model": "Modicon M221",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "AC500 PM591": {
            "vendor": "ABB",
            "model": "AC500 PM591",
            "device_type": "PLC",
            "confidence": 0.99
        },
        "STARDOM FCN-100": {
            "vendor": "Yokogawa",
            "model": "STARDOM FCN-100",
            "device_type": "RTU",
            "confidence": 0.99
        },
        "Cisco IOS": {
            "vendor": "Cisco",
            "model": "CP-8865",
            "device_type": "IP_Phone",
            "confidence": 0.85
        },
        "Hikvision DS-2CD2043G0-I": {
            "vendor": "Hikvision",
            "model": "DS-2CD2043G0-I",
            "device_type": "CCTV_Camera",
            "confidence": 0.98
        },
        "Dahua IPC-HDW2831T-AS": {
            "vendor": "Dahua",
            "model": "IPC-HDW2831T-AS",
            "device_type": "CCTV_Camera",
            "confidence": 0.98
        },

        # Telnet greeting keywords
        "Welcome to Hikvision IP Camera": {
            "vendor": "Hikvision",
            "model": "DS-2CD2043G0-I",
            "device_type": "CCTV_Camera",
            "confidence": 0.95
        },
        "Dahua Telnet Service": {
            "vendor": "Dahua",
            "model": "IPC-HDW2831T-AS",
            "device_type": "CCTV_Camera",
            "confidence": 0.95
        },
        "Siemens S7 Telnet Server": {
            "vendor": "Siemens",
            "model": "SIMATIC S7-1200",
            "device_type": "PLC",
            "confidence": 0.95
        },
        "Cisco CP-8865": {
            "vendor": "Cisco",
            "model": "CP-8865",
            "device_type": "IP_Phone",
            "confidence": 0.98
        },

        # UPnP XML keywords
        "MediaServer:1": {
            "vendor": "Samsung",
            "model": "QN65Q80B Smart TV",
            "device_type": "Smart_TV",
            "confidence": 0.80
        },
        "InternetGatewayDevice:1": {
            "vendor": "TP-Link",
            "model": "TL-SG1024D",
            "device_type": "Industrial_Switch",
            "confidence": 0.80
        },
        "Printer:1": {
            "vendor": "HP",
            "model": "LaserJet M428fdw",
            "device_type": "Printer",
            "confidence": 0.85
        },
        "Epson": {
            "vendor": "Epson",
            "model": "WF-3820",
            "device_type": "Printer",
            "confidence": 0.85
        }
    }

    @staticmethod
    def _extract_firmware(text: str) -> str:
        """Helper to extract firmware version from banner text using common regex patterns."""
        if not text:
            return "Unknown"
        patterns = [
            r"(?:version|Version|ver|Ver|v|V|Build|build|SV|R|fv|FV)\s*[:/]?\s*([a-zA-Z0-9\._\-]+)",
            r"([0-9]+\.[0-9]+\.[0-9]+(?:[\.\-_a-zA-Z0-9]+)?)",
            r"build\s*([0-9]+)"
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                val = match.group(1).strip()
                if val and (val[0].isdigit() or (len(val) > 1 and val[1].isdigit())):
                    return val
        return "Unknown"

    @staticmethod
    def _get_cves_for_device(vendor: str, model: str, firmware: str) -> List[str]:
        """Lookup CVEs for specific vendor and model based on a simulated database."""
        cve_map = {
            "Hikvision": ["CVE-2021-36260", "CVE-2017-7921"],
            "Dahua": ["CVE-2021-33044", "CVE-2021-33045"],
            "Cisco": ["CVE-2020-3161"],
            "Siemens": ["CVE-2022-38773", "CVE-2020-7589"],
            "Schneider Electric": ["CVE-2020-7537", "CVE-2020-7538"],
            "ABB": ["CVE-2020-11649"],
            "Yokogawa": ["CVE-2018-16194"],
            "HP": ["CVE-2021-39238", "CVE-2021-39237"],
            "Samsung": ["CVE-2021-24021"],
            "TP-Link": ["CVE-2022-24355"],
            "Epson": ["CVE-2021-44731"]
        }
        return cve_map.get(vendor, [])

    @classmethod
    def fingerprint_from_http_banner(cls, banner: str) -> Dict[str, Any]:
        """Parses HTTP Server / WWW-Authenticate banner to identify device."""
        if not banner:
            return cls._unknown_fingerprint()

        vendor = "Unknown"
        model = "Unknown"
        device_type = "Unknown"
        confidence = 0.0

        for kw, meta in cls.FINGERPRINT_DB.items():
            if kw.lower() in banner.lower():
                vendor = meta["vendor"]
                model = meta["model"]
                device_type = meta["device_type"]
                confidence = meta["confidence"]
                break

        firmware = cls._extract_firmware(banner)
        open_cves = cls._get_cves_for_device(vendor, model, firmware)

        return {
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "firmware": firmware,
            "confidence": confidence,
            "open_cves": open_cves
        }

    @classmethod
    def fingerprint_from_snmp(cls, sys_descr: str) -> Dict[str, Any]:
        """Parses SNMP sysDescr string to identify device."""
        if not sys_descr:
            return cls._unknown_fingerprint()

        vendor = "Unknown"
        model = "Unknown"
        device_type = "Unknown"
        confidence = 0.0

        for kw, meta in cls.FINGERPRINT_DB.items():
            if kw.lower() in sys_descr.lower():
                vendor = meta["vendor"]
                model = meta["model"]
                device_type = meta["device_type"]
                confidence = meta["confidence"]
                break

        firmware = cls._extract_firmware(sys_descr)
        open_cves = cls._get_cves_for_device(vendor, model, firmware)

        return {
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "firmware": firmware,
            "confidence": confidence,
            "open_cves": open_cves
        }

    @classmethod
    def fingerprint_from_telnet(cls, greeting: str) -> Dict[str, Any]:
        """Parses Telnet banner / greeting to identify device."""
        if not greeting:
            return cls._unknown_fingerprint()

        vendor = "Unknown"
        model = "Unknown"
        device_type = "Unknown"
        confidence = 0.0

        for kw, meta in cls.FINGERPRINT_DB.items():
            if kw.lower() in greeting.lower():
                vendor = meta["vendor"]
                model = meta["model"]
                device_type = meta["device_type"]
                confidence = meta["confidence"]
                break

        firmware = cls._extract_firmware(greeting)
        open_cves = cls._get_cves_for_device(vendor, model, firmware)

        return {
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "firmware": firmware,
            "confidence": confidence,
            "open_cves": open_cves
        }

    @classmethod
    def fingerprint_from_upnp(cls, xml: str) -> Dict[str, Any]:
        """Parses UPnP XML device descriptions."""
        if not xml:
            return cls._unknown_fingerprint()

        vendor = "Unknown"
        model = "Unknown"
        device_type = "Unknown"
        confidence = 0.0

        # Try XML tags extraction
        manufacturer_match = re.search(r"<manufacturer>(.*?)</manufacturer>", xml, re.IGNORECASE)
        model_match = re.search(r"<modelName>(.*?)</modelName>", xml, re.IGNORECASE)
        device_type_match = re.search(r"<deviceType>(.*?)</deviceType>", xml, re.IGNORECASE)
        firmware_match = re.search(r"<firmware>(.*?)</firmware>", xml, re.IGNORECASE)

        if manufacturer_match:
            vendor = manufacturer_match.group(1).strip()
            confidence = 0.5
        if model_match:
            model = model_match.group(1).strip()
            confidence = 0.7
        if device_type_match:
            dt = device_type_match.group(1).strip()
            if ":" in dt:
                parts = dt.split(":")
                device_type = parts[-2] if len(parts) >= 4 else parts[-1]
            else:
                device_type = dt

        # Refine using database keywords
        for kw, meta in cls.FINGERPRINT_DB.items():
            if kw.lower() in xml.lower():
                vendor = meta["vendor"]
                model = meta["model"]
                device_type = meta["device_type"]
                confidence = max(confidence, meta["confidence"])
                break

        firmware = firmware_match.group(1).strip() if firmware_match else cls._extract_firmware(xml)
        open_cves = cls._get_cves_for_device(vendor, model, firmware)

        return {
            "vendor": vendor,
            "model": model,
            "device_type": device_type,
            "firmware": firmware,
            "confidence": confidence,
            "open_cves": open_cves
        }

    @classmethod
    def fingerprint_device(cls, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrator checking all HTTP, SNMP, Telnet, and UPnP sources,
        returning a merged fingerprint result.
        """
        results = []

        # HTTP check
        http_keys = ["http_banner", "http_server", "banner", "http"]
        http_val = next((device_info[k] for k in http_keys if k in device_info and device_info[k]), None)
        if http_val:
            results.append(cls.fingerprint_from_http_banner(http_val))

        # SNMP check
        snmp_keys = ["snmp_sys_descr", "sys_descr", "snmp", "sysDescr"]
        snmp_val = next((device_info[k] for k in snmp_keys if k in device_info and device_info[k]), None)
        if snmp_val:
            results.append(cls.fingerprint_from_snmp(snmp_val))

        # Telnet check
        telnet_keys = ["telnet_greeting", "greeting", "telnet"]
        telnet_val = next((device_info[k] for k in telnet_keys if k in device_info and device_info[k]), None)
        if telnet_val:
            results.append(cls.fingerprint_from_telnet(telnet_val))

        # UPnP check
        upnp_keys = ["upnp_xml", "xml", "upnp"]
        upnp_val = next((device_info[k] for k in upnp_keys if k in device_info and device_info[k]), None)
        if upnp_val:
            results.append(cls.fingerprint_from_upnp(upnp_val))

        if not results:
            vendor = device_info.get("vendor", "Unknown")
            model = device_info.get("model", "Unknown")
            device_type = device_info.get("device_type", "Unknown")
            firmware = device_info.get("firmware", "Unknown")
            return {
                "vendor": vendor,
                "model": model,
                "device_type": device_type,
                "firmware": firmware,
                "confidence": 0.5 if vendor != "Unknown" else 0.0,
                "open_cves": cls._get_cves_for_device(vendor, model, firmware)
            }

        # Merging logic: Select highest confidence as baseline
        best_match = max(results, key=lambda x: x["confidence"])

        merged = {
            "vendor": best_match["vendor"],
            "model": best_match["model"],
            "device_type": best_match["device_type"],
            "firmware": best_match["firmware"],
            "confidence": best_match["confidence"],
            "open_cves": best_match["open_cves"]
        }

        all_cves = set(merged["open_cves"])

        # Populate unknowns and aggregate CVEs
        for r in results:
            if r["vendor"] != "Unknown" and merged["vendor"] == "Unknown":
                merged["vendor"] = r["vendor"]
            if r["model"] != "Unknown" and merged["model"] == "Unknown":
                merged["model"] = r["model"]
            if r["device_type"] != "Unknown" and merged["device_type"] == "Unknown":
                merged["device_type"] = r["device_type"]
            if r["firmware"] != "Unknown" and merged["firmware"] == "Unknown":
                merged["firmware"] = r["firmware"]
            if r["confidence"] > merged["confidence"]:
                merged["confidence"] = r["confidence"]
            all_cves.update(r["open_cves"])

        merged["open_cves"] = sorted(list(all_cves))
        logger.info(f"Fingerprinted device to {merged['vendor']} {merged['model']} (confidence: {merged['confidence']})")
        return merged

    @staticmethod
    def _unknown_fingerprint() -> Dict[str, Any]:
        """Default unknown fingerprint response."""
        return {
            "vendor": "Unknown",
            "model": "Unknown",
            "device_type": "Unknown",
            "firmware": "Unknown",
            "confidence": 0.0,
            "open_cves": []
        }
