from typing import Dict, Any

class ASNMapper:
    @staticmethod
    def map_ip_to_asn(ip: str) -> Dict[str, Any]:
        """Queries mock WHOIS data to determine ASN, Org name, and IP subnet ranges."""
        asn = 45820
        org = "Tamil Nadu State Data Centre"
        subnet = "185.220.101.0/24" if ip.startswith("185.220") else "10.0.0.0/8"

        if ip.startswith("185.220") or ip.startswith("91.240"):
            asn = 1337
            org = "Global Tor Exit Transit"

        return {
            "ip": ip,
            "asn": asn,
            "org_name": org,
            "subnet": subnet
        }
