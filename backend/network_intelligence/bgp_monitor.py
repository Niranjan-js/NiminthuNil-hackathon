from typing import List, Dict, Any

class BGPMonitor:
    @staticmethod
    def inspect_prefix_announcements(asn: int, prefix: str, path_list: List[int]) -> Dict[str, Any]:
        """Detects potential BGP prefix hijacking by validating ASN origins."""
        suspicious = False
        reason = "Normal prefix announcement"
        
        # Simulated check: if prefix is government asset but origin ASN is overseas (e.g. AS1337)
        if "gov.in" in prefix.lower() or prefix.startswith("10.0."):
            if len(path_list) > 0 and path_list[-1] in [1337, 9999]:
                suspicious = True
                reason = "BGP Route Hijack: Government subnet advertised by unauthorized overseas ASN origin!"

        return {
            "monitored_asn": asn,
            "prefix": prefix,
            "as_path": path_list,
            "suspicious": suspicious,
            "alert_description": reason
        }
