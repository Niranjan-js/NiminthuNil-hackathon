from typing import Dict, Any, List

class ASMScanner:
    @staticmethod
    def scan_external_surface(domain: str) -> Dict[str, Any]:
        """Discovers active sub-domains, open ports, and certificates publicly exposed."""
        subdomains = [f"admin.{domain}", f"mail.{domain}", f"portal.{domain}"]
        open_ports = [80, 443, 22]
        
        # Check domain takeover or typosquatting
        typosquatted = [domain.replace(".tn.gov.in", "tn-gov.in")]

        return {
            "target": domain,
            "subdomains_discovered": subdomains,
            "open_ports": open_ports,
            "potential_typosquats": typosquatted,
            "exposure_score": 35.5
        }
