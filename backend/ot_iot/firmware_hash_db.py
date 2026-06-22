import logging
from typing import Dict, Any

logger = logging.getLogger("niravan.ot_iot.firmware_hash_db")


class FirmwareHashDB:
    """
    Firmware Hash Integrity Database for NIRAVAN OT/IoT Defense Layer.
    Maintains cryptographic signature catalogs for clean and malicious firmware payloads.
    Detects compromise attempts, custom implants, or bootloader malware (e.g. Mirai, VPNFilter, Mozi).
    """

    # Catalog of known legitimate manufacturer firmware hashes
    KNOWN_GOOD_HASHES: Dict[str, Dict[str, Any]] = {
        "a5b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0": {
            "vendor": "Siemens",
            "model": "SIMATIC S7-1200",
            "version": "V4.5.0",
            "release_date": "2021-06-01",
            "file_name": "s71200_v450.bin"
        },
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": {
            "vendor": "Hikvision",
            "model": "DS-2CD2043G0-I",
            "version": "V5.7.3",
            "release_date": "2021-03-19",
            "file_name": "digicap.dav"
        },
        "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": {
            "vendor": "Dahua",
            "model": "IPC-HDW2831T-AS",
            "version": "V2.820.0000000.2.R",
            "release_date": "2020-12-05",
            "file_name": "dh_ipc.bin"
        },
        "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4": {
            "vendor": "Cisco",
            "model": "CP-8865",
            "version": "12.8.1",
            "release_date": "2020-04-15",
            "file_name": "sip88xx.12-8-1-0101.loads"
        },
        "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5": {
            "vendor": "Schneider Electric",
            "model": "Modicon M221",
            "version": "SV1.13.0.0",
            "release_date": "2019-11-20",
            "file_name": "m221_sv11300.firm"
        }
    }

    # Catalog of known malicious hashes targeting OT/IoT platforms
    KNOWN_MALICIOUS_HASHES: Dict[str, Dict[str, Any]] = {
        "8c3d7d2459b2d829cfda978bf44f849fb75631481b376b1b590e66b4ef6c5478": {
            "malware_family": "Mirai",
            "threat_actor": "Unknown",
            "description": "Mirai botnet agent targeting IP cameras and routers using default credentials",
            "severity": "CRITICAL"
        },
        "e43ba6d1efea703352ef2e55ef9c8a98cf7e868a2bf6d1e43b185ec2842410a8": {
            "malware_family": "VPNFilter",
            "threat_actor": "Fancy Bear (APT28)",
            "description": "VPNFilter stage 2 malware module targeting Cisco and Netgear routers",
            "severity": "CRITICAL"
        },
        "f85b3f2d26f21255e4e840a1b6f6f966113b2c28659d0e145b2f293b6e8a8b0c": {
            "malware_family": "Mozi",
            "threat_actor": "Mozi Botnet Group",
            "description": "DHT-based P2P botnet executable exploiting router firmware vulnerabilities",
            "severity": "CRITICAL"
        }
    }

    def check_hash(self, sha256: str) -> Dict[str, Any]:
        """
        Queries the database for a SHA-256 hash.
        Returns the match status ('clean', 'malicious', or 'unknown') and detailed metadata.
        """
        normalized_hash = sha256.strip().lower()

        if normalized_hash in self.KNOWN_GOOD_HASHES:
            logger.info(f"Integrity Check: Hash {normalized_hash} verified CLEAN.")
            return {
                "status": "clean",
                "details": self.KNOWN_GOOD_HASHES[normalized_hash]
            }

        if normalized_hash in self.KNOWN_MALICIOUS_HASHES:
            logger.error(f"Integrity Check: Hash {normalized_hash} detected MALICIOUS!")
            return {
                "status": "malicious",
                "details": self.KNOWN_MALICIOUS_HASHES[normalized_hash]
            }

        logger.warning(f"Integrity Check: Hash {normalized_hash} is UNKNOWN to signature databases.")
        return {
            "status": "unknown",
            "details": {}
        }

    def add_hash(self, sha256: str, metadata: Dict[str, Any], is_malicious: bool) -> None:
        """Adds a hash to either the clean or malicious database repository."""
        normalized_hash = sha256.strip().lower()

        if is_malicious:
            self.KNOWN_MALICIOUS_HASHES[normalized_hash] = metadata
            logger.info(f"Successfully added malicious signature hash: {normalized_hash}")
        else:
            self.KNOWN_GOOD_HASHES[normalized_hash] = metadata
            logger.info(f"Successfully added clean signature hash: {normalized_hash}")

    def get_stats(self) -> Dict[str, int]:
        """Returns statistical counts for clean, malicious, and total hashes."""
        clean_count = len(self.KNOWN_GOOD_HASHES)
        malicious_count = len(self.KNOWN_MALICIOUS_HASHES)
        return {
            "clean_hashes_count": clean_count,
            "malicious_hashes_count": malicious_count,
            "total_hashes_count": clean_count + malicious_count
        }
