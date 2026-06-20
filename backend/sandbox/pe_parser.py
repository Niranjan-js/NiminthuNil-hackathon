from typing import Dict, Any, List

class PEFileParser:
    @staticmethod
    def parse_headers(file_data: bytes) -> Dict[str, Any]:
        """Parses mock PE headers: MZ magic, COFF header, sections, and export address tables."""
        if len(file_data) < 64:
            return {"valid_pe": False}

        is_mz = file_data[:2] == b"MZ"
        if not is_mz:
            return {"valid_pe": False, "reason": "Missing MZ header magic"}

        sections = [
            {"name": ".text", "entropy": 6.2, "virtual_size": 20480},
            {"name": ".rdata", "entropy": 5.4, "virtual_size": 4096},
            {"name": ".data", "entropy": 2.1, "virtual_size": 1024}
        ]

        imports = ["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"]
        return {
            "valid_pe": True,
            "machine_type": "x64",
            "section_count": len(sections),
            "sections": sections,
            "imported_dlls": imports
        }
