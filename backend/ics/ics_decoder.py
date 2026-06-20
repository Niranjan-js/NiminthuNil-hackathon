from typing import Dict, Any

class ICSProtocolDecoder:
    @staticmethod
    def decode_modbus_frame(raw_hex: str) -> Dict[str, Any]:
        """Decodes raw ModbusTCP bytes to inspect function codes and target coil values."""
        if len(raw_hex) < 12:
            return {"valid": False}
        
        # Mock parsing: Transaction ID, Protocol ID, Length, Unit ID, Function Code
        func_code = int(raw_hex[14:16], 16) if len(raw_hex) >= 16 else 3
        is_write = func_code in [5, 6, 15, 16]

        return {
            "valid": True,
            "protocol": "ModbusTCP",
            "function_code": func_code,
            "operation": "WRITE" if is_write else "READ",
            "suspicious": is_write  # Write commands on operational grids are highly anomalous
        }

    @staticmethod
    def decode_bacnet_frame(raw_hex: str) -> Dict[str, Any]:
        return {
            "valid": True,
            "protocol": "BACnet",
            "apdu_type": "ConfirmedServiceRequest",
            "service_choice": "writeProperty"
        }
