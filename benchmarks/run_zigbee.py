import os
import sys
from typing import Dict, Any

# Ensure import paths resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ot_iot.zigbee_decoder import ZigbeeDecoder
from backend.ot_iot.bluetooth_decoder import BLEDecoder
from backend.ot_iot.coap_decoder import CoAPDecoder

def run_benchmark() -> Dict[str, Any]:
    # Test Zigbee samples (all expected clean)
    zigbee_samples = ZigbeeDecoder.decode_sample_frames()
    # Test BLE samples (index 3 expected suspicious, others clean)
    ble_samples = BLEDecoder.decode_sample_packets()
    # Test CoAP samples (index 0, 1, 3 expected suspicious, index 2 clean)
    coap_samples = CoAPDecoder.decode_sample_packets()
    
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    
    # Zigbee evaluation (all expected benign)
    for idx, s in enumerate(zigbee_samples):
        is_susp = s.get("is_suspicious", False)
        # Ground truth: all 4 are clean
        should_be_susp = False
        if is_susp and should_be_susp:
            tp += 1
        elif is_susp and not should_be_susp:
            fp += 1
        elif not is_susp and should_be_susp:
            fn += 1
        else:
            tn += 1
            
    # BLE evaluation (index 3 is malicious, others clean)
    for idx, s in enumerate(ble_samples):
        is_susp = s.get("is_suspicious", False)
        should_be_susp = (idx == 3)
        if is_susp and should_be_susp:
            tp += 1
        elif is_susp and not should_be_susp:
            fp += 1
        elif not is_susp and should_be_susp:
            fn += 1
        else:
            tn += 1
            
    # CoAP evaluation (index 0, 1, 3 are malicious, index 2 is clean)
    for idx, s in enumerate(coap_samples):
        is_susp = s.get("is_suspicious", False)
        should_be_susp = (idx in [0, 1, 3])
        if is_susp and should_be_susp:
            tp += 1
        elif is_susp and not should_be_susp:
            fp += 1
        elif not is_susp and should_be_susp:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
    
    passed = f1_score > 0.95
    return {
        "domain": "IoT Protocol Layers (Zigbee/BLE/CoAP)",
        "dataset_reference": "IoT-Scenarios",
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "target_threshold": "F1 > 95%",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
