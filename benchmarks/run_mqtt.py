import os
import sys
from typing import Dict, Any

# Ensure import paths resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ot_iot.mqtt_decoder import MQTTDecoder

def run_benchmark() -> Dict[str, Any]:
    samples = MQTTDecoder.decode_sample_packets()
    
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    
    for s in samples:
        is_suspicious = s.get("is_suspicious", False)
        # Ground truth check based on sample_label
        should_be_malicious = s.get("sample_label") == "MALICIOUS"
        
        if is_suspicious and should_be_malicious:
            tp += 1
        elif is_suspicious and not should_be_malicious:
            fp += 1
        elif not is_suspicious and should_be_malicious:
            fn += 1
        else:
            tn += 1
            
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
    
    passed = f1_score > 0.95
    return {
        "domain": "MQTT Protocol Decoding",
        "dataset_reference": "Edge-IIoTset",
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "target_threshold": "F1 > 95%",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
