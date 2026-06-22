import os
import sys
from typing import Dict, Any

# Ensure import paths resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ot_iot.iot_ml_detector import IoTMLDetector

def run_benchmark() -> Dict[str, Any]:
    detector = IoTMLDetector()
    stats = detector.benchmark_accuracy()
    
    # Compute mean precision and recall
    datasets = ["TON_IoT", "N-BaIoT", "Edge-IIoTset"]
    mean_precision = sum(stats[ds]["precision"] for ds in datasets) / len(datasets)
    mean_recall = sum(stats[ds]["recall"] for ds in datasets) / len(datasets)
    mean_f1 = stats["aggregate_performance"]["mean_f1"]
    
    passed = mean_f1 > 0.95
    return {
        "domain": "IoT ML Anomaly Detection",
        "dataset_reference": "TON_IoT / N-BaIoT",
        "precision": round(mean_precision, 4),
        "recall": round(mean_recall, 4),
        "f1_score": round(mean_f1, 4),
        "target_threshold": "F1 > 95%",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
