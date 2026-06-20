import time
from typing import Dict, Any
from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.path_analyzer import PathAnalyzer
from backend.attack_graph.blast_radius import BlastRadiusCalculator

def run_benchmark() -> Dict[str, Any]:
    # Construct a BloodHound-like scale network (50 hosts, AD controller, databases, users)
    builder = AttackGraphBuilder()
    builder.add_node("User:compromised", "Compromised User", "User", risk_score=50)
    for i in range(1, 40):
        builder.add_node(f"Host:ws-{i}", f"Workstation {i}", "Host", risk_score=30)
    builder.add_node("AD:domain_controller", "Domain Controller", "AD", risk_score=95)
    builder.add_node("Asset:critical_db", "Critical Database", "Critical Asset", risk_score=98)

    # Link paths
    builder.add_edge("User:compromised", "Host:ws-1", "CONNECTS")
    for i in range(1, 39):
        builder.add_edge(f"Host:ws-{i}", f"Host:ws-{i+1}", "CAN_REACH")
    builder.add_edge("Host:ws-39", "AD:domain_controller", "EXPLOITS", cvss=9.8)
    builder.add_edge("AD:domain_controller", "Asset:critical_db", "USES")

    # Time Traversal speed
    analyzer = PathAnalyzer(builder)
    start_time = time.time()
    path_res = analyzer.find_shortest_attack_path("User:compromised", "Asset:critical_db")
    end_time = time.time()
    elapsed_ms = (end_time - start_time) * 1000.0

    # Path check: path must have 42 nodes
    path_correctness = 0.0
    if path_res["status"] == "success":
        path_correctness = 1.0 if len(path_res["path"]) == 42 else 0.5

    # Blast radius correctness
    br = BlastRadiusCalculator(builder)
    br_res = br.calculate_blast_radius("User:compromised", max_hops=3)
    # inside 3 hops we should reach compromised -> ws-1 -> ws-2 -> ws-3 (3 nodes)
    br_accuracy = 1.0 if br_res["total_compromised_count"] == 3 else 0.0

    passed = path_correctness > 0.95 and elapsed_ms < 50.0  # target: path accuracy > 95%, speed < 50ms
    return {
        "domain": "Attack Graph Engine",
        "competitor_reference": "BloodHound",
        "path_accuracy": path_correctness,
        "traversal_speed_ms": round(elapsed_ms, 3),
        "blast_radius_accuracy": br_accuracy,
        "target_thresholds": ">95% path accuracy, speed < 50ms",
        "passed": passed
    }

if __name__ == "__main__":
    print(run_benchmark())
