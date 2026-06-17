# Implementation Plan: NIRAVAN Active Cyber Defense Platform

This plan details the implementation of five core python back-end engines and their frontend integration:
1. **`backend/asm_engine.py`**: Active Asset Discovery (DNS, subdomains, SSL certificate details, port scans, technologies, and risk calculation).
2. **`backend/intel_sync.py`**: Threat Intelligence Correlation (normalizing AlienVault OTX, AbuseIPDB, and emerging threat indicators).
3. **`backend/attack_graph.py`**: Algorithmic Path Solver (BFS/Dijkstra resolving exploit likelihoods and privilege escalation paths).
4. **`backend/wazuh_ingestor.py`**: Unified agent log parsing (Sysmon, auth failures, auditd events).
5. **`backend/correlation_engine.py`**: Core orchestrator merging telemetry, assets, threat intel, and graph nodes to generate unified incidents.
6. **One-Action Mitigation**: Dynamic integration allowing administrators to one-click block malicious IPs or isolate systems in a user-friendly fashion.

---

## 🏛️ System Architecture

```text
  [ Wazuh / Telemetry Ingest ] ──► [ wazuh_ingestor.py ]
                                           │
  [ Target Network Scans ] ─────► [ asm_engine.py ]
                                           │
  [ Threat Intelligence ] ──────► [ intel_sync.py ]
                                           │
                                           ▼
                                 [ correlation_engine.py ] ◄──► [ attack_graph.py ]
                                           │
                                           ▼
                                 [ SQLite / Postgres ] ◄──► [ frontend UI (One-Click Block) ]
```

---

## 📋 Proposed Changes

### Component 1 — 🔍 Active Asset Discovery (`backend/asm_engine.py`)
* Implement active host port mapping, DNS querying, SSL verification (using Python standard library socket/ssl connection timeouts), and technology identification.
* Calculate Exposure Score = `Internet Exposure` + `Critical Service Weight` + `Vulnerabilities` + `Threat Intel Hits`.

### Component 2 — 🛡️ Threat Intelligence Normalizer (`backend/intel_sync.py`)
* Normalizes Threat Indicators from AlienVault OTX, AbuseIPDB, and emerging threat lists into a unified structure.

### Component 3 — 🕸️ Graph Exploitation Solver (`backend/attack_graph.py`)
* Model network topologies, assets, credentials, and vulnerabilities.
* Implement Dijkstra's algorithm to solve paths, using edge weights based on CVSS scores, network distance, and exploitability.

### Component 4 — 📋 Telemetry & Wazuh Ingestion (`backend/wazuh_ingestor.py`)
* Ingests JSON log structures representing wazuh agents and maps them to security telemetry events.

### Component 5 — ⚙️ Correlation Orchestrator (`backend/correlation_engine.py`)
* Merges telemetry records, asset details, active intelligence hits, and paths to create unified high-fidelity security incidents.

### Component 6 — 🚫 One-Click Defensive Mitigations
* Hook response triggers to modify state, simulate active host blocking, and display simple user-friendly alert badges in the UI.

---

## 📋 Verification Plan

### Automated Tests
* Run `pytest backend/test_core.py` to verify all five modules are integrated and run without errors.
* Run `python test_nav.py` to confirm the frontend handles all pages.

### Manual Verification
* Trigger a network scan on `127.0.0.1` and verify that the local HTTP server on port 3000 is discovered and added to the Asset Grid.
