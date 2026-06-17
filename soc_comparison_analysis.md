# Strategic Comparison & Feature-Gap Matrix: NIRAVAN vs. Industry Platforms

This document compares the current implementation of **NIRAVAN** against **NIRAN Guard AI**, **Precogly** (threat modeling), and **Enterprise SIEM/SOAR** systems (such as Splunk ES, Wazuh, and Palo Alto Cortex XSOAR). It maps out key feature gaps and strategic pathways to help you elevate the project for state-level enterprise deployment.

---

## 📊 Feature-Gap Matrix

| Functional Area | NIRAVAN (Current Production) | NIRAN Guard AI | Precogly | Enterprise SIEM/SOAR | Gap & Upgrade Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Scope** | Live SOC Operations & local telemetry analysis | Endpoint Protection & local AI firewall | Architecture & automated Threat Modeling | Centralized SIEM logging, threat hunting, & SOAR | **Bridge**: Connect NIRAVAN with real SIEM feeds (Wazuh agent logging). |
| **Authentication** | JWT Auth with rate-limiting & account lockout | Local credentials & system keys | RBAC & OAuth authentication | SAML 2.0, OpenID Connect (OIDC), & Multi-Tenant AD | **Gap**: Add OIDC/SAML integration for government email services. |
| **Threat Intelligence** | Local mock DB + CISA KEV fallback seeding | Real-time memory threat shields | Threat vectors database | MISP, OTX, VirusTotal, & TAXII feeds | **Bridge**: Connect NIRAVAN backend to open APIs (e.g. AlienVault OTX, VirusTotal). |
| **Asset Discovery** | Pre-seeded static assets DB with active statuses | Active localhost agent scanning | Abstract data flow components | Active IP scanners, passive packet inspection | **Bridge**: Integrate basic Nmap/arp-scan scripts into NIRAVAN backend. |
| **Response Actions** | One-click front-end triggers ("Block IP", "Mark Safe") | Automated process termination | Mitigations & design policies | Playbook automation (Palo Alto XSOAR, Ansible) | **Bridge**: Bind response buttons to actual local host firewall blocking rules. |
| **Compliance Engine** | CERT-In 6h SLA tracker, DPDP 2023, IT Act 2000 | System privacy controls | GDPR, ISO 27001 models | Compliance log binders (HIPAA, PCI-DSS, SOC2) | **Bridge**: Integrate automated monthly PDF compliance reporting scripts. |

---

## 🛠️ Strategic Roadmap to Bridge the Gaps

### 1. Active Asset Discovery & ASM Integration
Instead of loading static assets from a database:
* **Upgrade**: Add an admin trigger `POST /api/v1/assets/scan` that executes a background Python `nmap` subnet scan.
* **Benefit**: Turns the monitoring dashboard into an active Attack Surface Management (ASM) scanner.

### 2. Multi-Tenant Government Dashboard
If deploying for the entire Tamil Nadu state:
* **Upgrade**: Partition the database tables by `tn_district` and `tn_dept_type`.
* **Benefit**: Allows the central Chennai SOC to view a unified dashboard for all districts, while individual district administrators (e.g., Salem Collectorate) can only see their own department data.

### 3. Open Threat Intelligence Integration (MISP / TAXII)
Automate IOC synchronization:
* **Upgrade**: Add a background scheduler task that fetches hourly indicator feeds from open sources (like AlienVault OTX or a local government MISP instance) and matches incoming syslog IPs against them.
* **Benefit**: Enables real-time, real-world correlation.

### 4. Integration with Wazuh Agent
Instead of simulated telemetry:
* **Upgrade**: Configure NIRAVAN to parse syslog inputs from a deployed Wazuh manager.
* **Benefit**: Immediately upgrades the platform into an enterprise-ready dashboard powered by real, active host agents.
