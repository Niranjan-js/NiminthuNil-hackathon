# NIRAVAN – Production Deployment Manual
## நிரவன் – உற்பத்தி வரிசைப்படுத்தல் கையேடு

This directory contains the production configuration and deployment package for deploying the NIRAVAN Cybersecurity Intelligence Platform to Tamil Nadu State Government infrastructure (ELCOT / TNeGA / NIC servers).

---

## 🏛️ System Architecture / கணினி கட்டமைப்பு

NIRAVAN is deployed as a 3-tier architecture:
1. **Frontend**: Static HTML5/CSS3/JavaScript localized in English and Tamil (served by Nginx).
2. **Backend**: FastAPI REST API running on Uvicorn systemd daemon workers.
3. **Database**: PostgreSQL 16 relational database (connection pool size 10, max overflow 20).

---

## 🚀 Deployment Options / வரிசைப்படுத்தல் விருப்பங்கள்

### Option 1: Automated Shell Installer (Recommended for Ubuntu 22.04 LTS)
### விருப்பம் 1: தானியங்கி நிறுவல் ஸ்கிரிப்ட் (உபுண்டு சர்வர்)

Runs as a single command to automatically provision PostgreSQL, Nginx reverse proxy, Systemd daemon services, SSL certificates, and codebase setup.

```bash
cd deploy/
sudo bash setup.sh
```

### Option 2: Docker Compose Containerization
### விருப்பம் 2: டாக்கர் கொள்கலன் முறை

Run the full stack inside isolated container environments. Best for microservice clusters and cloud servers.

```bash
cd deploy/
docker-compose up -d
```

---

## 🔒 Security Requirements / பாதுகாப்பு தேவைகள்

Ensure the following environment variables are set in `/var/www/niravan/backend/.env`:

| Key | Description | Example |
|-----|-------------|---------|
| `NIRAVAN_JWT_SECRET` | 256-bit Hexadecimal secret key | `5d8f28f01b34...` |
| `NIRAVAN_DB_URL` | Production PostgreSQL connection URL | `postgresql://user:pass@host/db` |
| `NIRAVAN_ENV` | Environment context (production/staging) | `production` |
| `NIRAVAN_ALLOWED_ORIGINS` | Permitted origins for CORS lockdown | `https://niravan.tn.gov.in` |

---

## 📋 CERT-In Compliance / CERT-In இணக்கம்

NIRAVAN is pre-configured to comply with the Indian Information Technology Act 2000 (Section 70B directives):
- **6-Hour Reporting SLA**: Critical incidents (such as ransomware, SQL injections targeting treasury servers, or data exfiltration) display a countdown timer.
- **Form XML Export**: Security coordinators can click "Export CERT-In Incident Form" in Executive Reports to download a pre-filled JSON/XML report to send directly to CERT-In.

---

## 📞 Support & Maintenance / ஆதரவு மற்றும் பராமரிப்பு

For infrastructure integrations, NIC VPN routing configuration, or TNeGA single sign-on requests, contact the State SOC Administrator at:
- **Email**: state.soc@tn.gov.in
- **Portal**: https://soc.tn.gov.in
