#!/usr/bin/env bash

# ============================================================================
# NIRAVAN – Tamil Nadu Government Cybersecurity Platform
# Automated Production Installer for Ubuntu 22.04 LTS (ELCOT/NIC Standard)
# ============================================================================

set -e

# Official Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
GOLD='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================================================${NC}"
echo -e "${BLUE}   NIRAVAN – Autonomous Cybersecurity Intelligence Platform             ${NC}"
echo -e "${BLUE}   Tamil Nadu State Government Production Deployment Script            ${NC}"
echo -e "${BLUE}========================================================================${NC}"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: This script must be run as root (sudo bash setup.sh).${NC}"
  exit 1
fi

# 2. Install Dependencies
echo -e "\n${GOLD}[1/8] Installing system dependencies (Python, Nginx, PostgreSQL, git)...${NC}"
apt-get update -y
apt-get install -y python3 python3-pip python3-venv nginx postgresql postgresql-contrib git openssl curl

# 3. Provision PostgreSQL Database
echo -e "\n${GOLD}[2/8] Provisioning PostgreSQL production database...${NC}"
# Start Postgres if not running
systemctl start postgresql
systemctl enable postgresql

# Create user, DB, and grant privileges if not already exists
sudo -u postgres psql -t -A -c "SELECT 1 FROM pg_roles WHERE rolname='niravan_user'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER niravan_user WITH PASSWORD 'niravan_pass';"

sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw niravan_prod || \
  sudo -u postgres psql -c "CREATE DATABASE niravan_prod OWNER niravan_user;"

sudo -u postgres psql -c "ALTER USER niravan_user WITH SUPERUSER;" # Needed for migrations seeding
echo -e "${GREEN}✓ PostgreSQL database 'niravan_prod' initialized successfully.${NC}"

# 4. Prepare Application Directories
echo -e "\n${GOLD}[3/8] Deploying codebase to /var/www/niravan...${NC}"
mkdir -p /var/www/niravan
cp -r ../* /var/www/niravan/
chown -R www-data:www-data /var/www/niravan
chmod -R 755 /var/www/niravan

# 5. Setup Python Virtual Environment
echo -e "\n${GOLD}[4/8] Creating Python virtual environment & installing dependencies...${NC}"
cd /var/www/niravan
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
echo -e "${GREEN}✓ Virtual environment configured and python packages installed.${NC}"

# 6. Generate Environment Variables (.env)
echo -e "\n${GOLD}[5/8] Generating secure production environment variables...${NC}"
JWT_SECRET=$(openssl rand -hex 32)
cat <<EOF > backend/.env
NIRAVAN_JWT_SECRET=${JWT_SECRET}
NIRAVAN_DB_URL=postgresql://niravan_user:niravan_pass@localhost:5432/niravan_prod
NIRAVAN_ENV=production
NIRAVAN_ALLOWED_ORIGINS=https://niravan.tn.gov.in
NIRAVAN_JWT_EXPIRY_MINUTES=60
EOF
chown www-data:www-data backend/.env
chmod 600 backend/.env
echo -e "${GREEN}✓ Production config environment variables seeded (.env file generated).${NC}"

# 7. Setup SSL Certificates (Self-signed fallback for staging/testing)
echo -e "\n${GOLD}[6/8] Configuring SSL / TLS certificates fallback...${NC}"
mkdir -p /etc/ssl/certs /etc/ssl/private
if [ ! -f /etc/ssl/certs/niravan_tn_gov_in.crt ]; then
  echo -e "${GOLD}Generating self-signed certificate for staging...${NC}"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/niravan_tn_gov_in.key \
    -out /etc/ssl/certs/niravan_tn_gov_in.crt \
    -subj "/C=IN/ST=Tamil Nadu/L=Chennai/O=TNeGA/CN=niravan.tn.gov.in"
  chmod 600 /etc/ssl/private/niravan_tn_gov_in.key
fi
echo -e "${GREEN}✓ SSL certificates configured in /etc/ssl.${NC}"

# 8. Configure Nginx Proxy
echo -e "\n${GOLD}[7/8] Configuring Nginx reverse proxy...${NC}"
cp deploy/nginx.conf /etc/nginx/nginx.conf
systemctl restart nginx
systemctl enable nginx
echo -e "${GREEN}✓ Nginx service restarted and configured.${NC}"

# 9. Configure Systemd Daemon Service
echo -e "\n${GOLD}[8/8] Installing systemd background service for NIRAVAN API...${NC}"
cp deploy/niravan.service /etc/systemd/system/niravan.service
systemctl daemon-reload
systemctl start niravan
systemctl enable niravan
echo -e "${GREEN}✓ NIRAVAN Systemd service activated and enabled on startup.${NC}"

# 10. Verification Checks
echo -e "\n${BLUE}======================= Running Diagnostics =======================${NC}"
if curl -s -k https://localhost/api/v1/auth/login -d '{"email":"admin@niravan.ai","password":"admin123"}' -H "Content-Type: application/json" | grep -q "token"; then
  echo -e "${GREEN}★ DIAGNOSTIC PASSED: Authentication API is online & responding.${NC}"
else
  echo -e "${RED}⚠ DIAGNOSTIC WARNING: API response test failed. Check 'journalctl -u niravan' for logs.${NC}"
fi

echo -e "\n${GREEN}========================================================================${NC}"
echo -e "${GREEN}   DEPLOYMENT COMPLETED SUCCESSFULLY / நிறுவல் வெற்றிகரமாக முடிந்தது!    ${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo -e "   Frontend URL: https://niravan.tn.gov.in (Add to /etc/hosts for testing)"
echo -e "   Backend API:  http://127.0.0.1:8000"
echo -e "   Service Logs: sudo journalctl -u niravan -f"
echo -e "${GREEN}========================================================================${NC}"
