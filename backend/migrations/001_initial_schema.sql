-- NIRAVAN Cybersecurity Intelligence Platform
-- Initial DB Schema for PostgreSQL Migration

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'analyst',
    department VARCHAR(255),
    source_device VARCHAR(255),
    risk_score INT DEFAULT 0,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP,
    last_login TIMESTAMP,
    tn_district VARCHAR(100),
    tn_dept_type VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    criticality VARCHAR(50) NOT NULL,
    riskScore INT DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',
    vulnerabilities INT DEFAULT 0,
    owner VARCHAR(255),
    operating_system VARCHAR(255),
    open_services TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'open',
    "user" VARCHAR(255),
    host VARCHAR(255),
    category VARCHAR(100),
    mitre VARCHAR(255),
    technique VARCHAR(255),
    timeStr VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    technical TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    indicator VARCHAR(255) NOT NULL,
    actor VARCHAR(100),
    confidence INT,
    lastSeen VARCHAR(50),
    threat VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS cves (
    id VARCHAR(50) PRIMARY KEY,
    score NUMERIC(3, 1),
    severity VARCHAR(50),
    "desc" TEXT,
    affected TEXT,
    published VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(255) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    assignee VARCHAR(255),
    incident_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_notes (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(id) ON DELETE CASCADE,
    author VARCHAR(255) NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_evidence (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(255) REFERENCES cases(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    added_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_email VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    detail TEXT,
    ip_address VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS login_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    success BOOLEAN NOT NULL,
    reason VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS api_access_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_email VARCHAR(255),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(255) NOT NULL,
    status_code INT NOT NULL,
    ip_address VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS admin_action_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    admin_email VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    target_user VARCHAR(255),
    details TEXT
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'enabled',
    log_source VARCHAR(100),
    yaml_content TEXT,
    condition_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS honeypot_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    honeypot_type VARCHAR(50) NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    attack_payload TEXT,
    severity VARCHAR(50) DEFAULT 'medium',
    status VARCHAR(50) DEFAULT 'open'
);

-- Indexing for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
