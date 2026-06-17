-- Seed Default Admin User
-- default hash for 'admin123'
INSERT INTO users (id, email, password_hash, role, department, source_device, risk_score)
VALUES ('usr-001', 'admin@niravan.ai', '$2b$12$Z0bB1bYmRlh5Z1J61eJyeOze2xPZ5zC0nI/bX2rT8eT0UuL6j6K6i', 'admin', 'Security Operations', 'SEC-LAPTOP-01', 15)
ON CONFLICT (id) DO NOTHING;

-- Seed default critical infrastructure assets (NIC server cluster, TNeGA core databases)
INSERT INTO assets (id, name, ip, type, criticality, riskScore, status, vulnerabilities, owner, operating_system, open_services)
VALUES 
('ast-001', 'TN-DC-GW-01', '10.0.1.10', 'Gateway Server', 'critical', 82, 'active', 2, 'admin@niravan.ai', 'RHEL 8.8', '22/tcp,443/tcp'),
('ast-002', 'TNEGA-DB-PROD', '10.0.2.15', 'Database Server', 'critical', 92, 'active', 1, 'db-admin@niravan.ai', 'Ubuntu 22.04', '5432/tcp'),
('ast-003', 'TN-GOV-WEB', '10.0.3.1', 'Web Server', 'high', 45, 'active', 4, 'web-admin@niravan.ai', 'Ubuntu 20.04', '80/tcp,443/tcp'),
('ast-004', 'NIC-VPN-GW', '10.0.0.1', 'VPN Gateway', 'critical', 78, 'active', 3, 'net-admin@niravan.ai', 'FortiOS 7.2', '443/tcp')
ON CONFLICT (id) DO NOTHING;
