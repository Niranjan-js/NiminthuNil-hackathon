/* ============================================================
   NIRAVAN – Data Simulation Engine
   Generates realistic cybersecurity events in real-time
   ============================================================ */

window.NIRAVAN_DATA = {
  events: [],
  incidents: [],
  assets: [],
  iocs: [],
  cisaKev: [],
  cases: [],
  auditLogs: [],
  loginLogs: [],
  apiLogs: [],
  adminActions: [],
  detectionRules: [],
  stats: {
    threatsToday: 0,
    activeIncidents: 0,
    blockedEvents: 0,
    eventsPerSec: 4231
  }
};

// ── Threat Actor Profiles ──
const THREAT_ACTORS = [
  { name: 'APT28 (Fancy Bear)', origin: 'Russia', type: 'Nation-State', tactics: ['Spear Phishing', 'Credential Harvesting', 'Lateral Movement'], color: '#ff2d55' },
  { name: 'Lazarus Group', origin: 'North Korea', type: 'Nation-State', tactics: ['Ransomware', 'SWIFT Attacks', 'Crypto Theft'], color: '#ff6b35' },
  { name: 'APT41', origin: 'China', type: 'Nation-State + Criminal', tactics: ['Supply Chain', 'Zero-Day Exploitation', 'Espionage'], color: '#ffd60a' },
  { name: 'REvil', origin: 'Russia', type: 'Ransomware Group', tactics: ['Ransomware-as-a-Service', 'Data Extortion'], color: '#bf5af2' },
  { name: 'DarkSide', origin: 'Eastern Europe', type: 'Ransomware Group', tactics: ['Double Extortion', 'Critical Infrastructure'], color: '#ff2d80' },
  { name: 'Charming Kitten', origin: 'Iran', type: 'Nation-State', tactics: ['Social Engineering', 'Credential Phishing'], color: '#00d4ff' },
  { name: 'TA505', origin: 'Unknown', type: 'Cybercriminal', tactics: ['Malware Distribution', 'BEC Fraud'], color: '#30d158' },
  { name: 'Cozy Bear (APT29)', origin: 'Russia', type: 'Nation-State', tactics: ['Supply Chain', 'Cloud Exploitation', 'MFA Bypass'], color: '#ff2d55' }
];

// ── Attack Origins (lat/lon as percentage of world map) ──
const ATTACK_ORIGINS = [
  { city: 'Moscow',    x: 0.582, y: 0.275, country: 'Russia' },
  { city: 'Beijing',   x: 0.762, y: 0.350, country: 'China' },
  { city: 'Pyongyang', x: 0.788, y: 0.322, country: 'N. Korea' },
  { city: 'Tehran',    x: 0.622, y: 0.385, country: 'Iran' },
  { city: 'Minsk',     x: 0.566, y: 0.260, country: 'Belarus' },
  { city: 'Lagos',     x: 0.488, y: 0.498, country: 'Nigeria' },
  { city: 'Bucharest', x: 0.553, y: 0.285, country: 'Romania' },
  { city: 'São Paulo', x: 0.318, y: 0.620, country: 'Brazil' },
];

// ── Attack Targets ──
const ATTACK_TARGETS = [
  { city: 'New York',  x: 0.253, y: 0.310 },
  { city: 'London',    x: 0.480, y: 0.255 },
  { city: 'Tokyo',     x: 0.820, y: 0.330 },
  { city: 'Frankfurt', x: 0.515, y: 0.262 },
  { city: 'Singapore', x: 0.760, y: 0.480 },
  { city: 'Sydney',    x: 0.845, y: 0.650 },
  { city: 'Mumbai',    x: 0.670, y: 0.415 },
  { city: 'Toronto',   x: 0.228, y: 0.290 },
];

// ── Security Event Templates ──
const EVENT_TEMPLATES = [
  {
    type: 'BRUTE_FORCE',
    severity: 'high',
    title: 'Brute Force Attack Detected',
    getDesc: (d) => `${d.attempts} failed login attempts from ${d.ip} targeting ${d.target}`,
    getTech: (d) => `[AUTH-FAIL] src=${d.ip} target=${d.target} attempts=${d.attempts} timespan=5min proto=SSH`,
    mitre: ['T1110.001', 'T1110.003'],
    tactic: 'Credential Access',
    technique: 'Brute Force',
    category: 'Authentication'
  },
  {
    type: 'LATERAL_MOVEMENT',
    severity: 'critical',
    title: 'Lateral Movement Detected',
    getDesc: (d) => `Suspicious internal network traversal from ${d.src} to ${d.dst} using ${d.proto}`,
    getTech: (d) => `[NET-SCAN] src=${d.src} dst=${d.dst} proto=${d.proto} ports=${d.ports} duration=${d.duration}s`,
    mitre: ['T1021.002', 'T1570'],
    tactic: 'Lateral Movement',
    technique: 'SMB/Admin Shares',
    category: 'Network'
  },
  {
    type: 'DATA_EXFILTRATION',
    severity: 'critical',
    title: 'Data Exfiltration Attempt',
    getDesc: (d) => `Large outbound transfer of ${d.size}MB to external IP ${d.ip} (${d.country})`,
    getTech: (d) => `[EXFIL] src=${d.user}@${d.src} dst=${d.ip} bytes=${d.size}MB proto=HTTPS dns_beaconing=true`,
    mitre: ['T1048', 'T1567.002'],
    tactic: 'Exfiltration',
    technique: 'Exfiltration Over C2',
    category: 'Data Loss'
  },
  {
    type: 'MALWARE_C2',
    severity: 'critical',
    title: 'Malware C2 Beacon Detected',
    getDesc: (d) => `Endpoint ${d.host} communicating with known C2 server ${d.c2ip} every ${d.interval}s`,
    getTech: (d) => `[C2-BEACON] host=${d.host} c2=${d.c2ip} interval=${d.interval}s jitter=20% proto=HTTPS tls_fingerprint=${d.fp}`,
    mitre: ['T1071.001', 'T1573.002'],
    tactic: 'Command and Control',
    technique: 'Application Layer Protocol',
    category: 'Malware'
  },
  {
    type: 'PRIVILEGE_ESCALATION',
    severity: 'high',
    title: 'Privilege Escalation Attempt',
    getDesc: (d) => `User ${d.user} attempted to escalate privileges using ${d.method} on ${d.host}`,
    getTech: (d) => `[PRIVESC] user=${d.user} method=${d.method} host=${d.host} pid=${d.pid} cmd="${d.cmd}"`,
    mitre: ['T1068', 'T1548.002'],
    tactic: 'Privilege Escalation',
    technique: 'Exploitation for Privilege Escalation',
    category: 'Access Control'
  },
  {
    type: 'RECON',
    severity: 'medium',
    title: 'Network Reconnaissance',
    getDesc: (d) => `Port scan detected from ${d.ip} — ${d.ports} ports scanned in ${d.duration}s`,
    getTech: (d) => `[RECON] src=${d.ip} scan_type=SYN ports_scanned=${d.ports} duration=${d.duration}s detected_services=${d.services}`,
    mitre: ['T1046', 'T1595.001'],
    tactic: 'Discovery',
    technique: 'Network Service Discovery',
    category: 'Reconnaissance'
  },
  {
    type: 'PHISHING',
    severity: 'high',
    title: 'Phishing Campaign Detected',
    getDesc: (d) => `Spear-phishing email targeting ${d.target} with malicious attachment ${d.filename}`,
    getTech: (d) => `[PHISH] sender=${d.sender} target=${d.target} subject="${d.subject}" attachment=${d.filename} hash=${d.hash}`,
    mitre: ['T1566.001', 'T1204.002'],
    tactic: 'Initial Access',
    technique: 'Spearphishing Attachment',
    category: 'Email'
  },
  {
    type: 'INSIDER_THREAT',
    severity: 'high',
    title: 'Insider Threat Indicator',
    getDesc: (d) => `${d.user} accessed ${d.count}x more files than normal baseline (${d.baseline}/day vs ${d.count}/day)`,
    getTech: (d) => `[INSIDER] user=${d.user} files_accessed=${d.count} baseline=${d.baseline} anomaly_score=${d.score} dept=${d.dept}`,
    mitre: ['T1078', 'T1213'],
    tactic: 'Collection',
    technique: 'Data from Information Repositories',
    category: 'Insider Threat'
  },
  {
    type: 'RANSOMWARE',
    severity: 'critical',
    title: 'Ransomware Activity Detected',
    getDesc: (d) => `Mass file encryption detected on ${d.host} — ${d.count} files encrypted in ${d.duration}s`,
    getTech: (d) => `[RANSOMWARE] host=${d.host} files_encrypted=${d.count} duration=${d.duration}s ext=${d.ext} ransom_note=${d.note}`,
    mitre: ['T1486', 'T1490'],
    tactic: 'Impact',
    technique: 'Data Encrypted for Impact',
    category: 'Ransomware'
  },
  {
    type: 'ZERO_DAY',
    severity: 'critical',
    title: 'Zero-Day Exploitation Attempt',
    getDesc: (d) => `Unknown exploit targeting ${d.service} on ${d.host} — no existing signature match`,
    getTech: (d) => `[ZERO-DAY] host=${d.host} service=${d.service} payload_entropy=${d.entropy} no_signature=true behavior_anomaly=HIGH`,
    mitre: ['T1203', 'T1190'],
    tactic: 'Execution',
    technique: 'Exploitation for Client Execution',
    category: 'Zero-Day'
  },
  {
    type: 'DNS_TUNNELING',
    severity: 'high',
    title: 'DNS Tunneling Detected',
    getDesc: (d) => `Suspicious DNS activity from ${d.host} — ${d.queries} queries/min to ${d.domain}`,
    getTech: (d) => `[DNS-TUNNEL] src=${d.host} domain=${d.domain} queries_per_min=${d.queries} avg_len=${d.avglen} entropy=HIGH`,
    mitre: ['T1071.004', 'T1048.003'],
    tactic: 'Command and Control',
    technique: 'DNS',
    category: 'Network'
  },
  {
    type: 'MFA_BYPASS',
    severity: 'high',
    title: 'MFA Bypass Attempt',
    getDesc: (d) => `MFA push bombing attack targeting ${d.user} — ${d.attempts} push notifications in ${d.duration}min`,
    getTech: (d) => `[MFA-BOMB] user=${d.user} src_ip=${d.ip} attempts=${d.attempts} duration_min=${d.duration} success=${d.success}`,
    mitre: ['T1621', 'T1556.006'],
    tactic: 'Credential Access',
    technique: 'Multi-Factor Authentication Request Generation',
    category: 'Authentication'
  }
];

// ── Asset Templates ──
const ASSET_TEMPLATES = [
  { name: 'PROD-WEB-01', type: 'server', os: 'Ubuntu 22.04', ip: '10.0.1.10', criticality: 'critical' },
  { name: 'PROD-WEB-02', type: 'server', os: 'Ubuntu 22.04', ip: '10.0.1.11', criticality: 'critical' },
  { name: 'DB-PRIMARY', type: 'server', os: 'RHEL 8', ip: '10.0.2.10', criticality: 'critical' },
  { name: 'DB-REPLICA', type: 'server', os: 'RHEL 8', ip: '10.0.2.11', criticality: 'high' },
  { name: 'API-GATEWAY', type: 'server', os: 'Ubuntu 20.04', ip: '10.0.1.20', criticality: 'critical' },
  { name: 'K8S-MASTER', type: 'server', os: 'K8s 1.28', ip: '10.0.3.1', criticality: 'critical' },
  { name: 'K8S-NODE-01', type: 'server', os: 'K8s 1.28', ip: '10.0.3.10', criticality: 'high' },
  { name: 'K8S-NODE-02', type: 'server', os: 'K8s 1.28', ip: '10.0.3.11', criticality: 'high' },
  { name: 'WIN-DC-01', type: 'server', os: 'Windows Server 2022', ip: '10.0.4.1', criticality: 'critical' },
  { name: 'WIN-DC-02', type: 'server', os: 'Windows Server 2022', ip: '10.0.4.2', criticality: 'high' },
  { name: 'MAIL-SERVER', type: 'server', os: 'Exchange 2019', ip: '10.0.5.1', criticality: 'high' },
  { name: 'VPN-GW', type: 'network', os: 'Cisco ASA', ip: '10.0.0.1', criticality: 'critical' },
  { name: 'FIREWALL-01', type: 'network', os: 'Palo Alto PAN-OS', ip: '10.0.0.2', criticality: 'critical' },
  { name: 'CORE-SWITCH', type: 'network', os: 'Cisco IOS 15', ip: '10.0.0.10', criticality: 'high' },
  { name: 'WAF-01', type: 'network', os: 'ModSecurity 3.0', ip: '10.0.0.20', criticality: 'high' },
  { name: 'AWS-PROD-VPC', type: 'cloud', os: 'AWS EC2', ip: '52.14.x.x', criticality: 'critical' },
  { name: 'GCP-ML-CLUSTER', type: 'cloud', os: 'GKE 1.27', ip: '34.102.x.x', criticality: 'high' },
  { name: 'AZURE-AD', type: 'cloud', os: 'Azure AD', ip: 'cloud', criticality: 'critical' },
  { name: 'S3-DATA-LAKE', type: 'cloud', os: 'AWS S3', ip: 'cloud', criticality: 'high' },
  { name: 'WORKSTATION-001', type: 'endpoint', os: 'Windows 11', ip: '10.1.0.1', criticality: 'medium' },
  { name: 'WORKSTATION-042', type: 'endpoint', os: 'Windows 11', ip: '10.1.0.42', criticality: 'medium' },
  { name: 'MACBOOK-HR-01', type: 'endpoint', os: 'macOS 14', ip: '10.1.1.1', criticality: 'medium' },
  { name: 'MACBOOK-DEV-03', type: 'endpoint', os: 'macOS 14', ip: '10.1.1.3', criticality: 'high' },
  { name: 'LINUX-DEV-07', type: 'endpoint', os: 'Ubuntu 22.04', ip: '10.1.2.7', criticality: 'high' },
  { name: 'HVAC-SENSOR-01', type: 'iot', os: 'Embedded', ip: '10.2.0.1', criticality: 'medium' },
  { name: 'SECURITY-CAM-04', type: 'iot', os: 'Embedded', ip: '10.2.0.4', criticality: 'low' },
  { name: 'BADGE-READER-12', type: 'iot', os: 'Embedded', ip: '10.2.0.12', criticality: 'medium' },
];

// ── CVE Database ──
const CVE_DATA = [
  { id: 'CVE-2024-3400', score: 10.0, severity: 'critical', desc: 'PAN-OS command injection in GlobalProtect — affects your VPN-GW', affected: 'VPN-GW', published: '2024-04-12' },
  { id: 'CVE-2024-21762', score: 9.8, severity: 'critical', desc: 'Fortinet SSL VPN out-of-bounds write, allows RCE without authentication', affected: 'FIREWALL-01', published: '2024-02-08' },
  { id: 'CVE-2023-44487', score: 7.5, severity: 'high', desc: 'HTTP/2 Rapid Reset DoS — affects API-GATEWAY (nginx 1.24)', affected: 'API-GATEWAY', published: '2023-10-10' },
  { id: 'CVE-2024-1709', score: 10.0, severity: 'critical', desc: 'ConnectWise ScreenConnect authentication bypass — critical RCE', affected: 'WIN-DC-01', published: '2024-02-19' },
  { id: 'CVE-2023-46604', score: 10.0, severity: 'critical', desc: 'Apache ActiveMQ RCE — allows attackers to run arbitrary code', affected: 'PROD-WEB-01', published: '2023-11-01' },
  { id: 'CVE-2024-6387', score: 8.1, severity: 'high', desc: 'OpenSSH regreSSHion — race condition allowing unauthenticated RCE', affected: 'DB-PRIMARY', published: '2024-07-01' },
  { id: 'CVE-2024-29988', score: 8.8, severity: 'high', desc: 'Windows SmartScreen bypass — used in active campaigns', affected: 'WORKSTATION-001', published: '2024-04-09' },
  { id: 'CVE-2023-36025', score: 8.8, severity: 'high', desc: 'Windows SmartScreen Prompt Security Feature Bypass', affected: 'WORKSTATION-042', published: '2023-11-14' },
];

// ── IOC Database ──
const IOC_DATA = [
  { type: 'IP', indicator: '185.220.101.47', actor: 'APT28', confidence: 98, lastSeen: '2m ago', threat: 'C2 Server' },
  { type: 'DOMAIN', indicator: 'update-secure-cdn.com', actor: 'Lazarus', confidence: 94, lastSeen: '5m ago', threat: 'Phishing' },
  { type: 'HASH', indicator: 'a3f4b2c1d8e9...', actor: 'REvil', confidence: 99, lastSeen: '12m ago', threat: 'Ransomware' },
  { type: 'IP', indicator: '45.142.212.100', actor: 'APT41', confidence: 87, lastSeen: '18m ago', threat: 'Scanner' },
  { type: 'URL', indicator: 'hxxps://cdn.evil-corp[.]ru/payload', actor: 'Cozy Bear', confidence: 92, lastSeen: '34m ago', threat: 'Dropper' },
  { type: 'DOMAIN', indicator: 'microsoft-update-srv.net', actor: 'TA505', confidence: 88, lastSeen: '1h ago', threat: 'Phishing' },
  { type: 'IP', indicator: '91.215.85.36', actor: 'Charming Kitten', confidence: 76, lastSeen: '2h ago', threat: 'Recon' },
  { type: 'HASH', indicator: 'f7e6d5c4b3a2...', actor: 'DarkSide', confidence: 96, lastSeen: '3h ago', threat: 'Ransomware' },
  { type: 'IP', indicator: '103.140.186.50', actor: 'APT28', confidence: 82, lastSeen: '4h ago', threat: 'Spear Phish' },
  { type: 'DOMAIN', indicator: 'auth-portal-login.xyz', actor: 'Unknown', confidence: 71, lastSeen: '6h ago', threat: 'Credential Harvesting' },
];

// ── MITRE ATT&CK Tactics ──
const MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'C2', 'Exfiltration', 'Impact'
];

// ── Helper Functions ──
function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randomIP() { return `${randomInt(10,220)}.${randomInt(0,255)}.${randomInt(0,255)}.${randomInt(1,254)}`; }
function randomInternalIP() { return `10.${randomInt(0,5)}.${randomInt(0,5)}.${randomInt(1,254)}`; }
function randomHash() { return Array.from({length:8},()=>Math.floor(Math.random()*16).toString(16)).join(''); }
function timeNow() { return new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function randomUser() { return randomItem(['j.smith','a.patel','m.chen','r.gupta','k.wilson','n.kumar','s.raj','t.jones']); }
function randomHost() { return randomItem(ASSET_TEMPLATES).name; }

// ── Event Generator ──
function generateEvent() {
  const template = randomItem(EVENT_TEMPLATES);
  let origin, target;

  if (localStorage.getItem("NIRAVAN_ONBOARDED") === "true") {
    const districtName = localStorage.getItem("NIRAVAN_DISTRICT") || "Chennai";
    const deptName = localStorage.getItem("NIRAVAN_DEPT_NAME") || "TN Department Office";
    
    const districts = [
      "Chennai", "Coimbatore", "Madurai", "Salem", "Tiruchirappalli", 
      "Vellore", "Erode", "Tirunelveli", "Thanjavur", "Kancheepuram", 
      "Tiruvallur", "Chengalpattu", "Dindigul", "Thoothukudi", "Ramanathapuram"
    ];
    
    // Attack source from another TN district or simulated rogue IP
    const attackerCity = districts[Math.floor(Math.random() * districts.length)];
    origin = { city: attackerCity, x: 0.5, y: 0.5, country: 'Tamil Nadu, India' };
    target = { city: districtName, x: 0.5, y: 0.5, name: deptName };
  } else {
    origin   = randomItem(ATTACK_ORIGINS);
    target   = randomItem(ATTACK_TARGETS);
  }
  let data = {};

  switch(template.type) {
    case 'BRUTE_FORCE':
      data = { ip: randomIP(), target: randomHost(), attempts: randomInt(50, 500) }; break;
    case 'LATERAL_MOVEMENT':
      data = { src: randomInternalIP(), dst: randomInternalIP(), proto: randomItem(['SMB','RDP','SSH','WMI']), ports: randomInt(3,20), duration: randomInt(10,300) }; break;
    case 'DATA_EXFILTRATION':
      data = { user: randomUser(), src: randomInternalIP(), ip: randomIP(), size: randomInt(50,2000), country: origin.country }; break;
    case 'MALWARE_C2':
      data = { host: randomHost(), c2ip: randomIP(), interval: randomInt(30,300), fp: randomHash() }; break;
    case 'PRIVILEGE_ESCALATION':
      data = { user: randomUser(), method: randomItem(['CVE-2024-3400','Sudo Abuse','DLL Hijack','Token Impersonation']), host: randomHost(), pid: randomInt(1000,9999), cmd: randomItem(['sudo -l','net user /add','whoami /all','Set-MpPreference']) }; break;
    case 'RECON':
      data = { ip: randomIP(), ports: randomInt(100,65000), duration: randomInt(5,120), services: randomInt(3,20) }; break;
    case 'PHISHING':
      data = { sender: `noreply@${randomItem(['secure-update.net','hr-portal.xyz','it-helpdesk.co'])}`, target: randomUser() + '@corp.com', subject: randomItem(['Urgent: Password Reset Required','Invoice #INV-2024-0892','HR Policy Update']), filename: randomItem(['Invoice_Q4.exe','Policy_Update.docm','Report.xlsm']), hash: randomHash() }; break;
    case 'INSIDER_THREAT':
      data = { user: randomUser(), count: randomInt(200,800), baseline: randomInt(15,30), score: (Math.random()*4+6).toFixed(1), dept: randomItem(['Finance','HR','Engineering','Sales']) }; break;
    case 'RANSOMWARE':
      data = { host: randomHost(), count: randomInt(500,10000), duration: randomInt(30,300), ext: randomItem(['.locked','.encrypted','.CRYPT','.RANSOM']), note: 'READ_ME.txt' }; break;
    case 'ZERO_DAY':
      data = { host: randomHost(), service: randomItem(['OpenSSH 9.3','Apache 2.4.57','nginx 1.24','Windows LSASS']), entropy: (Math.random()*2+6).toFixed(2) }; break;
    case 'DNS_TUNNELING':
      data = { host: randomHost(), domain: randomItem(['analytics-cdn.net','update-svc.io','telemetry.xyz']), queries: randomInt(200,2000), avglen: randomInt(60,250) }; break;
    case 'MFA_BYPASS':
      data = { user: randomUser(), ip: randomIP(), attempts: randomInt(20,100), duration: randomInt(5,30), success: randomItem(['false','false','false','true']) }; break;
    default: data = {};
  }

  return {
    id: 'EVT-' + Date.now() + '-' + randomInt(100,999),
    timestamp: new Date(),
    timeStr: timeNow(),
    type: template.type,
    severity: template.severity,
    title: template.title,
    description: template.getDesc(data),
    technical: template.getTech(data),
    mitre: template.mitre,
    tactic: template.tactic,
    technique: template.technique,
    category: template.category,
    origin: origin,
    target: target,
    data: data,
    actor: randomItem(THREAT_ACTORS),
    acknowledged: false,
    resolved: false
  };
}

// ── Initialize Assets with Risk Scores ──
function initAssets() {
  const riskMap = { critical: [70,95], high: [45,70], medium: [20,45], low: [5,20] };
  const colorMap = { critical: '#ff2d55', high: '#ff6b35', medium: '#ffd60a', low: '#30d158' };

  window.NIRAVAN_DATA.assets = ASSET_TEMPLATES.map(a => {
    const range = riskMap[a.criticality];
    const risk  = randomInt(range[0], range[1]);
    const vulns = a.criticality === 'critical' ? randomInt(8,20) : a.criticality === 'high' ? randomInt(4,10) : randomInt(0,5);
    return {
      ...a,
      riskScore: risk,
      riskColor: colorMap[a.criticality],
      vulnerabilities: vulns,
      lastSeen: timeNow(),
      status: randomItem(['active','active','active','warning'])
    };
  });
}

// ── Pre-populate Events ──
function initEvents() {
  const count = 24;
  for(let i = 0; i < count; i++) {
    const evt = generateEvent();
    evt.timestamp = new Date(Date.now() - (count - i) * randomInt(120000, 300000));
    evt.timeStr = evt.timestamp.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    window.NIRAVAN_DATA.events.unshift(evt);
  }
  // Force some criticals at the top
  window.NIRAVAN_DATA.events[0].severity = 'critical';
  window.NIRAVAN_DATA.events[0].type = 'RANSOMWARE';
  window.NIRAVAN_DATA.events[0].title = 'Ransomware Activity Detected';
  window.NIRAVAN_DATA.events[1].severity = 'critical';
  window.NIRAVAN_DATA.events[1].type = 'LATERAL_MOVEMENT';
  window.NIRAVAN_DATA.events[1].title = 'Lateral Movement Detected';
  window.NIRAVAN_DATA.events[2].severity = 'critical';
  window.NIRAVAN_DATA.events[2].type = 'DATA_EXFILTRATION';
  window.NIRAVAN_DATA.events[2].title = 'Data Exfiltration Attempt';
  window.NIRAVAN_DATA.events[3].severity = 'high';
  window.NIRAVAN_DATA.events[3].type = 'MALWARE_C2';
  window.NIRAVAN_DATA.events[3].title = 'Malware C2 Beacon Detected';
  window.NIRAVAN_DATA.events[4].severity = 'high';
  window.NIRAVAN_DATA.events[4].type = 'PRIVILEGE_ESCALATION';

  // Set stats
  const criticals = window.NIRAVAN_DATA.events.filter(e => e.severity === 'critical').length;
  const highs     = window.NIRAVAN_DATA.events.filter(e => e.severity === 'high').length;
  window.NIRAVAN_DATA.stats.threatsToday    = window.NIRAVAN_DATA.events.length + randomInt(8,20);
  window.NIRAVAN_DATA.stats.activeIncidents = criticals + Math.floor(highs/2);
  window.NIRAVAN_DATA.stats.blockedEvents   = randomInt(60, 120);
}

// ── 24h Trend Data ──
function getTrendData() {
  const labels = [];
  const data   = [];
  for(let h = 23; h >= 0; h--) {
    const d = new Date();
    d.setHours(d.getHours() - h);
    labels.push(d.getHours().toString().padStart(2,'0') + ':00');
    const base = h < 4 ? randomInt(2,8) : h < 8 ? randomInt(5,15) : h < 12 ? randomInt(10,25) : h < 16 ? randomInt(15,35) : h < 20 ? randomInt(20,45) : randomInt(25,60);
    data.push(base);
  }
  return { labels, data };
}

// ── Geo Attack Data ──
const GEO_DATA = {
  labels: ['Russia', 'China', 'N. Korea', 'Iran', 'Nigeria', 'Romania', 'Unknown', 'Brazil'],
  data:   [342, 287, 198, 156, 134, 98, 210, 87]
};

// ── Attack Vector Data ──
const VECTOR_DATA = {
  labels: ['Brute Force','Phishing','Malware C2','Lateral Mvmt','Data Exfil','Recon','Ransomware','Zero-Day'],
  data:   [28, 22, 18, 12, 9, 7, 3, 1]
};

// ── API Integration ──
window.API_URL = 'http://127.0.0.1:8000/api/v1';
window.NIRAVAN_API_ACTIVE = false;

window.getHeaders = function() {
  const token = localStorage.getItem('niravan_token');
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

window.checkApiStatus = async function() {
  try {
    const headers = window.getHeaders();
    const res = await fetch(`${window.API_URL}/stats`, { headers });
    if(res.ok || res.status === 401) {
      window.NIRAVAN_API_ACTIVE = true;
      console.log('[NIRAVAN] Backend API detected at ' + window.API_URL);
    } else {
      window.NIRAVAN_API_ACTIVE = false;
    }
  } catch(e) {
    window.NIRAVAN_API_ACTIVE = false;
  }
};

window.syncFromBackend = async function() {
  if (!window.NIRAVAN_API_ACTIVE) return;
  const token = localStorage.getItem('niravan_token');
  if (!token) return;
  
  try {
    const headers = window.getHeaders();
    
    // 1. Fetch Stats
    const statsRes = await fetch(`${window.API_URL}/stats`, { headers });
    if (statsRes.status === 401) {
      if (window.handleLogout) window.handleLogout();
      return;
    }
    if (statsRes.ok) {
      const stats = await statsRes.json();
      window.NIRAVAN_DATA.stats = stats;
    }
    // 2. Fetch Assets
    const assetsRes = await fetch(`${window.API_URL}/assets`, { headers });
    if (assetsRes.ok) {
      const dbAssets = await assetsRes.json();
      window.NIRAVAN_DATA.assets = dbAssets.map(a => ({
        id: a.id,
        name: a.name,
        ip: a.ip,
        type: a.type,
        criticality: a.criticality,
        riskScore: a.riskScore,
        status: a.status,
        vulnerabilities: a.vulnerabilities
      }));
    }
    // 3. Fetch Incidents
    const incidentsRes = await fetch(`${window.API_URL}/incidents`, { headers });
    if (incidentsRes.ok) {
      const dbIncidents = await incidentsRes.json();
      const mappedEvents = dbIncidents.map(i => {
        const mitreList = typeof i.mitre === 'string' ? i.mitre.split(',').map(m => m.trim()) : (Array.isArray(i.mitre) ? i.mitre : []);
        const actor = THREAT_ACTORS.find(act => mitreList.some(m => act.tactics.includes(i.technique))) || THREAT_ACTORS[0];
        
        const dataObj = {
          ip: i.technical ? (i.technical.match(/src=([0-9\.]+)/)?.[1] || i.technical.match(/(?:IP|source)\s+([0-9\.]+)/i)?.[1] || '185.220.101.47') : '185.220.101.47',
          target: i.host || 'PROD-WEB-01',
          attempts: 142,
          size: '4.2GB',
          count: 142,
          baseline: 20,
          score: 8.2,
          user: i.user || 's.raj',
          host: i.host || 'PROD-WEB-01'
        };

        if (i.technical) {
          const attemptsMatch = i.technical.match(/(?:attempts|count)[:=]\s*(\d+)/i) || i.technical.match(/(\d+)\s+attempts/i);
          if (attemptsMatch) dataObj.attempts = parseInt(attemptsMatch[1]);

          const filesMatch = i.technical.match(/(\d+)\s+files/i);
          if (filesMatch) dataObj.count = parseInt(filesMatch[1]);

          const rateMatch = i.technical.match(/rate[:=]\s*(\d+)/i);
          if (rateMatch) dataObj.count = parseInt(rateMatch[1]);
        }

        return {
          id: i.id,
          title: i.title,
          type: i.type,
          severity: i.severity,
          description: i.description,
          status: i.status,
          user: i.user,
          host: i.host,
          category: i.category,
          mitre: mitreList,
          technique: i.technique,
          timeStr: i.timeStr,
          timestamp: new Date(i.timestamp),
          technical: i.technical,
          actor: actor,
          tactic: i.category,
          data: dataObj
        };
      });
      window.NIRAVAN_DATA.events = mappedEvents;
      window.NIRAVAN_DATA.incidents = mappedEvents;
    }
    // 4. Fetch Intelligence
    const intelRes = await fetch(`${window.API_URL}/intelligence`, { headers });
    if (intelRes.ok) {
      const intel = await intelRes.json();
      window.NIRAVAN_DATA.iocs = intel.iocs;
      window.NIRAVAN_DATA.cves = intel.cves.map(c => ({
        id: c.id,
        score: c.score,
        severity: c.severity,
        desc: c.desc,
        affected: c.affected,
        published: c.published
      }));
    }
    // 5. Fetch Cases
    const casesRes = await fetch(`${window.API_URL}/cases`, { headers });
    if (casesRes.ok) {
      window.NIRAVAN_DATA.cases = await casesRes.json();
    }

    // Fetch Detection Rules
    try {
      const detectionRes = await fetch(`${window.API_URL}/detection/rules`, { headers });
      if (detectionRes.ok) {
        window.NIRAVAN_DATA.detectionRules = await detectionRes.json();
      }
    } catch (err) {
      console.error("Error fetching detection rules:", err);
    }

    // Fetch Deception Honeypots & Threat Attribution
    try {
      const deceptionRes = await fetch(`${window.API_URL}/deception/honeypots`, { headers });
      if (deceptionRes.ok) {
        const deceptionData = await deceptionRes.json();
        window.NIRAVAN_DATA.deceptionHoneypots = deceptionData.honeypots;
        window.NIRAVAN_DATA.deceptionLogs = deceptionData.recent_logs;
      }
    } catch (err) {
      console.error("Error fetching deception honeypots:", err);
    }

    try {
      const attributionRes = await fetch(`${window.API_URL}/deception/attribution`, { headers });
      if (attributionRes.ok) {
        window.NIRAVAN_DATA.threatAttribution = await attributionRes.json();
      }
    } catch (err) {
      console.error("Error fetching threat attribution:", err);
    }

    // Fetch Threat Graph nodes and edges
    try {
      const nodesRes = await fetch(`${window.API_URL}/graph/nodes`, { headers });
      if (nodesRes.ok) {
        window.NIRAVAN_DATA.graphNodes = await nodesRes.json();
      }
      const edgesRes = await fetch(`${window.API_URL}/graph/edges`, { headers });
      if (edgesRes.ok) {
        window.NIRAVAN_DATA.graphEdges = await edgesRes.json();
      }
    } catch (err) {
      console.error("Error fetching threat graph data:", err);
    }

    // Fetch campaigns
    try {
      const campaignsRes = await fetch(`${window.API_URL}/campaigns`, { headers });
      if (campaignsRes.ok) {
        window.NIRAVAN_DATA.campaigns = await campaignsRes.json();
      }
    } catch (err) {
      console.error("Error fetching campaigns:", err);
    }

    // Fetch Evidence Vault files & suspicious activity log ledger
    try {
      const vaultRes = await fetch(`${window.API_URL}/vault/evidence`, { headers });
      if (vaultRes.ok) {
        const vaultData = await vaultRes.json();
        window.NIRAVAN_DATA.suspiciousActivities = vaultData.suspicious_activities || [];
        window.NIRAVAN_DATA.caseEvidence = vaultData.case_evidence || [];
      }
    } catch (err) {
      console.error("Error fetching evidence vault:", err);
    }

    // 6. Fetch Admin logs if role is admin
    const userRole = localStorage.getItem('niravan_user_role');
    if (userRole === 'admin') {
      try {
        const auditRes = await fetch(`${window.API_URL}/admin/audit-logs`, { headers });
        if (auditRes.ok) {
          const auditData = await auditRes.json();
          window.NIRAVAN_DATA.auditLogs = auditData.audits || [];
          window.NIRAVAN_DATA.adminActions = auditData.admin_actions || [];
        }
      } catch (err) {
        console.error("Error fetching audit logs:", err);
      }
      
      try {
        const loginRes = await fetch(`${window.API_URL}/admin/login-logs`, { headers });
        if (loginRes.ok) {
          window.NIRAVAN_DATA.loginLogs = await loginRes.json();
        }
      } catch (err) {
        console.error("Error fetching login logs:", err);
      }
      
      try {
        const apiRes = await fetch(`${window.API_URL}/admin/api-logs`, { headers });
        if (apiRes.ok) {
          window.NIRAVAN_DATA.apiLogs = await apiRes.json();
        }
      } catch (err) {
        console.error("Error fetching API logs:", err);
      }
    }
  } catch (e) {
    console.error("[NIRAVAN] Error syncing from backend:", e);
    window.NIRAVAN_API_ACTIVE = false;
  }
};

// ── Initialize ──
async function initializeData() {
  await window.checkApiStatus();
  if (window.NIRAVAN_API_ACTIVE) {
    await window.syncFromBackend();
  } else {
    initAssets();
    initEvents();
    window.NIRAVAN_DATA.iocs  = IOC_DATA;
    window.NIRAVAN_DATA.actors = THREAT_ACTORS;
    window.NIRAVAN_DATA.cves  = CVE_DATA;
    
    // Seed cases fallback
    window.NIRAVAN_DATA.cases = [
      {
        id: "case-9481",
        title: "PROD-WEB-01 Ransomware Intrusion",
        description: "Comprehensive investigation into ransomware encryption signals on primary IIS web host.",
        severity: "critical",
        status: "in_progress",
        assignee: "analyst@niravan.ai",
        incident_id: "inc-9481",
        created_at: new Date(Date.now() - 3600000).toISOString(),
        updated_at: new Date(Date.now() - 1800000).toISOString(),
        notes: [
          { id: 1, author: "system", note: "Case automatically generated via Incident escalation.", created_at: new Date(Date.now() - 3600000).toISOString() },
          { id: 2, author: "analyst@niravan.ai", note: "Initiating host containment block. Validating process tree.", created_at: new Date(Date.now() - 1800000).toISOString() }
        ],
        evidence: [
          { id: 1, name: "Malicious Hash", value: "a3f4b2c1d8e9a2b1f8e7d5c3b1a203948576d5e4", type: "Hash", added_by: "analyst@niravan.ai", created_at: new Date(Date.now() - 3000000).toISOString() },
          { id: 2, name: "Target Endpoint IP", value: "10.0.2.50", type: "IP", added_by: "analyst@niravan.ai", created_at: new Date(Date.now() - 2500000).toISOString() }
        ]
      },
      {
        id: "case-9480",
        title: "VPN Gateway Lateral Traversal",
        description: "Suspected domain administration harvest following VPN gateway breach telemetry.",
        severity: "high",
        status: "open",
        assignee: null,
        incident_id: "inc-9480",
        created_at: new Date(Date.now() - 7200000).toISOString(),
        updated_at: new Date(Date.now() - 7200000).toISOString(),
        notes: [],
        evidence: []
      }
    ];

    // Seed audit logs fallback
    window.NIRAVAN_DATA.auditLogs = [
      { id: 1, timestamp: new Date(Date.now() - 300000).toISOString(), user_email: "admin@niravan.ai", action: "CONTAIN_INCIDENT", detail: "Isolated host PROD-WEB-01 due to ransomware activity.", ip_address: "192.168.1.50" },
      { id: 2, timestamp: new Date(Date.now() - 600000).toISOString(), user_email: "analyst@niravan.ai", action: "ADD_NOTE", detail: "Added analysis note to case-9481.", ip_address: "192.168.1.51" },
      { id: 3, timestamp: new Date(Date.now() - 900000).toISOString(), user_email: "admin@niravan.ai", action: "ESCALATE_ALERT", detail: "Escalated inc-9480 to case-9480.", ip_address: "192.168.1.50" }
    ];
    window.NIRAVAN_DATA.adminActions = [
      { id: 1, timestamp: new Date(Date.now() - 1200000).toISOString(), admin_email: "admin@niravan.ai", action: "CONFIG_UPDATE", target_user: null, details: "Updated alert threshold for data volume to 75%." }
    ];
    window.NIRAVAN_DATA.loginLogs = [
      { id: 1, timestamp: new Date(Date.now() - 100000).toISOString(), email: "admin@niravan.ai", ip_address: "192.168.1.50", success: true, reason: null },
      { id: 2, timestamp: new Date(Date.now() - 200000).toISOString(), email: "analyst@niravan.ai", ip_address: "192.168.1.51", success: true, reason: null },
      { id: 3, timestamp: new Date(Date.now() - 400000).toISOString(), email: "admin@niravan.ai", ip_address: "192.168.1.99", success: false, reason: "invalid_password" },
      { id: 4, timestamp: new Date(Date.now() - 500000).toISOString(), email: "unknown@niravan.ai", ip_address: "192.168.1.99", success: false, reason: "user_not_found" },
      { id: 5, timestamp: new Date(Date.now() - 600000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "invalid_password" },
      { id: 6, timestamp: new Date(Date.now() - 610000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "invalid_password" },
      { id: 7, timestamp: new Date(Date.now() - 620000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "invalid_password" },
      { id: 8, timestamp: new Date(Date.now() - 630000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "invalid_password" },
      { id: 9, timestamp: new Date(Date.now() - 640000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "invalid_password" },
      { id: 10, timestamp: new Date(Date.now() - 650000).toISOString(), email: "brute_force_attacker@domain.com", ip_address: "198.51.100.42", success: false, reason: "account_locked" }
    ];
    window.NIRAVAN_DATA.apiLogs = [
      { id: 1, timestamp: new Date(Date.now() - 10000).toISOString(), user_email: "admin@niravan.ai", method: "GET", path: "/api/v1/cases", status_code: 200, ip_address: "192.168.1.50" },
      { id: 2, timestamp: new Date(Date.now() - 20000).toISOString(), user_email: "analyst@niravan.ai", method: "POST", path: "/api/v1/cases/case-9481/notes", status_code: 201, ip_address: "192.168.1.51" },
      { id: 3, timestamp: new Date(Date.now() - 30000).toISOString(), user_email: "admin@niravan.ai", method: "PUT", path: "/api/v1/incidents/inc-9480", status_code: 200, ip_address: "192.168.1.50" }
    ];

    window.NIRAVAN_DATA.detectionRules = [
      {
        id: "SIG-001",
        name: "SSH Brute Force Detection",
        description: "Triggers alert when SSH brute force login pattern matches telemetry (attempts >= 50).",
        severity: "high",
        status: "enabled",
        log_source: "authentication",
        yaml_content: "title: SSH Brute Force Detection\nid: SIG-001\ndescription: Detects SSH login brute force attempts.\nlogsource:\n    product: ssh\n    service: auth\ndetection:\n    selection:\n        type: BRUTE_FORCE\n        attempts: 50\n    condition: selection\nseverity: high",
        condition_json: '{"field": "type", "value": "BRUTE_FORCE", "subfield": "attempts", "threshold": 50}',
        created_at: new Date(Date.now() - 86400000).toISOString(),
        updated_at: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: "SIG-002",
        name: "Ransomware Shadow Copy Deletion",
        description: "Detects command executing shadow copy deletion (vssadmin delete shadows).",
        severity: "critical",
        status: "enabled",
        log_source: "process_creation",
        yaml_content: "title: Ransomware Shadow Copy Deletion\nid: SIG-002\ndescription: Detects shadow copy deletion commands typical of ransomware.\nlogsource:\n    category: process_creation\ndetection:\n    selection:\n        cmd: \"vssadmin.exe delete shadows\"\n    condition: selection\nseverity: critical",
        condition_json: '{"field": "technical", "contains": "vssadmin.exe delete shadows"}',
        created_at: new Date(Date.now() - 86400000).toISOString(),
        updated_at: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: "SIG-003",
        name: "Large Outbound Data Exfiltration",
        description: "Triggers when exfiltrated file size exceeds 2000MB.",
        severity: "critical",
        status: "enabled",
        log_source: "network_flow",
        yaml_content: "title: Large Outbound Data Exfiltration\nid: SIG-003\ndescription: Detects excessive outbound data transfer.\nlogsource:\n    category: network_flow\ndetection:\n    selection:\n        type: DATA_EXFILTRATION\n        size: 2000\n    condition: selection\nseverity: critical",
        condition_json: '{"field": "type", "value": "DATA_EXFILTRATION", "subfield": "size", "threshold": 2000}',
        created_at: new Date(Date.now() - 86400000).toISOString(),
        updated_at: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: "SIG-004",
        name: "PowerShell Download Cradle",
        description: "Detects execution of PowerShell download cradles accessing remote sites.",
        severity: "high",
        status: "enabled",
        log_source: "process_creation",
        yaml_content: "title: PowerShell Download Cradle\nid: SIG-004\ndescription: Detects PowerShell remote download cradles.\nlogsource:\n    category: process_creation\ndetection:\n    selection:\n        technical|contains: \"Net.WebClient\"\n    condition: selection\nseverity: high",
        condition_json: '{"field": "technical", "contains": "Net.WebClient"}',
        created_at: new Date(Date.now() - 86400000).toISOString(),
        updated_at: new Date(Date.now() - 86400000).toISOString()
      }
    ];

    // Seed deception status and logs fallback
    window.NIRAVAN_DATA.deceptionHoneypots = [
      { name: "SSH Honeypot", type: "SSH", status: "active", hits: 2, description: "Detects brute force and credential stuffing attempts on port 22." },
      { name: "Web Honeypot", type: "Web", status: "active", hits: 2, description: "Fakes administrative paths like /admin, /wp-admin, /phpmyadmin." },
      { name: "API Honeypot", type: "API", status: "active", hits: 1, description: "Detects token guessing and credential enumeration on web services." },
      { name: "Database Honeypot", type: "Database", status: "active", hits: 1, description: "Detects SQL injection probing and unauthorized schema queries." }
    ];

    window.NIRAVAN_DATA.deceptionLogs = [
      { id: 1, timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString(), honeypot_type: "SSH", source_ip: "198.51.100.22", username_attempt: "root", password_attempt: "password123", path_attempt: null, query_attempt: null, attribution: "Credential Stuffing Bot" },
      { id: 2, timestamp: new Date(Date.now() - 13 * 60 * 1000).toISOString(), honeypot_type: "SSH", source_ip: "198.51.100.22", username_attempt: "admin", password_attempt: "admin123", path_attempt: null, query_attempt: null, attribution: "Credential Stuffing Bot" },
      { id: 3, timestamp: new Date(Date.now() - 24 * 60 * 1000).toISOString(), honeypot_type: "Web", source_ip: "203.0.113.81", username_attempt: null, password_attempt: null, path_attempt: "/wp-admin", query_attempt: null, attribution: "Web Scanner Bot" },
      { id: 4, timestamp: new Date(Date.now() - 22 * 60 * 1000).toISOString(), honeypot_type: "Web", source_ip: "203.0.113.81", username_attempt: null, password_attempt: null, path_attempt: "/phpmyadmin", query_attempt: null, attribution: "Web Scanner Bot" },
      { id: 5, timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(), honeypot_type: "API", source_ip: "45.142.212.11", username_attempt: null, password_attempt: null, path_attempt: "/api/v2/auth/token", query_attempt: "apikey=guess", attribution: "Credential Stuffing Bot" },
      { id: 6, timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(), honeypot_type: "Database", source_ip: "198.51.100.74", username_attempt: null, password_attempt: null, path_attempt: null, query_attempt: "SELECT * FROM admin_users WHERE username = 'admin' OR '1'='1'--", attribution: "Security Scanner" }
    ];

    window.NIRAVAN_DATA.threatAttribution = {
      scanners: 42,
      bots: 28,
      humans: 12,
      apts: 5,
      insiders: 3,
      total: 90,
      breakdown_percentages: {
        "Scanner": 46.7,
        "Bot": 31.1,
        "Human Operator": 13.3,
        "APT-like Activity": 5.6,
        "Insider Threat": 3.3
      }
    };

    window.NIRAVAN_DATA.graphNodes = [
      { entity_type: "User", entity_id: "admin@niravan.ai", name: "NIRAVAN Admin", risk_weight: 10, properties: { role: "admin", department: "Security" } },
      { entity_type: "User", entity_id: "analyst@niravan.ai", name: "NIRAVAN Analyst", risk_weight: 5, properties: { role: "analyst", department: "Security" } },
      { entity_type: "User", entity_id: "j.smith@corp.com", name: "John Smith", risk_weight: 45, properties: { role: "developer", department: "Engineering" } },
      { entity_type: "Asset", entity_id: "ast-001", name: "WIN-DC-01", risk_weight: 90, properties: { ip: "10.0.1.10", os: "Windows Server 2022" } },
      { entity_type: "Asset", entity_id: "ast-003", name: "PROD-WEB-01", risk_weight: 75, properties: { ip: "10.0.2.50", os: "Ubuntu 22.04" } },
      { entity_type: "Asset", entity_id: "ast-004", name: "VPN-GW-01", risk_weight: 60, properties: { ip: "10.0.3.1", os: "PAN-OS" } },
      { entity_type: "Vulnerability", entity_id: "CVE-2024-3400", name: "CVE-2024-3400 RCE", risk_weight: 85, properties: { score: 9.8, severity: "Critical" } },
      { entity_type: "IOC", entity_id: "185.220.101.47", name: "185.220.101.47 (IP)", risk_weight: 70, properties: { country: "Russia", reputation: "Malicious" } },
      { entity_type: "IOC", entity_id: "198.51.100.15", name: "198.51.100.15 (IP)", risk_weight: 50, properties: { country: "Unknown", reputation: "Suspicious" } },
      { entity_type: "Incident", entity_id: "inc-9480", name: "RCE Execution VPN-GW", risk_weight: 80, properties: { severity: "critical", mitre: "T1190" } },
      { entity_type: "Incident", entity_id: "inc-9481", name: "Lateral Movement to DC", risk_weight: 90, properties: { severity: "critical", mitre: "T1021" } },
      { entity_type: "Case", entity_id: "case-9481", name: "Escalated Core Compromise Case", risk_weight: 95, properties: { status: "open" } },
      { entity_type: "Threat Actor", entity_id: "fancy-bear", name: "APT28 (Fancy Bear)", risk_weight: 95, properties: { origin: "Russia", focus: "Espionage" } }
    ];

    window.NIRAVAN_DATA.graphEdges = [
      { source_type: "User", source_id: "j.smith@corp.com", target_type: "Asset", target_id: "ast-003", relationship: "owns", weight: 1.0 },
      { source_type: "Asset", source_id: "ast-004", target_type: "Vulnerability", target_id: "CVE-2024-3400", relationship: "contains", weight: 2.0 },
      { source_type: "Vulnerability", source_id: "CVE-2024-3400", target_type: "IOC", target_id: "185.220.101.47", relationship: "exploited_by", weight: 2.5 },
      { source_type: "IOC", source_id: "185.220.101.47", target_type: "Incident", target_id: "inc-9480", relationship: "triggers", weight: 3.0 },
      { source_type: "Incident", source_id: "inc-9480", target_type: "Case", target_id: "case-9481", relationship: "escalated_to", weight: 1.0 },
      { source_type: "Incident", source_id: "inc-9481", target_type: "Case", target_id: "case-9481", relationship: "escalated_to", weight: 1.0 },
      { source_type: "IOC", source_id: "185.220.101.47", target_type: "Threat Actor", target_id: "fancy-bear", relationship: "associated_with", weight: 2.0 }
    ];

    window.NIRAVAN_DATA.campaigns = [
      {
        id: "cmp-shadowgate",
        name: "Operation ShadowGate",
        threat_actor: "APT28 (Fancy Bear)",
        confidence: 90,
        risk_score: 85,
        status: "active",
        created_at: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        updated_at: new Date().toISOString(),
        incident_ids: ["inc-9480", "inc-9481"],
        timeline_stages: {
          recon: [{ incident_id: "inc-recon", time: new Date(Date.now() - 24 * 3600 * 1000).toISOString(), desc: "Honeypot hit: Port scan from 185.220.101.47" }],
          credential_attack: [{ incident_id: "inc-auth", time: new Date(Date.now() - 23.5 * 3600 * 1000).toISOString(), desc: "Brute force attempts targeting VPN-GW-01" }],
          execution: [{ incident_id: "inc-9480", time: new Date(Date.now() - 22 * 3600 * 1000).toISOString(), desc: "PAN-OS RCE Command Injection on VPN-GW-01" }],
          lateral_movement: [{ incident_id: "inc-9481", time: new Date(Date.now() - 20 * 3600 * 1000).toISOString(), desc: "Lateral traversing SMB admin share connection to WIN-DC-01" }]
        }
      }
    ];

    window.NIRAVAN_DATA.suspiciousActivities = [
      { id: 1, who: "j.smith@corp.com", what: "Access from unknown IP segment", when: new Date(Date.now() - 2 * 3600 * 1000).toISOString(), where: "PROD-WEB-01", why: "Anomaly", how: "Connection from Tor exit node" },
      { id: 2, who: "admin@niravan.ai", what: "Successful Login", when: new Date(Date.now() - 4 * 3600 * 1000).toISOString(), where: "Console UI", why: "Audit", how: "Web GUI credentials matched" },
      { id: 3, who: "system", what: "Honeypot touch SSH", when: new Date(Date.now() - 14 * 60 * 1000).toISOString(), where: "198.51.100.22", why: "Deception", how: "Credential stuffing attempts as root" }
    ];

    window.NIRAVAN_DATA.caseEvidence = [
      { id: 1, case_id: "case-9481", name: "Malicious IP Indicator", value: "185.220.101.47", type: "IP", added_by: "system", created_at: new Date(Date.now() - 3600000).toISOString() },
      { id: 2, case_id: "case-9481", name: "Malicious Process Hash", value: "a52c3c907106db42188ff6e656d0d21d", type: "Hash", added_by: "analyst@niravan.ai", created_at: new Date(Date.now() - 1800000).toISOString() }
    ];
  }

  // Global exports for charts and other modules
  window.MITRE_TACTICS = MITRE_TACTICS;
  window.GEO_DATA = GEO_DATA;
  window.VECTOR_DATA = VECTOR_DATA;
  window.getTrendData = getTrendData;

  console.log('[NIRAVAN] Data engine initialized:', window.NIRAVAN_DATA.events.length, 'events,', window.NIRAVAN_DATA.assets.length, 'assets');
}

initializeData();
