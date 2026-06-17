/* ============================================================
   NIRAVAN – Threat Engine
   Risk scoring, kill chain analysis, attack path prediction,
   Quantum Risk Index, Neural Correlation
   ============================================================ */

window.NIRAVAN_ENGINE = {

  // ── Quantum Risk Index™ Calculation ──
  // Composite score: threat velocity + asset criticality + active incidents + vuln exposure
  calculateQRI() {
    const events = window.NIRAVAN_DATA.events;
    const assets = window.NIRAVAN_DATA.assets;

    const criticalEvents  = events.filter(e => e.severity === 'critical').length;
    const highEvents      = events.filter(e => e.severity === 'high').length;
    const criticalAssets  = assets.filter(a => a.criticality === 'critical').length;
    const avgAssetRisk    = assets.length > 0 ? (assets.reduce((s,a) => s + a.riskScore, 0) / assets.length) : 0;
    const totalVulns      = assets.reduce((s,a) => s + a.vulnerabilities, 0);

    const threatVelocity  = Math.min(100, (criticalEvents * 8 + highEvents * 3));
    const assetExposure   = Math.min(100, avgAssetRisk);
    const vulnDensity     = assets.length > 0 ? Math.min(100, (totalVulns / assets.length) * 10) : 0;
    const incidentWeight  = Math.min(100, window.NIRAVAN_DATA.stats.activeIncidents * 12);

    const qri = Math.round(
      threatVelocity  * 0.35 +
      assetExposure   * 0.25 +
      vulnDensity     * 0.20 +
      incidentWeight  * 0.20
    );

    return Math.min(100, Math.max(1, qri));
  },

  getQRILabel(score) {
    if (score >= 85) return { label: 'CRITICAL RISK', color: '#ff2d55' };
    if (score >= 65) return { label: 'HIGH RISK',     color: '#ff6b35' };
    if (score >= 40) return { label: 'MEDIUM RISK',   color: '#ffd60a' };
    if (score >= 20) return { label: 'LOW RISK',      color: '#30d158' };
    return                  { label: 'MINIMAL',        color: '#30d158' };
  },

  getQRIColor(score) {
    if (score >= 85) return '#ff2d55';
    if (score >= 65) return '#ff6b35';
    if (score >= 40) return '#ffd60a';
    return '#30d158';
  },

  // ── Kill Chain Stages (MITRE ATT&CK based) ──
  KILL_CHAIN_STAGES: [
    { id: 'recon',     label: 'Reconnaissance', icon: '🔍', short: 'RECON' },
    { id: 'weapon',    label: 'Weaponization',  icon: '⚡', short: 'WEAPON' },
    { id: 'deliver',   label: 'Delivery',       icon: '📨', short: 'DELIVER' },
    { id: 'exploit',   label: 'Exploitation',   icon: '💥', short: 'EXPLOIT' },
    { id: 'install',   label: 'Installation',   icon: '⚙️',  short: 'INSTALL' },
    { id: 'c2',        label: 'Command & Ctrl', icon: '📡', short: 'C2' },
    { id: 'exfil',     label: 'Exfiltration',   icon: '📤', short: 'EXFIL' },
  ],

  // Maps event types to kill chain stage
  getKillChainStage(eventType) {
    const map = {
      'RECON':              'recon',
      'PHISHING':           'deliver',
      'ZERO_DAY':           'exploit',
      'MALWARE_C2':         'c2',
      'LATERAL_MOVEMENT':   'install',
      'PRIVILEGE_ESCALATION':'install',
      'BRUTE_FORCE':        'exploit',
      'DATA_EXFILTRATION':  'exfil',
      'INSIDER_THREAT':     'exfil',
      'RANSOMWARE':         'exfil',
      'DNS_TUNNELING':      'c2',
      'MFA_BYPASS':         'exploit',
    };
    return map[eventType] || 'recon';
  },

  // ── Determines Kill Chain Progress ──
  getKillChainStatus() {
    const events   = window.NIRAVAN_DATA.events;
    const stages   = this.KILL_CHAIN_STAGES;
    const stageMap = {};
    events.forEach(e => { stageMap[this.getKillChainStage(e.type)] = e.severity; });

    return stages.map(s => ({
      ...s,
      status: stageMap[s.id]
        ? (s.id === 'exfil' || s.id === 'c2' ? 'active' : 'done')
        : 'inactive',
      severity: stageMap[s.id] || null
    }));
  },

  // ── Attack Path Predictor ──
  ATTACK_PATHS: [
    {
      title: 'Internet → VPN-GW → WIN-DC-01 → PROD-WEB-01',
      description: 'Attacker exploits CVE-2024-3400 on VPN gateway, pivots to Domain Controller via pass-the-hash, then moves to web server.',
      risk: 'critical',
      probability: 87,
      steps: ['CVE-2024-3400 exploit on VPN-GW', 'Credential dump via Mimikatz', 'Pass-the-hash to WIN-DC-01', 'Domain Admin acquisition', 'Lateral move to PROD-WEB-01'],
      nodes: [
        { x: 0.05, y: 0.5, label: 'Internet', color: '#ff2d55' },
        { x: 0.25, y: 0.35, label: 'VPN-GW', color: '#ff6b35' },
        { x: 0.5,  y: 0.25, label: 'WIN-DC-01', color: '#ff6b35' },
        { x: 0.75, y: 0.4,  label: 'PROD-WEB-01', color: '#ff2d55' },
        { x: 0.92, y: 0.55, label: 'DB-PRIMARY', color: '#ff2d55' }
      ]
    },
    {
      title: 'Phishing → Workstation → MAIL-SERVER → Azure AD',
      description: 'Spear-phishing compromises employee workstation. Token theft allows cloud identity compromise via Azure AD.',
      risk: 'critical',
      probability: 74,
      steps: ['Spear-phishing email delivered', 'Malicious macro execution', 'Credential harvesting from browser', 'OAuth token theft', 'Azure AD lateral movement'],
      nodes: [
        { x: 0.05, y: 0.5, label: 'Phishing Email', color: '#ff2d55' },
        { x: 0.28, y: 0.6, label: 'Workstation', color: '#ff6b35' },
        { x: 0.55, y: 0.5, label: 'MAIL-SERVER', color: '#ff6b35' },
        { x: 0.78, y: 0.35, label: 'AZURE-AD', color: '#ff2d55' }
      ]
    },
    {
      title: 'Supply Chain → K8S-NODE → K8S-MASTER → S3-DATA-LAKE',
      description: 'Compromised container image in K8s node allows container escape, then cluster admin pivot to steal S3 data lake.',
      risk: 'high',
      probability: 61,
      steps: ['Malicious container image deployed', 'Container escape via kernel exploit', 'K8s service account abuse', 'RBAC escalation to cluster-admin', 'S3 data exfiltration'],
      nodes: [
        { x: 0.05, y: 0.5, label: 'Supply Chain', color: '#ff6b35' },
        { x: 0.3,  y: 0.55, label: 'K8S-NODE-01', color: '#ff6b35' },
        { x: 0.58, y: 0.4,  label: 'K8S-MASTER', color: '#ff6b35' },
        { x: 0.82, y: 0.5,  label: 'S3-DATA-LAKE', color: '#ffd60a' }
      ]
    }
  ],

  // ── Neural Correlation Engine ──
  // Groups related events into correlated incident chains
  correlateEvents() {
    const events = window.NIRAVAN_DATA.events;
    const chains = [];

    // Chain 1: Ransomware Kill Chain
    const ransomwareChain = events.filter(e =>
      ['RECON','PHISHING','PRIVILEGE_ESCALATION','LATERAL_MOVEMENT','RANSOMWARE'].includes(e.type)
    ).slice(0,5);

    if(ransomwareChain.length >= 2) {
      chains.push({
        id: 'CHAIN-001',
        title: 'Ransomware Kill Chain Detected',
        events: ransomwareChain,
        confidence: 94,
        color: '#ff2d55',
        actor: 'REvil (likely)',
        description: 'Multi-stage attack progression consistent with ransomware deployment'
      });
    }

    // Chain 2: Data Exfiltration Chain
    const exfilChain = events.filter(e =>
      ['BRUTE_FORCE','PRIVILEGE_ESCALATION','DATA_EXFILTRATION','DNS_TUNNELING'].includes(e.type)
    ).slice(0,4);

    if(exfilChain.length >= 2) {
      chains.push({
        id: 'CHAIN-002',
        title: 'Data Theft Campaign',
        events: exfilChain,
        confidence: 87,
        color: '#ff6b35',
        actor: 'APT28 (likely)',
        description: 'Credential access followed by sustained data exfiltration pattern'
      });
    }

    // Chain 3: Nation-State APT
    const aptChain = events.filter(e =>
      ['MALWARE_C2','LATERAL_MOVEMENT','INSIDER_THREAT'].includes(e.type)
    ).slice(0,3);

    if(aptChain.length >= 2) {
      chains.push({
        id: 'CHAIN-003',
        title: 'APT Espionage Campaign',
        events: aptChain,
        confidence: 78,
        color: '#ffd60a',
        actor: 'APT41 (likely)',
        description: 'Long-dwell-time intrusion with covert C2 and slow data collection'
      });
    }

    return chains;
  },

  // ── NIRAVAN AI Summary Generator ──
  generateAssessment() {
    const qri    = this.calculateQRI();
    const events = window.NIRAVAN_DATA.events;
    const criticals = events.filter(e => e.severity === 'critical');

    const assessments = [
      {
        type: 'critical',
        title: '⚠️ Active Ransomware Threat',
        text: `NIRAVAN detected ransomware behavioral indicators on <strong>${randomHost()}</strong>. Immediate isolation recommended. ${criticals.length} critical events in the last hour.`
      },
      {
        type: 'high',
        title: '🔴 Lateral Movement in Progress',
        text: `An attacker appears to be moving laterally through your internal network. NIRAVAN has traced movement from <strong>10.0.1.x</strong> subnet towards Domain Controllers.`
      },
      {
        type: 'medium',
        title: '🟡 Credential Stuffing Campaign',
        text: `Ongoing brute-force campaign targeting <strong>VPN and SSH services</strong>. ${randomInt(200,800)} failed attempts detected. Consider geo-blocking and rate limiting.`
      },
      {
        type: 'good',
        title: '✅ WAF Successfully Blocking',
        text: `Your Web Application Firewall has automatically blocked <strong>${window.NIRAVAN_DATA.stats.blockedEvents} attack attempts</strong> in the past 24h. SQL injection and XSS attempts mitigated.`
      },
      {
        type: 'ai',
        title: '🧠 NIRAVAN Prediction',
        text: `Based on current attack patterns, NIRAVAN predicts a <strong>78% probability</strong> of data exfiltration attempt within the next 4 hours targeting S3 or Azure storage.`
      }
    ];

    return assessments;
  }
};

function randomHost() {
  const assets = window.NIRAVAN_DATA.assets || [];
  if (assets.length === 0) return "PROD-WEB-01";
  return randomItem(assets).name;
}

console.log('[NIRAVAN] Threat Engine initialized');
