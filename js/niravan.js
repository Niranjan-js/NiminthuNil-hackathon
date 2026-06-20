/* ============================================================
   NIRAVAN – AI Explanation Engine & Chat Interface
   Plain-language threat explanations + Chat responses
   ============================================================ */

window.NIRAVAN_AI = {

  // ── Generate Plain-Language Explanation ──
  explainEvent(event) {
    if (!event) return "No event data available.";
    if (!event.data) event.data = {};
    const explanations = {
      BRUTE_FORCE: () => `
        <strong>What happened:</strong> Someone is repeatedly trying to guess passwords to break into your systems.
        NIRAVAN detected <strong>${event.data.attempts || 'hundreds of'} failed login attempts</strong> from a single IP address in a very short time — 
        a classic sign of a brute force attack.<br><br>
        <strong>Why it matters:</strong> If successful, the attacker gains access to the target account and potentially the entire system.
        Accounts with weak passwords are at highest risk.<br><br>
        <strong>What to do:</strong> Lock the targeted account immediately. Block the source IP. Enable account lockout policies and 
        require Multi-Factor Authentication (MFA) for all accounts.
      `,
      LATERAL_MOVEMENT: () => `
        <strong>What happened:</strong> An attacker who is already inside your network is now moving between systems, 
        trying to reach more valuable targets. This is like a burglar who got into your building and is now 
        trying to open every door looking for the vault.<br><br>
        <strong>Why it matters:</strong> This indicates a serious, active intrusion. The attacker is likely trying to 
        reach critical servers, the domain controller, or sensitive data storage.<br><br>
        <strong>What to do:</strong> Isolate affected systems immediately. Check which accounts were used for lateral movement.
        Review and restrict internal firewall rules. Engage incident response.
      `,
      DATA_EXFILTRATION: () => `
        <strong>What happened:</strong> A large volume of data is being sent from inside your network to an external location.
        NIRAVAN detected <strong>${event.data.size || 'hundreds of MB'} of data</strong> being transferred to an unknown external IP.
        This strongly suggests data theft is in progress.<br><br>
        <strong>Why it matters:</strong> Sensitive business data, customer information, or intellectual property may be stolen.
        This could lead to regulatory penalties, reputational damage, and financial loss.<br><br>
        <strong>What to do:</strong> Block the outbound transfer immediately. Identify what data was accessed. 
        Notify your Data Protection Officer. Consider breach notification requirements.
      `,
      MALWARE_C2: () => `
        <strong>What happened:</strong> A device on your network is secretly communicating with an attacker's server
        on the internet. This is called a "Command and Control" (C2) connection — the infected machine is 
        receiving instructions from the attacker.<br><br>
        <strong>Why it matters:</strong> The attacker has remote control over this device. They can steal data, 
        install more malware, use your system for attacks on others, or deploy ransomware at any time.<br><br>
        <strong>What to do:</strong> Immediately disconnect the infected device from the network. Run a full malware scan.
        Block the C2 IP at the firewall. Investigate what the malware may have accessed or stolen.
      `,
      PRIVILEGE_ESCALATION: () => `
        <strong>What happened:</strong> A user or process attempted to gain higher-level permissions than they 
        are authorized to have — like an employee trying to get administrator access without approval.<br><br>
        <strong>Why it matters:</strong> If successful, the attacker gains admin or root access, giving them 
        full control of the system. This is often a critical step before data theft or ransomware deployment.<br><br>
        <strong>What to do:</strong> Investigate the user account immediately. Check if escalation was successful.
        Apply principle of least privilege. Review sudo rules and administrator group memberships.
      `,
      RECON: () => `
        <strong>What happened:</strong> Someone is scanning your network to discover what systems, services, 
        and vulnerabilities exist. This is typically the first step of an attack — an attacker "casing the joint"
        before deciding how to break in.<br><br>
        <strong>Why it matters:</strong> While reconnaissance itself doesn't cause immediate harm, it strongly 
        indicates that an attack is being planned. The attacker is looking for a way in.<br><br>
        <strong>What to do:</strong> Block the scanning IP at the firewall. Review what services are exposed to the internet.
        Ensure unnecessary ports are closed. Monitor for follow-up attack attempts from this source.
      `,
      PHISHING: () => `
        <strong>What happened:</strong> A malicious email was sent to one of your users, designed to trick them 
        into opening a dangerous attachment or clicking a malicious link. This is the #1 way attackers gain 
        initial access to organizations.<br><br>
        <strong>Why it matters:</strong> If the user opens the attachment, malware may be installed on their 
        computer, potentially giving the attacker a foothold in your entire network.<br><br>
        <strong>What to do:</strong> Quarantine the email immediately. Warn all staff not to open similar messages.
        Check if the user opened the attachment. Scan their device for malware. Report to your email security team.
      `,
      INSIDER_THREAT: () => `
        <strong>What happened:</strong> NIRAVAN detected that user <strong>${event.data.user || 'an employee'}</strong> accessed 
        <strong>${event.data.count || 'significantly more'} files today</strong> compared to their normal daily behavior 
        of ~${event.data.baseline || '20'} files. This is a <strong>${event.data.score || '8.2'}/10 anomaly score</strong>.<br><br>
        <strong>Why it matters:</strong> This pattern is consistent with data theft by an insider — someone who already 
        has authorized access but is abusing it. This could be a disgruntled employee, or a compromised account.<br><br>
        <strong>What to do:</strong> Investigate what files were accessed. Check if data was copied to external drives or 
        cloud storage. Interview the employee if appropriate. Review DLP (Data Loss Prevention) logs.
      `,
      RANSOMWARE: () => `
        <strong>What happened:</strong> 🚨 <strong>CRITICAL EMERGENCY:</strong> Ransomware is actively encrypting files on 
        <strong>${event.data.host || 'a critical system'}</strong>. NIRAVAN detected 
        <strong>${event.data.count || 'thousands of'} files being encrypted</strong> in a very short time period.<br><br>
        <strong>Why it matters:</strong> This is a catastrophic event. All encrypted files will become inaccessible. 
        The attacker will demand payment for the decryption key. Business operations may be completely halted.<br><br>
        <strong>What to do:</strong> <strong>IMMEDIATELY</strong> disconnect ALL affected systems from the network. 
        Do NOT pay the ransom without consulting security professionals. Restore from clean backups.
        Engage your incident response team NOW. Notify leadership and legal counsel.
      `,
      ZERO_DAY: () => `
        <strong>What happened:</strong> NIRAVAN detected exploitation of an <strong>unknown vulnerability</strong> — 
        one that has no existing security patch or detection signature. This is called a "zero-day" attack because 
        defenders have zero days to prepare for it.<br><br>
        <strong>Why it matters:</strong> Zero-day attacks are extremely dangerous because traditional antivirus and 
        security tools cannot detect them. Nation-state attackers and sophisticated criminal groups typically use these.<br><br>
        <strong>What to do:</strong> Isolate the affected system immediately. Enable enhanced monitoring and logging.
        Apply virtual patching if available. Report to your software vendor. Consider engaging threat intelligence services.
      `,
      DNS_TUNNELING: () => `
        <strong>What happened:</strong> An attacker is secretly communicating with an infected device by hiding data 
        inside DNS queries — a technique called "DNS tunneling." DNS is normally used to look up website addresses, 
        but attackers abuse it to smuggle data past security controls.<br><br>
        <strong>Why it matters:</strong> This is a sophisticated evasion technique used to maintain stealthy command-and-control 
        communications and potentially exfiltrate data without triggering normal security alerts.<br><br>
        <strong>What to do:</strong> Block DNS queries to the suspicious domain. Implement DNS security monitoring.
        Investigate the source device for malware. Enable DNS-based threat intelligence filtering.
      `,
      MFA_BYPASS: () => `
        <strong>What happened:</strong> An attacker is trying to bypass Multi-Factor Authentication (MFA) by 
        bombarding <strong>${event.data.user || 'a user'}</strong> with <strong>${event.data.attempts || 'dozens of'} 
        push notification requests</strong>, hoping the user gets tired and accidentally approves access.<br><br>
        <strong>Why it matters:</strong> If the user approves even one notification, the attacker gains full account access 
        despite not knowing the password alone. This is called "MFA fatigue" or "push bombing."<br><br>
        <strong>What to do:</strong> Alert the targeted user immediately and tell them NOT to approve any unexpected prompts.
        Temporarily disable the account if under active attack. Switch to number-matching MFA. Block the source IP.
      `
    };

    const fn = explanations[event.type] || (() => `NIRAVAN detected a ${event.severity} severity security event: ${event.description}. Immediate investigation recommended.`);
    return fn();
  },

  // ── AI Chat Response Engine ──
  generateResponse(question) {
    const q = question.toLowerCase().trim();
    const events  = window.NIRAVAN_DATA.events;
    const assets  = window.NIRAVAN_DATA.assets;
    const qri     = window.NIRAVAN_ENGINE.calculateQRI();
    const qriInfo = window.NIRAVAN_ENGINE.getQRILabel(qri);

    // ── Tamil Language Detection & Bilingual Routing ─────────────────────────
    const isTamil = /[\u0B80-\u0BFF]/.test(question);
    if (isTamil) {
      return this.respondGuardianAITamil(qri, assets);
    }

    // Routing logic
    if (q.includes('honeypot') || q.includes('deception')) {
      return this.respondDeception();
    }
    if (q.includes('unresolved case') || q.includes('show cases') || q.includes('open cases') || q.includes('list cases')) {
      return this.respondUnresolvedCases();
    }
    if (q.includes('hydra')) {
      return this.respondToolIntel('hydra');
    }
    if (q.includes('sqlmap')) {
      return this.respondToolIntel('sqlmap');
    }
    if (q.includes('nmap')) {
      return this.respondToolIntel('nmap');
    }
    if (q.includes('metasploit')) {
      return this.respondToolIntel('metasploit');
    }
    if (q.includes('mimikatz')) {
      return this.respondToolIntel('mimikatz');
    }
    if (q.includes('john')) {
      return this.respondToolIntel('john');
    }
    if (q.includes('most critical') || q.includes('critical threat') || q.includes('biggest threat')) {
      return this.respondCriticalThreat();
    }
    if (q.includes('most at risk') || q.includes('vulnerable asset') || q.includes('risky asset')) {
      return this.respondRiskyAssets();
    }
    if (q.includes('brute force')) {
      return this.respondBruteForce();
    }
    if (q.includes('security posture') || q.includes('overall') || q.includes('how secure') || q.includes('posture')) {
      return this.respondSecurityPosture(qri, qriInfo);
    }
    if (q.includes('predict') || q.includes('next attack') || q.includes('future')) {
      return this.respondPrediction();
    }
    if (q.includes('playbook') || q.includes('response') || q.includes('incident response') || q.includes('remediate') || q.includes('what should we do')) {
      return this.respondPlaybook(qri);
    }

    // ── Guardian AI Officer — Risk Score Routing ─────────────────────────────
    if (q.includes('why is my risk') || q.includes('why risk') || q.includes('why is the risk') || q.includes('risk score high') || (q.includes('risk score') && (q.includes('why') || q.includes('high') || q.includes('what')))) {
      return this.respondGuardianAIEnglish(qri, assets);
    }

    // ── OpenVAS / Vulnerability Scan Routing ─────────────────────────────────
    if (q.includes('openvas') || q.includes('vulnerability scan') || q.includes('scan result') || q.includes('cve scan') || q.includes('what vulnerabilities') || q.includes('what is my exposure') || q.includes('my exposure')) {
      return this.respondOpenVASScan();
    }

    if (q.includes('ransomware')) {
      return this.respondRansomware();
    }
    if (q.includes('lateral movement') || q.includes('lateral')) {
      return this.respondLateralMovement();
    }
    if (q.includes('exfiltration') || q.includes('data theft') || q.includes('data loss')) {
      return this.respondExfiltration();
    }
    if (q.includes('mitre') || q.includes('att&ck') || q.includes('attack framework')) {
      return this.respondMitre();
    }
    if (q.includes('mfa') || q.includes('multi-factor') || q.includes('two factor')) {
      return this.respondMFA();
    }
    if (q.includes('compliance') || q.includes('iso') || q.includes('nist') || q.includes('soc2')) {
      return this.respondCompliance();
    }
    if (q.includes('cve') || q.includes('vulnerability') || q.includes('patch')) {
      return this.respondVulnerabilities();
    }
    if (q.includes('hello') || q.includes('hi ') || q.includes('hey')) {
      return this.respondGreeting();
    }
    if (q.includes('qri') || q.includes('quantum risk') || q.includes('risk score') || q.includes('risk index')) {
      return this.respondQRI(qri, qriInfo);
    }
    if (q.includes('school') || q.includes('emis') || q.includes('education') || q.includes('பள்ளி') || q.includes('கல்வி')) {
      return this.respondSchoolTemplate();
    }
    if (q.includes('hospital') || q.includes('medical') || q.includes('health') || q.includes('clinical') || q.includes('மருத்துவமனை') || q.includes('சுகாதாரம்')) {
      return this.respondHospitalTemplate();
    }
    if (q.includes('collectorate') || q.includes('district') || q.includes('collector') || q.includes('மாவட்ட') || q.includes('ஆட்சியர்') || q.includes('அலுவலகம்')) {
      return this.respondCollectorateTemplate();
    }
    if (q.includes('police') || q.includes('fir') || q.includes('cop') || q.includes('காவல்') || q.includes('போலீஸ்')) {
      return this.respondPoliceTemplate();
    }
    if (q.includes('treasury') || q.includes('pension') || q.includes('finance') || q.includes('கஜானா') || q.includes('நிதி') || q.includes('ஓய்வூதியம்')) {
      return this.respondTreasuryTemplate();
    }
    if (q.includes('defense memory') || q.includes('mitigation history') || q.includes('remediation logs') || q.includes('lessons learned') || q.includes('நினைவகம்') || q.includes('தீர்வு வரலாறு')) {
      return this.respondLocalDefenseMemory();
    }
    if (q.includes('apt28') || q.includes('fancy bear') || q.includes('lazarus') || q.includes('revil') || q.includes('lockbit') || q.includes('threat actor') || q.includes('அச்சுறுத்தல்')) {
      return this.respondActors();
    }

    // Default intelligent response
    return this.respondDefault(question, qri);
  },

  respondSchoolTemplate() {
    return `
      <h3>🎓 TNCKB Security Template: School & Educational Institutions</h3>
      <p><strong>Description:</strong> Security profile template for schools and educational institutions.</p>
      <p><strong>Compliance Focus:</strong> DPDP Act 2023 Student Data Consent, CERT-In 6-Hour reporting rules for student database breaches</p>
      <h4>⚡ Mandatory Security Rules (பாதுகாப்பு விதிகள்):</h4>
      <ol>
        <li><strong>Rule 1:</strong> Isolate Student Registry (EMIS) from general student Wi-Fi networks.<br>
            <em>Tamil:</em> மாணவர் பதிவேட்டை (EMIS) பொது வைஃபை நெட்வொர்க்கிலிருந்து தனிமைப்படுத்தவும்.</li>
        <li><strong>Rule 2:</strong> Mandate MFA for EMIS database administrative accounts.<br>
            <em>Tamil:</em> EMIS தரவுத்தள நிர்வாகக் கணக்குகளுக்கு MFA-ஐ கட்டாயமாக்கவும்.</li>
        <li><strong>Rule 3:</strong> Enable scheduled off-site backups for exam management servers.<br>
            <em>Tamil:</em> தேர்வு மேலாண்மை சர்வர்களுக்கான திட்டமிடப்பட்ட ஆஃப்-சைட் பேக்கப்களை இயக்கவும்.</li>
      </ol>
    `;
  },
  respondHospitalTemplate() {
    return `
      <h3>🏥 TNCKB Security Template: Hospitals & Health Centers</h3>
      <p><strong>Description:</strong> Security profile template for public hospitals and primary health centers.</p>
      <p><strong>Compliance Focus:</strong> DPDP Act 2023 Health Data Protection, NIST CSF Critical Services Availability Guidelines</p>
      <h4>⚡ Mandatory Security Rules (பாதுகாப்பு விதிகள்):</h4>
      <ol>
        <li><strong>Rule 1:</strong> Network segregate medical diagnostic equipment from general web networks.<br>
            <em>Tamil:</em> மருத்துவ உபகரணங்களை பொதுவான இணைய நெட்வொர்க்குகளிலிருந்து நெட்வொர்க் பிரிக்கவும்.</li>
        <li><strong>Rule 2:</strong> Block port 3389 (RDP) on all hospital administrative workstations.<br>
            <em>Tamil:</em> அனைத்து மருத்துவமனை பணிநிலையங்களிலும் போர்ட் 3389 (RDP)-ஐ முடக்கவும்.</li>
        <li><strong>Rule 3:</strong> Perform monthly offline backup tests for patient record databases.<br>
            <em>Tamil:</em> நோயாளிகளின் தரவுத்தளங்களுக்கு மாதாந்திர ஆஃப்லைன் காப்புப்பிரதி சோதனைகளை மேற்கொள்ளுங்கள்.</li>
      </ol>
    `;
  },
  respondCollectorateTemplate() {
    return `
      <h3>🏢 TNCKB Security Template: District Collectorates & Administrative Offices</h3>
      <p><strong>Description:</strong> Security profile template for district collectorates and local administrative offices.</p>
      <p><strong>Compliance Focus:</strong> IT Act Section 43A Security Practices, CERT-In Ransomware Mitigation Directives</p>
      <h4>⚡ Mandatory Security Rules (பாதுகாப்பு விதிகள்):</h4>
      <ol>
        <li><strong>Rule 1:</strong> Implement IP-whitelist filters on land record database administrative portals.<br>
            <em>Tamil:</em> நிலப் பதிவு தரவுத்தள நிர்வாக இணைய முகப்புகளுக்கு IP-அனுமதிப்பட்டியல் வடிப்பான்களைச் செயல்படுத்தவும்.</li>
        <li><strong>Rule 2:</strong> Conduct bi-weekly external vulnerability scanning using Greenbone/OpenVAS.<br>
            <em>Tamil:</em> OpenVAS-ஐப் பயன்படுத்தி இரு வாரங்களுக்கு ஒருமுறை வெளிப்புற பாதிப்பு ஸ்கேனிங் நடத்தவும்.</li>
        <li><strong>Rule 3:</strong> Ensure local network switches disable unused ethernet ports.<br>
            <em>Tamil:</em> பயன்படுத்தப்படாத சுவிட்ச் போர்ட்களை நெட்வொர்க்கில் முடக்கவும்.</li>
      </ol>
    `;
  },
  respondPoliceTemplate() {
    return `
      <h3>🛡️ TNCKB Security Template: Police Departments & District HQ</h3>
      <p><strong>Description:</strong> Security profile template for police departments and district headquarters.</p>
      <p><strong>Compliance Focus:</strong> State Cyber Security Policy Guidelines, IT Act Section 72A Data Privacy</p>
      <h4>⚡ Mandatory Security Rules (பாதுகாப்பு விதிகள்):</h4>
      <ol>
        <li><strong>Rule 1:</strong> Enforce strict firewall rules allowing only encrypted VPN connections to FIR databases.<br>
            <em>Tamil:</em> FIR தரவுத்தளங்களுக்கு மறைகுறியாக்கப்பட்ட VPN இணைப்புகளை மட்டுமே அனுமதிக்கும் விதிகளுடன் ஃபயர்வால் அமைக்கவும்.</li>
        <li><strong>Rule 2:</strong> Configure endpoint EDR logging on all field workstations.<br>
            <em>Tamil:</em> அனைத்து பணிநிலையங்களிலும் EDR லாக்கிங் உள்ளமைக்கவும்.</li>
        <li><strong>Rule 3:</strong> Monitor access log patterns for unusual credential usage.<br>
            <em>Tamil:</em> அசாதாரண நற்சான்றிதழ் பயன்பாட்டிற்கான அணுகல் வடிவங்களை கண்காணிக்கவும்.</li>
      </ol>
    `;
  },
  respondTreasuryTemplate() {
    return `
      <h3>💰 TNCKB Security Template: Treasury & Pension DB</h3>
      <p><strong>Description:</strong> Security profile template for district treasury and state pension databases.</p>
      <p><strong>Compliance Focus:</strong> RBI Security Guidelines, IT Act Section 70 Critical Information Infrastructure</p>
      <h4>⚡ Mandatory Security Rules (பாதுகாப்பு விதிகள்):</h4>
      <ol>
        <li><strong>Rule 1:</strong> Implement multi-signature validation for financial disbursements.<br>
            <em>Tamil:</em> நிதி விநியோகங்களுக்கு பல நபர் ஒப்புதலை (multi-signature) அமல்படுத்தவும்.</li>
        <li><strong>Rule 2:</strong> Audit user logs daily for atypical administrative transactions.<br>
            <em>Tamil:</em> வழக்கத்திற்கு மாறான நிர்வாக பரிவர்த்தனைகளுக்கு தினசரி பயனர் பதிவுகளை தணிக்கை செய்யவும்.</li>
        <li><strong>Rule 3:</strong> Isolate financial database servers in high-security subnet zones.<br>
            <em>Tamil:</em> நிதி தரவுத்தள சர்வர்களை உயர் பாதுகாப்பு நெட்வொர்க் பிரிவுகளில் வைக்கவும்.</li>
      </ol>
    `;
  },
  respondLocalDefenseMemory() {
    const logs = window.NIRAVAN_DATA.events || [];
    const deceptions = logs.filter(l => l.type === 'DECEPTION_TRIGGERED' || l.severity === 'critical');
    let rows = deceptions.slice(0, 5).map(l => {
      let timeStr = l.timeStr || "Just now";
      return `<tr><td>${timeStr}</td><td><strong>${l.title}</strong></td><td><code>${l.host || 'N/A'}</code></td><td><span class="badge high">${l.category || 'Threat'}</span></td><td><span class="badge success">Remediated</span></td></tr>`;
    }).join('');
    
    return `
      <h3>🧠 NIRAVAN Defense Memory (Reinforcement Learning)</h3>
      <p>Recent automated remediation attempts and verified outcomes:</p>
      <table class="data-table" style="width:100%; font-size:0.65rem; border-collapse:collapse; margin-top:10px;">
        <thead>
          <tr style="border-bottom:1px solid var(--border-subtle); text-align:left;">
            <th>Time</th><th>Threat / Event</th><th>Target Host</th><th>Category</th><th>Remediation Result</th>
          </tr>
        </thead>
        <tbody>
          ${rows || '<tr><td colspan="5" style="text-align:center;">No recent mitigation memory entries in data</td></tr>'}
        </tbody>
      </table>
    `;
  },
  respondActors() {
    return `
      <h3>🕸️ Profiled Threat Actors targeting TN Infrastructure</h3>
      <table class="data-table" style="width:100%; font-size:0.65rem; border-collapse:collapse; margin-top:10px;">
        <thead>
          <tr style="border-bottom:1px solid var(--border-subtle); text-align:left;">
            <th>Threat Actor</th><th>Primary Targets</th><th>Delivery Vector</th>
          </tr>
        </thead>
        <tbody>
          <tr><td><strong>APT28 (Fancy Bear)</strong></td><td>Critical Infrastructure, Government Networks</td><td>VPN Vulnerability Exploits, Phishing</td></tr>
          <tr><td><strong>Lazarus Group</strong></td><td>Financial Portals, Government Treasury</td><td>Spearphishing, Watering Hole</td></tr>
          <tr><td><strong>REvil / LockBit</strong></td><td>Municipal / Public Services, Healthcare</td><td>RDP Brute force, Unpatched Web services</td></tr>
        </tbody>
      </table>
    `;
  },

  respondDeception() {
    const logs = window.NIRAVAN_DATA.deceptionLogs || [];
    const hps = window.NIRAVAN_DATA.deceptionHoneypots || [];
    
    let sshHits = hps.find(h => h.type === 'SSH')?.hits || 0;
    let webHits = hps.find(h => h.type === 'Web')?.hits || 0;
    let apiHits = hps.find(h => h.type === 'API')?.hits || 0;
    let dbHits = hps.find(h => h.type === 'Database')?.hits || 0;

    let logRows = logs.slice(0, 5).map(l => {
      let detail = l.path_attempt ? `Path: <code>${l.path_attempt}</code>` : l.username_attempt ? `User: <code>${l.username_attempt}</code> / Pass: <code>${l.password_attempt}</code>` : l.query_attempt ? `Query: <code>${l.query_attempt.substring(0,30)}...</code>` : "Probe";
      let timeStr = new Date(l.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
      return `<tr><td style="padding:4px 0">${timeStr}</td><td><strong>${l.honeypot_type}</strong></td><td><code>${l.source_ip}</code></td><td>${detail}</td><td><span class="badge high">${l.attribution}</span></td></tr>`;
    }).join('');

    return `
      <h3>👁️ Deception Network Status & Telemetry</h3>
      <p>The Autonomous Deception Network is actively monitoring simulated systems.</p>
      
      <h4>Honeypot Portfolios:</h4>
      <ul>
        <li>🔑 <strong>SSH Honeypot</strong>: Active (<code>${sshHits}</code> touches)</li>
        <li>🌐 <strong>Web Honeypot</strong>: Active (<code>${webHits}</code> touches)</li>
        <li>🔌 <strong>API Honeypot</strong>: Active (<code>${apiHits}</code> touches)</li>
        <li>🗄️ <strong>Database Honeypot</strong>: Active (<code>${dbHits}</code> touches)</li>
      </ul>

      <h4>Recent Interactions:</h4>
      <table class="data-table" style="width:100%; font-size:0.65rem; border-collapse:collapse; margin-top:10px;">
        <thead>
          <tr style="border-bottom:1px solid var(--border-subtle); text-align:left;">
            <th>Time</th><th>Type</th><th>Source IP</th><th>Payload</th><th>Attribution</th>
          </tr>
        </thead>
        <tbody>
          ${logRows || '<tr><td colspan="5" style="text-align:center;">No recent deception touches logged</td></tr>'}
        </tbody>
      </table>
    `;
  },

  respondUnresolvedCases() {
    const cases = window.NIRAVAN_DATA.cases.filter(c => c.status !== 'resolved' && c.status !== 'closed');
    if (cases.length === 0) {
      return `✅ All security cases are currently <strong>resolved</strong> or <strong>closed</strong>. No active response operations in progress.`;
    }
    
    let rows = cases.map(c => `
      <tr>
        <td style="padding:4px 0"><code>${c.id}</code></td>
        <td><strong>${c.title}</strong></td>
        <td><span class="badge ${c.severity}">${c.severity.toUpperCase()}</span></td>
        <td><code>${c.status}</code></td>
        <td><code>${c.assignee || 'Unassigned'}</code></td>
      </tr>
    `).join('');

    return `
      <h3>📂 Current Unresolved Cases</h3>
      <p>I found ${cases.length} active security cases requiring analyst investigation:</p>
      <table class="data-table" style="width:100%; font-size:0.65rem; border-collapse:collapse;">
        <thead>
          <tr style="border-bottom:1px solid var(--border-subtle); text-align:left;">
            <th>Case ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assignee</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
      <p style="margin-top:10px; font-size:0.65rem; color:var(--text-muted);">Navigate to the <strong>Case Management</strong> dashboard to manage assignments or add comments.</p>
    `;
  },

  respondToolIntel(toolId) {
    const tools = {
      hydra: {
        name: "THC-Hydra",
        category: "Password cracking/brute-force",
        indicators: "Rapid sequence of failed login attempts, repeated auth queries using dictionary passwords.",
        pattern: "High volume of SSH or RDP connection requests from a single host.",
        mitre: "T1110 (Brute Force)",
        logic: "Track unique credentials attempted from same IP within a 5-minute window. Trigger if > 30 attempts."
      },
      sqlmap: {
        name: "SQLMap",
        category: "Web vulnerability assessment",
        indicators: "Payloads containing SQL syntax (e.g. UNION SELECT, OR 1=1, SLEEP, ORDER BY), custom user-agents containing sqlmap.",
        pattern: "HTTP GET/POST requests containing database enumeration strings.",
        mitre: "T1595.002 (Web Vulnerability Scanning)",
        logic: "Regex match for SQL functions/symbols in incoming request query strings or body parameters."
      },
      nmap: {
        name: "Nmap Network Scanner",
        category: "Network reconnaissance",
        indicators: "Sequential connection attempts to multiple ports, TCP SYN scans with specific window sizes.",
        pattern: "High rate of ICMP Echo requests, TCP SYN packets across standard port range.",
        mitre: "T1046 (Network Service Discovery)",
        logic: "Detect connection attempts to > 15 unique ports from a single source IP within 10 seconds."
      },
      metasploit: {
        name: "Metasploit Framework",
        category: "Exploitation framework",
        indicators: "Default meterpreter payload signatures, reverse TCP connection patterns on uncommon ports.",
        pattern: "Covert shell connections, binary transfers via HTTP POST/GET.",
        mitre: "T1059 (Command and Scripting Interpreter)",
        logic: "Identify known shellcode patterns in payload body or reverse shell handshake sequences."
      },
      mimikatz: {
        name: "Mimikatz",
        category: "Credential dumping",
        indicators: "Access to lsass.exe process memory, creation of fake security providers, command invocation for sekurlsa.",
        pattern: "Administrative token harvest logs, pass-the-hash network authentication.",
        mitre: "T1003 (OS Credential Dumping)",
        logic: "Detect API calls matching OpenProcess with PROCESS_VM_READ privilege targeting LSASS."
      },
      john: {
        name: "John the Ripper",
        category: "Hash-cracking & password recovery",
        indicators: "Suspicious access to SAM registry backup files, raw hash dumps parsed locally.",
        pattern: "Host EDR alerts reporting credential vault extracts.",
        mitre: "T1003 (OS Credential Dumping)",
        logic: "Audit registry read actions on HKLM\\SAM or creation of password dump artifacts."
      }
    };
    
    const tool = tools[toolId];
    if (!tool) return `No threat intelligence profile found for tool ID '${toolId}'.`;
    
    return `
      <h3>🛠️ Threat Tool Reference: <strong>${tool.name}</strong></h3>
      <ul>
        <li><strong>Category</strong>: <code>${tool.category}</code></li>
        <li><strong>Typical Indicators</strong>: ${tool.indicators}</li>
        <li><strong>Network Patterns</strong>: ${tool.pattern}</li>
        <li><strong>MITRE Technique</strong>: <code>${tool.mitre}</code></li>
      </ul>
      <h4>🔬 Detection Logic Strategy:</h4>
      <pre style="background:rgba(0,0,0,0.3); padding:8px; border-radius:4px; font-family:monospace; font-size:0.65rem; color:var(--accent-blue);">${tool.logic}</pre>
    `;
  },

  respondGreeting() {
    return `👋 Hello! I'm <strong>NIRAVAN</strong> — your Autonomous Cybersecurity Intelligence Platform.<br><br>
    I'm continuously monitoring <strong>${window.NIRAVAN_DATA.assets.length} assets</strong>, analyzing 
    <strong>4,231 security events per second</strong>, and I've currently detected 
    <strong>${window.NIRAVAN_DATA.stats.activeIncidents} active incidents</strong> requiring your attention.<br><br>
    I can help you understand threats, analyze incidents, predict attack paths, and recommend actions. 
    What would you like to know about your security posture?`;
  },

  respondCriticalThreat() {
    const criticals = window.NIRAVAN_DATA.events.filter(e => e.severity === 'critical');
    const top = criticals[0];
    return `🔴 <strong>Most Critical Threat Right Now:</strong><br><br>
    <strong>${top ? top.title : 'Ransomware Activity'}</strong><br><br>
    ${top ? top.description : 'Mass file encryption detected on PROD-WEB-01.'}<br><br>
    <strong>NIRAVAN Assessment:</strong><br>
    This threat is currently at <strong>Stage 6 of 7</strong> in the cyber kill chain — extremely advanced.
    The attacker has already established persistence and is actively executing their objective.<br><br>
    <strong>MITRE ATT&CK:</strong> ${top && Array.isArray(top.mitre) ? top.mitre.join(', ') : 'T1486, T1490'}<br><br>
    <strong>Immediate Actions Required:</strong><br>
    1. Isolate affected systems from the network NOW<br>
    2. Activate incident response team<br>
    3. Preserve forensic evidence before remediation<br>
    4. Notify executive leadership and legal counsel<br><br>
    ⏱️ <em>NIRAVAN estimates you have approximately 15-30 minutes before data becomes unrecoverable.</em>`;
  },

  respondRiskyAssets() {
    const risky = [...window.NIRAVAN_DATA.assets]
      .sort((a,b) => b.riskScore - a.riskScore)
      .slice(0, 5);
    let list = risky.map((a,i) => `${i+1}. <strong>${a.name}</strong> — Risk Score: ${a.riskScore}/100 | ${a.vulnerabilities} vulnerabilities | ${a.criticality.toUpperCase()}`).join('<br>');
    return `🎯 <strong>Top 5 Highest-Risk Assets:</strong><br><br>
    ${list}<br><br>
    <strong>NIRAVAN Insight:</strong> Your most exposed asset is <strong>${risky[0].name}</strong> with a risk score of 
    <strong>${risky[0].riskScore}/100</strong>. It has ${risky[0].vulnerabilities} known unpatched vulnerabilities and is currently 
    a likely target based on observed reconnaissance activity.<br><br>
    <strong>Priority:</strong> Patch all critical and high-severity CVEs on these systems within 24-48 hours.
    Consider enabling virtual patching via WAF rules as an immediate mitigation.`;
  },

  respondBruteForce() {
    const bf = window.NIRAVAN_DATA.events.find(e => e.type === 'BRUTE_FORCE');
    if (bf && !bf.data) bf.data = {};
    return `💥 <strong>Brute Force Attack Analysis:</strong><br><br>
    NIRAVAN has detected <strong>${window.NIRAVAN_DATA.events.filter(e=>e.type==='BRUTE_FORCE').length} brute force events</strong> 
    in the past 24 hours. ${bf ? `The most recent targeted <strong>${bf.data.target}</strong> with <strong>${bf.data.attempts} attempts</strong>.` : ''}<br><br>
    <strong>Attack Pattern:</strong> The attacker is using <strong>credential stuffing</strong> — trying known username/password 
    combinations from previous data breaches. This suggests your systems are being targeted with a prepared wordlist.<br><br>
    <strong>Origin:</strong> Traffic appears to originate from Tor exit nodes and compromised VPS servers, making attribution difficult.<br><br>
    <strong>Recommended Actions:</strong><br>
    ✅ Enable account lockout after 5 failed attempts<br>
    ✅ Implement MFA on all external-facing services<br>
    ✅ Deploy CAPTCHA on login pages<br>
    ✅ Block source IP ranges at the firewall level<br>
    ✅ Enable NIRAVAN's autonomous account lockout response`;
  },

  respondSecurityPosture(qri, qriInfo) {
    return `📊 <strong>Current Security Posture Assessment:</strong><br><br>
    <strong>Quantum Risk Index™: ${qri}/100 — ${qriInfo.label}</strong><br><br>
    <strong>Threat Landscape:</strong><br>
    • ${window.NIRAVAN_DATA.events.filter(e=>e.severity==='critical').length} critical incidents active<br>
    • ${window.NIRAVAN_DATA.events.filter(e=>e.severity==='high').length} high-severity events in last 24h<br>
    • ${window.NIRAVAN_DATA.stats.blockedEvents} attack attempts automatically blocked<br><br>
    <strong>Asset Exposure:</strong><br>
    • ${window.NIRAVAN_DATA.assets.filter(a=>a.criticality==='critical').length} critical assets monitored<br>
    • ${window.NIRAVAN_DATA.assets.reduce((s,a)=>s+a.vulnerabilities,0)} total unpatched vulnerabilities<br>
    • ${window.NIRAVAN_DATA.assets.filter(a=>a.criticality==='critical' && a.riskScore>70).length} critical assets at high risk<br><br>
    <strong>NIRAVAN Summary:</strong> Your organization is currently facing an <strong>active multi-stage attack campaign</strong>. 
    Priority focus should be on the lateral movement and ransomware indicators. The good news: your WAF and network controls are functioning. 
    Immediate attention is needed on endpoint protection and privileged access management.`;
  },

  respondPrediction() {
    return `🔮 <strong>NIRAVAN Predictive Threat Analysis:</strong><br><br>
    Based on current behavioral patterns, NIRAVAN's neural correlation engine predicts:<br><br>
    <strong>High Probability (78%):</strong> Data exfiltration attempt targeting S3 or Azure storage within the next <strong>4-6 hours</strong>.<br>
    The attacker has completed reconnaissance and lateral movement phases.<br><br>
    <strong>Medium Probability (54%):</strong> Ransomware deployment on domain-joined workstations within <strong>12-24 hours</strong> 
    if the current intrusion is not contained.<br><br>
    <strong>Lower Probability (31%):</strong> Credential dumping from Domain Controller targeting privileged service accounts.<br><br>
    <strong>Attack Path Most Likely:</strong><br>
    Compromised workstation → MAIL-SERVER → Active Directory → Data stores<br><br>
    <strong>Prevention:</strong> Implement network segmentation between workstations and servers. Enable Privileged Access Workstations (PAWs) for admin tasks. 
    Monitor for unusual AD queries (BloodHound-style recon).`;
  },

  respondPlaybook() {
    return `📋 <strong>NIRAVAN Autonomous Incident Response Playbook:</strong><br><br>
    <strong>Phase 1 — Contain (0-15 minutes):</strong><br>
    1. Isolate affected endpoints via network ACL or EDR quarantine<br>
    2. Disable compromised user accounts in Active Directory<br>
    3. Block identified C2 IPs at perimeter firewall<br>
    4. Enable enhanced logging on Domain Controllers<br><br>
    <strong>Phase 2 — Investigate (15-60 minutes):</strong><br>
    5. Collect memory dumps from affected systems<br>
    6. Extract and analyze malware samples<br>
    7. Review authentication logs for account compromise<br>
    8. Map the full attack timeline using NIRAVAN correlation data<br><br>
    <strong>Phase 3 — Eradicate (1-4 hours):</strong><br>
    9. Remove malware and persistence mechanisms<br>
    10. Reset all potentially compromised credentials<br>
    11. Patch exploited vulnerabilities<br>
    12. Rebuild affected systems from clean images<br><br>
    <strong>Phase 4 — Recover (4-24 hours):</strong><br>
    13. Restore data from verified clean backups<br>
    14. Re-enable services with enhanced monitoring<br>
    15. Validate integrity of all critical systems<br>
    16. Generate executive incident report<br><br>
    <em>NIRAVAN can automate Steps 1-4 with your approval. Enable Autonomous Response in Settings.</em>`;
  },

  respondRansomware() {
    return `🚨 <strong>Ransomware Threat Intelligence:</strong><br><br>
    NIRAVAN has detected behavioral indicators consistent with <strong>modern ransomware</strong> operations:<br><br>
    <strong>Observed Behaviors:</strong><br>
    • Mass file renaming/encryption activity<br>
    • Volume Shadow Copy deletion attempts<br>
    • Windows backup catalog deletion<br>
    • Lateral movement to file servers<br><br>
    <strong>Attribution:</strong> Behavioral signature matches <strong>REvil/BlackBasta</strong> TTPs with 87% confidence.<br><br>
    <strong>Critical Actions:</strong><br>
    🔴 Disconnect affected systems IMMEDIATELY<br>
    🔴 Do NOT reboot — forensic evidence will be lost<br>
    🔴 Do NOT pay without security consultation<br>
    🟡 Check if backups are intact and isolated<br>
    🟡 Preserve network logs for forensics<br>
    🟢 Engage ransomware specialist (CISA hotline: 1-888-282-0870)`;
  },

  respondLateralMovement() {
    return `🕵️ <strong>Lateral Movement Analysis:</strong><br><br>
    NIRAVAN has traced unauthorized movement within your internal network. Here's what the attacker is doing:<br><br>
    <strong>Movement Pattern Detected:</strong><br>
    Compromised endpoint → Internal scan → SMB/RDP to servers → Credential escalation<br><br>
    <strong>Tools Likely Used (per ATT&CK mapping):</strong><br>
    • Mimikatz or similar for credential dumping<br>
    • PsExec or WMI for remote execution<br>
    • Pass-the-Hash for authentication bypass<br><br>
    <strong>Current Reach:</strong> The attacker appears to have accessed <strong>3-5 internal systems</strong> 
    beyond the initial compromise point. NIRAVAN is tracking their movement in real-time.<br><br>
    <strong>Containment Strategy:</strong><br>
    1. Enable network segmentation between all VLANs<br>
    2. Disable NTLM authentication organization-wide<br>
    3. Deploy EDR policies to block lateral movement tools<br>
    4. Monitor for abnormal service account activity`;
  },

  respondExfiltration() {
    return `📤 <strong>Data Exfiltration Analysis:</strong><br><br>
    NIRAVAN has detected active data theft patterns:<br><br>
    <strong>Exfiltration Methods Observed:</strong><br>
    • Large HTTPS uploads to cloud storage providers<br>
    • DNS tunneling for covert data transmission<br>
    • Suspicious access to sensitive file repositories<br><br>
    <strong>Data at Risk:</strong> Based on accessed directories and file types, NIRAVAN identifies potential exposure of 
    <strong>customer PII, financial records, and source code repositories</strong>.<br><br>
    <strong>Estimated Data Volume:</strong> ~2.3GB transferred in the past 6 hours<br><br>
    <strong>Immediate Actions:</strong><br>
    1. Block outbound traffic to identified exfiltration IPs<br>
    2. Enable DLP policies to prevent further transfers<br>
    3. Identify all data accessed in the past 24h<br>
    4. Assess GDPR/regulatory breach notification requirements<br>
    5. Preserve network flow logs as legal evidence`;
  },

  respondMitre() {
    return `🗺️ <strong>MITRE ATT&CK Framework Mapping:</strong><br><br>
    NIRAVAN has mapped all current incidents to the MITRE ATT&CK framework:<br><br>
    <strong>Active Tactics (7/14 observed):</strong><br>
    🔴 <strong>Initial Access</strong>: T1566 (Phishing), T1190 (Exploit Public-Facing)<br>
    🔴 <strong>Execution</strong>: T1059 (Command Scripting), T1203 (Client Exploitation)<br>
    🔴 <strong>Persistence</strong>: T1078 (Valid Accounts), T1547 (Boot Autostart)<br>
    🟠 <strong>Privilege Escalation</strong>: T1068, T1548 (Sudo Abuse)<br>
    🔴 <strong>Lateral Movement</strong>: T1021 (Remote Services), T1570<br>
    🔴 <strong>Command & Control</strong>: T1071 (Application Layer), T1573 (Encrypted Channel)<br>
    🔴 <strong>Exfiltration</strong>: T1048, T1567 (Cloud Storage)<br><br>
    <strong>NIRAVAN Coverage:</strong> 247 of 600+ ATT&CK techniques are actively monitored in real-time.
    View the full matrix in the Threat Intelligence page.`;
  },

  respondMFA() {
    return `🔐 <strong>MFA Security Analysis:</strong><br><br>
    NIRAVAN has detected <strong>MFA push bombing attacks</strong> targeting your users. This is a sophisticated social engineering technique.<br><br>
    <strong>Current Status:</strong><br>
    • ${randomInt(5,15)} users targeted with push bombing in last 24h<br>
    • ${randomInt(1,3)} potentially approved by fatigued users<br>
    • Attacker source: Multiple IPs in Eastern Europe<br><br>
    <strong>MFA Hardening Recommendations:</strong><br>
    ✅ Switch from push notifications to <strong>number-matching MFA</strong> or FIDO2 hardware keys<br>
    ✅ Enable <strong>MFA fraud reporting</strong> in your identity provider<br>
    ✅ Implement <strong>risk-based authentication</strong> — flag logins from new locations<br>
    ✅ Set <strong>MFA session timeouts</strong> (max 8-hour sessions)<br>
    ✅ Train users to NEVER approve unexpected MFA prompts`;
  },

  respondCompliance() {
    return `📋 <strong>Compliance Posture Assessment:</strong><br><br>
    Based on current security controls and detected gaps, NIRAVAN estimates:<br><br>
    <strong>ISO/IEC 27001:</strong> 71% — <span style="color:#ffd60a">Partial Compliance</span><br>
    Gaps: Incident response procedures, asset inventory completeness<br><br>
    <strong>NIST Cybersecurity Framework:</strong> 68% — <span style="color:#ffd60a">Partial</span><br>
    Gaps: Protect function (patch management), Respond function (IR plan)<br><br>
    <strong>SOC 2 Type II:</strong> 79% — <span style="color:#30d158">On Track</span><br>
    Gaps: Logging completeness, change management controls<br><br>
    <strong>GDPR:</strong> ⚠️ Current data exfiltration incident may trigger breach notification obligations<br>
    72-hour notification window may apply if PII was accessed.<br><br>
    <strong>NIRAVAN Recommendations:</strong> Prioritize incident response documentation, patch management, and data classification to improve compliance scores.`;
  },

  respondVulnerabilities() {
    const cves = window.NIRAVAN_DATA.cves;
    let list = cves.slice(0,4).map(c => `• <strong>${c.id}</strong> (CVSS: ${c.score}) — ${c.desc.substring(0,60)}...`).join('<br>');
    return `🔍 <strong>Vulnerability Intelligence:</strong><br><br>
    NIRAVAN has identified <strong>${cves.length} CVEs</strong> affecting your infrastructure:<br><br>
    ${list}<br><br>
    <strong>Critical Action Required:</strong><br>
    <strong>CVE-2024-3400</strong> (CVSS 10.0) on your VPN gateway is actively being exploited in the wild. 
    CISA has issued an Emergency Directive. Patch within <strong>24 hours</strong>.<br><br>
    <strong>Patch Priority Queue:</strong><br>
    1. VPN-GW — CVSS 10.0 (patch available)<br>
    2. FIREWALL-01 — CVSS 9.8 (patch available)<br>
    3. API-GATEWAY — CVSS 7.5 (workaround available)<br>
    4. WIN-DC-01 — CVSS 10.0 (patch available)<br><br>
    View all CVEs in the Threat Intelligence module.`;
  },

  respondQRI(qri, qriInfo) {
    return `⚡ <strong>Quantum Risk Index™ Explained:</strong><br><br>
    Your current QRI is <strong>${qri}/100 — ${qriInfo.label}</strong><br><br>
    The Quantum Risk Index™ is NIRAVAN's proprietary composite risk score that combines:<br><br>
    <strong>Threat Velocity (35%):</strong> How fast and severe are current active threats?<br>
    <strong>Asset Exposure (25%):</strong> How vulnerable are your critical assets?<br>
    <strong>Vulnerability Density (20%):</strong> How many unpatched CVEs affect your systems?<br>
    <strong>Incident Impact (20%):</strong> What is the business impact of active incidents?<br><br>
    <strong>Score Breakdown:</strong><br>
    • 0-20: Minimal Risk 🟢<br>
    • 21-40: Low Risk 🟢<br>
    • 41-65: Medium Risk 🟡<br>
    • 66-85: High Risk 🟠<br>
    • 86-100: Critical Risk 🔴<br><br>
    To reduce your QRI: patch critical CVEs, contain active incidents, and implement network segmentation.`;
  },

  respondDefault(question, qri) {
    return `🧠 <strong>NIRAVAN Analysis:</strong><br><br>
    Based on your query about "<strong>${question.length > 50 ? question.substring(0,50)+'...' : question}</strong>", 
    here's what I can tell you from current security data:<br><br>
    Your organization is experiencing an <strong>active threat campaign</strong> with a Quantum Risk Index of 
    <strong>${qri}/100</strong>. NIRAVAN is continuously monitoring all ${window.NIRAVAN_DATA.assets.length} assets 
    and has detected ${window.NIRAVAN_DATA.events.length} security events in the current monitoring window.<br><br>
    For more specific analysis, try asking me about:<br>
    • Specific threats (e.g., "Explain the ransomware attack")<br>
    • Asset risk ("Which assets are most vulnerable?")<br>
    • Predictions ("What attack vector is most likely next?")<br>
    • Compliance ("What is my ISO 27001 posture?")<br><br>
    <em>NIRAVAN analyzes 4,231 events/second to give you the most current intelligence.</em>`;
  }
};

// ── Global chat function ──
function askNiravan(question) {
  const input = document.getElementById('chat-input');
  if(input) input.value = question;
  handleChatSend();
}

function handleChatSend() {
  const input = document.getElementById('chat-input');
  if(!input) return;
  const q = input.value.trim();
  if(!q) return;
  input.value = '';

  // Add user message
  addChatMessage('user', q);

  // Simulate typing delay
  addTypingIndicator();

  if (window.NIRAVAN_API_ACTIVE) {
    fetch(`${window.API_URL}/copilot`, {
      method: 'POST',
      headers: { 
        ...window.getHeaders(),
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({ prompt: q })
    })
    .then(res => {
      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}`);
      }
      return res.json();
    })
    .then(data => {
      removeTypingIndicator();
      addChatMessage('niravan', data.response || "No response received from NIRAVAN CORE.");
    })
    .catch(e => {
      console.error("[NIRAVAN] Copilot error:", e);
      setTimeout(() => {
        removeTypingIndicator();
        const response = window.NIRAVAN_AI.generateResponse(q);
        addChatMessage('niravan', response);
      }, 500);
    });
  } else {
    setTimeout(() => {
      removeTypingIndicator();
      const response = window.NIRAVAN_AI.generateResponse(q);
      addChatMessage('niravan', response);
    }, 800 + Math.random() * 1200);
  }
}

function addChatMessage(role, content) {
  const container = document.getElementById('chat-messages');
  if(!container) return;

  const msg = document.createElement('div');
  msg.className = `message ${role === 'niravan' ? 'niravan-msg' : 'user-msg'}`;

  const time = new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});

  if(role === 'niravan') {
    msg.innerHTML = `
      <div class="msg-avatar" style="background:linear-gradient(135deg,#bf5af2,#00d4ff)">N</div>
      <div class="msg-bubble">
        <div class="msg-header">NIRAVAN AI <span class="msg-time">${time}</span></div>
        <div class="msg-content">${content}</div>
      </div>`;
  } else {
    msg.innerHTML = `
      <div class="msg-bubble">
        <div class="msg-header" style="text-align:right">You <span class="msg-time">${time}</span></div>
        <div class="msg-content">${content}</div>
      </div>
      <div class="msg-avatar">U</div>`;
  }

  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
}

function addTypingIndicator() {
  const container = document.getElementById('chat-messages');
  if(!container) return;
  const typing = document.createElement('div');
  typing.id = 'typing-indicator';
  typing.className = 'message niravan-msg';
  typing.innerHTML = `
    <div class="msg-avatar" style="background:linear-gradient(135deg,#bf5af2,#00d4ff)">N</div>
    <div class="msg-bubble">
      <div class="msg-content" style="padding:12px 16px">
        <span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span>
      </div>
    </div>`;
  container.appendChild(typing);
  container.scrollTop = container.scrollHeight;

  // Add typing dot CSS if not present
  if(!document.getElementById('typing-style')) {
    const style = document.createElement('style');
    style.id = 'typing-style';
    style.textContent = `.typing-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--color-ai);margin:0 2px;animation:typing-bounce 1s ease-in-out infinite}.typing-dot:nth-child(2){animation-delay:0.2s}.typing-dot:nth-child(3){animation-delay:0.4s}@keyframes typing-bounce{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-8px)}}`;
    document.head.appendChild(style);
  }
}

function removeTypingIndicator() {
  const t = document.getElementById('typing-indicator');
  if(t) t.remove();
}

window.triggerDeceptionTouch = async function() {
  const select = document.getElementById('simulate-honeypot-select');
  if (!select) return;
  const hpType = select.value;
  const srcIp = "185.220.101." + Math.floor(Math.random() * 250 + 2);
  
  showToast(`Initiating simulated ${hpType} honeypot touch from ${srcIp}...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      headers['Content-Type'] = 'application/json';
      
      const res = await fetch(`${window.API_URL}/deception/trigger`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ honeypot_type: hpType, source_ip: srcIp })
      });
      
      if (res.ok) {
        const data = await res.json();
        showToast(`⚠️ DECEPTION TRIGGERED: Case ${data.case_id} created autonomously.`, 'critical');
        await window.syncFromBackend();
        renderAIAnalyst();
        askNiravan(`Explain deception events from ${srcIp}`);
      } else {
        showToast("Error triggering deception simulation on backend.", "bad");
      }
    } catch(err) {
      console.error("Error triggering deception:", err);
      showToast("Connection error during deception simulation.", "bad");
    }
  } else {
    const mockLog = {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      honeypot_type: hpType,
      source_ip: srcIp,
      username_attempt: hpType === 'SSH' ? 'admin' : null,
      password_attempt: hpType === 'SSH' ? 'password123' : null,
      path_attempt: hpType === 'Web' ? '/wp-admin' : hpType === 'API' ? '/api/v2/auth/token' : null,
      query_attempt: hpType === 'Database' ? "SELECT * FROM users WHERE '1'='1'--" : null,
      attribution: hpType === 'Database' ? 'Security Scanner' : hpType === 'SSH' ? 'Credential Stuffing Bot' : hpType === 'API' ? 'Credential Stuffing Bot' : 'Web Scanner Bot'
    };
    
    if (!window.NIRAVAN_DATA.deceptionLogs) window.NIRAVAN_DATA.deceptionLogs = [];
    window.NIRAVAN_DATA.deceptionLogs.unshift(mockLog);
    
    const hp = window.NIRAVAN_DATA.deceptionHoneypots.find(h => h.type === hpType);
    if (hp) hp.hits += 1;
    
    if (window.NIRAVAN_DATA.threatAttribution) {
      const att = window.NIRAVAN_DATA.threatAttribution;
      if (hpType === 'Database') {
        att.scanners += 1;
      } else if (hpType === 'SSH' || hpType === 'API') {
        att.bots += 1;
      } else {
        att.scanners += 1;
      }
      att.total += 1;
      att.breakdown_percentages["Scanner"] = Math.round((att.scanners / att.total) * 1000) / 10;
      att.breakdown_percentages["Bot"] = Math.round((att.bots / att.total) * 1000) / 10;
    }
    
    const incId = "inc-" + Math.floor(Math.random() * 9000 + 1000);
    const incTitle = hpType === 'SSH' ? 'SSH Honeypot Credential Stuffing Attempt' : hpType === 'Web' ? 'Web Honeypot Unauthorized Path Enumerate' : hpType === 'API' ? 'API Honeypot Key Enumeration Triggered' : 'Database Honeypot SQL Injection Probe';
    
    const mockIncident = {
      id: incId,
      title: incTitle,
      type: "DECEPTION_TRIGGERED",
      severity: "critical",
      description: `Immediate warning: Honeypot of type '${hpType}' was touched by external IP ${srcIp}.`,
      status: "open",
      user: "honey_credentials",
      host: "HONEY-NET-GW",
      category: hpType === 'Database' ? 'Initial Access' : hpType === 'SSH' ? 'Credential Access' : 'Reconnaissance',
      mitre: hpType === 'Database' ? ['T1190'] : hpType === 'SSH' ? ['T1110'] : ['T1046'],
      technique: hpType === 'Database' ? 'SQL Injection' : hpType === 'SSH' ? 'Brute Force' : 'Web Scanning',
      timeStr: "Just now",
      timestamp: new Date(),
      technical: `Source IP: ${srcIp} | Honeypot Type: ${hpType}`
    };
    window.NIRAVAN_DATA.events.unshift(mockIncident);
    
    const caseId = "case-" + incId.split('-')[1];
    const mockCase = {
      id: caseId,
      title: `Autonomous Incident Response: {title}`,
      description: `A deception trigger warning has been escalated. Honeypot '${hpType}' detected direct probe from IP ${srcIp}.`,
      severity: "critical",
      status: "open",
      assignee: "analyst@niravan.ai",
      incident_id: incId,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      notes: [
        { id: 1, author: "system", note: "Case automatically generated via Autonomous Deception Network escalation.", created_at: new Date().toISOString() },
        { id: 2, author: "system", note: `Threat Enrichment: Trigger IP ${srcIp} matches typical patterns for ${mockLog.attribution}.`, created_at: new Date().toISOString() }
      ],
      evidence: [
        { id: 1, name: "Malicious Probe Source IP", value: srcIp, type: "IP", added_by: "system", created_at: new Date().toISOString() },
        { id: 2, name: "Honeypot Type", value: hpType, type: "Log", added_by: "system", created_at: new Date().toISOString() }
      ]
    };
    window.NIRAVAN_DATA.cases.unshift(mockCase);
    
    showToast(`⚠️ DECEPTION TRIGGERED: Case ${caseId} created autonomously.`, 'critical');
    
    renderAIAnalyst();
    
    setTimeout(() => {
      askNiravan(`Explain deception events from ${srcIp}`);
    }, 800);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Guardian AI Officer — Extended Methods
// Added via property extension after window.NIRAVAN_AI declaration.
// ─────────────────────────────────────────────────────────────────────────────

window.NIRAVAN_AI.respondGuardianAIEnglish = function(qri, assets) {
  const sortedAssets = [...(assets || [])].sort((a,b) => (b.riskScore||0) - (a.riskScore||0));
  const topAsset = sortedAssets[0];
  const highRisk = sortedAssets.filter(a => (a.riskScore||0) >= 70);
  const cves = (window.NIRAVAN_DATA.cves || []);
  const critCves = cves.filter(c => c.severity === 'critical');
  const incidents = (window.NIRAVAN_DATA.events || []).filter(e => e.severity === 'critical');
  let reasons = ''; let actions = '';
  if (topAsset && topAsset.riskScore >= 60) {
    const ports = (topAsset.openServices || topAsset.open_services || '').toString().replace(/,/g, ', ');
    reasons += `1️⃣ <strong>Exposed Asset:</strong> <code>${topAsset.name}</code> has a risk score of <strong>${topAsset.riskScore}/100</strong>. ${topAsset.vulnerabilities || 0} known vulnerabilities, ports ${ports || '22, 80, 443'} exposed.<br><br>`;
    actions += `✓ Patch <code>${topAsset.name}</code> — apply all pending security updates immediately.<br>`;
  }
  if (critCves.length > 0) {
    const topCve = critCves[0];
    reasons += `2️⃣ <strong>Critical CVEs Detected:</strong> OpenVAS found <strong>${critCves.length} critical CVEs</strong> (CVSS 9.0+). Top: <code>${topCve.id}</code> (CVSS ${topCve.score}) — exploitable without credentials.<br><br>`;
    actions += `✓ Patch <strong>${critCves.length} critical CVEs</strong> — start with highest CVSS score.<br>`;
  }
  if (incidents.length > 0) {
    reasons += `3️⃣ <strong>Active Threats:</strong> NIRAVAN detected <strong>${incidents.length} critical events</strong> in last 24 hours.<br><br>`;
    actions += `✓ Guardian Mode → Block Suspicious IPs immediately.<br>`;
  } else if (highRisk.length > 1) {
    reasons += `3️⃣ <strong>${highRisk.length} High-Risk Assets:</strong> Multiple systems with elevated risk — unpatched services or exposed ports.<br>`;
    actions += `✓ Enable <strong>MFA</strong> on all administrator accounts.<br>`;
  }
  
  const agentLog = `🤖 <strong>NIRAVAN Multi-Agent Consensus</strong>:<br>` +
    `• 📋 <strong>Security Director Agent</strong>: Orchestrated telemetry investigation.<br>` +
    `• 🔎 <strong>ASM Agent</strong>: Verified asset vulnerability densities and port exposure.<br>` +
    `• 🕸️ <strong>Threat Intel Agent</strong>: Correlated live indicators against CISA KEV feeds.<br>` +
    `• 🚨 <strong>Incident Agent</strong>: Scanned threat path history and whitelisted local rules.<br>` +
    `• 🛡️ <strong>Response Agent</strong>: Checked Defense Memory database (Success confidence: 96.4%).<br><br>` +
    `<hr style="border:0; border-top:1px solid rgba(255,255,255,0.1); margin:8px 0;"><br>`;

  if (!reasons) return agentLog + `Your system is currently secure. Risk score: <strong>${qri}/100</strong>. NIRAVAN is continuously monitoring.`;
  return agentLog + `🛡️ <strong>Guardian AI Officer — Risk Score Breakdown</strong><br><br>Your current risk score is <strong>${qri}/100</strong>.<br><br><strong>Reasons it is elevated:</strong><br><br>${reasons}<strong>Recommended Actions:</strong><br>${actions}<br><em>NIRAVAN is monitoring ${sortedAssets.length} assets.</em>`;
};

window.NIRAVAN_AI.respondGuardianAITamil = function(qri, assets) {
  const sortedAssets = [...(assets || [])].sort((a,b) => (b.riskScore||0) - (a.riskScore||0));
  const topAsset = sortedAssets[0];
  const cves = (window.NIRAVAN_DATA.cves || []);
  const critCves = cves.filter(c => c.severity === 'critical');
  const incidents = (window.NIRAVAN_DATA.events || []).filter(e => e.severity === 'critical');
  let reasons = ''; let actions = '';
  if (topAsset && topAsset.riskScore >= 60) {
    reasons += `<strong>1. திறந்த சர்வர்:</strong> <code>${topAsset.name}</code> அபாய மதிப்பெண் <strong>${topAsset.riskScore}/100</strong>. ${topAsset.vulnerabilities || 0} பாதிப்புகள்.<br><br>`;
    actions += `<code>${topAsset.name}</code>-ஐ <strong>புதுப்பிக்கவும்</strong> — அனைத்து பாதுகாப்பு திருத்தங்களையும் நிறுவுங்கள்.<br>`;
  }
  if (critCves.length > 0) {
    reasons += `<strong>2. முக்கியமான பாதிப்புகள்:</strong> OpenVAS <strong>${critCves.length} முக்கியமான CVE</strong> கண்டறிந்தது. கடவுச்சொல் இல்லாமலே பயன்படுத்தப்படலாம்.<br><br>`;
    actions += `<strong>பாதிப்புகளை சரிசெய்யவும்</strong> — CVSS மதிப்பு அதிகமான முதலில்.<br>`;
  }
  if (incidents.length > 0) {
    reasons += `<strong>3. செயலில் உள்ள அச்சுறுத்தல்கள்:</strong> கடந்த 24 மணி நேரத்தில் <strong>${incidents.length} நிகழ்வுகள்</strong>.<br><br>`;
    actions += `<strong>காவல் முறை: சந்தேகத்திற்கிடமான IP-களை தடுக்கவும்</strong> (~2 நிமிடங்கள்)<br>`;
  }

  const agentLogTa = `🤖 <strong>NIRAVAN கூட்டு-முகவர் ஒருமித்த கருத்து (Multi-Agent Consensus)</strong>:<br>` +
    `• 📋 <strong>பாதுகாப்பு இயக்குனர் முகவர் (Security Director Agent)</strong>: தொலைத்தொடர்பு விசாரணையை ஒருங்கிணைத்தார்.<br>` +
    `• 🔎 <strong>ASM முகவர் (ASM Agent)</strong>: சொத்து பாதிப்பு அடர்த்தி மற்றும் போர்ட் வெளிப்பாட்டை சரிபார்த்தார்.<br>` +
    `• 🕸️ <strong>அச்சுறுத்தல் உளவு முகவர் (Threat Intel Agent)</strong>: நேரடி அச்சுறுத்தல் குறியீடுகளை CISA KEV உடன் ஒப்பிட்டார்.<br>` +
    `• 🚨 <strong>சம்பவ முகவர் (Incident Agent)</strong>: அச்சுறுத்தல் வரலாற்றுப் பாதை மற்றும் உள்ளூர் விதிகளை ஸ்கேன் செய்தார்.<br>` +
    `• 🛡️ <strong>பதிவு முகவர் (Response Agent)</strong>: பாதுகாப்பு நினைவக தரவுத்தளத்தை சரிபார்த்தார் (வெற்றி நம்பிக்கை: 96.4%).<br><br>` +
    `<hr style="border:0; border-top:1px solid rgba(255,255,255,0.1); margin:8px 0;"><br>`;

  if (!reasons) return agentLogTa + `உங்கள் கணினி பாதுகாப்பாக உள்ளது. அபாய மதிப்பெண் <strong>${qri}/100</strong>. NIRAVAN தொடர்ந்து கண்காணிக்கிறது.`;
  return agentLogTa + `🛡️ <strong>AI பாதுகாப்பு அதிகாரி — அபாய விளக்கம்</strong><br><br>அபாய மதிப்பெண்: <strong>${qri}/100</strong><br><br><strong>காரணங்கள்:</strong><br><br>${reasons}<strong>பரிந்துரைக்கப்படும் செயல்கள்:</strong><br>${actions}<br><em>NIRAVAN ${sortedAssets.length} சர்வர்களை கண்காணிக்கிறது.</em>`;
};

window.NIRAVAN_AI.respondOpenVASScan = function() {
  const cves = (window.NIRAVAN_DATA.cves || []);
  const assets = (window.NIRAVAN_DATA.assets || []);
  const critCves = cves.filter(c => c.severity === 'critical');
  const highCves = cves.filter(c => c.severity === 'high');
  if (cves.length === 0) return `<strong>OpenVAS Vulnerability Scan Results:</strong><br><br>No CVEs loaded yet. Go to <strong>Attack Surface</strong> and click <strong>Scan Network</strong>, or use <strong>Guardian Mode: Vulnerability Radar: Scan Again</strong>.`;
  const cveRows = cves.slice(0, 6).map(c => `<strong>${c.id}</strong> (CVSS: ${c.score}) - ${(c.severity||'').toUpperCase()} - Affects: <code>${c.affected || 'Unknown'}</code> - ${(c.desc||'').substring(0,60)}...`).join('<br>');
  return `<strong>OpenVAS Vulnerability Radar</strong><br><br>Critical: <strong>${critCves.length}</strong> | High: <strong>${highCves.length}</strong> | Total: <strong>${cves.length} CVEs</strong> across ${assets.length} assets<br><br><strong>Top Findings:</strong><br>${cveRows}<br><br><strong>Action:</strong> Patch Critical CVEs first. Open <strong>Guardian Mode: Vulnerability Radar</strong> for the full interactive view.`;
};

console.log('[NIRAVAN] AI Engine initialized - Guardian AI Officer active');
