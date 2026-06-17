/* ============================================================
   NIRAVAN – Main Application Controller
   Navigation, real-time updates, page rendering, toasts
   ============================================================ */

// ── State ──
let currentPage = 'dashboard';
let eventsProcessed = 0;
let correlationsFound = 0;
let particleCtx, particles = [];

// ── Utility: convert hex + alpha to rgba ──
function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3), 16);
  const g = parseInt(hex.slice(3,5), 16);
  const b = parseInt(hex.slice(5,7), 16);
  return `rgba(${r},${g},${b},${alpha})`;
}

// ── Init ──
// ── Init ──
window.updateDistrictBadge = function() {
  const badge = document.getElementById("tn-district-badge");
  if (!badge) return;
  if (localStorage.getItem("NIRAVAN_ONBOARDED") === "true") {
    const district = localStorage.getItem("NIRAVAN_DISTRICT") || "Chennai";
    const type = localStorage.getItem("NIRAVAN_DEPT_TYPE") || "Dept";
    badge.innerText = `🏛️ ${district} (${type})`;
    badge.style.display = "inline-flex";
  } else {
    badge.style.display = "none";
  }
};

window.refreshApplicationData = function() {
  window.updateDistrictBadge();
  if (currentPage === 'dashboard') {
    renderDashboard();
  } else if (currentPage === 'tnmap') {
    if (window.initTNMap) window.initTNMap('tn-threat-map-container');
  }
};

document.addEventListener('DOMContentLoaded', async () => {
  initParticles();
  initNavigation();
  initClock();
  initChatInput();
  window.updateDistrictBadge();

  // Listen for onboarding updates
  window.addEventListener("niravanOnboardingCompleted", () => {
    window.refreshApplicationData();
    showToast(`System optimized for ${localStorage.getItem("NIRAVAN_DEPT_NAME")} in ${localStorage.getItem("NIRAVAN_DISTRICT")} District.`, 'good');
  });

  // Wait for API check & sync if present
  if (window.checkApiStatus) {
    await window.checkApiStatus();
    if (window.NIRAVAN_API_ACTIVE && window.syncFromBackend) {
      await window.syncFromBackend();
    }
  }

  renderDashboard();
  startRealTimeEngine();
  
  // Set up language on start
  if (window.setLanguage) {
    window.setLanguage(window.NIRAVAN_CURRENT_LANG);
    const btn = document.getElementById("btn-lang-toggle");
    if (btn) btn.innerText = window.NIRAVAN_CURRENT_LANG === "en" ? "தமிழ்" : "English";
  }

  setTimeout(() => showToast('NIRAVAN AI Engine fully operational — monitoring 247 assets in real time.', 'good'), 2000);
  setTimeout(() => showToast('⚠️ Critical: Ransomware activity detected on PROD-WEB-01', 'critical'), 4000);
  setTimeout(() => showToast('🔴 Lateral movement detected — internal network traversal in progress', 'critical'), 7000);
});

// ── Particle Background ──
function initParticles() {
  const canvas = document.getElementById('particle-canvas');
  if(!canvas) return;
  particleCtx = canvas.getContext('2d');
  canvas.width  = window.innerWidth;
  canvas.height = window.innerHeight;

  for(let i = 0; i < 80; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
      alpha: Math.random() * 0.4 + 0.1,
      color: Math.random() > 0.7 ? '#00d4ff' : Math.random() > 0.5 ? '#bf5af2' : '#ffffff'
    });
  }

  animateParticles();

  window.addEventListener('resize', () => {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  });
}

function animateParticles() {
  const canvas = document.getElementById('particle-canvas');
  if(!canvas || !particleCtx) return;

  particleCtx.clearRect(0, 0, canvas.width, canvas.height);

  particles.forEach(p => {
    p.x += p.vx;
    p.y += p.vy;
    if(p.x < 0) p.x = canvas.width;
    if(p.x > canvas.width) p.x = 0;
    if(p.y < 0) p.y = canvas.height;
    if(p.y > canvas.height) p.y = 0;

    particleCtx.beginPath();
    particleCtx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    particleCtx.fillStyle = hexToRgba(p.color, p.alpha);
    particleCtx.fill();
  });

  // Draw connecting lines between close particles
  for(let i = 0; i < particles.length; i++) {
    for(let j = i+1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = Math.sqrt(dx*dx + dy*dy);
      if(dist < 100) {
        particleCtx.beginPath();
        particleCtx.moveTo(particles[i].x, particles[i].y);
        particleCtx.lineTo(particles[j].x, particles[j].y);
        particleCtx.strokeStyle = `rgba(0,212,255,${0.06 * (1 - dist/100)})`;
        particleCtx.lineWidth = 0.5;
        particleCtx.stroke();
      }
    }
  }

  requestAnimationFrame(animateParticles);
}

// ── Navigation ──
function initNavigation() {
  // Nav items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const page = item.dataset.page;
      navigateTo(page);
    });
  });

  // Sidebar toggle
  const toggle = document.getElementById('sidebar-toggle');
  if(toggle) {
    toggle.addEventListener('click', () => {
      document.getElementById('sidebar').classList.toggle('collapsed');
      document.getElementById('main-content').classList.toggle('expanded');
    });
  }

  // Incident filter buttons
  document.querySelectorAll('[data-filter]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const parent = e.target.closest('.filter-group, .page-toolbar');
      if(parent) {
        parent.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
      }
      const filter = e.target.dataset.filter;
      renderIncidentsList(filter);
    });
  });

  // Asset filter
  document.getElementById('asset-type-filter')?.addEventListener('click', (e) => {
    if(!e.target.dataset.asset) return;
    document.querySelectorAll('#asset-type-filter .filter-btn').forEach(b => b.classList.remove('active'));
    e.target.classList.add('active');
    renderAssetGrid(e.target.dataset.asset);
  });

  // Incident search
  document.getElementById('incident-search')?.addEventListener('input', (e) => {
    renderIncidentsList('all', e.target.value);
  });

  // Case filter buttons
  document.querySelectorAll('[data-case-filter]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const parent = e.target.closest('.filter-group, .page-toolbar');
      if(parent) {
        parent.querySelectorAll('[data-case-filter]').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
      }
      const filter = e.target.dataset.caseFilter;
      renderCasesList(filter);
    });
  });

  // Case search
  document.getElementById('case-search')?.addEventListener('input', (e) => {
    renderCasesList('all', e.target.value);
  });
}

const PAGE_TITLES = {
  'guardian':       ['Guardian Mode',          'Simple, one-click protection for your organization'],
  'dashboard':      ['Command Center',        'AI-powered autonomous security operations'],
  'tnmap':          ['Tamil Nadu Threat Map',  'District-level threat coordinates and NIC telemetry uplinks'],
  'incidents':      ['Incidents & Alerts',    'Real-time security incident management'],
  'cases':          ['Case Management',       'SOC ticket tracking, investigator assignments, and evidence vault'],
  'attack-surface': ['Attack Surface Map',    'Asset discovery, vulnerability heatmap & attack paths'],
  'ai-analyst':     ['NIRAVAN CORE',    'Autonomous Cybersecurity Command Core'],
  'intelligence':   ['Threat Intelligence',   'IOC feeds, CVEs, threat actors & MITRE ATT&CK'],
  'reports':        ['Executive Reports',     'Auto-generated security posture & compliance reports'],
  'detection':      ['Detection Rules Console', 'Sigma rule configuration, syntax editing, and historical dry-run query console'],
  'settings':       ['Configuration',         'NIRAVAN platform settings & data sources'],
  'roadmap':        ['Platform Roadmap',      'From demonstration to enterprise production — 5-phase evolution'],
  'platform':       ['About NIRAVAN',         'Problem statement, honest scope, pitch, and business model'],
};

function navigateTo(page) {
  // Update page visibility
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(`page-${page}`);
  if(target) target.classList.add('active');

  // Update nav
  document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
  const navItem = document.getElementById(`nav-${page}`);
  if(navItem) navItem.classList.add('active');

  // Update title
  const [title, sub] = PAGE_TITLES[page] || ['NIRAVAN', ''];
  const titleEl = document.getElementById('page-title');
  const subtitleEl = document.getElementById('page-subtitle');
  if(titleEl) titleEl.textContent = title;
  if(subtitleEl) subtitleEl.textContent = sub;

  currentPage = page;

  // Page-specific render
  switch(page) {
    case 'guardian':       renderGuardianMode(); break;
    case 'dashboard':      renderDashboard(); break;
    case 'tnmap':          if (window.initTNMap) window.initTNMap('tn-threat-map-container'); break;
    case 'incidents':      renderIncidentsList('all'); break;
    case 'cases':          renderCasesPage(); break;
    case 'attack-surface': renderAttackSurface(); break;
    case 'ai-analyst':     renderAIAnalyst(); break;
    case 'intelligence':   renderIntelligence(); break;
    case 'reports':        generateReport(); break;
    case 'detection':      renderDetectionPage(); break;
    case 'settings':       renderSettings(); break;
    case 'roadmap':        renderRoadmap(); break;
    case 'platform':       renderPlatform(); break;
  }
}

// ── Clock ──
function initClock() {
  function tick() {
    const el = document.getElementById('live-clock');
    if(el) el.textContent = new Date().toLocaleString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',year:'numeric',month:'short',day:'numeric'});
  }
  tick();
  setInterval(tick, 1000);
}

// ── Chat Input ──
function initChatInput() {
  const input = document.getElementById('chat-input');
  if(input) {
    input.addEventListener('keypress', (e) => {
      if(e.key === 'Enter') handleChatSend();
    });
  }
  const timeEl = document.getElementById('chat-init-time');
  if(timeEl) timeEl.textContent = new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
}

// ── Real-Time Engine ──
function startRealTimeEngine() {
  // New event every 3-8 seconds
  setInterval(generateAndAddEvent, randomInt(3000, 8000));

  // Update KPI counters every 2 seconds
  setInterval(updateKPIs, 2000);

  // Update QRI every 10 seconds
  setInterval(updateQRI, 10000);

  // Update trend chart every 30 seconds
  setInterval(updateTrendChart, 30000);

  // Update ticker
  setInterval(updateTicker, 5000);

  // Update EPS counter every second
  setInterval(() => {
    const val = randomInt(4000, 4500);
    const el  = document.getElementById('eps-counter');
    if(el) el.textContent = val.toLocaleString() + ' events/sec';
    eventsProcessed += val;
    const amEl = document.getElementById('am-events');
    if(amEl) amEl.textContent = eventsProcessed.toLocaleString();
    correlationsFound += randomInt(1, 5);
    const corEl = document.getElementById('am-correlations');
    if(corEl) corEl.textContent = correlationsFound.toLocaleString();
    const evEl = document.getElementById('events-analyzed');
    if(evEl) evEl.textContent = val.toLocaleString();
  }, 1000);

  // Initial renders
  setTimeout(() => {
    updateKPIs();
    updateQRI();
    updateTicker();
  }, 500);
}

async function generateAndAddEvent() {
  if (window.NIRAVAN_API_ACTIVE) {
    const evt = generateEvent();
    try {
      const res = await fetch(`${window.API_URL}/ingest-event`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: evt.type,
          severity: evt.severity,
          title: evt.title,
          description: evt.description,
          technical: evt.technical || evt.description,
          mitre: evt.mitre || [],
          tactic: evt.tactic,
          technique: evt.technique,
          category: evt.category,
          host: evt.host || null,
          user: evt.user || null
        })
      });
      if (res.ok) {
        await window.syncFromBackend();
        const newEvt = window.NIRAVAN_DATA.events[0];
        if (newEvt) {
          if (currentPage === 'dashboard') {
            addEventToFeed(newEvt);
          }
          if (newEvt.severity === 'critical') {
            showToast(`🔴 ${newEvt.title}: ${newEvt.description.substring(0, 60)}...`, 'critical');
          }
        }
      }
    } catch (e) {
      console.error("[NIRAVAN] Error ingesting event:", e);
    }
  } else {
    const evt = generateEvent();
    
    // Evaluate detection rules offline
    let ruleTriggered = false;
    if (window.NIRAVAN_DATA.detectionRules) {
      const enabledRules = window.NIRAVAN_DATA.detectionRules.filter(r => r.status === 'enabled');
      for (const rule of enabledRules) {
        try {
          const cond = JSON.parse(rule.condition_json);
          const field = cond.field;
          let triggered = false;
          
          if (field === 'type') {
            const val = cond.value;
            if (evt.type === val) {
              const subfield = cond.subfield;
              const threshold = cond.threshold;
              if (subfield && threshold && evt.technical) {
                const match = evt.technical.match(new RegExp(subfield + '=(\\d+)'));
                if (match) {
                  const numVal = parseInt(match[1]);
                  if (numVal >= threshold) triggered = true;
                } else {
                  const match2 = evt.technical.match(/size=(\\d+)MB/);
                  if (match2 && subfield === 'size') {
                    const numVal = parseInt(match2[1]);
                    if (numVal >= threshold) triggered = true;
                  }
                }
              } else {
                triggered = true;
              }
            }
          } else if (field === 'technical') {
            const containsStr = cond.contains;
            if (containsStr && evt.technical && evt.technical.includes(containsStr)) {
              triggered = true;
            }
          }
          
          if (triggered) {
            ruleTriggered = true;
            window.NIRAVAN_DATA.auditLogs.unshift({
              id: Date.now(),
              timestamp: new Date().toISOString(),
              user_email: 'system@niravan.ai',
              action: 'RULE_TRIGGERED',
              detail: `Detection Rule '${rule.name}' (${rule.id}) triggered on ${evt.host || 'system'}. Category: ${evt.category}.`,
              ip_address: '127.0.0.1'
            });
            
            if (rule.severity === 'critical' && evt.severity !== 'critical') {
              evt.severity = 'critical';
            }
            console.log(`[NIRAVAN Local] Rule ${rule.id} TRIGGERED on ${evt.id}`);
          }
        } catch (err) {
          console.error("Offline rule eval error:", err);
        }
      }
    }
    
    window.NIRAVAN_DATA.events.unshift(evt);
    window.NIRAVAN_DATA.stats.threatsToday++;

    const badge = document.getElementById('nav-badge-dashboard');
    if(badge) badge.textContent = window.NIRAVAN_DATA.stats.threatsToday;

    if(currentPage === 'dashboard') {
      addEventToFeed(evt);
    }

    if(evt.severity === 'critical') {
      showToast(`🔴 ${evt.title}: ${evt.description.substring(0,60)}...`, 'critical');
    }
  }
}

// ── KPIs ──
function updateKPIs() {
  const data = window.NIRAVAN_DATA;
  animateCounter('kpi-threats-val', data.stats.threatsToday);
  animateCounter('kpi-incidents-val', data.stats.activeIncidents);
  animateCounter('kpi-blocked-val', data.stats.blockedEvents);
  data.stats.blockedEvents += randomInt(1, 3);

  const openCasesCount = data.cases.filter(c => c.status === 'open' || c.status === 'in_progress').length;
  const casesBadge = document.getElementById('nav-badge-cases');
  if(casesBadge) casesBadge.textContent = openCasesCount;
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if(!el) return;
  const current = parseInt(el.textContent) || 0;
  if(current === target) return;
  const step = (target - current) / 10;
  let count  = current;
  const interval = setInterval(() => {
    count += step;
    el.textContent = Math.round(count);
    if(Math.abs(count - target) < 1) {
      el.textContent = target;
      clearInterval(interval);
    }
  }, 30);
}

// ── QRI Update ──
function updateQRI() {
  const qri     = window.NIRAVAN_ENGINE.calculateQRI();
  const qriInfo = window.NIRAVAN_ENGINE.getQRILabel(qri);
  const color   = window.NIRAVAN_ENGINE.getQRIColor(qri);

  const valEl   = document.getElementById('kpi-qri-val');
  const labelEl = document.getElementById('kpi-qri-label');
  const barEl   = document.getElementById('sidebar-qri-bar');
  const scoreEl = document.getElementById('sidebar-qri-score');

  if(valEl)   { valEl.textContent = qri; valEl.style.color = color; }
  if(labelEl) { labelEl.textContent = qriInfo.label; labelEl.style.color = color; }
  if(barEl)   { barEl.style.width = qri + '%'; barEl.style.background = color; }
  if(scoreEl) { scoreEl.textContent = qri + '/100'; scoreEl.style.color = color; }
}

// ── Ticker ──
const tickerEvents = [];
function updateTicker() {
  if (!window.NIRAVAN_DATA || !window.NIRAVAN_DATA.events || window.NIRAVAN_DATA.events.length === 0) return;
  const evt = randomItem(window.NIRAVAN_DATA.events);
  if (!evt) return;
  tickerEvents.unshift(evt);
  if(tickerEvents.length > 20) tickerEvents.pop();
  renderTicker();
}

function renderTicker() {
  const track = document.getElementById('ticker-track');
  if(!track) return;
  const inner = document.createElement('div');
  inner.className = 'ticker-inner';

  const validEvents = tickerEvents.filter(e => e !== undefined && e !== null);
  if (validEvents.length === 0) {
    track.innerHTML = '';
    return;
  }
  const items = [...validEvents, ...validEvents]; // duplicate for seamless scroll
  items.forEach(evt => {
    const span = document.createElement('span');
    span.className = 'ticker-event';
    span.innerHTML = `
      <span class="ticker-sev ${evt.severity}">[${evt.severity.toUpperCase()}]</span>
      <span>${evt.timeStr} — ${evt.title}: ${evt.description.substring(0,80)}...</span>
      <span style="color:#4a5a7a">|</span>`;
    inner.appendChild(span);
  });

  track.innerHTML = '';
  track.appendChild(inner);
}

// ── Dashboard Render ──
function renderDashboard() {
  renderKillChain();
  renderEventFeed();
  renderNiravanSummary();

  // Charts with small delay for DOM
  setTimeout(() => {
    renderTrendChart();
    renderVectorChart();
    renderGeoChart();
    renderRadarChart();
    setTimeout(() => renderWorldMap(), 100);
  }, 100);
}

function renderKillChain() {
  const el = document.getElementById('killchain-viz');
  if(!el) return;
  const stages = window.NIRAVAN_ENGINE.getKillChainStatus();
  el.innerHTML = stages.map(s => `
    <div class="kc-stage">
      <div class="kc-icon">${s.icon}</div>
      <div class="kc-box ${s.status}">${s.short}</div>
      <div class="kc-label">${s.label}</div>
    </div>`).join('');
}

function renderEventFeed() {
  const el = document.getElementById('live-event-feed');
  if(!el) return;
  el.innerHTML = '';
  window.NIRAVAN_DATA.events.slice(0,10).forEach(evt => {
    addEventToFeed(evt, false);
  });
}

function addEventToFeed(evt, prepend = true) {
  const el = document.getElementById('live-event-feed');
  if(!el) return;
  const item = document.createElement('div');
  item.className = 'event-item';
  item.innerHTML = `
    <div class="event-sev-dot ${evt.severity}"></div>
    <div class="event-body">
      <div class="event-title">${evt.title}</div>
      <div class="event-meta">${evt.description.substring(0,70)}...</div>
    </div>
    <div class="event-time">${evt.timeStr}</div>`;
  if(prepend && el.firstChild) {
    el.insertBefore(item, el.firstChild);
    if(el.children.length > 10) el.removeChild(el.lastChild);
  } else {
    el.appendChild(item);
  }
}

function renderNiravanSummary() {
  const el = document.getElementById('niravan-summary');
  if(!el) return;

  // Show loading briefly
  setTimeout(() => {
    const assessments = window.NIRAVAN_ENGINE.generateAssessment();
    el.innerHTML = assessments.map(a => `
      <div class="assessment-item ${a.type}">
        <div class="assessment-title">${a.title}</div>
        <div class="assessment-text">${a.text}</div>
      </div>`).join('');
  }, 1200);
}

// ── Incidents Page ──
function renderIncidentsList(filter = 'all', search = '') {
  const el = document.getElementById('incidents-list');
  if(!el) return;

  let events = window.NIRAVAN_DATA.events;
  if(filter !== 'all') events = events.filter(e => e.severity === filter);
  if(search) events = events.filter(e =>
    e.title.toLowerCase().includes(search.toLowerCase()) ||
    e.description.toLowerCase().includes(search.toLowerCase()) ||
    e.type.toLowerCase().includes(search.toLowerCase())
  );

  el.innerHTML = '';
  events.forEach((evt, idx) => {
    const card = document.createElement('div');
    card.className = 'incident-card';
    card.innerHTML = `
      <div class="incident-card-header">
        <span class="severity-badge ${evt.severity}">${evt.severity}</span>
        <span class="incident-title">${evt.title}</span>
      </div>
      <div class="incident-desc">${evt.description.substring(0,80)}...</div>
      <div class="incident-footer">
        <span class="incident-meta">🕐 ${evt.timeStr} · ${evt.category}</span>
        <span class="incident-mitre">${evt.mitre ? evt.mitre[0] : ''}</span>
      </div>`;
    card.addEventListener('click', () => {
      document.querySelectorAll('.incident-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      renderIncidentDetail(evt);
    });
    el.appendChild(card);
  });
}

function renderIncidentDetail(evt) {
  const el = document.getElementById('incident-detail');
  if(!el) return;

  const explanation = window.NIRAVAN_AI.explainEvent(evt);
  const sevColor = { critical:'#ff2d55', high:'#ff6b35', medium:'#ffd60a', low:'#30d158' }[evt.severity];

  el.innerHTML = `
    <div class="detail-content">
      <div class="detail-header">
        <span class="severity-badge ${evt.severity}">${evt.severity}</span>
        <div>
          <div class="detail-title">${evt.title}</div>
          <div class="detail-meta-row">
            <span class="incident-meta">🕐 ${evt.timeStr}</span>
            <span class="incident-meta">📁 ${evt.category}</span>
            <span class="incident-meta">🎭 ${evt.actor.name}</span>
            <span class="incident-meta">⚡ ${evt.tactic}</span>
          </div>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Technical Event Log</div>
        <div class="technical-log">${evt.technical || evt.description}<br>[EVT-ID] ${evt.id}<br>[TIMESTAMP] ${evt.timestamp.toISOString()}<br>[SENSOR] NIRAVAN-AGENT-v2.4</div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">🧠 NIRAVAN AI Explanation</div>
        <div class="niravan-explanation">${explanation}</div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">MITRE ATT&CK Mapping</div>
        <div class="mitre-tags">
          <span class="mitre-tag">⚔️ ${evt.tactic}</span>
          ${(evt.mitre||[]).map(m => `<span class="mitre-tag">${m}</span>`).join('')}
          <span class="mitre-tag">${evt.technique}</span>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Threat Actor Intelligence</div>
        <div class="assessment-item high">
          <div class="assessment-title">🎭 ${evt.actor.name} — ${evt.actor.type}</div>
          <div class="assessment-text">Origin: <strong>${evt.actor.origin}</strong> · Known Tactics: ${evt.actor.tactics.join(', ')}</div>
        </div>
      </div>

      <div class="detail-section">
        <div class="detail-section-title">Response Actions</div>
        <div class="action-buttons">
          <button class="btn-danger" onclick="acknowledgeIncident(this, '${evt.id}')">🔒 Contain</button>
          ${evt.host ? `<button class="btn-danger" onclick="window.triggerMitigationIsolateHost('${evt.host}')" style="background:#ff9f0a;color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600;font-size:0.7rem;">🔒 Isolate Host</button>` : ''}
          ${evt.technical && evt.technical.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) ? 
            `<button class="btn-danger" onclick="window.triggerMitigationBlockIP('${evt.technical.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)[0]}')" style="background:#bf5af2;color:#fff;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600;font-size:0.7rem;">🚫 Block IP</button>` : ''}
          ${evt.status === 'escalated' ? 
            `<button class="btn-warning" onclick="navigateTo('cases'); selectedCaseId = 'case-${evt.id.split('-')[1] || evt.id}'; renderCasesList(); renderCaseDetail(selectedCaseId);">👁️ View Case</button>` : 
            `<button class="btn-warning" onclick="escalateIncident(this, '${evt.id}')">⬆️ Escalate</button>`
          }
          <button class="btn-primary" onclick="runPlaybook(this, '${evt.id}')">📋 Auto-Playbook</button>
          <button class="btn-secondary" onclick="suppressIncident(this, '${evt.id}')">🔕 Suppress</button>
          <button class="btn-ai" onclick="investigateIncident(this, '${evt.id}')" style="background:linear-gradient(135deg,var(--accent-purple),var(--accent-blue));color:#fff;border:none;box-shadow:var(--glow-blue);grid-column:1/3;padding:10px 14px;border-radius:var(--radius-sm);font-weight:600;font-size:0.75rem;cursor:pointer;margin-top:6px;transition:all var(--transition);">🧠 AI Forensic Investigation</button>
        </div>
      </div>

      <div id="ai-investigation-report-${evt.id}" class="detail-section" style="display:none; transition: all 0.3s ease;">
        <div class="detail-section-title">🧠 NIRAVAN Autonomous Forensics Report</div>
        <div class="ai-report-box" style="background:rgba(255,255,255,0.02);border:1px solid rgba(0,212,255,0.15);padding:14px;border-radius:var(--radius-sm);font-size:0.7rem;line-height:1.5;color:var(--text-secondary);overflow-x:auto;">
          <div class="report-content" id="report-content-${evt.id}">Loading AI analysis...</div>
        </div>
      </div>
    </div>`;
}

async function updateIncidentStatus(id, status) {
  if (window.NIRAVAN_API_ACTIVE && id) {
    try {
      const res = await fetch(`${window.API_URL}/incidents/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('niravan_token')}`
        },
        body: JSON.stringify({ status })
      });
      if (res.status === 403) {
        showToast('⚠️ Access Denied: Action requires Analyst or Admin privileges.', 'critical');
        navigateTo(currentPage); // reload details panel state
        return;
      }
      if (res.status === 401) {
        window.handleLogout();
        return;
      }
      await window.syncFromBackend();
    } catch(e) {
      console.error("[NIRAVAN] Error updating incident status:", e);
    }
  }
}

function acknowledgeIncident(btn, id) { 
  btn.textContent = '✅ Contained'; 
  btn.disabled = true; 
  showToast('Incident contained — NIRAVAN isolation protocols activated.', 'good'); 
  if (window.NIRAVAN_API_ACTIVE) {
    updateIncidentStatus(id, 'contained');
  } else {
    window.NIRAVAN_DATA.auditLogs.unshift({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
      action: "CONTAIN_INCIDENT",
      detail: `Contained incident ${id} — network isolation partition activated.`,
      ip_address: "127.0.0.1"
    });
  }
}
function escalateIncident(btn, id)    { 
  btn.textContent = '📨 Escalating...'; 
  btn.disabled = true; 
  handleIncidentEscalated(id);
}
function suppressIncident(btn, id)    { 
  btn.textContent = '✓ Suppressed'; 
  btn.disabled = true; 
  showToast('Event suppressed and added to whitelist.', 'good'); 
  if (window.NIRAVAN_API_ACTIVE) {
    updateIncidentStatus(id, 'suppressed');
  } else {
    window.NIRAVAN_DATA.auditLogs.unshift({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
      action: "SUPPRESS_INCIDENT",
      detail: `Suppressed incident ${id} and added to whitelist.`,
      ip_address: "127.0.0.1"
    });
  }
}
function runPlaybook(btn, id)         { 
  btn.textContent = '⚙️ Running...'; 
  setTimeout(()=>{ 
    btn.textContent='✅ Playbook Done'; 
    btn.disabled=true; 
    showToast('NIRAVAN autonomous playbook executed successfully — 4 actions completed.', 'good'); 
    if (window.NIRAVAN_API_ACTIVE) {
      updateIncidentStatus(id, 'contained');
    } else {
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "RUN_PLAYBOOK",
        detail: `Executed response playbook for incident ${id}.`,
        ip_address: "127.0.0.1"
      });
    }
  }, 2000); 
}

// ── Attack Surface ──
function renderAttackSurface() {
  renderAssetGrid('all');
  renderAttackPaths();
  setTimeout(() => renderAttackPathCanvas(), 200);
}

function renderAssetGrid(typeFilter = 'all') {
  const el = document.getElementById('asset-grid');
  if(!el) return;

  let assets = window.NIRAVAN_DATA.assets;
  if(typeFilter !== 'all') assets = assets.filter(a => a.type === typeFilter);

  const riskBarColor = { critical:'#ff2d55', high:'#ff6b35', medium:'#ffd60a', low:'#30d158' };

  el.innerHTML = assets.map(a => {
    const sev   = a.criticality;
    const color = riskBarColor[sev];
    return `
      <div class="asset-item ${sev}">
        <div class="asset-type-badge">${a.type.toUpperCase()} · ${a.os}</div>
        <div class="asset-name">${a.name}</div>
        <div class="asset-risk-bar-wrap">
          <div class="asset-risk-bar" style="width:${a.riskScore}%;background:${color}"></div>
        </div>
        <div class="asset-risk-score">${a.riskScore}/100 Risk</div>
        <div class="asset-vulns">⚠️ ${a.vulnerabilities} vulnerabilities</div>
      </div>`;
  }).join('');
}

function renderAttackPaths() {
  const el = document.getElementById('attack-paths-list');
  if(!el) return;
  const paths = window.NIRAVAN_ENGINE.ATTACK_PATHS;
  el.innerHTML = paths.map(p => `
    <div class="attack-path-item">
      <div class="attack-path-title">⚠️ ${p.title} (${p.probability}% probability)</div>
      <div class="attack-path-desc">${p.description}</div>
    </div>`).join('');
}

// ── AI Analyst Page ──
function renderAIAnalyst() {
  renderCoreAlertFeed();
  renderDeceptionHoneypots();
  renderAttributionEngine();
}

function renderCoreAlertFeed() {
  const el = document.getElementById('core-alert-feed');
  if(!el) return;
  
  const incidents = window.NIRAVAN_DATA.events.slice(0, 5);
  const hpLogs = window.NIRAVAN_DATA.deceptionLogs ? window.NIRAVAN_DATA.deceptionLogs.slice(0, 3) : [];
  
  const feedItems = [];
  
  incidents.forEach(inc => {
    feedItems.push({
      time: new Date(inc.timestamp),
      title: inc.title,
      severity: inc.severity,
      description: inc.description,
      type: 'incident',
      mitre: inc.mitre ? (Array.isArray(inc.mitre) ? inc.mitre : inc.mitre.split(',')) : []
    });
  });
  
  hpLogs.forEach(log => {
    feedItems.push({
      time: new Date(log.timestamp),
      title: `Deception Trigger: ${log.honeypot_type} Honeypot Touch`,
      severity: 'critical',
      description: `Connection from ${log.source_ip} to honeypot. Attributed to ${log.attribution}.`,
      type: 'deception',
      mitre: log.honeypot_type === 'SSH' ? ['T1110'] : log.honeypot_type === 'Web' ? ['T1046'] : ['T1595']
    });
  });
  
  feedItems.sort((a, b) => b.time - a.time);
  
  el.innerHTML = feedItems.map(item => {
    const tagIcon = item.type === 'deception' ? '👁️' : '⚠️';
    const mitreBadges = item.mitre.map(m => `<span style="font-size:0.55rem; background:rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); padding:1px 4px; border-radius:3px; color:var(--text-muted); margin-right:4px;">${m}</span>`).join('');
    
    return `
      <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-subtle); padding: 10px; border-radius: var(--radius-sm); font-size: 0.65rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <strong style="color:${item.severity === 'critical' ? '#ff2d55' : item.severity === 'high' ? '#ff6b35' : '#ffd60a'}">${tagIcon} ${item.title}</strong>
          <span style="font-size:0.55rem; color:var(--text-muted); margin-left: auto;">${item.time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
        </div>
        <div style="color:var(--text-secondary); line-height:1.3; margin-bottom:6px;">${item.description}</div>
        <div style="display:flex; align-items:center;">${mitreBadges}</div>
      </div>
    `;
  }).join('');
}

function renderDeceptionHoneypots() {
  const el = document.getElementById('deception-honeypots-grid');
  if(!el) return;
  
  const honeypots = window.NIRAVAN_DATA.deceptionHoneypots || [
    { name: "SSH Honeypot", type: "SSH", status: "active", hits: 2 },
    { name: "Web Honeypot", type: "Web", status: "active", hits: 2 },
    { name: "API Honeypot", type: "API", status: "active", hits: 1 },
    { name: "Database Honeypot", type: "Database", status: "active", hits: 1 }
  ];
  
  el.innerHTML = honeypots.map(hp => {
    let icon = "🌐";
    if (hp.type === "SSH") icon = "🔑";
    if (hp.type === "API") icon = "🔌";
    if (hp.type === "Database") icon = "🗄️";
    
    return `
      <div style="background: rgba(255,255,255,0.01); border: 1px solid var(--border-subtle); padding: 8px; border-radius: var(--radius-sm); display: flex; align-items: center; gap: 8px;">
        <div style="font-size: 1.1rem; filter: drop-shadow(0 0 4px rgba(0,212,255,0.2));">${icon}</div>
        <div style="flex:1; min-width:0;">
          <div style="font-size: 0.65rem; font-weight: 600; color: var(--text-primary); text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${hp.name}</div>
          <div style="font-size: 0.55rem; color: var(--text-muted);">Hits: <strong style="color:var(--accent-blue)">${hp.hits}</strong></div>
        </div>
        <span class="status-indicator-light green pulse-dot" style="width:5px; height:5px; background:#30d158; border-radius:50%;"></span>
      </div>
    `;
  }).join('');
}

function renderAttributionEngine() {
  const el = document.getElementById('attribution-visualizer');
  if(!el) return;
  
  const attribution = window.NIRAVAN_DATA.threatAttribution || {
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
  
  const categories = [
    { name: "Scanner / Recon", key: "Scanner", count: attribution.scanners, pct: attribution.breakdown_percentages["Scanner"], color: "#ffd60a" },
    { name: "Credential Stuffing Bot", key: "Bot", count: attribution.bots, pct: attribution.breakdown_percentages["Bot"], color: "#ff6b35" },
    { name: "Human Operator Pivot", key: "Human Operator", count: attribution.humans, pct: attribution.breakdown_percentages["Human Operator"], color: "#ff2d55" },
    { name: "APT-like Espionage", key: "APT-like Activity", count: attribution.apts, pct: attribution.breakdown_percentages["APT-like Activity"], color: "#bf5af2" },
    { name: "Insider / Exfil Threat", key: "Insider Threat", count: attribution.insiders, pct: attribution.breakdown_percentages["Insider Threat"], color: "#ff9f0a" }
  ];
  
  el.innerHTML = categories.map(cat => `
    <div style="font-size: 0.62rem; display: flex; flex-direction: column; gap: 2px;">
      <div style="display:flex; justify-content:space-between; color:var(--text-secondary);">
        <span>${cat.name}</span>
        <span><strong>${cat.count}</strong> (${cat.pct}%)</span>
      </div>
      <div style="height: 4px; background: rgba(255,255,255,0.04); border-radius: 2px; overflow: hidden;">
        <div style="width: ${cat.pct}%; height: 100%; background: ${cat.color}; border-radius: 2px;"></div>
      </div>
    </div>
  `).join('');
}

// ── Threat Intelligence ──
function renderIntelligence() {
  renderIOCTable();
  renderCVEList();
  renderActorGrid();
  renderMitreMatrix();
}

function renderIOCTable() {
  const el = document.getElementById('ioc-table-body');
  if(!el) return;
  const confidenceColor = (c) => c >= 90 ? '#30d158' : c >= 75 ? '#ffd60a' : '#ff6b35';
  el.innerHTML = window.NIRAVAN_DATA.iocs.map(ioc => `
    <tr>
      <td><span class="severity-badge medium">${ioc.type}</span></td>
      <td style="color:#7fdbff">${ioc.indicator}</td>
      <td style="color:#bf5af2">${ioc.actor}</td>
      <td style="color:${confidenceColor(ioc.confidence)}">${ioc.confidence}%</td>
      <td>${ioc.lastSeen}</td>
    </tr>`).join('');
}

function renderCVEList() {
  const el = document.getElementById('cve-list');
  if(!el) return;
  const sevColor = { critical:'#ff2d55', high:'#ff6b35', medium:'#ffd60a' };

  // Real CISA KEV data section
  const kevData = window.NIRAVAN_DATA.cisaKev || [];
  const kevHtml = kevData.length > 0 ? `
    <div style="margin-bottom:10px;padding:6px 10px;background:rgba(48,209,88,0.06);border:1px solid rgba(48,209,88,0.2);border-radius:8px;display:flex;align-items:center;gap:8px">
      <span style="color:#30d158;font-size:0.6rem;font-weight:700;letter-spacing:1px">✅ REAL DATA</span>
      <span style="color:#8899bb;font-size:0.65rem">CISA Known Exploited Vulnerabilities Catalog — Real entries, static snapshot</span>
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:#00d4ff;font-size:0.6rem;margin-left:auto">View Live Source ↗</a>
    </div>
    ${kevData.map(kev => `
      <div class="cve-item" style="border-left-color:#ff2d55">
        <span class="cve-id" style="color:#ff2d55">${kev.id}</span>
        <span class="cve-score" style="color:#30d158;font-size:0.65rem">⚠️ CISA KEV</span>
        <div class="cve-desc">${kev.notes}</div>
        <div style="font-size:0.62rem;color:#4a5a7a;margin-top:3px">
          ${kev.vendor} · ${kev.product} · Added: ${kev.dateAdded} · Patch Due: ${kev.dueDate}
        </div>
      </div>`).join('')}
    <div style="margin:10px 0 6px;font-size:0.6rem;font-weight:700;color:#4a5a7a;letter-spacing:1px;text-transform:uppercase;padding-top:10px;border-top:1px solid rgba(255,255,255,0.04)">
      ─── SIMULATED CVE DATA (context model) ───
    </div>
  ` : '';

  const simHtml = window.NIRAVAN_DATA.cves.map(cve => `
    <div class="cve-item" style="border-left-color:${sevColor[cve.severity]||'#ffd60a'}">
      <span class="cve-id" style="color:${sevColor[cve.severity]||'#ffd60a'}">${cve.id}</span>
      <span class="cve-score" style="color:${sevColor[cve.severity]||'#ffd60a'}">CVSS: ${cve.score}</span>
      <div class="cve-desc">${cve.desc}</div>
      <div style="font-size:0.62rem;color:#4a5a7a;margin-top:3px">Affects: ${cve.affected} · Published: ${cve.published}</div>
    </div>`).join('');

  el.innerHTML = kevHtml + simHtml;
}


function renderActorGrid() {
  const el = document.getElementById('actor-grid');
  if(!el) return;
  el.innerHTML = window.NIRAVAN_DATA.actors.slice(0,6).map(a => `
    <div class="actor-card-item">
      <div class="actor-name" style="color:${a.color}">${a.name}</div>
      <div class="actor-origin">🌍 ${a.origin} · ${a.type}</div>
      <div class="actor-tags">${a.tactics.map(t => `<span class="actor-tag">${t}</span>`).join('')}</div>
    </div>`).join('');
}

function renderMitreMatrix() {
  const el = document.getElementById('mitre-matrix');
  if(!el) return;
  const colors = ['#ff2d55','#ff6b35','#ffd60a','#30d158','#00d4ff','#bf5af2'];
  const activeCount = randomInt(8,18);
  let cells = '';
  MITRE_TACTICS.forEach((t, ti) => {
    cells += `<div class="mitre-tactic-header">${t.substring(0,8)}</div>`;
  });
  for(let row = 0; row < 5; row++) {
    MITRE_TACTICS.forEach((t, ti) => {
      const isActive = Math.random() < 0.35;
      const color = colors[Math.floor(Math.random() * colors.length)];
      const label = `T1${randomInt(100,600)}`;
      cells += `<div class="mitre-cell ${isActive?'active':''}" 
        style="background:${isActive?color+'25':'rgba(255,255,255,0.02)'};color:${isActive?color:'#4a5a7a'};border:1px solid ${isActive?color+'50':'rgba(255,255,255,0.04)'}"
        title="${label}">${label.substring(0,5)}</div>`;
    });
  }
  el.innerHTML = cells;
}

// ── Executive Reports ──
async function generateReport() {
  const el = document.getElementById('report-document');
  if(!el) return;

  // Show a loading indicator
  el.innerHTML = `
    <div style="text-align: center; padding: 50px; color: var(--text-muted);">
      <div style="border: 3px solid rgba(255,255,255,0.1); border-top: 3px solid var(--tn-gold); border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto 12px auto;"></div>
      Loading Executive Security Report & Compliance Matrices...
    </div>
  `;

  let compliance = {
    composite_score: 91.5,
    cert_in: 95,
    iso_27001: 88,
    nist_csf: 91,
    dpdp_act: 92,
    checklist: [
      { name: "CERT-In 6-Hour Incident Reporting SLA Compliance", status: "compliant" },
      { name: "DPDP Act 2023 Personal Data Protection controls", status: "compliant" },
      { name: "Multi-Factor Authentication (MFA) enforcement", status: "compliant" },
      { name: "OpenVAS Vulnerability Scanning frequency", status: "compliant" },
      { name: "Role-Based Access Control (RBAC) validations", status: "compliant" }
    ]
  };

  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/compliance/stats`, {
      headers: headers
    });
    if (res.ok) {
      compliance = await res.json();
    }
  } catch (err) {
    console.error("Error fetching compliance stats:", err);
  }

  const qri     = window.NIRAVAN_ENGINE.calculateQRI();
  const qriInfo = window.NIRAVAN_ENGINE.getQRILabel(qri);
  const color   = window.NIRAVAN_ENGINE.getQRIColor(qri);
  const data    = window.NIRAVAN_DATA;
  const now     = new Date();

  const criticals = data.events.filter(e => e.severity === 'critical').length;
  const highs     = data.events.filter(e => e.severity === 'high').length;
  const mediums   = data.events.filter(e => e.severity === 'medium').length;

  const topThreats = data.events.slice(0,5);

  const getScoreColor = (score) => score >= 80 ? '#30d158' : (score >= 60 ? '#ffd60a' : '#ff3b30');
  const certInColor = getScoreColor(compliance.cert_in);
  const dpdpColor = getScoreColor(compliance.dpdp_act);
  const isoColor = getScoreColor(compliance.iso_27001);
  const nistColor = getScoreColor(compliance.nist_csf);

  el.innerHTML = `
    <div class="report-header">
      <div class="report-logo">NIRAVAN</div>
      <div class="report-title">Executive Cybersecurity Intelligence Report</div>
      <div class="report-date">Generated: ${now.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})} at ${now.toLocaleTimeString()}</div>
      <div class="report-date">Classification: CONFIDENTIAL · For Authorized Personnel Only</div>
    </div>

    <div class="report-section">
      <h3>Security Posture Summary</h3>
      <div class="report-kpi-grid">
        <div class="report-kpi">
          <div class="report-kpi-val" style="color:${color}">${qri}/100</div>
          <div class="report-kpi-label">Quantum Risk Index™</div>
        </div>
        <div class="report-kpi">
          <div class="report-kpi-val" style="color:#ff2d55">${data.stats.threatsToday}</div>
          <div class="report-kpi-label">Threats Detected</div>
        </div>
        <div class="report-kpi">
          <div class="report-kpi-val" style="color:#30d158">${data.stats.blockedEvents}</div>
          <div class="report-kpi-label">Auto-Blocked Events</div>
        </div>
        <div class="report-kpi">
          <div class="report-kpi-val" style="color:#ffd60a">${data.assets.length}</div>
          <div class="report-kpi-label">Assets Monitored</div>
        </div>
      </div>
      <div class="assessment-item ${qri>=65?'critical':'medium'}" style="margin-top:12px">
        <div class="assessment-title">NIRAVAN Executive Summary</div>
        <div class="assessment-text">
          Your organization's current Quantum Risk Index™ is <strong>${qri}/100 — ${qriInfo.label}</strong>. 
          In the past 24 hours, NIRAVAN detected <strong>${criticals} critical</strong>, <strong>${highs} high</strong>, 
          and <strong>${mediums} medium-severity</strong> security events. 
          ${criticals > 0 ? `<strong>Immediate executive attention is required</strong> for the active critical incidents listed below.` : 'The security team is actively managing all identified threats.'}
          NIRAVAN's autonomous systems have blocked <strong>${data.stats.blockedEvents} attack attempts</strong> automatically.
        </div>
      </div>
    </div>

    <div class="report-section">
      <h3>Top Threats This Period</h3>
      ${topThreats.map((t, i) => `
        <div class="report-risk-item">
          <span class="severity-badge ${t.severity}">${t.severity}</span>
          <span style="flex:1"><strong>${t.title}</strong> — ${t.description.substring(0,80)}...</span>
          <span style="font-family:monospace;font-size:0.65rem;color:#4a5a7a">${t.mitre?.[0]||''}</span>
        </div>`).join('')}
    </div>

    <div class="report-section">
      <h3>Vulnerability Intelligence</h3>
      ${data.cves.slice(0,4).map(cve => `
        <div class="report-risk-item">
          <span class="severity-badge ${cve.severity}">${cve.severity}</span>
          <span style="flex:1;font-family:monospace;color:#00d4ff">${cve.id}</span>
          <span style="flex:2;font-size:0.7rem;color:#8899bb">${cve.desc.substring(0,80)}</span>
          <span style="font-weight:700;color:${cve.score>=9?'#ff2d55':'#ff6b35'}">CVSS ${cve.score}</span>
        </div>`).join('')}
    </div>

    <div class="report-section">
      <h3>Strategic Recommendations</h3>
      <div class="report-recommendation">
        <strong>1. Immediate (0-24 hours):</strong> Patch CVE-2024-3400 on VPN-GW (CVSS 10.0). Apply emergency virtual patching via WAF. 
        Isolate all systems showing ransomware indicators. Reset credentials for all potentially compromised accounts.
      </div>
      <div class="report-recommendation">
        <strong>2. Short-term (1-7 days):</strong> Deploy MFA push-bombing protections across all identity providers. 
        Implement network segmentation between workstations and server infrastructure. 
        Enable EDR advanced hunting rules for lateral movement detection.
      </div>
      <div class="report-recommendation">
        <strong>3. Medium-term (1-4 weeks):</strong> Complete vulnerability patching program for all critical assets. 
        Deploy Data Loss Prevention (DLP) solution to monitor sensitive data access. 
        Implement NIRAVAN autonomous response playbooks for common attack patterns.
      </div>
      <div class="report-recommendation">
        <strong>4. Strategic (1-3 months):</strong> Achieve ISO 27001 certification for remaining gaps. 
        Deploy Zero Trust Network Architecture. Establish Purple Team exercises with NIRAVAN threat simulation. 
        Build 24/7 SOC capability using NIRAVAN as the intelligence backbone.
      </div>
    </div>

    <div class="report-section">
      <h3 data-i18n="reports-compliance-tab">National & State Compliance Matrices (CERT-In / DPDP Act / IT Act)</h3>
      <p class="section-desc" style="font-size:0.72rem; color:var(--text-secondary); margin-bottom:12px;">
        Mandatory reporting obligations under Indian IT law and NCIIPC guidelines. Composite Compliance Score: <strong>${compliance.composite_score}%</strong>.
      </p>

      <div style="background:rgba(201, 162, 39, 0.05); border:1px dashed var(--tn-gold); border-radius:8px; padding:15px; margin-bottom:15px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <strong style="color:var(--tn-gold-light); font-size:0.85rem;" data-i18n="reports-certin-deadline">CERT-In 6-Hour Reporting Window</strong>
          <span class="severity-badge critical" style="font-size:0.6rem;">MANDATORY</span>
        </div>
        <div style="font-size:0.72rem; line-height:1.5; color:#e0e6ed;">
          CERT-In directions under Section 70B of IT Act mandate reporting of cybersecurity incidents within <strong>6 hours</strong> of discovery.
          <br>
          <div style="margin-top:8px; display:flex; gap:15px; align-items:center; flex-wrap:wrap;">
            <span>Unreported incidents: <strong>${criticals}</strong></span>
            <span>Target SLA: <strong style="color:#ff2d55;">6 Hours</strong></span>
            <span style="background:rgba(255,45,85,0.1); border:1px solid var(--color-critical); padding:2px 6px; border-radius:4px; font-weight:700; color:var(--color-critical);">
              SLA Countdown: 3h 14m remaining
            </span>
          </div>
          <button class="btn btn-outline" style="margin-top:10px; font-size:0.7rem; padding:4px 10px; height:28px; cursor:pointer;" onclick="window.downloadCERTInReport()">
            📥 Export CERT-In Incident Form XML/PDF
          </button>
        </div>
      </div>

      <div class="compliance-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
        <div class="compliance-item" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 12px;">
          <div class="compliance-name" style="font-weight: 600; color: var(--text-primary); font-size: 0.75rem;">CERT-In SLA Compliance</div>
          <div class="compliance-score" style="color:${certInColor}; font-size: 1.1rem; font-weight: 700; margin-top: 4px;">${compliance.cert_in}%</div>
          <div class="compliance-bar-wrap" style="background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px;">
            <div class="compliance-bar" style="width:${compliance.cert_in}%; background:${certInColor}; height: 100%;"></div>
          </div>
          <div style="font-size:0.65rem; color:var(--text-secondary); margin-top:6px;">
            Section 70B incident reporting SLA tracking.
          </div>
        </div>

        <div class="compliance-item" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 12px;">
          <div class="compliance-name" style="font-weight: 600; color: var(--text-primary); font-size: 0.75rem;">DPDP Act 2023 (Data Protection)</div>
          <div class="compliance-score" style="color:${dpdpColor}; font-size: 1.1rem; font-weight: 700; margin-top: 4px;">${compliance.dpdp_act}%</div>
          <div class="compliance-bar-wrap" style="background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px;">
            <div class="compliance-bar" style="width:${compliance.dpdp_act}%; background:${dpdpColor}; height: 100%;"></div>
          </div>
          <div style="font-size:0.65rem; color:var(--text-secondary); margin-top:6px;">
            PII data classification & breach notification controls.
          </div>
        </div>

        <div class="compliance-item" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 12px;">
          <div class="compliance-name" style="font-weight: 600; color: var(--text-primary); font-size: 0.75rem;">ISO 27001 Information Security</div>
          <div class="compliance-score" style="color:${isoColor}; font-size: 1.1rem; font-weight: 700; margin-top: 4px;">${compliance.iso_27001}%</div>
          <div class="compliance-bar-wrap" style="background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px;">
            <div class="compliance-bar" style="width:${compliance.iso_27001}%; background:${isoColor}; height: 100%;"></div>
          </div>
          <div style="font-size:0.65rem; color:var(--text-secondary); margin-top:6px;">
            Audit logs persistence and access control parameters.
          </div>
        </div>

        <div class="compliance-item" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 12px;">
          <div class="compliance-name" style="font-weight: 600; color: var(--text-primary); font-size: 0.75rem;">NIST CSF Cyber Defense Framework</div>
          <div class="compliance-score" style="color:${nistColor}; font-size: 1.1rem; font-weight: 700; margin-top: 4px;">${compliance.nist_csf}%</div>
          <div class="compliance-bar-wrap" style="background: rgba(255,255,255,0.1); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px;">
            <div class="compliance-bar" style="width:${compliance.nist_csf}%; background:${nistColor}; height: 100%;"></div>
          </div>
          <div style="font-size:0.65rem; color:var(--text-secondary); margin-top:6px;">
            Maturity level of detection and autonomous response systems.
          </div>
        </div>
      </div>
    </div>

    <div style="text-align:center;padding:20px 0;color:#4a5a7a;font-size:0.65rem;border-top:1px solid rgba(255,255,255,0.06);margin-top:24px">
      Generated by NIRAVAN Autonomous Cybersecurity Intelligence Platform v2.4 ENTERPRISE<br>
      This report is confidential and intended for authorized security personnel only.
    </div>`;
}

let currentReportTab = 'exec';

window.switchReportsTab = function(tabName) {
  currentReportTab = tabName;
  
  // Update button active states
  const tabs = ['exec', 'econ', 'graph'];
  tabs.forEach(t => {
    const btn = document.getElementById(`report-tab-${t}`);
    if (btn) {
      if (t === tabName) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    }
  });
  
  // Update content container visibility
  const containers = {
    'exec': 'report-document',
    'econ': 'report-economics',
    'graph': 'report-graph'
  };
  
  Object.keys(containers).forEach(k => {
    const el = document.getElementById(containers[k]);
    if (el) {
      if (k === tabName) {
        el.style.display = 'block';
      } else {
        el.style.display = 'none';
      }
    }
  });
  
  // Trigger data load
  window.regenerateActiveReportTab();
};

window.regenerateActiveReportTab = function() {
  if (currentReportTab === 'exec') {
    generateReport();
  } else if (currentReportTab === 'econ') {
    window.loadEconomicsData();
  } else if (currentReportTab === 'graph') {
    window.loadKnowledgeGraphData();
  }
};

window.loadEconomicsData = async function() {
  const riskExposureEl = document.getElementById('econ-risk-exposure');
  const patchCostEl = document.getElementById('econ-patch-cost');
  const breachImpactEl = document.getElementById('econ-breach-impact');
  const tableBody = document.querySelector('#econ-assets-table tbody');
  
  if (tableBody) {
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted);">Loading economics stats...</td></tr>`;
  }
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/economics/stats`, {
      headers: headers
    });
    if (res.ok) {
      const data = await res.json();
      
      // Update KPIs formatted as Indian Rupees
      const formatRupees = (val) => new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 }).format(val);
      if (riskExposureEl) riskExposureEl.textContent = formatRupees(data.total_risk_exposure);
      if (patchCostEl) patchCostEl.textContent = formatRupees(data.total_patch_cost);
      if (breachImpactEl) breachImpactEl.textContent = formatRupees(data.total_breach_impact);
      
      if (tableBody) {
        if (!data.assets || data.assets.length === 0) {
          tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted);">No asset economics data found</td></tr>`;
        } else {
          tableBody.innerHTML = data.assets.map(a => {
            const riskColor = a.risk_score >= 75 ? '#ff3b30' : (a.risk_score >= 50 ? '#ffd60a' : '#30d158');
            return `<tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
              <td style="padding: 8px;">🖥️ ${a.name}</td>
              <td style="padding: 8px; font-family: monospace;">${a.ip}</td>
              <td style="padding: 8px;"><span class="severity-badge ${a.criticality.toLowerCase()}" style="font-size:0.55rem;">${a.criticality.toUpperCase()}</span></td>
              <td style="padding: 8px; font-weight:700; color:${riskColor};">${a.risk_score}</td>
              <td style="padding: 8px; font-weight:600; color:#ffd60a;">${formatRupees(a.patch_cost)}</td>
              <td style="padding: 8px; font-weight:600; color:#30d158;">${formatRupees(a.potential_impact)}</td>
              <td style="padding: 8px; font-weight:700; color:#ff3b30;">${formatRupees(a.risk_exposure)}</td>
            </tr>`;
          }).join('');
        }
      }
    }
  } catch (err) {
    console.error("Error loading economics stats:", err);
  }
};

window.loadKnowledgeGraphData = async function(query = "") {
  const nodesTable = document.querySelector('#graph-nodes-table tbody');
  const edgesTable = document.querySelector('#graph-edges-table tbody');
  
  if (nodesTable) nodesTable.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:10px; color:var(--text-muted);">Loading graph nodes...</td></tr>`;
  if (edgesTable) edgesTable.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:10px; color:var(--text-muted);">Loading graph edges...</td></tr>`;
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    let url = `${window.API_URL || '/api/v1'}/knowledge-graph`;
    if (query) {
      url += `?query=${encodeURIComponent(query)}`;
    }
    const res = await fetch(url, {
      headers: headers
    });
    if (res.ok) {
      const data = await res.json();
      
      if (nodesTable) {
        if (!data.nodes || data.nodes.length === 0) {
          nodesTable.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:10px; color:var(--text-muted);">No graph nodes found</td></tr>`;
        } else {
          nodesTable.innerHTML = data.nodes.map(n => {
            const riskColor = n.risk_weight >= 75 ? '#ff3b30' : (n.risk_weight >= 50 ? '#ffd60a' : '#30d158');
            return `<tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
              <td style="padding: 4px; font-weight:700; color:var(--tn-gold);">${n.entity_type}</td>
              <td style="padding: 4px; font-family:monospace; font-size:0.6rem; max-width:80px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${n.entity_id}">${n.entity_id}</td>
              <td style="padding: 4px; max-width:100px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${n.name}">${n.name}</td>
              <td style="padding: 4px; font-weight:700; color:${riskColor};">${n.risk_weight}</td>
            </tr>`;
          }).join('');
        }
      }
      
      if (edgesTable) {
        if (!data.edges || data.edges.length === 0) {
          edgesTable.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:10px; color:var(--text-muted);">No graph edges found</td></tr>`;
        } else {
          edgesTable.innerHTML = data.edges.map(e => {
            return `<tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
              <td style="padding: 4px; max-width:70px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${e.source_type}:${e.source_id}">${e.source_type}:${e.source_id.split('@')[0]}</td>
              <td style="padding: 4px; max-width:70px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${e.target_type}:${e.target_id}">${e.target_type}:${e.target_id.split('@')[0]}</td>
              <td style="padding: 4px; font-weight:600; color:#5856d6;">${e.relationship.toUpperCase()}</td>
              <td style="padding: 4px; font-family:monospace;">${e.weight}</td>
            </tr>`;
          }).join('');
        }
      }
    }
  } catch (err) {
    console.error("Error loading knowledge graph data:", err);
  }
};

window.downloadCERTInReport = function() {
  const onboardedDept = localStorage.getItem("NIRAVAN_DEPT_NAME") || "TN Government Office";
  const onboardedDist = localStorage.getItem("NIRAVAN_DISTRICT") || "Chennai";
  
  const reportData = {
    reporter: {
      organization: onboardedDept,
      district: onboardedDist,
      state: "Tamil Nadu, India",
      role: "Cybersecurity Coordinator"
    },
    incident: {
      type: "Ransomware & Unauthorized Access Attempt",
      severity: "CRITICAL",
      discovery_time: new Date().toISOString(),
      obligatory_reporting_sla: "6 hours (IT Act Sec 70B)",
      nciipc_status: "Critical Information Infrastructure Alert raised"
    },
    payload: {
      source_ips: ["185.220.101.47"],
      affected_hosts: ["WIN-DC-01", "PROD-DB-01"],
      impact: "Attempted shadow copy deletion and SQL injection telemetry detected"
    }
  };

  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `cert_in_report_${onboardedDept.replace(/\s+/g, '_')}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  
  showToast("CERT-TN Compliance incident dossier downloaded successfully.", "good");
};

// ── Settings ──
// ── Settings ──
function renderSettings() {
  window.switchSettingsTab('config');
}

function switchSettingsTab(tabName) {
  const tabs = ['config', 'audit-logs', 'auth-logs', 'api-logs'];
  tabs.forEach(t => {
    const btn = document.getElementById(`settings-tab-${t}`);
    if (btn) {
      if (t === tabName) {
        btn.classList.add('active');
        btn.style.background = 'rgba(255,255,255,0.03)';
        btn.style.color = 'var(--text-primary)';
      } else {
        btn.classList.remove('active');
        btn.style.background = 'transparent';
        btn.style.color = 'var(--text-secondary)';
      }
    }
  });
  renderSettingsSubpage(tabName);
}

function renderSettingsSubpage(tabName) {
  const role = localStorage.getItem('niravan_user_role') || 'viewer';
  
  if (tabName === 'config') {
    renderConfigSettings();
    return;
  }
  
  const pane = document.getElementById('settings-content-pane');
  if (!pane) return;
  
  if (role !== 'admin') {
    pane.innerHTML = `
      <div class="glass-card" style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:300px;text-align:center;padding:40px;border:1px solid rgba(255,45,85,0.15);background:rgba(255,45,85,0.02);box-shadow:0 12px 40px rgba(255,45,85,0.05);margin-top:10px;">
        <span style="font-size:3rem;filter:drop-shadow(0 0 10px rgba(255,45,85,0.4));margin-bottom:16px;">🛑</span>
        <h2 style="font-family:'Space Grotesk',sans-serif;font-size:1.4rem;font-weight:700;color:var(--text-primary);margin-bottom:8px;">Access Denied</h2>
        <p style="font-size:0.75rem;color:var(--text-muted);max-width:320px;line-height:1.5;">This control panel contains audited security ledger records. Access is strictly restricted to accounts with the <strong>ADMIN</strong> role.</p>
        <div style="margin-top:20px;font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);background:rgba(255,255,255,0.02);padding:6px 12px;border-radius:4px;border:1px solid rgba(255,255,255,0.05);">
          CURRENT ROLE: ${role.toUpperCase()} · REQUIRED: ADMIN
        </div>
      </div>
    `;
    return;
  }
  
  if (tabName === 'audit-logs') {
    renderSecurityAuditLogs();
  } else if (tabName === 'auth-logs') {
    renderAuthenticationLogs();
  } else if (tabName === 'api-logs') {
    renderAPIAccessLogs();
  }
}

function renderConfigSettings() {
  const pane = document.getElementById('settings-content-pane');
  if (!pane) return;
  
  pane.innerHTML = `
    <div class="settings-grid" id="settings-config-grid">
      <div class="glass-card settings-card">
        <h2 class="settings-section-title">Data Collection Sources</h2>
        <div class="settings-list" id="settings-sources"></div>
      </div>
      <div class="glass-card settings-card">
        <h2 class="settings-section-title">Alert Thresholds</h2>
        <div class="settings-list" id="settings-thresholds"></div>
      </div>
      <div class="glass-card settings-card">
        <h2 class="settings-section-title">Notification Channels</h2>
        <div class="settings-list" id="settings-notifications"></div>
      </div>
      <div class="glass-card settings-card">
        <h2 class="settings-section-title">NIRAVAN AI Configuration</h2>
        <div class="settings-list" id="settings-ai"></div>
      </div>
    </div>
  `;

  const sourcesEl = document.getElementById('settings-sources');
  if(sourcesEl) {
    const sources = [
      { label:'Windows Event Logs',        sub:'4,231 events/sec', on:true },
      { label:'Network Flow Data (NetFlow)',sub:'12.4 Gbps monitored', on:true },
      { label:'Firewall Logs',             sub:'Palo Alto PAN-OS 11.0', on:true },
      { label:'Cloud Security (AWS/Azure)',sub:'34 cloud accounts', on:true },
      { label:'Endpoint EDR Telemetry',    sub:'247 endpoints', on:true },
      { label:'Threat Intelligence Feeds', sub:'34 external feeds', on:true },
      { label:'Email Security Gateway',    sub:'Microsoft 365 Defender', on:true },
      { label:'DNS Query Logs',            sub:'2.1M queries/hour', on:false },
    ];
    sourcesEl.innerHTML = sources.map(s => `
      <div class="setting-item">
        <div><div class="setting-label">${s.label}</div><div class="setting-sub">${s.sub}</div></div>
        <div class="toggle-switch ${s.on?'on':''}" onclick="this.classList.toggle('on')"></div>
      </div>`).join('');
  }

  const threshEl = document.getElementById('settings-thresholds');
  if(threshEl) {
    const thresholds = [
      { label:'Brute Force Threshold',    sub:'Failed attempts before alert' },
      { label:'Data Volume Alert (MB)',   sub:'Outbound transfer limit' },
      { label:'Anomaly Score Cutoff',     sub:'User behavior deviation' },
      { label:'QRI Critical Level',       sub:'Risk index alert threshold' },
    ];
    threshEl.innerHTML = thresholds.map(t => `
      <div class="setting-item" style="flex-direction:column;align-items:flex-start;gap:8px">
        <div><div class="setting-label">${t.label}</div><div class="setting-sub">${t.sub}</div></div>
        <input type="range" class="setting-slider" min="1" max="100" value="${randomInt(30,70)}" style="width:100%">
      </div>`).join('');
  }

  const notifEl = document.getElementById('settings-notifications');
  if(notifEl) {
    const notifs = [
      { label:'Email Alerts (Critical)',  sub:'security@corp.com', on:true },
      { label:'SMS Notifications',        sub:'+1-555-0192 (SOC Lead)', on:true },
      { label:'Slack Integration',        sub:'#security-alerts channel', on:true },
      { label:'PagerDuty Escalation',     sub:'24/7 on-call rotation', on:false },
      { label:'Microsoft Teams',          sub:'SOC Operations channel', on:true },
      { label:'SIEM Integration',         sub:'Splunk Enterprise Security', on:false },
    ];
    notifEl.innerHTML = notifs.map(n => `
      <div class="setting-item">
        <div><div class="setting-label">${n.label}</div><div class="setting-sub">${n.sub}</div></div>
        <div class="toggle-switch ${n.on?'on':''}" onclick="this.classList.toggle('on')"></div>
      </div>`).join('');
  }

  const aiEl = document.getElementById('settings-ai');
  if(aiEl) {
    const aiSettings = [
      { label:'Autonomous Response Mode',     sub:'Auto-contain critical threats', on:true },
      { label:'Plain-Language Explanations',  sub:'AI-generated event descriptions', on:true },
      { label:'Predictive Threat Analysis',   sub:'Attack path prediction engine', on:true },
      { label:'Neural Correlation Engine',    sub:'Multi-event incident chaining', on:true },
      { label:'Attack DNA Fingerprinting',    sub:'Attacker pattern recognition', on:true },
      { label:'Zero-Day Behavioral Radar',    sub:'Unknown threat pattern detection', on:false },
    ];
    aiEl.innerHTML = aiSettings.map(s => `
      <div class="setting-item">
        <div><div class="setting-label">${s.label}</div><div class="setting-sub">${s.sub}</div></div>
        <div class="toggle-switch ${s.on?'on':''}" onclick="this.classList.toggle('on')"></div>
      </div>`).join('');
  }
}

async function renderSecurityAuditLogs() {
  const pane = document.getElementById('settings-content-pane');
  if (!pane) return;
  
  pane.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:200px;">
      <div class="ai-spinner"></div>
    </div>
  `;
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      await window.syncFromBackend();
    } catch (e) {
      console.error(e);
    }
  }
  
  const audits = window.NIRAVAN_DATA.auditLogs || [];
  const adminActions = window.NIRAVAN_DATA.adminActions || [];
  
  let auditRows = audits.map(a => `
    <tr>
      <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${new Date(a.timestamp).toLocaleString()}</td>
      <td style="color:#00d4ff;font-weight:600;">${a.user_email}</td>
      <td><span class="severity-badge medium" style="font-size:0.55rem;padding:2px 6px;">${a.action}</span></td>
      <td style="color:var(--text-secondary);font-size:0.7rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${a.detail}">${a.detail}</td>
      <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${a.ip_address}</td>
    </tr>
  `).join('');
  
  if (!auditRows) {
    auditRows = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">No platform audit logs recorded.</td></tr>`;
  }
  
  let adminRows = adminActions.map(aa => `
    <tr>
      <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${new Date(aa.timestamp).toLocaleString()}</td>
      <td style="color:#ff2d55;font-weight:600;">${aa.admin_email}</td>
      <td><span class="severity-badge critical" style="font-size:0.55rem;padding:2px 6px;">${aa.action}</span></td>
      <td style="color:var(--text-secondary);font-size:0.7rem;">${aa.target_user || 'N/A'}</td>
      <td style="color:var(--text-muted);font-size:0.68rem;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${aa.details}">${aa.details}</td>
    </tr>
  `).join('');
  
  if (!adminRows) {
    adminRows = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:20px;">No admin action logs recorded.</td></tr>`;
  }
  
  pane.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:20px;height:100%;">
      <!-- General Audit Logs -->
      <div class="glass-card" style="padding:20px;display:flex;flex-direction:column;gap:12px;flex:1;min-height:240px;overflow:hidden;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h2 class="settings-section-title" style="margin:0;">🛡️ General Platform Audit Log</h2>
          <span style="font-size:0.6rem;background:rgba(0,212,255,0.1);color:var(--accent-blue);padding:2px 8px;border-radius:4px;font-weight:700;">TAMPER-RESISTANT</span>
        </div>
        <div style="flex:1;overflow-y:auto;border:1px solid rgba(255,255,255,0.03);border-radius:4px;">
          <table class="data-table" style="width:100%;border-collapse:collapse;text-align:left;">
            <thead>
              <tr>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Timestamp</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">User</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Action</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Detail</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">IP Address</th>
              </tr>
            </thead>
            <tbody>
              ${auditRows}
            </tbody>
          </table>
        </div>
      </div>
      
      <!-- Admin Action Logs -->
      <div class="glass-card" style="padding:20px;display:flex;flex-direction:column;gap:12px;flex:1;min-height:240px;overflow:hidden;">
        <h2 class="settings-section-title" style="margin:0;">👑 Admin Administrative Action Log</h2>
        <div style="flex:1;overflow-y:auto;border:1px solid rgba(255,255,255,0.03);border-radius:4px;">
          <table class="data-table" style="width:100%;border-collapse:collapse;text-align:left;">
            <thead>
              <tr>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Timestamp</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Administrator</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Action</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Target</th>
                <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Action Details</th>
              </tr>
            </thead>
            <tbody>
              ${adminRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function renderAuthenticationLogs() {
  const pane = document.getElementById('settings-content-pane');
  if (!pane) return;
  
  pane.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:200px;">
      <div class="ai-spinner"></div>
    </div>
  `;
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      await window.syncFromBackend();
    } catch (e) {
      console.error(e);
    }
  }
  
  const loginLogs = window.NIRAVAN_DATA.loginLogs || [];
  
  let rows = loginLogs.map(l => {
    const statusText = l.success ? 'SUCCESS' : 'FAILED';
    const statusColor = l.success ? '#30d158' : '#ff2d55';
    const reasonText = l.reason ? `(${l.reason})` : '';
    
    return `
      <tr>
        <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${new Date(l.timestamp).toLocaleString()}</td>
        <td style="color:var(--text-primary);font-weight:600;">${l.email}</td>
        <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${l.ip_address}</td>
        <td style="color:${statusColor};font-weight:700;font-size:0.65rem;">${statusText} <span style="font-size:0.58rem;font-weight:normal;color:var(--text-muted);">${reasonText}</span></td>
      </tr>
    `;
  }).join('');
  
  if (!rows) {
    rows = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:20px;">No login attempts recorded.</td></tr>`;
  }
  
  pane.innerHTML = `
    <div class="glass-card" style="padding:20px;display:flex;flex-direction:column;gap:12px;height:100%;overflow:hidden;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h2 class="settings-section-title" style="margin:0;">🔑 Authentication Attempts Log</h2>
        <span style="font-size:0.6rem;background:rgba(48,209,88,0.1);color:var(--accent-green);padding:2px 8px;border-radius:4px;font-weight:700;">LOCKOUT MONITORED</span>
      </div>
      <div style="flex:1;overflow-y:auto;border:1px solid rgba(255,255,255,0.03);border-radius:4px;">
        <table class="data-table" style="width:100%;border-collapse:collapse;text-align:left;">
          <thead>
            <tr>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Timestamp</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Security Email</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">IP Address</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Auth Status</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function renderAPIAccessLogs() {
  const pane = document.getElementById('settings-content-pane');
  if (!pane) return;
  
  pane.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;height:100%;min-height:200px;">
      <div class="ai-spinner"></div>
    </div>
  `;
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      await window.syncFromBackend();
    } catch (e) {
      console.error(e);
    }
  }
  
  const apiLogs = window.NIRAVAN_DATA.apiLogs || [];
  
  let rows = apiLogs.map(l => {
    const statusColor = l.status_code >= 400 ? '#ff2d55' : l.status_code >= 300 ? '#ffd60a' : '#30d158';
    const methodColor = { 'GET': '#30d158', 'POST': '#00d4ff', 'PUT': '#ffd60a', 'DELETE': '#ff2d55' }[l.method] || 'var(--text-primary)';
    
    return `
      <tr>
        <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${new Date(l.timestamp).toLocaleString()}</td>
        <td style="color:var(--text-primary);font-weight:600;font-size:0.68rem;">${l.user_email || 'Unauthenticated'}</td>
        <td style="font-family:var(--font-mono);font-weight:700;font-size:0.65rem;color:${methodColor};">${l.method}</td>
        <td style="font-family:var(--font-mono);font-size:0.68rem;color:#7fdbff;">${l.path}</td>
        <td style="color:${statusColor};font-weight:700;font-family:var(--font-mono);font-size:0.68rem;">${l.status_code}</td>
        <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);">${l.ip_address}</td>
      </tr>
    `;
  }).join('');
  
  if (!rows) {
    rows = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">No API traffic logs recorded.</td></tr>`;
  }
  
  pane.innerHTML = `
    <div class="glass-card" style="padding:20px;display:flex;flex-direction:column;gap:12px;height:100%;overflow:hidden;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h2 class="settings-section-title" style="margin:0;">🌐 API Endpoint Interceptor traffic</h2>
        <span style="font-size:0.6rem;background:rgba(191,90,242,0.1);color:#bf5af2;padding:2px 8px;border-radius:4px;font-weight:700;">ROUTE INTERCEPTOR</span>
      </div>
      <div style="flex:1;overflow-y:auto;border:1px solid rgba(255,255,255,0.03);border-radius:4px;">
        <table class="data-table" style="width:100%;border-collapse:collapse;text-align:left;">
          <thead>
            <tr>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Timestamp</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Initiating Identity</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Method</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Endpoint Path</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">HTTP Code</th>
              <th style="padding:10px 12px;font-size:0.65rem;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.06);">Client Host IP</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// ── Toast Notifications ──
function showToast(message, type = 'medium') {
  const container = document.getElementById('toast-container');
  if(!container) return;

  const icons = { critical:'🔴', high:'🟠', medium:'🟡', good:'✅', info:'ℹ️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type]||'ℹ️'}</span><span class="toast-msg">${message}</span><span class="toast-close" onclick="this.parentElement.remove()">✕</span>`;
  container.appendChild(toast);

  // Auto-remove
  setTimeout(() => {
    toast.style.animation = 'toast-out 0.3s ease-out forwards';
    setTimeout(() => toast.remove(), 300);
  }, 6000);
}

// Add toast-out animation
const toastOutStyle = document.createElement('style');
toastOutStyle.textContent = '@keyframes toast-out{to{opacity:0;transform:translateX(20px)}}';
document.head.appendChild(toastOutStyle);

console.log('[NIRAVAN] Application controller initialized — all systems go');

// ══════════════════════════════════════════════════
// ROADMAP PAGE RENDERER
// ══════════════════════════════════════════════════
function renderRoadmap() {
  renderPhases();
  renderTechStack();
}

const ROADMAP_PHASES = [
  {
    num: 'PHASE 1',
    icon: '📊',
    name: 'Knowledge Graph Engine',
    desc: 'Build a security relationship database linking Users, Assets, Vulnerabilities, IOCs, Incidents, Cases, and Threat Actors for blast radius analysis and attack path prediction.',
    items: ['Entity Relation Store', 'Blast Radius Analyzer', 'Attack Path Predictor', 'Threat Correlation Maps'],
    timeline: '4–6 weeks',
    color: '#00d4ff',
    progress: 15,
    current: true
  },
  {
    num: 'PHASE 2',
    icon: '🔗',
    name: 'Correlation Engine V2',
    desc: 'Chain telemetry stages (Recon → Credential Attack → Execution → Persistence → Privilege Escalation → Lateral Movement) into unified campaigns like a senior SOC analyst.',
    items: ['Attack Chain Linking', 'Campaign Correlation', 'MITRE ATT&CK Chaining', 'Anomaly Sequence Graph'],
    timeline: '6–10 weeks',
    color: '#bf5af2',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 3',
    icon: '🔌',
    name: 'Real Telemetry Ingest',
    desc: 'Ingest direct feeds from Windows (Security Events, Sysmon, Defender, PowerShell), Linux (Syslog, Auditd, Auth Logs), Web (Nginx, Apache, IIS), and Cloud (CloudTrail, Azure, GCP).',
    items: ['Syslog & Sysmon Parsers', 'Windows/Linux Collectors', 'Web Service Log Ingestion', 'Cloud Audit Logs Hub'],
    timeline: '10–14 weeks',
    color: '#ff6b35',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 4',
    icon: '⚙️',
    name: 'Detection Engineering',
    desc: 'Support Sigma Rules (rule parser, execution, editor, dry-run testing) and build a Detection Library targeting brute force, credential theft, persistence, and exfiltration.',
    items: ['Sigma Parser & Run', 'Sigma Rule Editor', 'Threat Detection Library', 'Rule Testing Console'],
    timeline: '14–18 weeks',
    color: '#ffd60a',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 5',
    icon: '🌐',
    name: 'ASM Layer',
    desc: 'Perform selective external discovery of assets (subdomains, DNS, SSL, ports, services) and public exposure risk analysis (weak services, certificate risks).',
    items: ['External Asset Scan', 'Subdomain/DNS Discovery', 'SSL & Certificate Risks', 'Public Exposure Map'],
    timeline: '18–22 weeks',
    color: '#ff2d80',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 6',
    icon: '🏥',
    name: 'Vulnerability Intel',
    desc: 'Integrate dynamic results from Nuclei, OpenVAS, ZAP, and Trivy. Explain business impact, prioritize key risks, and justify why they matter.',
    items: ['Tool API Integration', 'Vulnerability Explainer', 'Business Impact Score', 'Remediation Lifecycle'],
    timeline: '22–26 weeks',
    color: '#30d158',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 7',
    icon: '🤖',
    name: 'AI Agent Swarm',
    desc: 'Deploy multiple specialized background agents: Threat Hunter (anomalies), Investigator (timelines), Risk Analyst (business impact), Deception Analyst, and Executive Advisor.',
    items: ['Hunter & Investigator', 'Risk & Deception Agents', 'Board Report Generator', 'Multi-Agent Broker'],
    timeline: '26–30 weeks',
    color: '#ff9f0a',
    progress: 0,
    current: false
  },
  {
    num: 'PHASE 8',
    icon: '🧠',
    name: 'RAG & SOAR Core',
    desc: 'Power the command core with a RAG brain (MITRE, CVE, CISA KEV, cases) and SOAR autonomous mitigation (block, isolate, password resets) under human approval.',
    items: ['RAG Security Knowledge', 'CISA KEV Integration', 'SOAR Control Actions', 'Human Approval Gate'],
    timeline: '30–36 weeks',
    color: '#00d4ff',
    progress: 0,
    current: false
  }
];

function renderPhases() {
  const el = document.getElementById('roadmap-phases');
  if(!el) return;
  el.innerHTML = ROADMAP_PHASES.map(p => `
    <div class="phase-card ${p.current ? 'current' : ''}">
      <span class="phase-num">${p.num}</span>
      <span class="phase-icon">${p.icon}</span>
      <div class="phase-name">${p.name}</div>
      <div class="phase-desc">${p.desc}</div>
      <div class="phase-items">
        ${p.items.map(i => `<div class="phase-item">${i}</div>`).join('')}
      </div>
      <div class="phase-timeline" style="color:${p.color}">
        ⏱ ${p.timeline}
        <div class="phase-bar" style="background:${p.color};width:${p.progress}%;opacity:${p.current?1:0.3}"></div>
      </div>
    </div>`).join('');
}

const TECH_STACK = [
  {
    name: 'Data Layer',
    color: '#00d4ff',
    items: ['Winlogbeat/Filebeat', 'Elastic Stack', 'Apache Kafka', 'AWS CloudWatch', 'Sysmon'],
    bg: 'rgba(0,212,255,0.05)', border: 'rgba(0,212,255,0.2)'
  },
  {
    name: 'Processing',
    color: '#bf5af2',
    items: ['Python / FastAPI', 'Celery Workers', 'Redis Queue', 'Sigma Rule Engine', 'YARA Scanner'],
    bg: 'rgba(191,90,242,0.05)', border: 'rgba(191,90,242,0.2)'
  },
  {
    name: 'AI & ML',
    color: '#ffd60a',
    items: ['LLM (Mistral 7B)', 'RAG Architecture', 'LangChain Agents', 'scikit-learn', 'FAISS Vector DB'],
    bg: 'rgba(255,214,10,0.05)', border: 'rgba(255,214,10,0.2)'
  },
  {
    name: 'Storage',
    color: '#30d158',
    items: ['Elasticsearch', 'PostgreSQL', 'TimescaleDB', 'Redis Cache', 'S3 / MinIO'],
    bg: 'rgba(48,209,88,0.05)', border: 'rgba(48,209,88,0.2)'
  },
  {
    name: 'Frontend',
    color: '#ff6b35',
    items: ['React / Next.js', 'Chart.js / D3.js', 'WebSocket real-time', 'REST & GraphQL APIs', 'PWA / Mobile'],
    bg: 'rgba(255,107,53,0.05)', border: 'rgba(255,107,53,0.2)'
  }
];

function renderTechStack() {
  const el = document.getElementById('tech-stack-grid');
  if(!el) return;
  el.innerHTML = TECH_STACK.map(layer => `
    <div class="tech-layer" style="background:${layer.bg};border:1px solid ${layer.border}">
      <span class="tech-layer-name" style="color:${layer.color}">${layer.name}</span>
      <div class="tech-badges">
        ${layer.items.map(item => `
          <span class="tech-badge" style="background:${layer.color}18;color:${layer.color};border:1px solid ${layer.color}30">${item}</span>
        `).join('')}
      </div>
    </div>`).join('');
}

// ══════════════════════════════════════════════════
// ABOUT / PLATFORM PAGE RENDERER
// ══════════════════════════════════════════════════
function renderPlatform() {
  renderProblemItems();
  renderSolutionItems();
  renderHonestScope();
  renderMarketItems();
}

function renderProblemItems() {
  const el = document.getElementById('problem-items');
  if(!el) return;
  const problems = [
    { icon: '👥', title: 'Security Talent Shortage', desc: 'Organizations face a severe shortage of cybersecurity professionals and cannot hire or afford high-cost dedicated SOC teams.' },
    { icon: '🌊', title: 'Alert Fatigue & Overload', desc: 'Existing security tools produce thousands of noisy alerts but provide limited context, letting critical threats slip through.' },
    { icon: '🐢', title: 'Slow Threat Investigation', desc: 'Investigating complex attack patterns manually is highly time-consuming, leading to delayed response times.' },
    { icon: '🕳️', title: 'Lack of Unified Visibility', desc: 'Security data remains siloed across endpoints, networks, databases, and cloud environments with no correlation.' },
    { icon: '❓', title: 'Difficulty Understanding Threats', desc: 'Technical threat details and complex logs are difficult to interpret without senior analyst intervention.' },
    { icon: '🚨', title: 'Delayed Containment & Response', desc: 'Slow incident escalation and lack of automated playbook guidance lead to increased blast radius during breaches.' },
  ];
  el.innerHTML = problems.map(p => `
    <div class="problem-item">
      <span class="problem-icon">${p.icon}</span>
      <div class="problem-text"><strong>${p.title}</strong>${p.desc}</div>
    </div>`).join('');
}

function renderSolutionItems() {
  const el = document.getElementById('solution-items');
  if(!el) return;
  const solutions = [
    { icon: '🧠', title: 'Autonomous Command Core', desc: 'Acts as a unified AI analyst that correlates logs, detects multi-stage campaigns, and automates initial triage.' },
    { icon: '💬', title: 'Conversational SOC Mentor', desc: 'Explains complex threat tool behavior, CVEs, and compliance risks in clear plain-language text.' },
    { icon: '🕸️', title: 'Deception & Honeypots', desc: 'Deploys active deception networks (SSH, Web, API, Database) to snare attackers early in the reconnaissance phase.' },
    { icon: '🗺️', title: 'MITRE ATT&CK Alignment', desc: 'Automatically maps incidents to MITRE tactics and attributes threats to scanners, bots, or human actors.' },
    { icon: '📋', title: 'Incident to Case Escalation', desc: 'Autonomously elevates high-confidence alerts to cases, updates evidence vaults, and creates detailed audit trails.' },
    { icon: '⚡', title: 'Playbook Containment Scripts', desc: 'Offers step-by-step containment instructions (e.g. host isolation, credential rotation) to minimize incident impact.' },
  ];
  el.innerHTML = solutions.map(s => `
    <div class="solution-item">
      <span class="solution-icon">${s.icon}</span>
      <div class="solution-text"><strong>${s.title}</strong>${s.desc}</div>
    </div>`).join('');
}

function renderHonestScope() {
  const realEl    = document.getElementById('honest-real');
  const plannedEl = document.getElementById('honest-planned');
  if(!realEl || !plannedEl) return;

  const real = [
    '✅ Unified AI Command Core chat',
    '✅ Autonomous Deception Honeypots (SSH, Web, API, Database)',
    '✅ Bot & Scanner Classification Engine',
    '✅ Threat Attribution Engine (Bot/Scanner/Human/APT/Insider)',
    '✅ Threat Tool Intel Knowledge base (Mimikatz, SQLMap, etc.)',
    '✅ MITRE ATT&CK technique mapping',
    '✅ Playbook Guidance & Containment scripts',
    '✅ EDR Host containment & cases workflow',
    '✅ Stand-alone offline simulation fallback',
    '✅ Quantum Risk Indexing & QRI trends',
    '✅ Case Management & Evidence Vaults',
    '✅ Enterprise security audits & Lockouts',
  ];

  const planned = [
    '🔜 Phase 1: Knowledge Graph Engine (Critical Priority)',
    '🔜 Phase 2: Correlation Engine V2 (Multi-stage attack chaining)',
    '🔜 Phase 3: Real Telemetry Ingestion (Windows, Linux, Web, Cloud)',
    '🔜 Phase 4: Detection Engineering (Sigma rules engine & parser)',
    '🔜 Phase 5: Attack Surface Management (ASM) Layer',
    '🔜 Phase 6: Vulnerability Intelligence (Nuclei/OpenVAS explainers)',
    '🔜 Phase 7: AI Agent Swarm (Specialized Hunter/Investigator)',
    '🔜 Phase 8: RAG Security Brain & SOAR (Containment blocks)',
  ];

  realEl.innerHTML    = real.map(i    => `<div class="honest-item real">${i}</div>`).join('');
  plannedEl.innerHTML = planned.map(i => `<div class="honest-item planned">${i}</div>`).join('');
}

function renderMarketItems() {
  const el = document.getElementById('market-items');
  if(!el) return;
  const markets = [
    { icon: '🏫', title: 'Educational Institutions', desc: 'Universities, colleges, and schools managing sensitive student data with limited IT security budgets.' },
    { icon: '🏛️', title: 'Government & Public Sector', desc: 'Local and state government offices lacking dedicated SOC teams but managing critical citizen data.' },
    { icon: '🏥', title: 'Healthcare Organizations', desc: 'Hospitals and clinics facing ransomware epidemics, HIPAA compliance, and legacy infrastructure.' },
    { icon: '🏢', title: 'SME Enterprises', desc: 'Small-to-medium businesses that need enterprise-grade security without enterprise-grade budgets.' },
    { icon: '🏦', title: 'Financial Services', desc: 'Credit unions, regional banks, and fintech startups needing PCI-DSS compliance and fraud detection.' },
  ];
  el.innerHTML = markets.map(m => `
    <div class="market-item">
      <span class="market-icon">${m.icon}</span>
      <div class="market-text"><strong>${m.title}</strong>${m.desc}</div>
    </div>`).join('');
}

// ── CISA KEV Real Data (Static snapshot — production would fetch live) ──
// Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
const REAL_CISA_KEV = [
  { id: 'CVE-2024-3400', vendor: 'Palo Alto', product: 'PAN-OS GlobalProtect', dateAdded: '2024-04-12', dueDate: '2024-04-19', notes: 'OS command injection via GlobalProtect feature. CVSS 10.0. Actively exploited in the wild.' },
  { id: 'CVE-2024-21762', vendor: 'Fortinet', product: 'FortiOS/FortiProxy', dateAdded: '2024-02-09', dueDate: '2024-02-16', notes: 'Out-of-bounds write allowing unauthenticated RCE via HTTP. CVSS 9.6. Nation-state exploitation confirmed.' },
  { id: 'CVE-2023-46805', vendor: 'Ivanti', product: 'Connect Secure/Policy Secure', dateAdded: '2024-01-10', dueDate: '2024-01-22', notes: 'Authentication bypass allowing access to restricted resources. Chained with CVE-2024-21887.' },
  { id: 'CVE-2024-1709',  vendor: 'ConnectWise', product: 'ScreenConnect', dateAdded: '2024-02-22', dueDate: '2024-02-29', notes: 'Authentication bypass allowing unauthenticated RCE. Exploited within 48h of disclosure.' },
  { id: 'CVE-2024-6387',  vendor: 'OpenSSH', product: 'OpenSSH Server', dateAdded: '2024-07-01', dueDate: '2024-07-22', notes: 'regreSSHion: Race condition RCE without auth. Affects millions of Linux servers globally.' },
  { id: 'CVE-2024-29988', vendor: 'Microsoft', product: 'Windows SmartScreen', dateAdded: '2024-04-09', dueDate: '2024-04-30', notes: 'Security feature bypass actively used in phishing campaigns with .zip file delivery.' },
  { id: 'CVE-2023-44487', vendor: 'IETF/Various', product: 'HTTP/2 Protocol', dateAdded: '2023-10-10', dueDate: '2023-10-31', notes: 'HTTP/2 Rapid Reset DDoS attack. Exploited at 398 million requests/second. All HTTP/2 servers affected.' },
  { id: 'CVE-2024-49138', vendor: 'Microsoft', product: 'Windows CLFS Driver', dateAdded: '2024-12-10', dueDate: '2024-12-31', notes: 'Heap-based buffer overflow enabling local privilege escalation to SYSTEM. Patch Tuesday Dec 2024.' },
];

// Make accessible globally for intelligence page
window.NIRAVAN_DATA.cisaKev = REAL_CISA_KEV;

// ── Authentication & RBAC Handlers ──
window.handleLoginSubmit = async function() {
  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  if (!emailInput || !passwordInput) return;

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('niravan_token', data.token);
        localStorage.setItem('niravan_user_email', data.email);
        localStorage.setItem('niravan_user_role', data.role);
        
        showToast(`Welcome back, ${data.role}! Authenticated successfully.`, 'good');
        hideLoginScreen();
        
        await window.syncFromBackend();
        navigateTo('dashboard');
      } else {
        const err = await res.json();
        showToast(`⚠️ Decryption Failed: ${err.detail || 'Invalid credentials'}`, 'critical');
      }
    } catch(e) {
      console.error("[NIRAVAN] Auth server connection failure:", e);
      showToast('⚠️ Connection Failed. Authenticating in Simulation Mode...', 'medium');
      
      let role = 'analyst';
      if (email.includes('admin')) role = 'admin';
      if (email.includes('viewer')) role = 'viewer';

      localStorage.setItem('niravan_token', 'mock_simulation_jwt_token_2026');
      localStorage.setItem('niravan_user_email', email);
      localStorage.setItem('niravan_user_role', role);

      showToast(`Welcome, ${role}! Authenticated in simulation mode.`, 'good');
      hideLoginScreen();
      navigateTo('dashboard');
    }
  } else {
    let role = 'analyst';
    if (email.includes('admin')) role = 'admin';
    if (email.includes('viewer')) role = 'viewer';

    localStorage.setItem('niravan_token', 'mock_simulation_jwt_token_2026');
    localStorage.setItem('niravan_user_email', email);
    localStorage.setItem('niravan_user_role', role);

    showToast(`Welcome, ${role}! Authenticated in simulation mode.`, 'good');
    hideLoginScreen();
    navigateTo('dashboard');
  }
};

window.autofillLogin = function(email, password) {
  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  if (emailInput && passwordInput) {
    emailInput.value = email;
    passwordInput.value = password;
    showToast("Autofilled demo credentials. Authenticating...", "info");
    window.handleLoginSubmit();
  }
};

window.handleLogout = function() {
  localStorage.removeItem('niravan_token');
  localStorage.removeItem('niravan_user_email');
  localStorage.removeItem('niravan_user_role');
  showToast('Logged out of security enclave.', 'medium');
  showLoginScreen();
};

function showLoginScreen() {
  const overlay = document.getElementById('login-screen');
  if (overlay) overlay.style.display = 'flex';
  const profileCard = document.getElementById('user-profile-card');
  if (profileCard) profileCard.style.display = 'none';
}

function hideLoginScreen() {
  const overlay = document.getElementById('login-screen');
  if (overlay) overlay.style.display = 'none';
  
  // Show profile card in sidebar
  const email = localStorage.getItem('niravan_user_email') || 'user@niravan.ai';
  const role = localStorage.getItem('niravan_user_role') || 'analyst';
  
  const profileCard = document.getElementById('user-profile-card');
  if (profileCard) profileCard.style.display = 'flex';
  
  const emailEl = document.getElementById('user-email');
  if (emailEl) emailEl.textContent = email;
  
  const roleEl = document.getElementById('user-role-badge');
  if (roleEl) {
    roleEl.textContent = role;
    if (role === 'admin') {
      roleEl.style.background = 'rgba(255,45,85,0.15)';
      roleEl.style.color = '#ff2d55';
    } else if (role === 'viewer') {
      roleEl.style.background = 'rgba(48,209,88,0.15)';
      roleEl.style.color = '#30d158';
    } else {
      roleEl.style.background = 'rgba(0,212,255,0.15)';
      roleEl.style.color = '#00d4ff';
    }
  }

  // Trigger Onboarding Wizard if not completed
  if (window.initOnboardingWizard) {
    window.initOnboardingWizard();
  }
  if (window.updateDistrictBadge) {
    window.updateDistrictBadge();
  }
}

// Check auth state on start
function checkAuthState() {
  const token = localStorage.getItem('niravan_token');
  if (token) {
    hideLoginScreen();
  } else {
    showLoginScreen();
  }
}

// Hook auth checks into init
setTimeout(checkAuthState, 100);

// ── AI Forensics Investigation Functions ──
window.investigateIncident = async function(btn, id) {
  const reportContainer = document.getElementById(`ai-investigation-report-${id}`);
  const reportContent = document.getElementById(`report-content-${id}`);
  if (!reportContainer || !reportContent) return;

  reportContainer.style.display = 'block';
  reportContent.innerHTML = `<div style="display:flex;align-items:center;gap:10px;color:var(--accent-blue)"><span style="font-size:1.1rem;animation:spin 1s linear infinite;display:inline-block">🌀</span> Generating Forensics Report...</div>`;
  
  // Slide scroll to report
  setTimeout(() => reportContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/incidents/${id}/investigate`, {
        method: 'POST',
        headers: window.getHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        reportContent.innerHTML = formatMarkdownToHTML(data.report);
      } else {
        const err = await res.json();
        reportContent.innerHTML = `<span style="color:#ff2d55">⚠️ Investigation Error: ${err.detail || 'Could not compile report'}</span>`;
      }
    } catch(e) {
      console.error(e);
      reportContent.innerHTML = `<span style="color:#ff2d55">⚠️ Connection Error to AI Core</span>`;
    }
  } else {
    // Offline simulation report fallback
    setTimeout(() => {
      const mockReport = `# 🧠 NIRAVAN Autonomous Forensics Report: \`${id}\`

## 🔍 Incident Overview
* **Alert Title**: **Ransomware Behavioral Signature Detected** (Simulation Mode)
* **Detected On**: \`PROD-WEB-01\`
* **Trigger Account**: \`s.raj\`
* **Timestamp**: \`Just now (Simulated)\`

---

## 💥 Blast Radius & Impact Analysis
* **Host Criticality**: **HIGH**
* **Calculated Risk Index**: **88/100**
* **Linked Data Risks**: Confirmed network connectivity to Core database and internal servers. Potential data access threat.

---

## 🔬 Attack Vector Reconstruction (Root Cause Analysis)
1. **Intrusion Vector**: Threat actor exploited exposed vulnerability on external web interfaces.
2. **Hash Dumping**: Executed credentials harvesting from memory.
3. **Lateral Movement**: Pivoted via admin SMB shares.
4. **Execution**: Commenced encryption actions.

---

## 📋 Prescribed Remediation & Containment Actions
\`\`\`bash
# 1. Isolate the target host from the network partition
niravan-cli network isolate PROD-WEB-01 --force
# 2. Terminate the compromised process tree
niravan-cli process kill-tree --host PROD-WEB-01 --pid 4184
\`\`\`
`;
      reportContent.innerHTML = formatMarkdownToHTML(mockReport);
    }, 1500);
  }
};

function formatMarkdownToHTML(md) {
  if (!md) return "";
  let html = md;
  
  // Headers
  html = html.replace(/^# (.*$)/gim, '<h1 style="color:var(--text-primary);font-size:1.15rem;margin-top:16px;margin-bottom:10px;font-family:\'Space Grotesk\', sans-serif;font-weight:700;">$1</h1>');
  html = html.replace(/^## (.*$)/gim, '<h2 style="color:var(--text-primary);font-size:0.92rem;margin-top:14px;margin-bottom:8px;border-bottom:1px solid rgba(255,255,255,0.06);padding-bottom:4px;font-family:\'Space Grotesk\', sans-serif;font-weight:600;">$1</h2>');
  html = html.replace(/^### (.*$)/gim, '<h3 style="color:var(--text-primary);font-size:0.8rem;margin-top:12px;margin-bottom:6px;font-weight:600;">$1</h3>');
  
  // Bold
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--text-primary);font-weight:700;">$1</strong>');
  
  // Code block
  html = html.replace(/```bash([\s\S]*?)```/g, '<pre style="background:#030712;padding:10px;border-radius:4px;border:1px solid rgba(255,255,255,0.05);font-family:var(--font-mono);font-size:0.65rem;color:#30d158;overflow-x:auto;margin:8px 0;white-space:pre;"><code>$1</code></pre>');
  html = html.replace(/```([\s\S]*?)```/g, '<pre style="background:#030712;padding:10px;border-radius:4px;border:1px solid rgba(255,255,255,0.05);font-family:var(--font-mono);font-size:0.65rem;overflow-x:auto;margin:8px 0;white-space:pre;"><code>$1</code></pre>');
  
  // Inline Code
  html = html.replace(/`(.*?)`/g, '<code style="background:rgba(255,255,255,0.08);padding:2px 4px;border-radius:3px;font-family:var(--font-mono);font-size:0.65rem;color:var(--accent-blue);">$1</code>');
  
  // Lists
  html = html.replace(/^\* (.*$)/gim, '<li style="margin-left:14px;list-style-type:disc;padding:2px 0;">$1</li>');
  html = html.replace(/^\d+\. (.*$)/gim, '<li style="margin-left:14px;list-style-type:decimal;padding:2px 0;">$1</li>');
  
  // Horizontal Rule
  html = html.replace(/^---$/gim, '<hr style="border:none;border-top:1px solid rgba(255,255,255,0.06);margin:14px 0;">');
  
  // Linebreaks
  html = html.replace(/\n/g, '<br>');
  
  // Clean up duplicate breaks after pre tags and list tags
  html = html.replace(/<\/pre><br>/g, '</pre>');
  html = html.replace(/<\/li><br>/g, '</li>');
  html = html.replace(/<hr><br>/g, '<hr>');

  return html;
}

// ── Case Management UI Implementation ──
let selectedCaseId = null;

function renderCasesPage() {
  selectedCaseId = null;
  
  // Set filter buttons state
  document.querySelectorAll('[data-case-filter]').forEach(b => {
    b.classList.remove('active');
  });
  const allBtn = document.querySelector('[data-case-filter="all"]');
  if(allBtn) allBtn.classList.add('active');
  
  // Clear search input
  const searchInput = document.getElementById('case-search');
  if(searchInput) searchInput.value = '';

  renderCasesList('all');
  
  // Render placeholder detail
  const detailEl = document.getElementById('case-detail');
  if(detailEl) {
    detailEl.innerHTML = `
      <div class="detail-placeholder">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#bf5af2" stroke-width="1.5" opacity="0.6"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>
        <p>Select a security case to view details, notes timeline, and digital evidence vault</p>
      </div>
    `;
  }
}

async function renderCasesList(filter = 'all', searchQuery = '') {
  const listEl = document.getElementById('cases-list');
  if (!listEl) return;
  listEl.innerHTML = '';

  let cases = window.NIRAVAN_DATA.cases || [];

  // Filter by status
  if (filter !== 'all') {
    cases = cases.filter(c => c.status === filter);
  }

  // Filter by search query
  if (searchQuery.trim() !== '') {
    const q = searchQuery.toLowerCase();
    cases = cases.filter(c => 
      c.id.toLowerCase().includes(q) || 
      c.title.toLowerCase().includes(q) || 
      (c.description && c.description.toLowerCase().includes(q)) ||
      (c.assignee && c.assignee.toLowerCase().includes(q))
    );
  }

  if (cases.length === 0) {
    listEl.innerHTML = `
      <div style="text-align:center;padding:30px;color:var(--text-muted);font-size:0.75rem;">
        No cases found matching filter
      </div>
    `;
    return;
  }

  cases.forEach(c => {
    const card = document.createElement('div');
    card.className = `incident-card ${c.id === selectedCaseId ? 'active' : ''}`;
    card.style.cursor = 'pointer';
    card.style.display = 'flex';
    card.style.flexDirection = 'column';
    card.style.gap = '6px';
    card.style.padding = '12px';
    card.style.borderLeft = `3px solid ${c.severity === 'critical' ? 'var(--accent-red)' : c.severity === 'high' ? 'var(--accent-orange)' : 'var(--accent-yellow)'}`;
    
    const statusText = c.status === 'in_progress' ? 'In Progress' : c.status.toUpperCase();
    const statusColor = c.status === 'open' ? 'var(--accent-blue)' : c.status === 'in_progress' ? 'var(--accent-yellow)' : c.status === 'resolved' ? 'var(--accent-green)' : 'var(--text-muted)';
    
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-secondary);font-weight:600;">${c.id}</span>
        <span style="font-size:0.58rem;padding:2px 6px;border-radius:3px;background:rgba(255,255,255,0.03);color:${statusColor};text-transform:uppercase;font-weight:700;letter-spacing:0.5px;">${statusText}</span>
      </div>
      <div style="font-size:0.75rem;font-weight:600;color:var(--text-primary);line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${c.title}</div>
      <div style="display:flex;justify-content:space-between;align-items:center;font-size:0.6rem;color:var(--text-muted);margin-top:2px;">
        <span>Assignee: <strong style="color:var(--text-secondary);">${c.assignee ? c.assignee.split('@')[0] : 'Unassigned'}</strong></span>
        <span style="display:flex;align-items:center;gap:6px;">
          <span>📝 ${c.notes_count || (c.notes ? c.notes.length : 0)}</span>
          <span>📎 ${c.evidence_count || (c.evidence ? c.evidence.length : 0)}</span>
        </span>
      </div>
    `;

    card.addEventListener('click', () => {
      selectedCaseId = c.id;
      document.querySelectorAll('#cases-list .incident-card').forEach(cardEl => cardEl.classList.remove('active'));
      card.classList.add('active');
      renderCaseDetail(c.id);
    });

    listEl.appendChild(card);
  });

  if (selectedCaseId) {
    const activeCard = Array.from(listEl.children).find(child => child.innerHTML.includes(selectedCaseId));
    if (activeCard) activeCard.classList.add('active');
  }
}

async function renderCaseDetail(caseId) {
  const detailEl = document.getElementById('case-detail');
  if (!detailEl) return;

  detailEl.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:center;height:100%;">
      <div class="ai-spinner"></div>
    </div>
  `;

  let caseObj = null;

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}`, {
        headers: window.getHeaders()
      });
      if (res.ok) {
        caseObj = await res.json();
      }
    } catch (e) {
      console.error("[NIRAVAN] Error fetching case details:", e);
    }
  } else {
    caseObj = (window.NIRAVAN_DATA.cases || []).find(c => c.id === caseId);
  }

  if (!caseObj) {
    detailEl.innerHTML = `<div style="padding:20px;color:var(--accent-red);font-size:0.75rem;">Failed to load case details.</div>`;
    return;
  }

  const role = localStorage.getItem('niravan_user_role') || 'viewer';
  const isReadOnly = role === 'viewer';
  const disabledAttr = isReadOnly ? 'disabled' : '';
  const selectStyle = "background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:6px 12px;border-radius:var(--radius-sm);font-size:0.7rem;outline:none;";
  const dateStr = new Date(caseObj.created_at).toLocaleString();

  // SOAR Actions building
  const isSoarExecuted = localStorage.getItem(`niravan_soar_executed_${caseObj.id}`) === 'true';
  const isSoarDismissed = localStorage.getItem(`niravan_soar_dismissed_${caseObj.id}`) === 'true';
  
  const pendingActions = [];
  if (caseObj.evidence) {
    caseObj.evidence.forEach((ev, idx) => {
      if (ev.type === 'IP') {
        pendingActions.push({ action: 'Block IP', value: ev.value, label: `🚫 Block Attacker IP in WAF/Firewall: ${ev.value}` });
      } else if (ev.type === 'Host') {
        pendingActions.push({ action: 'Isolate Host', value: ev.value, label: `🖥️ Isolate Host via EDR: ${ev.value}` });
      } else if (ev.type === 'User') {
        pendingActions.push({ action: 'Reset Session', value: ev.value, label: `👤 Force AD password rotation & revoke session: ${ev.value}` });
      }
    });
  }
  
  if (pendingActions.length === 0) {
    pendingActions.push({ action: 'Block IP', value: '185.220.101.47', label: '🚫 Block Attacker IP 185.220.101.47 in Edge WAF' });
    pendingActions.push({ action: 'Isolate Host', value: 'VPN-GW-01', label: '🖥️ Network-isolate target host VPN-GW-01' });
  }

  let soarHtml = '';
  if (isSoarDismissed) {
    soarHtml = '';
  } else if (!isSoarExecuted) {
    soarHtml = `
      <div id="soar-approval-card" style="background:rgba(255,45,85,0.02); border:1px solid rgba(255,45,85,0.15); padding:14px; border-radius:var(--radius-sm); display:flex; flex-direction:column; gap:10px; margin-bottom: 16px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="font-size:0.68rem; font-weight:700; color:#ff2d55; text-transform:uppercase; letter-spacing:0.5px;">🛡️ SOAR Autonomous Response Layer (Awaiting Approval)</div>
          <span style="font-size:0.52rem; background:rgba(255,45,85,0.12); color:#ff2d55; padding:2px 6px; border-radius:4px; font-weight:700; letter-spacing:0.5px; animation:kc-pulse 2s infinite;">PENDING APPROVAL</span>
        </div>
        <p style="font-size:0.62rem; color:var(--text-muted); line-height:1.3; margin:0;">Based on correlated threat behavior signals, NIRAVAN recommends executing the following containment actions. Select actions to authorize:</p>
        
        <div style="display:flex; flex-direction:column; gap:6px; margin:4px 0;">
          ${pendingActions.map((act, i) => `
            <label style="display:flex; align-items:center; gap:8px; font-size:0.65rem; color:var(--text-secondary); cursor:pointer; margin:0;">
              <input type="checkbox" class="soar-action-cb" data-action="${act.action}" data-value="${act.value}" checked style="accent-color:#ff2d55;">
              <span>${act.label}</span>
            </label>
          `).join('')}
        </div>
        
        <div style="display:flex; gap:8px; align-items:center;">
          <button onclick="window.approveSOARActions('${caseObj.id}')" class="btn-primary" style="font-size:0.62rem; height:26px; background:#ff2d55; border:none; padding:0 12px; border-radius:var(--radius-sm); font-weight:600; cursor:pointer; color:#fff; text-transform:uppercase;">Approve & Contain</button>
          <button onclick="window.dismissSOARActions('${caseObj.id}')" class="btn-secondary" style="font-size:0.62rem; height:28px; padding:0 12px; border-radius:var(--radius-sm); cursor:pointer; text-transform:uppercase;">Dismiss</button>
        </div>
      </div>
    `;
  } else {
    soarHtml = `
      <div style="background:rgba(48,209,88,0.02); border:1px solid rgba(48,209,88,0.15); padding:14px; border-radius:var(--radius-sm); display:flex; align-items:center; gap:10px; margin-bottom: 16px;">
        <span style="font-size:1.2rem; filter:drop-shadow(0 0 4px rgba(48,209,88,0.4));">✅</span>
        <div>
          <div style="font-size:0.68rem; font-weight:700; color:#30d158; text-transform:uppercase; letter-spacing:0.5px;">SOAR Containment Executed</div>
          <p style="font-size:0.62rem; color:var(--text-muted); margin:2px 0 0 0; line-height:1.3;">Threat containment actions have been successfully deployed. Target segments isolated.</p>
        </div>
      </div>
    `;
  }

  let htmlContent = `
    <div class="detail-content" style="display:flex;flex-direction:column;height:100%;">
      <!-- Case Detail Header -->
      <div style="border-bottom:1px solid rgba(255,255,255,0.06);padding-bottom:16px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px;">
          <div>
            <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);font-weight:600;">CASE TELEMETRY INDEX: ${caseObj.id}</span>
            <h2 style="font-size:1.15rem;font-weight:700;color:var(--text-primary);margin-top:4px;font-family:'Space Grotesk',sans-serif;">${caseObj.title}</h2>
            <div style="font-size:0.62rem;color:var(--text-muted);margin-top:4px;">Created: ${dateStr}</div>
          </div>
          
          <div style="display:flex;gap:8px;align-items:flex-end;">
            <div style="display:flex;flex-direction:column;gap:3px;">
              <label style="font-size:0.55rem;color:var(--text-muted);text-transform:uppercase;font-weight:700;letter-spacing:0.5px;">Status</label>
              <select id="case-status-select" onchange="handleCaseStatusChange('${caseObj.id}', this.value)" ${disabledAttr} style="${selectStyle}">
                <option value="open" ${caseObj.status === 'open' ? 'selected' : ''}>Open</option>
                <option value="in_progress" ${caseObj.status === 'in_progress' ? 'selected' : ''}>In Progress</option>
                <option value="resolved" ${caseObj.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                <option value="closed" ${caseObj.status === 'closed' ? 'selected' : ''}>Closed</option>
              </select>
            </div>
            
            <div style="display:flex;flex-direction:column;gap:3px;">
              <label style="font-size:0.55rem;color:var(--text-muted);text-transform:uppercase;font-weight:700;letter-spacing:0.5px;">Assignee</label>
              <select id="case-assignee-select" onchange="handleCaseAssigneeChange('${caseObj.id}', this.value)" ${disabledAttr} style="${selectStyle}">
                <option value="" ${!caseObj.assignee ? 'selected' : ''}>Unassigned</option>
                <option value="admin@niravan.ai" ${caseObj.assignee === 'admin@niravan.ai' ? 'selected' : ''}>admin@niravan.ai</option>
                <option value="analyst@niravan.ai" ${caseObj.assignee === 'analyst@niravan.ai' ? 'selected' : ''}>analyst@niravan.ai</option>
              </select>
            </div>

            <button onclick="window.generatePDFInvestigationReport('${caseObj.id}')" class="btn-primary" style="font-size:0.62rem; height:28px; background:#ffd60a; color:#000; border:none; padding:0 10px; border-radius:var(--radius-sm); font-weight:600; cursor:pointer; text-transform:uppercase; display:flex; align-items:center; gap:4px; box-shadow:0 0 8px rgba(255,214,10,0.2);">
              📄 Dossier PDF
            </button>
          </div>
        </div>

        ${caseObj.incident_id ? `
          <div style="display:inline-flex;align-items:center;gap:6px;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.1);padding:4px 10px;border-radius:4px;font-size:0.6rem;color:var(--accent-blue);cursor:pointer;" onclick="navigateTo('incidents'); setTimeout(()=> { const card=Array.from(document.querySelectorAll('#incidents-list .incident-card')).find(c=>c.innerHTML.includes('${caseObj.incident_id}')); if(card) card.click(); }, 150);">
            <span>🔗 Linked Incident: <strong>${caseObj.incident_id}</strong></span>
          </div>
        ` : ''}
      </div>

      <!-- Scrollable content area -->
      <div style="flex:1;overflow-y:auto;display:grid;grid-template-columns:1fr 280px;gap:20px;">
        
        <!-- Left: Case Overview, SOAR approvals, & Notes Timeline -->
        <div style="display:flex;flex-direction:column;gap:14px;min-width:0;">
          <div style="background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);padding:14px;border-radius:var(--radius-sm);">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Case Summary</div>
            <p style="font-size:0.75rem;color:var(--text-secondary);line-height:1.45;margin:0;">${caseObj.description}</p>
          </div>

          ${soarHtml}

          <div style="display:flex;flex-direction:column;flex:1;min-height:220px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;">Case Activity Log & Analyst Notes</div>
            
            <div id="case-notes-timeline" style="flex:1;background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);border-radius:var(--radius-sm);padding:16px;overflow-y:auto;display:flex;flex-direction:column;gap:14px;max-height:240px;">
              ${(caseObj.notes && caseObj.notes.length > 0) ? caseObj.notes.map(note => {
                const isSys = note.author === 'system';
                return `
                  <div style="display:flex;gap:10px;align-items:flex-start;">
                    <div style="width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.6rem;font-weight:700;background:${isSys ? 'rgba(255,255,255,0.05)' : 'rgba(191,90,242,0.1)'};color:${isSys ? 'var(--text-muted)' : '#bf5af2'}">
                      ${isSys ? '🤖' : note.author.charAt(0).toUpperCase()}
                    </div>
                    <div style="flex:1;min-width:0;">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px;">
                        <span style="font-size:0.62rem;font-weight:700;color:${isSys ? 'var(--text-muted)' : 'var(--text-secondary)'};">${note.author}</span>
                        <span style="font-size:0.54rem;color:var(--text-muted);">${new Date(note.created_at).toLocaleTimeString()}</span>
                      </div>
                      <div style="font-size:0.7rem;color:${isSys ? 'var(--text-muted)' : 'var(--text-primary)'};line-height:1.4;white-space:pre-wrap;background:${isSys ? 'transparent' : 'rgba(255,255,255,0.01)'};padding:${isSys ? '0' : '8px'};border-radius:4px;">${note.note}</div>
                    </div>
                  </div>
                `;
              }).join('') : `<div style="text-align:center;padding:40px;color:var(--text-muted);font-size:0.7rem;">No activity log entries yet.</div>`}
            </div>

            <div style="display:flex;gap:10px;margin-top:10px;">
              <input type="text" id="case-note-input" placeholder="${isReadOnly ? 'Read-only. Viewer cannot add notes.' : 'Type investigator note or correlation findings...'}" ${disabledAttr} style="flex:1;background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:8px 12px;border-radius:var(--radius-sm);font-size:0.72rem;outline:none;">
              <button onclick="handleAddCaseNote('${caseObj.id}')" ${disabledAttr} class="btn-primary" style="padding:0 16px;font-size:0.72rem;height:34px;">Add Note</button>
            </div>
          </div>
        </div>

        <!-- Right: Evidence Vault -->
        <div style="border-left:1px solid rgba(255,255,255,0.06);padding-left:20px;display:flex;flex-direction:column;gap:16px;">
          <div>
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
              <span>🛡️ Evidence Vault</span>
              <span style="font-size:0.58rem;background:rgba(48,209,88,0.1);color:var(--accent-green);padding:1px 6px;border-radius:4px;">SECURE</span>
            </div>
            <p style="font-size:0.6rem;color:var(--text-muted);line-height:1.3;margin-bottom:12px;">Hash profiles, offending IP addresses, payload hosts, and compromised accounts logged in active custody.</p>
            
            <div id="case-evidence-vault" style="display:flex;flex-direction:column;gap:8px;max-height:220px;overflow-y:auto;background:rgba(0,0,0,0.1);border-radius:4px;padding:6px;border:1px solid rgba(255,255,255,0.02);">
              ${(caseObj.evidence && caseObj.evidence.length > 0) ? caseObj.evidence.map(ev => {
                const icon = ev.type === 'IP' ? '🌐' : ev.type === 'Hash' ? '🔑' : ev.type === 'Host' ? '🖥️' : ev.type === 'User' ? '👤' : '📁';
                return `
                  <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.03);padding:8px;border-radius:4px;display:flex;flex-direction:column;gap:3px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;font-size:0.54rem;">
                      <span style="color:var(--accent-blue);font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">${icon} ${ev.type}</span>
                      <span style="color:var(--text-muted);">${ev.added_by.split('@')[0]}</span>
                    </div>
                    <div style="font-size:0.68rem;font-weight:600;color:var(--text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${ev.name}">${ev.name}</div>
                    <div style="font-size:0.62rem;font-family:var(--font-mono);color:var(--text-primary);background:rgba(0,0,0,0.2);padding:2px 6px;border-radius:3px;word-break:break-all;user-select:all;">${ev.value}</div>
                  </div>
                `;
              }).join('') : `<div style="text-align:center;padding:30px;color:var(--text-muted);font-size:0.62rem;">No evidence logged.</div>`}
            </div>
          </div>

          ${!isReadOnly ? `
            <div style="background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);padding:12px;border-radius:var(--radius-sm);display:flex;flex-direction:column;gap:8px;">
              <div style="font-size:0.58rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;">Log New Evidence</div>
              
              <select id="evidence-type" style="${selectStyle} padding:4px 8px; font-size:0.65rem;">
                <option value="IP">IP Address</option>
                <option value="Domain">Domain Name</option>
                <option value="Hash">MD5/SHA256 Hash</option>
                <option value="Host">Target Hostname</option>
                <option value="User">User Account</option>
                <option value="Log">System Log Line</option>
              </select>
              
              <input type="text" id="evidence-name" placeholder="Label (e.g. C2 IPv4)" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:5px 8px;border-radius:var(--radius-sm);font-size:0.65rem;outline:none;">
              <input type="text" id="evidence-value" placeholder="Value" style="background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:5px 8px;border-radius:var(--radius-sm);font-size:0.65rem;outline:none;">
              
              <button onclick="handleAddCaseEvidence('${caseObj.id}')" class="btn-secondary" style="padding:6px;font-size:0.65rem;">Sync to Vault</button>
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `;

  detailEl.innerHTML = htmlContent;
}

async function handleCaseStatusChange(caseId, status) {
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}`, {
        method: 'PUT',
        headers: {
          ...window.getHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        showToast(`Case ${caseId} status updated to ${status}.`, 'good');
        await window.syncFromBackend();
        renderCasesList();
        renderCaseDetail(caseId);
      } else if (res.status === 403) {
        showToast("Access Denied: Read-only permissions.", "critical");
        renderCaseDetail(caseId);
      }
    } catch (e) {
      console.error("[NIRAVAN] Error updating case status:", e);
    }
  } else {
    const c = window.NIRAVAN_DATA.cases.find(item => item.id === caseId);
    if (c) {
      const old = c.status;
      c.status = status;
      c.updated_at = new Date().toISOString();
      if (!c.notes) c.notes = [];
      c.notes.push({
        id: Date.now(),
        author: "system",
        note: `Case status updated from '${old}' to '${status}' by local analyst.`,
        created_at: new Date().toISOString()
      });
      showToast(`Local Fallback: Case status updated to ${status}.`, 'good');
      
      // trigger offline audit log
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "UPDATE_CASE",
        detail: `Updated status of case ${caseId} from '${old}' to '${status}'.`,
        ip_address: "127.0.0.1"
      });
      
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

async function handleCaseAssigneeChange(caseId, assignee) {
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}`, {
        method: 'PUT',
        headers: {
          ...window.getHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ assignee: assignee || null })
      });
      if (res.ok) {
        showToast(assignee ? `Case assigned to ${assignee}.` : `Case unassigned.`, 'good');
        await window.syncFromBackend();
        renderCasesList();
        renderCaseDetail(caseId);
      } else if (res.status === 403) {
        showToast("Access Denied: Read-only permissions.", "critical");
        renderCaseDetail(caseId);
      }
    } catch (e) {
      console.error("[NIRAVAN] Error updating case assignee:", e);
    }
  } else {
    const c = window.NIRAVAN_DATA.cases.find(item => item.id === caseId);
    if (c) {
      const old = c.assignee || 'None';
      c.assignee = assignee || null;
      c.updated_at = new Date().toISOString();
      if (!c.notes) c.notes = [];
      c.notes.push({
        id: Date.now(),
        author: "system",
        note: `Case assignee updated from '${old}' to '${assignee || 'None'}' by local analyst.`,
        created_at: new Date().toISOString()
      });
      showToast(assignee ? `Local Fallback: Case assigned to ${assignee}.` : `Local Fallback: Case unassigned.`, 'good');
      
      // trigger offline audit log
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "UPDATE_CASE",
        detail: `Updated assignee of case ${caseId} from '${old}' to '${assignee || 'None'}'.`,
        ip_address: "127.0.0.1"
      });
      
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

async function handleAddCaseNote(caseId) {
  const input = document.getElementById('case-note-input');
  if (!input || !input.value.trim()) return;
  const note = input.value.trim();

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}/notes`, {
        method: 'POST',
        headers: {
          ...window.getHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ note })
      });
      if (res.ok) {
        input.value = '';
        showToast("Note successfully logged.", 'good');
        await window.syncFromBackend();
        renderCasesList();
        renderCaseDetail(caseId);
      } else if (res.status === 403) {
        showToast("Access Denied: Action requires analyst privileges.", "critical");
      }
    } catch (e) {
      console.error("[NIRAVAN] Error adding note:", e);
    }
  } else {
    const c = window.NIRAVAN_DATA.cases.find(item => item.id === caseId);
    if (c) {
      const author = localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai';
      if (!c.notes) c.notes = [];
      c.notes.push({
        id: Date.now(),
        author: author,
        note: note,
        created_at: new Date().toISOString()
      });
      c.updated_at = new Date().toISOString();
      input.value = '';
      showToast("Local Fallback: Note added successfully.", 'good');
      
      // trigger offline audit log
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: author,
        action: "ADD_NOTE",
        detail: `Added investigator note to case ${caseId}.`,
        ip_address: "127.0.0.1"
      });
      
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

async function handleAddCaseEvidence(caseId) {
  const typeSelect = document.getElementById('evidence-type');
  const nameInput = document.getElementById('evidence-name');
  const valueInput = document.getElementById('evidence-value');

  if (!typeSelect || !nameInput || !valueInput) return;
  
  const type = typeSelect.value;
  const name = nameInput.value.trim();
  const value = valueInput.value.trim();

  if (!name || !value) {
    showToast("Please provide evidence label and value.", 'critical');
    return;
  }

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}/evidence`, {
        method: 'POST',
        headers: {
          ...window.getHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type, name, value })
      });
      if (res.ok) {
        nameInput.value = '';
        valueInput.value = '';
        showToast("Evidence successfully synchronized.", 'good');
        await window.syncFromBackend();
        renderCasesList();
        renderCaseDetail(caseId);
      } else if (res.status === 403) {
        showToast("Access Denied: Action requires analyst privileges.", "critical");
      }
    } catch (e) {
      console.error("[NIRAVAN] Error adding evidence:", e);
    }
  } else {
    const c = window.NIRAVAN_DATA.cases.find(item => item.id === caseId);
    if (c) {
      const author = localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai';
      if (!c.evidence) c.evidence = [];
      if (!c.notes) c.notes = [];
      c.evidence.push({
        id: Date.now(),
        name,
        value,
        type,
        added_by: author,
        created_at: new Date().toISOString()
      });
      c.notes.push({
        id: Date.now(),
        author: "system",
        note: `Evidence artifact added: ${type} - '${name}' by local analyst.`,
        created_at: new Date().toISOString()
      });
      c.updated_at = new Date().toISOString();
      nameInput.value = '';
      valueInput.value = '';
      showToast("Local Fallback: Evidence added successfully.", 'good');
      
      // trigger offline audit log
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: author,
        action: "ADD_EVIDENCE",
        detail: `Added evidence artifact '${name}' (${type}) to case ${caseId}.`,
        ip_address: "127.0.0.1"
      });
      
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

async function handleIncidentEscalated(incidentId) {
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/incidents/${incidentId}/escalate`, {
        method: 'POST',
        headers: window.getHeaders()
      });
      if (res.ok) {
        const body = await res.json();
        showToast("Incident successfully escalated to Case.", 'good');
        await window.syncFromBackend();
        
        navigateTo('cases');
        selectedCaseId = body.id;
        renderCasesList();
        renderCaseDetail(body.id);
      } else if (res.status === 403) {
        showToast("Access Denied: Escalation requires analyst privileges.", "critical");
      } else {
        showToast("Failed to escalate incident.", "critical");
      }
    } catch (e) {
      console.error("[NIRAVAN] Error escalating incident:", e);
    }
  } else {
    const inc = window.NIRAVAN_DATA.events.find(e => e.id === incidentId);
    if (inc) {
      const existing = window.NIRAVAN_DATA.cases.find(c => c.incident_id === incidentId);
      if (existing) {
        navigateTo('cases');
        selectedCaseId = existing.id;
        renderCasesList();
        renderCaseDetail(existing.id);
        return;
      }

      inc.status = 'escalated';
      const caseId = `case-${incidentId.split('-')[1] || incidentId}`;
      const newCase = {
        id: caseId,
        title: `Escalated Alert: ${inc.title}`,
        description: inc.description,
        severity: inc.severity,
        status: "open",
        assignee: null,
        incident_id: incidentId,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        notes: [
          { id: Date.now(), author: "system", note: "Case opened automatically via local escalation.", created_at: new Date().toISOString() }
        ],
        evidence: []
      };
      
      if (inc.host) {
        newCase.evidence.push({ id: Date.now() + 1, name: "Target Endpoint Hostname", value: inc.host, type: "Host", added_by: "system", created_at: new Date().toISOString() });
      }
      if (inc.user) {
        newCase.evidence.push({ id: Date.now() + 2, name: "Trigger User Account", value: inc.user, type: "User", added_by: "system", created_at: new Date().toISOString() });
      }

      window.NIRAVAN_DATA.cases.unshift(newCase);
      showToast("Local Fallback: Incident escalated to Case.", 'good');
      
      // trigger offline audit log
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "ESCALATE_ALERT",
        detail: `Escalated incident ${incidentId} to case ${caseId}.`,
        ip_address: "127.0.0.1"
      });

      navigateTo('cases');
      selectedCaseId = caseId;
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

// ── Detection Engineering Subsystem Console ──
let selectedRuleId = null;

function renderDetectionPage() {
  const rules = window.NIRAVAN_DATA.detectionRules || [];
  if (rules.length > 0 && !selectedRuleId) {
    selectedRuleId = rules[0].id;
  }
  renderDetectionList();
  if (selectedRuleId) {
    renderDetectionDetail(selectedRuleId);
  } else {
    const detailEl = document.getElementById('detection-rule-detail');
    if (detailEl) {
      detailEl.innerHTML = `
        <div class="detail-placeholder">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" stroke-width="1.5" opacity="0.6"><circle cx="12" cy="12" r="10"/><path d="M12 8v8M8 12h8"/></svg>
          <p>Select a detection rule to view matching logic, YAML definitions, and execution dry-run test consoles.</p>
        </div>
      `;
    }
  }
}

function renderDetectionList(searchQuery = "") {
  const listEl = document.getElementById('detection-rules-list');
  if (!listEl) return;

  const rules = window.NIRAVAN_DATA.detectionRules || [];
  const query = searchQuery.toLowerCase().trim();

  const filteredRules = rules.filter(r => 
    r.id.toLowerCase().includes(query) || 
    r.name.toLowerCase().includes(query) || 
    r.description.toLowerCase().includes(query) ||
    r.log_source.toLowerCase().includes(query)
  );

  if (filteredRules.length === 0) {
    listEl.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-muted);font-size:0.7rem;">No rules found.</div>`;
    return;
  }

  listEl.innerHTML = filteredRules.map(rule => {
    const isSelected = rule.id === selectedRuleId;
    const isEnabled = rule.status === 'enabled';
    const activeClass = isSelected ? 'active' : '';
    const severityClass = rule.severity.toLowerCase();

    return `
      <div class="incident-card ${activeClass}" onclick="window.renderDetectionDetail('${rule.id}')" style="cursor:pointer;padding:12px;display:flex;flex-direction:column;gap:6px;border-radius:var(--radius-sm);background:rgba(255,255,255,${isSelected ? '0.04' : '0.01'});border:1px solid ${isSelected ? 'var(--accent-blue)' : 'rgba(255,255,255,0.03)'};position:relative;transition:all var(--transition);">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);">${rule.id}</span>
          <span class="severity-badge ${severityClass}" style="font-size:0.52rem;padding:2px 6px;text-transform:uppercase;border-radius:3px;">${rule.severity}</span>
        </div>
        <div style="font-size:0.75rem;font-weight:700;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${rule.name}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:2px;">
          <span style="font-size:0.62rem;color:var(--text-muted);">Source: ${rule.log_source}</span>
          <span style="font-size:0.62rem;font-weight:600;color:${isEnabled ? 'var(--accent-green)' : 'var(--text-muted)'};">${isEnabled ? '● Active' : '○ Disabled'}</span>
        </div>
      </div>
    `;
  }).join('');
}

async function renderDetectionDetail(ruleId) {
  selectedRuleId = ruleId;
  
  // Highlight list item
  document.querySelectorAll('#detection-rules-list .incident-card').forEach(card => {
    card.classList.remove('active');
    card.style.border = '1px solid rgba(255,255,255,0.03)';
    card.style.background = 'rgba(255,255,255,0.01)';
  });

  const detailEl = document.getElementById('detection-rule-detail');
  if (!detailEl) return;

  const ruleObj = (window.NIRAVAN_DATA.detectionRules || []).find(r => r.id === ruleId);
  if (!ruleObj) {
    detailEl.innerHTML = `<div class="detail-placeholder"><p>Rule not found.</p></div>`;
    return;
  }

  const role = localStorage.getItem('niravan_user_role') || 'viewer';
  const isReadOnly = role === 'viewer';
  const disabledAttr = isReadOnly ? 'disabled' : '';
  const selectStyle = "background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:6px 12px;border-radius:var(--radius-sm);font-size:0.7rem;outline:none;";
  const inputStyle = "background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:8px 10px;border-radius:var(--radius-sm);font-size:0.72rem;outline:none;width:100%;";

  detailEl.innerHTML = `
    <div class="detail-content" style="display:flex;flex-direction:column;height:100%;overflow:hidden;">
      <!-- Rule Detail Header -->
      <div style="border-bottom:1px solid rgba(255,255,255,0.06);padding-bottom:16px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);font-weight:600;">RULE TELEMETRY ID: ${ruleObj.id}</span>
          <h2 style="font-size:1.2rem;font-weight:700;color:var(--text-primary);margin-top:4px;font-family:'Space Grotesk',sans-serif;">${ruleObj.name}</h2>
        </div>
        <div style="display:flex;align-items:center;gap:12px;">
          <span class="severity-badge ${ruleObj.severity.toLowerCase()}" style="text-transform:uppercase;font-size:0.6rem;padding:4px 8px;border-radius:4px;font-weight:600;">${ruleObj.severity}</span>
          <div style="display:flex;align-items:center;gap:6px;">
            <label style="font-size:0.65rem;color:var(--text-secondary);font-weight:600;">Status:</label>
            <select onchange="window.toggleRuleStatus('${ruleObj.id}', this.value)" ${disabledAttr} style="${selectStyle}">
              <option value="enabled" ${ruleObj.status === 'enabled' ? 'selected' : ''}>Enabled</option>
              <option value="disabled" ${ruleObj.status === 'disabled' ? 'selected' : ''}>Disabled</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Main Content Grid -->
      <div style="flex:1;overflow-y:auto;display:grid;grid-template-columns:1.2fr 1fr;gap:20px;padding-right:4px;">
        <!-- Left: Settings Form & Dry Run -->
        <div style="display:flex;flex-direction:column;gap:16px;min-width:0;">
          <div style="background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);padding:16px;border-radius:var(--radius-sm);display:flex;flex-direction:column;gap:12px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px;">Rule Configuration</div>
            
            <div style="display:flex;flex-direction:column;gap:4px;">
              <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Rule Name</label>
              <input type="text" id="rule-edit-name" value="${ruleObj.name}" ${disabledAttr} style="${inputStyle}">
            </div>

            <div style="display:flex;flex-direction:column;gap:4px;">
              <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Description</label>
              <textarea id="rule-edit-desc" rows="2" ${disabledAttr} style="${inputStyle} resize:none;">${ruleObj.description}</textarea>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Log Source</label>
                <input type="text" id="rule-edit-logsource" value="${ruleObj.log_source}" ${disabledAttr} style="${inputStyle}">
              </div>
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Severity</label>
                <select id="rule-edit-severity" ${disabledAttr} style="${selectStyle} width:100%;">
                  <option value="low" ${ruleObj.severity === 'low' ? 'selected' : ''}>Low</option>
                  <option value="medium" ${ruleObj.severity === 'medium' ? 'selected' : ''}>Medium</option>
                  <option value="high" ${ruleObj.severity === 'high' ? 'selected' : ''}>High</option>
                  <option value="critical" ${ruleObj.severity === 'critical' ? 'selected' : ''}>Critical</option>
                </select>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:4px;">
              <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;display:flex;justify-content:space-between;">
                <span>Condition JSON</span>
                <span style="color:var(--accent-blue);font-size:0.55rem;text-transform:none;">Field match query for engine</span>
              </label>
              <input type="text" id="rule-edit-condition" value='${ruleObj.condition_json}' ${disabledAttr} style="${inputStyle} font-family:var(--font-mono); font-size:0.68rem;">
            </div>

            <div style="display:flex;gap:10px;margin-top:4px;">
              <button onclick="window.saveRuleDetails('${ruleObj.id}')" ${disabledAttr} class="btn-primary" style="flex:1;font-size:0.7rem;height:34px;">Save Rule</button>
              <button onclick="window.testRuleDetails('${ruleObj.id}')" class="btn-secondary" style="flex:1;font-size:0.7rem;height:34px;border-color:var(--accent-blue);color:var(--accent-blue);background:transparent;">Run Dry-Run Test</button>
            </div>
          </div>
        </div>

        <!-- Right: YAML Editor & Dry Run Console -->
        <div style="display:flex;flex-direction:column;gap:16px;min-width:0;">
          <div style="display:flex;flex-direction:column;flex:1;min-height:220px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">YAML Rule Definition</div>
            <textarea id="rule-edit-yaml" ${disabledAttr} style="flex:1;background:rgba(0,0,0,0.3);border:1px solid var(--border-subtle);color:#e2e8f0;padding:12px;border-radius:var(--radius-sm);font-family:var(--font-mono);font-size:0.68rem;line-height:1.4;outline:none;resize:none;tab-size:4;min-height:160px;">${ruleObj.yaml_content}</textarea>
          </div>

          <div style="display:flex;flex-direction:column;height:180px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Dry-Run Simulation Output</div>
            <div id="rule-test-console" style="flex:1;background:rgba(3,7,18,0.6);border:1px solid rgba(255,255,255,0.06);border-radius:var(--radius-sm);padding:12px;overflow-y:auto;font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);line-height:1.45;">
              Console idle. Click 'Run Dry-Run Test' to scan historical log telemetry.
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function toggleRuleStatus(ruleId, status) {
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/detection/rules/${ruleId}`, {
        method: 'PUT',
        headers: {
          ...window.getHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });
      if (res.ok) {
        showToast(`Rule ${ruleId} status updated to ${status}.`, 'good');
        await window.syncFromBackend();
        renderDetectionPage();
      } else if (res.status === 403) {
        showToast("Access Denied: Action requires analyst privileges.", "critical");
        renderDetectionDetail(ruleId);
      }
    } catch (e) {
      console.error("[NIRAVAN] Error updating rule status:", e);
    }
  } else {
    const rule = (window.NIRAVAN_DATA.detectionRules || []).find(r => r.id === ruleId);
    if (rule) {
      const old = rule.status;
      rule.status = status;
      rule.updated_at = new Date().toISOString();
      showToast(`Local Fallback: Rule status updated to ${status}.`, 'good');
      
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "UPDATE_RULE",
        detail: `Updated status of rule ${ruleId} from '${old}' to '${status}'.`,
        ip_address: "127.0.0.1"
      });
      
      renderDetectionPage();
    }
  }
}

function showCreateRuleForm() {
  selectedRuleId = null;
  const detailEl = document.getElementById('detection-rule-detail');
  if (!detailEl) return;

  const role = localStorage.getItem('niravan_user_role') || 'viewer';
  if (role === 'viewer') {
    showToast("Access Denied: Action requires analyst privileges.", "critical");
    return;
  }

  const selectStyle = "background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:6px 12px;border-radius:var(--radius-sm);font-size:0.7rem;outline:none;";
  const inputStyle = "background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);color:var(--text-primary);padding:8px 10px;border-radius:var(--radius-sm);font-size:0.72rem;outline:none;width:100%;";

  detailEl.innerHTML = `
    <div class="detail-content" style="display:flex;flex-direction:column;height:100%;overflow:hidden;">
      <!-- Rule Detail Header -->
      <div style="border-bottom:1px solid rgba(255,255,255,0.06);padding-bottom:16px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);font-weight:600;">NEW DETECTION RULE</span>
          <h2 style="font-size:1.2rem;font-weight:700;color:var(--text-primary);margin-top:4px;font-family:'Space Grotesk',sans-serif;">Create Custom Sigma Rule</h2>
        </div>
        <div>
          <span class="severity-badge medium" style="text-transform:uppercase;font-size:0.6rem;padding:4px 8px;border-radius:4px;font-weight:600;">CUSTOM</span>
        </div>
      </div>

      <!-- Main Content Grid -->
      <div style="flex:1;overflow-y:auto;display:grid;grid-template-columns:1.2fr 1fr;gap:20px;padding-right:4px;">
        <!-- Left: Settings Form -->
        <div style="display:flex;flex-direction:column;gap:16px;min-width:0;">
          <div style="background:rgba(255,255,255,0.01);border:1px solid rgba(255,255,255,0.03);padding:16px;border-radius:var(--radius-sm);display:flex;flex-direction:column;gap:12px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px;">Rule Configuration</div>
            
            <div style="display:grid;grid-template-columns:100px 1fr;gap:10px;">
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Rule ID</label>
                <input type="text" id="rule-edit-id" placeholder="SIG-005" style="${inputStyle}">
              </div>
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Rule Name</label>
                <input type="text" id="rule-edit-name" placeholder="Suspicious Executable Execution" style="${inputStyle}">
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:4px;">
              <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Description</label>
              <textarea id="rule-edit-desc" rows="2" placeholder="Detects execution of executables from temp path..." style="${inputStyle} resize:none;"></textarea>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Log Source</label>
                <input type="text" id="rule-edit-logsource" placeholder="process_creation" style="${inputStyle}">
              </div>
              <div style="display:flex;flex-direction:column;gap:4px;">
                <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;">Severity</label>
                <select id="rule-edit-severity" style="${selectStyle} width:100%;">
                  <option value="low">Low</option>
                  <option value="medium" selected>Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>

            <div style="display:flex;flex-direction:column;gap:4px;">
              <label style="font-size:0.6rem;color:var(--text-muted);font-weight:600;text-transform:uppercase;display:flex;justify-content:space-between;">
                <span>Condition JSON</span>
                <span style="color:var(--accent-blue);font-size:0.55rem;text-transform:none;">Field match query for engine</span>
              </label>
              <input type="text" id="rule-edit-condition" value='{"field": "technical", "contains": "temp"}' style="${inputStyle} font-family:var(--font-mono); font-size:0.68rem;">
            </div>

            <div style="display:flex;gap:10px;margin-top:4px;">
              <button onclick="window.saveRuleDetails(null)" class="btn-primary" style="flex:1;font-size:0.7rem;height:34px;">Create Rule</button>
              <button onclick="navigateTo('detection')" class="btn-secondary" style="flex:1;font-size:0.7rem;height:34px;background:transparent;">Cancel</button>
            </div>
          </div>
        </div>

        <!-- Right: YAML Editor -->
        <div style="display:flex;flex-direction:column;gap:16px;min-width:0;">
          <div style="display:flex;flex-direction:column;flex:1;min-height:350px;">
            <div style="font-size:0.68rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">YAML Rule Definition</div>
            <textarea id="rule-edit-yaml" style="flex:1;background:rgba(0,0,0,0.3);border:1px solid var(--border-subtle);color:#e2e8f0;padding:12px;border-radius:var(--radius-sm);font-family:var(--font-mono);font-size:0.68rem;line-height:1.4;outline:none;resize:none;tab-size:4;min-height:280px;">title: Custom Rule Name
id: SIG-005
description: Detects custom threat pattern.
logsource:
    category: process_creation
detection:
    selection:
        technical|contains: "temp"
    condition: selection
severity: medium</textarea>
          </div>
        </div>
      </div>
    </div>
  `;
}

async function saveRuleDetails(ruleId) {
  const name = document.getElementById('rule-edit-name')?.value;
  const description = document.getElementById('rule-edit-desc')?.value;
  const log_source = document.getElementById('rule-edit-logsource')?.value;
  const severity = document.getElementById('rule-edit-severity')?.value;
  const condition_json = document.getElementById('rule-edit-condition')?.value;
  const yaml_content = document.getElementById('rule-edit-yaml')?.value;

  if (!name || !description || !log_source || !severity || !condition_json || !yaml_content) {
    showToast("Please fill in all configuration fields.", "critical");
    return;
  }

  try {
    JSON.parse(condition_json);
  } catch (err) {
    showToast("Condition JSON is invalid. Must be valid JSON string.", "critical");
    return;
  }

  if (ruleId) {
    if (window.NIRAVAN_API_ACTIVE) {
      try {
        const res = await fetch(`${window.API_URL}/detection/rules/${ruleId}`, {
          method: 'PUT',
          headers: {
            ...window.getHeaders(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ name, description, log_source, severity, condition_json, yaml_content })
        });
        if (res.ok) {
          showToast(`Rule ${ruleId} successfully updated.`, 'good');
          await window.syncFromBackend();
          renderDetectionPage();
        } else if (res.status === 403) {
          showToast("Access Denied: Action requires analyst privileges.", "critical");
        }
      } catch (err) {
        console.error("Error updating rule:", err);
      }
    } else {
      const rule = (window.NIRAVAN_DATA.detectionRules || []).find(r => r.id === ruleId);
      if (rule) {
        rule.name = name;
        rule.description = description;
        rule.log_source = log_source;
        rule.severity = severity;
        rule.condition_json = condition_json;
        rule.yaml_content = yaml_content;
        rule.updated_at = new Date().toISOString();

        showToast(`Local Fallback: Rule ${ruleId} updated.`, 'good');
        
        window.NIRAVAN_DATA.auditLogs.unshift({
          id: Date.now(),
          timestamp: new Date().toISOString(),
          user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
          action: "UPDATE_RULE",
          detail: `Updated properties of rule ${ruleId}.`,
          ip_address: "127.0.0.1"
        });

        renderDetectionPage();
      }
    }
  } else {
    const id = document.getElementById('rule-edit-id')?.value;
    if (!id) {
      showToast("Please specify a unique Rule ID.", "critical");
      return;
    }

    if (window.NIRAVAN_API_ACTIVE) {
      try {
        const res = await fetch(`${window.API_URL}/detection/rules`, {
          method: 'POST',
          headers: {
            ...window.getHeaders(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ id, name, description, log_source, severity, condition_json, yaml_content })
        });
        if (res.ok) {
          showToast(`Rule ${id} created successfully.`, 'good');
          selectedRuleId = id;
          await window.syncFromBackend();
          renderDetectionPage();
        } else if (res.status === 400) {
          showToast(`Error: Rule ID ${id} already exists.`, "critical");
        } else if (res.status === 403) {
          showToast("Access Denied: Action requires analyst privileges.", "critical");
        }
      } catch (err) {
        console.error("Error creating rule:", err);
      }
    } else {
      const existing = (window.NIRAVAN_DATA.detectionRules || []).find(r => r.id === id);
      if (existing) {
        showToast(`Error: Rule ID ${id} already exists locally.`, "critical");
        return;
      }

      const newRuleObj = {
        id, name, description, severity, status: 'enabled', log_source, yaml_content, condition_json,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      if (!window.NIRAVAN_DATA.detectionRules) {
        window.NIRAVAN_DATA.detectionRules = [];
      }
      window.NIRAVAN_DATA.detectionRules.push(newRuleObj);
      selectedRuleId = id;
      showToast(`Local Fallback: Rule ${id} created.`, 'good');
      
      window.NIRAVAN_DATA.auditLogs.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
        action: "CREATE_RULE",
        detail: `Created custom detection rule ${id}: '${name}'.`,
        ip_address: "127.0.0.1"
      });

      renderDetectionPage();
    }
  }
}

async function testRuleDetails(ruleId) {
  const consoleEl = document.getElementById('rule-test-console');
  if (!consoleEl) return;

  consoleEl.innerHTML = `<span style="color:var(--accent-blue)">[DRY-RUN] Running rule scanning over historical event database...</span>`;

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/detection/rules/${ruleId}/test`, {
        method: 'POST',
        headers: window.getHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        renderTestResults(data.matches);
      } else {
        consoleEl.innerHTML = `<span style="color:var(--accent-red)">[ERROR] Failed to run test on server. Status: ${res.status}</span>`;
      }
    } catch (err) {
      consoleEl.innerHTML = `<span style="color:var(--accent-red)">[ERROR] Server communication failure: ${err}</span>`;
    }
  } else {
    const ruleObj = (window.NIRAVAN_DATA.detectionRules || []).find(r => r.id === ruleId);
    if (!ruleObj) {
      consoleEl.innerHTML = `<span style="color:var(--accent-red)">[ERROR] Rule not found locally.</span>`;
      return;
    }

    try {
      const cond = JSON.parse(ruleObj.condition_json);
      const field = cond.field;
      const matches = [];
      const events = window.NIRAVAN_DATA.events.slice(0, 50);
      
      for (const evt of events) {
        let triggered = false;
        if (field === 'type') {
          const val = cond.value;
          if (evt.type === val) {
            const subfield = cond.subfield;
            const threshold = cond.threshold;
            if (subfield && threshold && evt.technical) {
              const match = evt.technical.match(new RegExp(subfield + '=(\\d+)'));
              if (match) {
                const numVal = parseInt(match[1]);
                if (numVal >= threshold) triggered = true;
              } else {
                const match2 = evt.technical.match(/size=(\\d+)MB/);
                if (match2 && subfield === 'size') {
                  const numVal = parseInt(match2[1]);
                  if (numVal >= threshold) triggered = true;
                }
              }
            } else {
              triggered = true;
            }
          }
        } else if (field === 'technical') {
          const containsStr = cond.contains;
          if (containsStr && evt.technical && evt.technical.includes(containsStr)) {
            triggered = true;
          }
        }
        
        if (triggered) {
          matches.push({
            id: evt.id,
            title: evt.title,
            host: evt.host || 'system',
            user: evt.user || 'system',
            timestamp: evt.timestamp.toISOString ? evt.timestamp.toISOString() : new Date(evt.timestamp).toISOString()
          });
        }
      }

      setTimeout(() => {
        renderTestResults(matches);
      }, 500);

    } catch (err) {
      consoleEl.innerHTML = `<span style="color:var(--accent-red)">[ERROR] Parsing condition JSON failed: ${err}</span>`;
    }
  }

  function renderTestResults(matches) {
    if (matches.length === 0) {
      consoleEl.innerHTML = `
        <span style="color:var(--accent-green)">[DRY-RUN COMPLETE] SCANNING FINISHED.</span><br>
        <span style="color:var(--text-muted)">Matched Events: 0 / 50 logs scanned.</span><br>
        No historical alerts matched this rule definition.
      `;
    } else {
      let html = `
        <span style="color:var(--accent-green)">[DRY-RUN COMPLETE] SCANNING FINISHED.</span><br>
        <span style="color:#ffd60a">Matched Events: ${matches.length} / 50 logs scanned.</span><br>
        <div style="display:flex; flex-direction:column; gap:6px; margin-top:8px;">
      `;
      matches.forEach(m => {
        html += `
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); padding:6px; border-radius:3px;">
            <div style="display:flex; justify-content:space-between; font-weight:600; color:var(--text-primary);">
              <span>${m.id} - ${m.title}</span>
              <span style="color:var(--accent-blue); font-size:0.58rem;">${m.host}</span>
            </div>
            <div style="color:var(--text-muted); font-size:0.58rem; margin-top:2px;">User: ${m.user} | Time: ${new Date(m.timestamp).toLocaleTimeString()}</div>
          </div>
        `;
      });
      html += `</div>`;
      consoleEl.innerHTML = html;
    }
  }
}

// Bind to window context
window.renderCasesPage = renderCasesPage;
window.renderCasesList = renderCasesList;
window.renderCaseDetail = renderCaseDetail;
window.handleCaseStatusChange = handleCaseStatusChange;
window.handleCaseAssigneeChange = handleCaseAssigneeChange;
window.handleAddCaseNote = handleAddCaseNote;
window.handleAddCaseEvidence = handleAddCaseEvidence;
window.handleIncidentEscalated = handleIncidentEscalated;
window.switchSettingsTab = switchSettingsTab;
window.renderSettingsSubpage = renderSettingsSubpage;
window.renderDetectionPage = renderDetectionPage;
window.renderDetectionList = renderDetectionList;
window.renderDetectionDetail = renderDetectionDetail;
window.toggleRuleStatus = toggleRuleStatus;
window.showCreateRuleForm = showCreateRuleForm;
window.saveRuleDetails = saveRuleDetails;
window.testRuleDetails = testRuleDetails;

// ── Cyber Intelligence Commands & Threat Graph ──

window.currentConsoleTab = 'deception';

function switchConsoleTab(tabId) {
  window.currentConsoleTab = tabId;
  
  // Hide all panels
  document.querySelectorAll('.console-panel').forEach(panel => {
    panel.style.display = 'none';
  });
  
  // Remove active state from all tab buttons
  document.querySelectorAll('.console-tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  
  // Show target panel
  const targetPanel = document.getElementById(`console-panel-${tabId}`);
  if (targetPanel) {
    targetPanel.style.display = 'flex';
  }
  
  // Set active class on tab button
  const targetBtn = document.getElementById(`console-tab-${tabId}`);
  if (targetBtn) {
    targetBtn.classList.add('active');
  }
  
  // Render subpage content
  if (tabId === 'deception') {
    renderDeceptionHoneypots();
    renderAttributionEngine();
  } else if (tabId === 'graph') {
    initThreatGraph();
  } else if (tabId === 'campaigns') {
    renderCampaigns();
  } else if (tabId === 'vault') {
    renderVault();
  }
}

let graphState = {
  nodes: [],
  edges: [],
  zoom: 1,
  offsetX: 0,
  offsetY: 0,
  draggedNode: null,
  selectedNode: null,
  sourceNode: null,
  targetNode: null,
  blastRadiusIds: new Set(),
  attackPathIds: new Set(),
  attackPathEdgeIds: new Set(),
  isDraggingCanvas: false,
  lastMouseX: 0,
  lastMouseY: 0
};

let graphAnimationId = null;

function initThreatGraph() {
  const canvas = document.getElementById('threat-graph-canvas');
  if (!canvas) return;
  
  const container = canvas.parentElement;
  canvas.width = container.clientWidth;
  canvas.height = 240;
  
  // Load nodes and edges from window.NIRAVAN_DATA
  const rawNodes = window.NIRAVAN_DATA.graphNodes || [];
  const rawEdges = window.NIRAVAN_DATA.graphEdges || [];
  
  const nodeMap = new Map();
  graphState.nodes.forEach(n => nodeMap.set(n.id, n));
  
  graphState.nodes = rawNodes.map(rn => {
    const existing = nodeMap.get(rn.entity_id);
    return {
      id: rn.entity_id,
      entity_type: rn.entity_type,
      name: rn.name,
      risk: rn.risk_weight,
      properties: rn.properties || {},
      x: existing ? existing.x : Math.random() * (canvas.width - 60) + 30,
      y: existing ? existing.y : Math.random() * (canvas.height - 60) + 30,
      vx: 0,
      vy: 0,
      radius: 8 + (rn.risk_weight || 0) * 0.08
    };
  });
  
  graphState.edges = rawEdges.map(re => {
    return {
      source: re.source_id,
      target: re.target_id,
      relationship: re.relationship,
      weight: re.weight || 1.0
    };
  });
  
  if (!graphState.selectedNode) {
    graphState.blastRadiusIds.clear();
    graphState.attackPathIds.clear();
    graphState.attackPathEdgeIds.clear();
  }

  populateVaultDropdowns();

  if (!canvas.dataset.handlersBound) {
    canvas.dataset.handlersBound = 'true';
    
    window.addEventListener('resize', () => {
      if (canvas.offsetParent) {
        canvas.width = container.clientWidth;
        canvas.height = 240;
      }
    });

    canvas.addEventListener('mousedown', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      
      const graphX = (mouseX - graphState.offsetX) / graphState.zoom;
      const graphY = (mouseY - graphState.offsetY) / graphState.zoom;
      
      let clickedNode = null;
      for (let node of graphState.nodes) {
        const dist = Math.hypot(node.x - graphX, node.y - graphY);
        if (dist <= node.radius) {
          clickedNode = node;
          break;
        }
      }
      
      if (clickedNode) {
        graphState.draggedNode = clickedNode;
        graphState.selectedNode = clickedNode;
        showGraphToolbar(clickedNode, e.clientX, e.clientY);
      } else {
        graphState.isDraggingCanvas = true;
        graphState.lastMouseX = mouseX;
        graphState.lastMouseY = mouseY;
        document.getElementById('graph-toolbar').style.display = 'none';
      }
    });
    
    canvas.addEventListener('mousemove', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      
      if (graphState.draggedNode) {
        const graphX = (mouseX - graphState.offsetX) / graphState.zoom;
        const graphY = (mouseY - graphState.offsetY) / graphState.zoom;
        graphState.draggedNode.x = graphX;
        graphState.draggedNode.y = graphY;
        graphState.draggedNode.vx = 0;
        graphState.draggedNode.vy = 0;
      } else if (graphState.isDraggingCanvas) {
        graphState.offsetX += mouseX - graphState.lastMouseX;
        graphState.offsetY += mouseY - graphState.lastMouseY;
        graphState.lastMouseX = mouseX;
        graphState.lastMouseY = mouseY;
      }
    });
    
    canvas.addEventListener('mouseup', () => {
      graphState.draggedNode = null;
      graphState.isDraggingCanvas = false;
    });
    
    canvas.addEventListener('mouseleave', () => {
      graphState.draggedNode = null;
      graphState.isDraggingCanvas = false;
    });
    
    canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      const newZoom = Math.min(Math.max(graphState.zoom * zoomFactor, 0.2), 5);
      
      graphState.offsetX = mouseX - (mouseX - graphState.offsetX) * (newZoom / graphState.zoom);
      graphState.offsetY = mouseY - (mouseY - graphState.offsetY) * (newZoom / graphState.zoom);
      graphState.zoom = newZoom;
    });
    
    canvas.addEventListener('dblclick', (e) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      
      const graphX = (mouseX - graphState.offsetX) / graphState.zoom;
      const graphY = (mouseY - graphState.offsetY) / graphState.zoom;
      
      let clickedNode = null;
      for (let node of graphState.nodes) {
        const dist = Math.hypot(node.x - graphX, node.y - graphY);
        if (dist <= node.radius) {
          clickedNode = node;
          break;
        }
      }
      
      if (clickedNode) {
        openProfileModal(clickedNode.entity_type, clickedNode.id);
      }
    });
  }
  
  if (graphAnimationId) {
    cancelAnimationFrame(graphAnimationId);
  }
  
  function runPhysicsAndRender() {
    const width = canvas.width;
    const height = canvas.height;
    
    // Repel force
    for (let i = 0; i < graphState.nodes.length; i++) {
      let n1 = graphState.nodes[i];
      for (let j = i + 1; j < graphState.nodes.length; j++) {
        let n2 = graphState.nodes[j];
        let dx = n2.x - n1.x;
        let dy = n2.y - n1.y;
        if (dx === 0) dx = 0.1;
        let dist = Math.hypot(dx, dy);
        
        if (dist < 120) {
          let force = 120 / (dist * dist);
          let fx = force * (dx / dist);
          let fy = force * (dy / dist);
          
          if (n1 !== graphState.draggedNode) {
            n1.vx -= fx;
            n1.vy -= fy;
          }
          if (n2 !== graphState.draggedNode) {
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }
    }
    
    // Link forces
    const nodeIndex = new Map();
    graphState.nodes.forEach(n => nodeIndex.set(n.id, n));
    
    graphState.edges.forEach(edge => {
      let s = nodeIndex.get(edge.source);
      let t = nodeIndex.get(edge.target);
      if (s && t) {
        let dx = t.x - s.x;
        let dy = t.y - s.y;
        let dist = Math.hypot(dx, dy);
        if (dist === 0) dist = 0.1;
        
        let desiredDist = 70;
        let force = 0.015 * (dist - desiredDist);
        let fx = force * (dx / dist);
        let fy = force * (dy / dist);
        
        if (s !== graphState.draggedNode) {
          s.vx += fx;
          s.vy += fy;
        }
        if (t !== graphState.draggedNode) {
          t.vx -= fx;
          t.vy -= fy;
        }
      }
    });
    
    // Center pull
    graphState.nodes.forEach(node => {
      if (node === graphState.draggedNode) return;
      
      let cx = width / 2;
      let cy = height / 2;
      node.vx += (cx - node.x) * 0.003;
      node.vy += (cy - node.y) * 0.003;
      
      node.x += node.vx;
      node.y += node.vy;
      
      node.vx *= 0.85;
      node.vy *= 0.85;
      
      node.x = Math.max(node.radius, Math.min(width - node.radius, node.x));
      node.y = Math.max(node.radius, Math.min(height - node.radius, node.y));
    });
    
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, width, height);
    
    ctx.save();
    ctx.translate(graphState.offsetX, graphState.offsetY);
    ctx.scale(graphState.zoom, graphState.zoom);
    
    // Draw links
    graphState.edges.forEach(edge => {
      let s = nodeIndex.get(edge.source);
      let t = nodeIndex.get(edge.target);
      if (s && t) {
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        
        const isPath = graphState.attackPathEdgeIds.has(`${edge.source}->${edge.target}`) ||
                       graphState.attackPathEdgeIds.has(`${edge.target}->${edge.source}`);
        const isBlast = graphState.blastRadiusIds.has(edge.source) && graphState.blastRadiusIds.has(edge.target);
        
        if (isPath) {
          ctx.strokeStyle = '#ff2d55';
          ctx.lineWidth = 2.0;
          ctx.shadowColor = '#ff2d55';
          ctx.shadowBlur = 6;
        } else if (isBlast) {
          ctx.strokeStyle = '#ffd60a';
          ctx.lineWidth = 1.8;
          ctx.shadowColor = '#ffd60a';
          ctx.shadowBlur = 5;
        } else {
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
          ctx.lineWidth = 0.8;
          ctx.shadowBlur = 0;
        }
        ctx.stroke();
      }
    });
    ctx.shadowBlur = 0;
    
    // Draw nodes
    const colors = {
      User: '#bf5af2',
      Asset: '#00d4ff',
      Vulnerability: '#ff9f0a',
      IOC: '#ffd60a',
      Incident: '#ff2d55',
      Case: '#ff453a',
      'Threat Actor': '#ff2d55'
    };
    
    graphState.nodes.forEach(node => {
      const isPathActive = graphState.attackPathIds.size > 0;
      const isBlastActive = graphState.blastRadiusIds.size > 0;
      let isDimmed = false;
      
      if (isPathActive && !graphState.attackPathIds.has(node.id)) {
        isDimmed = true;
      }
      if (isBlastActive && !graphState.blastRadiusIds.has(node.id)) {
        isDimmed = true;
      }
      
      const opacity = isDimmed ? 0.25 : 1.0;
      const color = colors[node.entity_type] || '#8e8e93';
      
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.globalAlpha = opacity;
      
      const isSelected = graphState.selectedNode && graphState.selectedNode.id === node.id;
      const isSrc = graphState.sourceNode && graphState.sourceNode.id === node.id;
      const isTgt = graphState.targetNode && graphState.targetNode.id === node.id;
      
      if (isSelected || isSrc || isTgt) {
        ctx.shadowColor = isSelected ? '#00d4ff' : (isSrc ? '#30d158' : '#ff2d55');
        ctx.shadowBlur = 10;
      } else if (node.risk > 70) {
        ctx.shadowColor = '#ff2d55';
        ctx.shadowBlur = 6;
      } else {
        ctx.shadowBlur = 0;
      }
      ctx.fill();
      ctx.shadowBlur = 0;
      
      if (isSrc || isTgt) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + 3, 0, 2 * Math.PI);
        ctx.strokeStyle = isSrc ? '#30d158' : '#ff2d55';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }
      
      ctx.font = 'bold 7px Space Grotesk';
      ctx.fillStyle = isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.8)';
      ctx.textAlign = 'center';
      
      let label = node.name || node.id;
      if (label.length > 15) {
        label = label.substring(0, 12) + '...';
      }
      ctx.fillText(label, node.x, node.y - node.radius - 3);
      
      ctx.globalAlpha = 1.0;
    });
    
    ctx.restore();
    graphAnimationId = requestAnimationFrame(runPhysicsAndRender);
  }
  
  runPhysicsAndRender();
}

function showGraphToolbar(node, clientX, clientY) {
  const toolbar = document.getElementById('graph-toolbar');
  const label = document.getElementById('graph-selected-label');
  if (!toolbar || !label) return;
  
  label.textContent = `${node.name || node.id} (${node.entity_type.toUpperCase()})`;
  
  document.getElementById('btn-graph-inspect').onclick = () => openProfileModal(node.entity_type, node.id);
  
  document.getElementById('btn-graph-blast').onclick = () => {
    runBlastRadius(node.entity_type, node.id);
  };
  
  document.getElementById('btn-graph-source').onclick = () => {
    graphState.sourceNode = node;
    showToast(`Path source: ${node.name || node.id}`, 'info');
    if (graphState.targetNode) {
      findAttackPath(graphState.sourceNode, graphState.targetNode);
    }
  };
  
  document.getElementById('btn-graph-target').onclick = () => {
    graphState.targetNode = node;
    showToast(`Path target: ${node.name || node.id}`, 'info');
    if (graphState.sourceNode) {
      findAttackPath(graphState.sourceNode, graphState.targetNode);
    }
  };
  
  toolbar.style.display = 'flex';
}

function resetGraphView() {
  graphState.zoom = 1;
  graphState.offsetX = 0;
  graphState.offsetY = 0;
  graphState.selectedNode = null;
  graphState.sourceNode = null;
  graphState.targetNode = null;
  graphState.blastRadiusIds.clear();
  graphState.attackPathIds.clear();
  graphState.attackPathEdgeIds.clear();
  document.getElementById('graph-toolbar').style.display = 'none';
  showToast("Graph view reset", "info");
}

function runBlastRadiusFromUI() {
  if (!graphState.selectedNode) {
    showToast("Please click a node in the graph first to select it.", "info");
    return;
  }
  runBlastRadius(graphState.selectedNode.entity_type, graphState.selectedNode.id);
}

function findAttackPathFromUI() {
  if (!graphState.sourceNode || !graphState.targetNode) {
    showToast("Use graph toolbar buttons to set Source and Target nodes first.", "info");
    return;
  }
  findAttackPath(graphState.sourceNode, graphState.targetNode);
}

async function runBlastRadius(entityType, entityId) {
  showToast(`Computing blast radius for ${entityType} ${entityId}...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      const res = await fetch(`${window.API_URL}/graph/blast-radius/${entityType}/${entityId}`, { headers });
      if (res.ok) {
        const data = await res.json();
        const nodes = data.blast_radius;
        graphState.blastRadiusIds = new Set(nodes.map(n => n.entity_id));
        showToast(`Blast radius contains ${nodes.length} connected entities.`, 'success');
      } else {
        showToast("Error computing blast radius on backend", "bad");
      }
    } catch(err) {
      console.error(err);
      showToast("Connection error during blast radius computation", "bad");
    }
  } else {
    const nodes = traverseBlastRadiusOffline(entityType, entityId);
    graphState.blastRadiusIds = new Set(nodes.map(n => n.entity_id));
    showToast(`Offline Blast Radius: ${nodes.length} connected entities.`, 'success');
  }
}

async function findAttackPath(sourceNode, targetNode) {
  showToast(`Tracing attack path from ${sourceNode.name} to ${targetNode.name}...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      const res = await fetch(`${window.API_URL}/graph/attack-path/${sourceNode.entity_type}/${sourceNode.id}/${targetNode.entity_type}/${targetNode.id}`, { headers });
      if (res.ok) {
        const data = await res.json();
        const path = data.attack_path;
        if (path && path.length > 0) {
          graphState.attackPathIds.clear();
          graphState.attackPathEdgeIds.clear();
          
          for (let i = 0; i < path.length; i++) {
            const step = path[i];
            graphState.attackPathIds.add(step.entity_id);
            if (i > 0) {
              const prev = path[i - 1];
              graphState.attackPathEdgeIds.add(`${prev.entity_id}->${step.entity_id}`);
              graphState.attackPathEdgeIds.add(`${step.entity_id}->${prev.entity_id}`);
            }
          }
          showToast(`Attack path found: ${path.length} hops.`, 'success');
        } else {
          showToast("No direct attack path found between entities.", "info");
        }
      } else {
        showToast("Error tracing attack path on backend", "bad");
      }
    } catch (err) {
      console.error(err);
      showToast("Connection error during pathfinding", "bad");
    }
  } else {
    const path = traverseAttackPathOffline(sourceNode, targetNode);
    if (path && path.length > 0) {
      graphState.attackPathIds.clear();
      graphState.attackPathEdgeIds.clear();
      for (let i = 0; i < path.length; i++) {
        const node = path[i];
        graphState.attackPathIds.add(node.entity_id);
        if (i > 0) {
          const prev = path[i - 1];
          graphState.attackPathEdgeIds.add(`${prev.entity_id}->${node.entity_id}`);
          graphState.attackPathEdgeIds.add(`${node.entity_id}->${prev.entity_id}`);
        }
      }
      showToast(`Offline Attack Path found: ${path.length} hops.`, 'success');
    } else {
      showToast("No offline attack path found between entities.", "info");
    }
  }
}

function traverseBlastRadiusOffline(entityType, entityId) {
  const nodes = window.NIRAVAN_DATA.graphNodes || [];
  const edges = window.NIRAVAN_DATA.graphEdges || [];
  
  const visited = new Set();
  const queue = [entityId];
  visited.add(entityId);
  
  let hopMap = {};
  hopMap[entityId] = 0;
  
  while (queue.length > 0) {
    const currId = queue.shift();
    const currHop = hopMap[currId];
    if (currHop >= 3) continue;
    
    edges.forEach(edge => {
      let neighbor = null;
      if (edge.source_id === currId) neighbor = edge.target_id;
      else if (edge.target_id === currId) neighbor = edge.source_id;
      
      if (neighbor && !visited.has(neighbor)) {
        visited.add(neighbor);
        hopMap[neighbor] = currHop + 1;
        queue.push(neighbor);
      }
    });
  }
  
  return nodes.filter(n => visited.has(n.entity_id));
}

function traverseAttackPathOffline(sourceNode, targetNode) {
  const nodes = window.NIRAVAN_DATA.graphNodes || [];
  const edges = window.NIRAVAN_DATA.graphEdges || [];
  
  const queue = [[sourceNode.id]];
  const visited = new Set();
  visited.add(sourceNode.id);
  
  while (queue.length > 0) {
    const path = queue.shift();
    const currId = path[path.length - 1];
    
    if (currId === targetNode.id) {
      return path.map(id => nodes.find(n => n.entity_id === id)).filter(Boolean);
    }
    
    edges.forEach(edge => {
      let neighbor = null;
      if (edge.source_id === currId) neighbor = edge.target_id;
      else if (edge.target_id === currId) neighbor = edge.source_id;
      
      if (neighbor && !visited.has(neighbor)) {
        visited.add(neighbor);
        queue.push([...path, neighbor]);
      }
    });
  }
  
  return [];
}

async function openProfileModal(entityType, entityId) {
  const modal = document.getElementById('profile-modal');
  if (!modal) return;
  
  const title = document.getElementById('profile-modal-title');
  const subtitle = document.getElementById('profile-modal-subtitle');
  const riskBadge = document.getElementById('profile-modal-risk-badge');
  const body = document.getElementById('profile-modal-body');
  
  title.textContent = `Loading...`;
  subtitle.textContent = `${entityType} Profile`;
  riskBadge.textContent = `RISK: --`;
  body.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--text-muted);">Retrieving intelligence profile...</div>`;
  modal.style.display = 'flex';
  
  document.getElementById('profile-modal-blast-btn').onclick = () => {
    runBlastRadius(entityType, entityId);
    window.closeProfileModal();
  };

  let profile = null;

  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      let route = '';
      if (entityType.toLowerCase() === 'user') route = `user/${entityId}`;
      else if (entityType.toLowerCase() === 'asset') route = `asset/${entityId}`;
      else route = `ip/${entityId}`;
      
      const res = await fetch(`${window.API_URL}/profiles/${route}`, { headers });
      if (res.ok) {
        profile = await res.json();
      }
    } catch(err) {
      console.error(err);
    }
  }
  
  if (!profile) {
    profile = getMockProfileOffline(entityType, entityId);
  }
  
  if (profile) {
    title.textContent = profile.name || profile.ip || profile.email || entityId;
    const score = profile.risk_score !== undefined ? profile.risk_score : (profile.reputation_score !== undefined ? profile.reputation_score : 50);
    
    riskBadge.textContent = `RISK: ${score}`;
    riskBadge.className = `severity-badge ${score >= 75 ? 'critical' : (score >= 40 ? 'medium' : 'low')}`;
    riskBadge.style.background = score >= 75 ? 'rgba(255,45,85,0.15)' : (score >= 40 ? 'rgba(255,214,10,0.15)' : 'rgba(48,209,88,0.15)');
    riskBadge.style.color = score >= 75 ? '#ff2d55' : (score >= 40 ? '#ffd60a' : '#30d158');

    let html = '';
    if (entityType.toLowerCase() === 'user') {
      subtitle.textContent = `User Profile`;
      html = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
          <div><strong style="color:var(--text-muted)">Email:</strong><br>${profile.email}</div>
          <div><strong style="color:var(--text-muted)">Role:</strong><br>${profile.role}</div>
          <div><strong style="color:var(--text-muted)">Department:</strong><br>${profile.department}</div>
          <div><strong style="color:var(--text-muted)">Source Device:</strong><br><code>${profile.source_device}</code></div>
          <div><strong style="color:var(--text-muted)">Successful Logins:</strong><br><span style="color:#30d158">${profile.successful_logins}</span></div>
          <div><strong style="color:var(--text-muted)">Failed Logins:</strong><br><span style="color:#ff2d55">${profile.failed_logins}</span></div>
        </div>
        <div style="margin-top: 6px;">
          <strong style="color:var(--text-muted)">Assigned Cases:</strong><br>
          ${profile.cases_assigned.length > 0 ? profile.cases_assigned.map(c => `<span class="severity-badge medium" style="margin-right:4px; margin-top:2px; display:inline-block">${c}</span>`).join('') : 'None'}
        </div>
        <div style="margin-top: 6px;">
          <strong style="color:var(--text-muted)">Incidents Triggered:</strong><br>
          ${profile.incidents_triggered.length > 0 ? profile.incidents_triggered.map(i => `<span class="severity-badge critical" style="margin-right:4px; margin-top:2px; display:inline-block">${i}</span>`).join('') : 'None'}
        </div>
      `;
    } else if (entityType.toLowerCase() === 'asset') {
      subtitle.textContent = `Asset Profile`;
      html = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
          <div><strong style="color:var(--text-muted)">Asset Name:</strong><br>${profile.name}</div>
          <div><strong style="color:var(--text-muted)">IP Address:</strong><br><code>${profile.ip}</code></div>
          <div><strong style="color:var(--text-muted)">Type:</strong><br>${profile.type}</div>
          <div><strong style="color:var(--text-muted)">Operating System:</strong><br>${profile.operating_system}</div>
          <div><strong style="color:var(--text-muted)">Criticality:</strong><br><span style="color:#ff6b35">${profile.criticality}</span></div>
          <div><strong style="color:var(--text-muted)">Status:</strong><br><span style="color:#30d158">${profile.status}</span></div>
        </div>
        <div style="margin-top: 6px;">
          <strong style="color:var(--text-muted)">Open Services:</strong><br>
          <div style="display:flex; flex-wrap:wrap; gap:4px; margin-top:2px;">
            ${profile.open_services.map(s => `<code style="font-size:0.58rem; background:rgba(255,255,255,0.06); padding:2px 4px; border-radius:3px; border:1px solid rgba(255,255,255,0.08);">${s}</code>`).join('')}
          </div>
        </div>
        <div style="margin-top: 6px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
          <div>
            <strong style="color:var(--text-muted)">Vulnerabilities:</strong><br>
            <span style="color:#ff2d55; font-weight:bold">${profile.vulnerabilities} CVEs</span>
          </div>
          <div>
            <strong style="color:var(--text-muted)">Owner/Contact:</strong><br>
            <span>${profile.owner}</span>
          </div>
        </div>
        <div style="margin-top: 6px;">
          <strong style="color:var(--text-muted)">Associated Incidents:</strong><br>
          ${profile.incidents.length > 0 ? profile.incidents.map(i => `<span class="severity-badge critical" style="margin-right:4px; margin-top:2px; display:inline-block">${i}</span>`).join('') : 'None'}
        </div>
      `;
    } else {
      subtitle.textContent = `IP Intelligence Profile`;
      html = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 8px;">
          <div><strong style="color:var(--text-muted)">IP Address:</strong><br><code>${profile.ip}</code></div>
          <div><strong style="color:var(--text-muted)">Reputation:</strong><br><strong style="color:${profile.reputation === 'Malicious' ? '#ff2d55' : (profile.reputation === 'Suspicious' ? '#ffd60a' : '#30d158')}">${profile.reputation}</strong></div>
          <div><strong style="color:var(--text-muted)">Country:</strong><br>${profile.country}</div>
          <div><strong style="color:var(--text-muted)">Sightings Today:</strong><br>${profile.sightings}</div>
          <div><strong style="color:var(--text-muted)">ISP:</strong><br>${profile.isp}</div>
          <div><strong style="color:var(--text-muted)">ASN:</strong><br><code>${profile.asn}</code></div>
        </div>
        <div style="margin-top: 6px; display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
          <div>
            <strong style="color:var(--text-muted)">Honeypot Touches:</strong><br>
            <span style="color:#bf5af2; font-weight:bold">${profile.honeypot_hits} hits</span>
          </div>
          <div>
            <strong style="color:var(--text-muted)">Associated Campaign:</strong><br>
            <span>${profile.campaign_id ? `<span class="severity-badge critical">${profile.campaign_id}</span>` : 'None'}</span>
          </div>
        </div>
      `;
    }
    body.innerHTML = html;
  } else {
    body.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--color-critical);">Profile not found.</div>`;
  }
}

function closeProfileModal() {
  const modal = document.getElementById('profile-modal');
  if (modal) modal.style.display = 'none';
}

function getMockProfileOffline(entityType, entityId) {
  if (entityType.toLowerCase() === 'user') {
    return {
      email: entityId || "j.smith@corp.com",
      role: entityId === "admin@niravan.ai" ? "admin" : "developer",
      department: entityId === "admin@niravan.ai" ? "Security" : "Engineering",
      source_device: entityId === "admin@niravan.ai" ? "SEC-WORKSTATION-01" : "WORKSTATION-01",
      risk_score: entityId === "admin@niravan.ai" ? 10 : 45,
      failed_logins: entityId === "admin@niravan.ai" ? 1 : 12,
      successful_logins: entityId === "admin@niravan.ai" ? 42 : 110,
      cases_assigned: entityId === "analyst@niravan.ai" ? ["case-9481"] : [],
      incidents_triggered: []
    };
  } else if (entityType.toLowerCase() === 'asset') {
    return {
      id: entityId || "ast-003",
      name: entityId === "ast-001" ? "WIN-DC-01" : (entityId === "ast-004" ? "VPN-GW-01" : "PROD-WEB-01"),
      ip: entityId === "ast-001" ? "10.0.1.10" : (entityId === "ast-004" ? "10.0.3.1" : "10.0.2.50"),
      type: entityId === "ast-001" ? "Domain Controller" : (entityId === "ast-004" ? "Firewall" : "Server"),
      criticality: entityId === "ast-001" ? "High" : "Medium",
      risk_score: entityId === "ast-001" ? 90 : (entityId === "ast-004" ? 60 : 75),
      status: "active",
      vulnerabilities: entityId === "ast-004" ? 3 : 1,
      owner: "admin@niravan.ai",
      operating_system: entityId === "ast-001" ? "Windows Server 2022" : (entityId === "ast-004" ? "PAN-OS" : "Ubuntu 22.04 LTS"),
      open_services: ["22/tcp (SSH)", "80/tcp (HTTP)", "443/tcp (HTTPS)"],
      cases: entityId === "ast-003" ? ["case-9481"] : [],
      incidents: []
    };
  } else {
    return {
      ip: entityId || "185.220.101.47",
      country: entityId === "185.220.101.47" ? "Russia" : "Unknown",
      asn: "AS394711",
      isp: "Tor Exit Node",
      reputation: entityId === "185.220.101.47" ? "Malicious" : "Suspicious",
      reputation_score: entityId === "185.220.101.47" ? 98 : 72,
      sightings: 15,
      honeypot_hits: entityId === "185.220.101.47" ? 8 : 1,
      campaign_id: entityId === "185.220.101.47" ? "cmp-shadowgate" : null
    };
  }
}

function populateVaultDropdowns() {
  const caseSelect = document.getElementById('vault-export-case-select');
  if (!caseSelect) return;
  
  const cases = window.NIRAVAN_DATA.cases || [];
  caseSelect.innerHTML = `<option value="">Select Case to Export...</option>`;
  cases.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = `${c.id} - ${c.title || c.description.substring(0, 30)}`;
    caseSelect.appendChild(opt);
  });
}

function renderCampaigns() {
  const container = document.getElementById('campaign-list-container');
  if (!container) return;
  
  const campaigns = window.NIRAVAN_DATA.campaigns || [];
  if (campaigns.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding: 20px; color: var(--text-muted); font-size: 0.65rem;">No active threat campaigns detected.</div>`;
    return;
  }
  
  container.innerHTML = campaigns.map(c => {
    const stages = c.timeline_stages || {};
    const stageNames = ["recon", "credential_attack", "execution", "lateral_movement"];
    const activeStagesCount = stageNames.filter(name => stages[name] && stages[name].length > 0).length;
    
    const timelineDots = stageNames.map(name => {
      const active = stages[name] && stages[name].length > 0;
      const label = name.replace('_', ' ').toUpperCase();
      return `
        <div style="display:flex; flex-direction:column; align-items:center; gap:4px; flex:1;">
          <div class="campaign-stage-dot ${active ? 'active' : ''}"></div>
          <span style="font-size:0.42rem; text-transform:uppercase; color:${active ? 'var(--text-primary)' : 'var(--text-muted)'}; text-align:center;">${label}</span>
        </div>
      `;
    }).join('');

    return `
      <div class="campaign-card" style="margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <strong style="font-size:0.68rem; color:#ff2d55;">🕵️ ${c.name}</strong>
          <span class="severity-badge critical" style="font-size:0.52rem;">RISK: ${c.risk_score}</span>
        </div>
        <div style="display:flex; gap:12px; font-size:0.58rem; color:var(--text-secondary); margin-bottom:8px;">
          <span>Actor: <strong style="color:#bf5af2">${c.threat_actor}</strong></span>
          <span>Confidence: <strong>${c.confidence}%</strong></span>
          <span>Status: <strong style="color:#30d158">${c.status.toUpperCase()}</strong></span>
        </div>
        
        <div style="display:flex; justify-content:space-between; background:rgba(0,0,0,0.3); padding:8px 4px; border-radius:4px; border:1px solid var(--border-subtle); margin-bottom:8px;">
          ${timelineDots}
        </div>
        
        <div style="font-size:0.55rem; color:var(--text-muted);">
          <div style="font-weight:700; margin-bottom:4px;">Clustered Evidence Alerts:</div>
          <div style="display:flex; flex-direction:column; gap:4px;">
            ${c.incident_ids.map(incId => {
              const matched = (window.NIRAVAN_DATA.events || []).find(ev => ev.id === incId);
              return `
                <div style="display:flex; justify-content:space-between; background:rgba(255,255,255,0.01); border:1px solid rgba(255,255,255,0.05); padding:4px 6px; border-radius:3px;">
                  <span style="color:var(--text-secondary)">⚠️ ${matched ? matched.title : incId}</span>
                  <span style="color:#00d4ff">${incId}</span>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function renderVault() {
  const ledger = document.getElementById('suspicious-activities-table-body');
  const countEl = document.getElementById('vault-evidence-count');
  if (!ledger) return;
  
  const activities = window.NIRAVAN_DATA.suspiciousActivities || [];
  countEl.textContent = `${activities.length} entries`;
  
  if (activities.length === 0) {
    ledger.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:12px; color:var(--text-muted); font-size:0.58rem;">No entries logged in vault</td></tr>`;
    return;
  }
  
  ledger.innerHTML = activities.map(act => {
    const date = new Date(act.when || act.timestamp);
    const timeStr = date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    
    return `
      <tr style="border-bottom:1px solid rgba(255,255,255,0.03); cursor:pointer;" onclick="window.inspectVaultEntry('${act.who}', '${act.where}')">
        <td style="padding:6px 8px; color:var(--accent-blue); font-size:0.58rem;"><code>${act.who}</code></td>
        <td style="padding:6px 8px; color:var(--text-secondary); text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:120px; font-size:0.58rem;">${act.what}</td>
        <td style="padding:6px 8px; color:var(--text-muted); font-size:0.58rem;"><code>${act.where}</code></td>
        <td style="padding:6px 8px; color:var(--text-muted); font-size:0.58rem;">${timeStr}</td>
      </tr>
    `;
  }).join('');
}

function inspectVaultEntry(who, where) {
  if (who && who.includes('@')) {
    openProfileModal('User', who);
  } else if (where && where !== 'UNKNOWN') {
    openProfileModal('Asset', where);
  } else {
    showToast(`Inspecting entry: Target ${who} on host ${where}`, 'info');
  }
}

async function triggerSandboxIngestion() {
  const select = document.getElementById('sandbox-log-type');
  const hostInput = document.getElementById('sandbox-host-input');
  if (!select) return;
  
  const type = select.value;
  const host = hostInput.value.trim() || "WIN-APP-SRV";
  
  let logData = {};
  let sourceType = "";
  if (type === "windows_sysmon_ransomware") {
    sourceType = "windows_sysmon";
    logData = { CommandLine: "vssadmin.exe delete shadows /all /quiet", user: "Administrator" };
  } else if (type === "windows_sysmon_mimikatz") {
    sourceType = "windows_sysmon";
    logData = { CommandLine: "powershell.exe -ep bypass -command sekurlsa::logonpasswords", user: "SYSTEM" };
  } else if (type === "linux_syslog_bruteforce") {
    sourceType = "linux_syslog";
    logData = { message: "Failed password for invalid user root from 185.220.101.78 port 5900 ssh2" };
  } else if (type === "web_nginx_probe") {
    sourceType = "web_nginx";
    logData = { path: "/wp-admin/index.php", status_code: 404, ip_address: "185.220.101.47" };
  } else if (type === "cloud_cloudtrail_denial") {
    sourceType = "cloud_cloudtrail";
    logData = { eventName: "CreateAccessKey", status: "failure", errorCode: "AccessDenied", userArn: "arn:aws:iam::12345:user/backup-bot", user: "backup-bot" };
  }
  
  showToast(`Sending ingestion log payload to telemetry pipeline...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      headers['Content-Type'] = 'application/json';
      const res = await fetch(`${window.API_URL}/ingest/telemetry`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({
          source_type: sourceType,
          host: host,
          log_data: logData
        })
      });
      if (res.ok) {
        const result = await res.json();
        if (result.status === "triggered") {
          showToast(`🚨 TELEMETRY THREAT DETECTED: Escalated incident ${result.incident_id}`, 'critical');
        } else {
          showToast(`Log ingested successfully. No signatures matched.`, 'success');
        }
        await window.syncFromBackend();
        renderAIAnalyst();
        if (window.currentConsoleTab === 'graph') initThreatGraph();
        if (window.currentConsoleTab === 'vault') renderVault();
      } else {
        showToast("Ingestion failed on backend server", "bad");
      }
    } catch(err) {
      console.error(err);
      showToast("Ingestion connection failure", "bad");
    }
  } else {
    ingestTelemetryOffline(sourceType, host, logData);
  }
}

function ingestTelemetryOffline(sourceType, host, logData) {
  let triggered = false;
  let ruleName = "";
  let incTitle = "";
  let mitre = [];
  let description = "";
  let technical = "";
  let category = "";
  let technique = "";
  let severity = "high";
  let user = logData.user || logData.username || "system";
  let ip = logData.ip_address || logData.src_ip || "192.168.1.100";
  
  if (sourceType === "windows_sysmon") {
    const cmd = logData.CommandLine || "";
    if (cmd.includes("vssadmin") && cmd.includes("delete")) {
      triggered = true;
      ruleName = "Ransomware Shadow Copy Deletion (SIG-002)";
      incTitle = "Ransomware Command Activity - Sysmon";
      mitre = ["T1486"];
      description = `Shadow copy deletion command detected on host ${host} in Sysmon log: ${cmd}`;
      technical = `[Sysmon-Event-1] Process: vssadmin.exe\nCommand: ${cmd}`;
      category = "Impact";
      technique = "Data Encrypted for Impact";
      severity = "critical";
    } else if (cmd.includes("sekurlsa") || cmd.includes("mimikatz")) {
      triggered = true;
      ruleName = "PowerShell Credential Dump (SIG-004)";
      incTitle = "Credential Dumping Invocation - Sysmon";
      mitre = ["T1003"];
      description = `Lsass dump tool invocation detected on host ${host} in Sysmon log: ${cmd}`;
      technical = `[Sysmon-Event-1] Process: mimikatz.exe\nCommand: ${cmd}`;
      category = "Credential Access";
      technique = "OS Credential Dumping";
      severity = "critical";
    }
  } else if (sourceType === "linux_syslog") {
    const msg = logData.message || "";
    if (msg.includes("Failed password") || msg.includes("Authentication failure")) {
      triggered = true;
      ruleName = "SSH Brute Force Detection (SIG-001)";
      incTitle = "Failed Authentication Sequence - Syslog";
      mitre = ["T1110.001"];
      description = `Failed SSH login attempt detected on host ${host} in syslog: ${msg}`;
      technical = `[Syslog-Auth] Message: ${msg}\nSource IP: 185.220.101.78\nTarget Host: ${host}`;
      category = "Credential Access";
      technique = "Brute Force";
      severity = "high";
      user = "root";
      ip = "185.220.101.78";
    }
  } else if (sourceType === "web_nginx") {
    const path = logData.path || "";
    if (path.includes("/wp-admin") || path.includes("/admin")) {
      triggered = true;
      ruleName = "Web Honeypot Unauthorized Path Enumerate (SIG-005)";
      incTitle = "Web Vulnerability Scan - Nginx";
      mitre = ["T1046"];
      description = `Probe on administrative path ${path} detected on Web Server ${host}.`;
      technical = `[Nginx-Access] RemoteIP: 185.220.101.47\nPath: ${path}\nHTTP Status: 404`;
      category = "Reconnaissance";
      technique = "Web Vulnerability Scanning";
      severity = "high";
      ip = "185.220.101.47";
    }
  } else if (sourceType === "cloud_cloudtrail") {
    const ev = logData.eventName || "";
    if (ev === "CreateAccessKey" && logData.errorCode === "AccessDenied") {
      triggered = true;
      ruleName = "Cloud Privilege Misuse (SIG-006)";
      incTitle = "Cloud API Call Denial - CloudTrail";
      mitre = ["T1548"];
      description = `CloudTrail API authorization failure: User ${user} denied event ${ev} on ${host}`;
      technical = `[CloudTrail-API] Event: ${ev}\nError: AccessDenied\nUserArn: ${logData.userArn}`;
      category = "Privilege Escalation";
      technique = "Exploitation for Privilege Escalation";
      severity = "high";
    }
  }
  
  if (triggered) {
    const incId = "inc-" + Math.floor(Math.random() * 9000 + 1000);
    const mockIncident = {
      id: incId,
      title: incTitle,
      type: "TELEMETRY_ESCALATION",
      severity: severity,
      description: description,
      status: "open",
      user: user,
      host: host,
      category: category,
      mitre: mitre,
      technique: technique,
      timeStr: "Just now",
      timestamp: new Date().toISOString(),
      technical: technical
    };
    
    window.NIRAVAN_DATA.events.unshift(mockIncident);
    
    const mockAct = {
      id: Date.now(),
      who: user,
      what: incTitle,
      when: new Date().toISOString(),
      where: host,
      why: ruleName,
      how: description
    };
    if (!window.NIRAVAN_DATA.suspiciousActivities) window.NIRAVAN_DATA.suspiciousActivities = [];
    window.NIRAVAN_DATA.suspiciousActivities.unshift(mockAct);
    
    const graphNodes = window.NIRAVAN_DATA.graphNodes || [];
    const graphEdges = window.NIRAVAN_DATA.graphEdges || [];
    
    if (!graphNodes.find(n => n.entity_id === incId)) {
      graphNodes.push({
        entity_type: "Incident",
        entity_id: incId,
        name: incTitle,
        risk_weight: severity === "critical" ? 90 : 75,
        properties: { severity }
      });
    }
    
    const asset = (window.NIRAVAN_DATA.assets || []).find(a => a.name === host || a.id === host);
    if (asset) {
      graphEdges.push({
        source_type: "Asset",
        source_id: asset.id,
        target_type: "Incident",
        target_id: incId,
        relationship: "affected_by",
        weight: 2.0
      });
    }
    
    correlateOfflineCampaigns(ip, incId, mitre[0], host, description);
    
    showToast(`🚨 TELEMETRY THREAT DETECTED: Escalated incident ${incId}`, 'critical');
    
    renderAIAnalyst();
    if (window.currentConsoleTab === 'graph') initThreatGraph();
    if (window.currentConsoleTab === 'vault') renderVault();
  } else {
    showToast(`Log ingested successfully. No signatures matched.`, 'success');
  }
}

function correlateOfflineCampaigns(srcIp, incidentId, mitreStage, host, description) {
  if (!window.NIRAVAN_DATA.campaigns) window.NIRAVAN_DATA.campaigns = [];
  
  let cmp = window.NIRAVAN_DATA.campaigns.find(c => c.id === "cmp-shadowgate");
  if (!cmp) {
    cmp = {
      id: "cmp-shadowgate",
      name: "Operation ShadowGate",
      threat_actor: "APT28 (Fancy Bear)",
      confidence: 80,
      risk_score: 75,
      status: "active",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      incident_ids: [],
      timeline_stages: {}
    };
    window.NIRAVAN_DATA.campaigns.unshift(cmp);
  }
  
  cmp.incident_ids.push(incidentId);
  cmp.updated_at = new Date().toISOString();
  
  const stage = mitreStage === "T1046" ? "recon" : (mitreStage === "T1110.001" ? "credential_attack" : "execution");
  if (!cmp.timeline_stages[stage]) cmp.timeline_stages[stage] = [];
  cmp.timeline_stages[stage].push({
    incident_id: incidentId,
    time: new Date().toISOString(),
    desc: description
  });
  
  cmp.risk_score = Math.min(100, cmp.risk_score + 10);
  cmp.confidence = Math.min(100, cmp.confidence + 5);
}

async function updateRetentionPolicy() {
  const select = document.getElementById('vault-retention-select');
  if (!select) return;
  const days = parseInt(select.value);
  
  showToast(`Updating retention policy to ${days} days...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      headers['Content-Type'] = 'application/json';
      const res = await fetch(`${window.API_URL}/vault/retention`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ days })
      });
      if (res.ok) {
        showToast(`Retention policy updated.`, 'success');
      } else {
        showToast("Failed to update retention on backend", "bad");
      }
    } catch (err) {
      console.error(err);
    }
  } else {
    showToast(`Offline Mode: Retention policy updated to ${days} days.`, 'success');
  }
}

async function purgeVault() {
  const select = document.getElementById('vault-retention-select');
  if (!select) return;
  const days = parseInt(select.value);
  
  if (!confirm(`Are you sure you want to purge all records older than ${days} days? This action is irreversible.`)) return;
  
  showToast(`Initiating vault purge...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      headers['Content-Type'] = 'application/json';
      const res = await fetch(`${window.API_URL}/vault/purge`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ days })
      });
      if (res.ok) {
        const result = await res.json();
        showToast(`Purge complete. Cleaned up ${result.purged_incidents || 0} incidents.`, 'success');
        await window.syncFromBackend();
        renderAIAnalyst();
        if (window.currentConsoleTab === 'vault') renderVault();
      } else {
        showToast("Purge request rejected by administrative policy", "bad");
      }
    } catch(err) {
      console.error(err);
      showToast("Purge request connection failure", "bad");
    }
  } else {
    window.NIRAVAN_DATA.suspiciousActivities = [];
    showToast(`Offline Mode: Purged suspicious activity ledger.`, 'success');
    renderVault();
  }
}

async function exportCasePackage() {
  const select = document.getElementById('vault-export-case-select');
  if (!select || !select.value) {
    showToast("Please select a case to export.", "info");
    return;
  }
  const caseId = select.value;
  showToast(`Packing case dossier for ${caseId}...`, 'info');
  
  let packageData = null;
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      const res = await fetch(`${window.API_URL}/cases/${caseId}/download-package`, { headers });
      if (res.ok) {
        packageData = await res.json();
      }
    } catch (err) {
      console.error(err);
    }
  }
  
  if (!packageData) {
    const c = (window.NIRAVAN_DATA.cases || []).find(x => x.id === caseId);
    const notes = c ? (c.notes || []) : [];
    const evidence = c ? (c.evidence || []) : [];
    packageData = {
      case_id: caseId,
      title: c ? c.title : "Incident Response Escalation",
      description: c ? c.description : "Investigation package",
      severity: c ? c.severity : "high",
      status: c ? c.status : "open",
      created_at: new Date().toISOString(),
      notes: notes,
      evidence: evidence,
      remediation_playbook: [
        "Step 1: Network isolate host in the active subnet.",
        "Step 2: Kill active process handles.",
        "Step 3: Reset passwords."
      ]
    };
  }
  
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(packageData, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `NIRAVAN_CASE_DOSSIER_${caseId}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  showToast(`Dossier package downloaded: NIRAVAN_CASE_DOSSIER_${caseId}.json`, 'success');
}

async function triggerCorrelationScan() {
  showToast(`Running multi-stage correlation scan...`, 'info');
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const headers = window.getHeaders();
      const res = await fetch(`${window.API_URL}/campaigns/correlate`, {
        method: 'POST',
        headers: headers
      });
      if (res.ok) {
        showToast(`Correlation scans completed.`, 'success');
        await window.syncFromBackend();
        renderCampaigns();
      } else {
        showToast("Correlation request rejected", "bad");
      }
    } catch (err) {
      console.error(err);
    }
  } else {
    showToast(`Offline Mode: Correlation scan computed. No new patterns clustered.`, 'success');
  }
}

async function approveSOARActions(caseId) {
  const checkboxes = document.querySelectorAll('#soar-approval-card .soar-action-cb');
  const executedActions = [];
  checkboxes.forEach(cb => {
    if (cb.checked) {
      executedActions.push({
        action: cb.getAttribute('data-action'),
        value: cb.getAttribute('data-value'),
        label: cb.nextElementSibling ? cb.nextElementSibling.textContent.trim() : cb.getAttribute('data-action')
      });
    }
  });

  if (executedActions.length === 0) {
    showToast("No containment actions selected to authorize.", "warning");
    return;
  }

  localStorage.setItem(`niravan_soar_executed_${caseId}`, 'true');
  showToast("Containment actions approved. Deploying blocks...", "info");

  const notesToPost = executedActions.map(act => `[SOAR Action Executed] Authorized and deployed: ${act.label}`);
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      for (const noteText of notesToPost) {
        await fetch(`${window.API_URL}/cases/${caseId}/notes`, {
          method: 'POST',
          headers: {
            ...window.getHeaders(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ note: noteText })
        });
      }
      showToast("Containment deployed successfully. Audit logs updated.", "good");
      await window.syncFromBackend();
      renderCasesList();
      renderCaseDetail(caseId);
    } catch (e) {
      console.error("[NIRAVAN] Error deploying SOAR actions:", e);
      showToast("Error communicating with backend during containment.", "bad");
    }
  } else {
    const c = window.NIRAVAN_DATA.cases.find(item => item.id === caseId);
    if (c) {
      if (!c.notes) c.notes = [];
      executedActions.forEach(act => {
        const noteText = `[SOAR Action Executed] Authorized and deployed: ${act.label}`;
        c.notes.push({
          id: Date.now() + Math.random(),
          author: 'system',
          note: noteText,
          created_at: new Date().toISOString()
        });
        
        window.NIRAVAN_DATA.auditLogs.unshift({
          id: Date.now() + Math.random(),
          timestamp: new Date().toISOString(),
          user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
          action: "SOAR_CONTAINMENT",
          details: `Executed containment: ${act.label}`
        });
      });
      c.updated_at = new Date().toISOString();
      showToast("Local Fallback: Containment executed and logged.", "good");
      renderCasesList();
      renderCaseDetail(caseId);
    }
  }
}

function dismissSOARActions(caseId) {
  localStorage.setItem(`niravan_soar_dismissed_${caseId}`, 'true');
  showToast("Containment recommendations dismissed.", "info");
  renderCaseDetail(caseId);
}

async function generatePDFInvestigationReport(caseId) {
  let caseObj = null;
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/cases/${caseId}`, {
        headers: window.getHeaders()
      });
      if (res.ok) {
        caseObj = await res.json();
      }
    } catch (e) {
      console.error("[NIRAVAN] Error fetching case details for PDF:", e);
    }
  }
  
  if (!caseObj) {
    caseObj = (window.NIRAVAN_DATA.cases || []).find(c => c.id === caseId);
  }

  if (!caseObj) {
    showToast("Case data not found.", "bad");
    return;
  }

  const printWindow = window.open('', '_blank', 'width=900,height=1000');
  if (!printWindow) {
    showToast("Popup blocker prevented opening the dossier window.", "bad");
    return;
  }

  const dateStr = new Date(caseObj.created_at).toLocaleString();
  const notesHtml = (caseObj.notes && caseObj.notes.length > 0)
    ? caseObj.notes.map(note => `
        <div class="note-row">
          <div class="note-meta">
            <span class="note-author">${note.author}</span>
            <span class="note-time">${new Date(note.created_at).toLocaleString()}</span>
          </div>
          <div class="note-content">${note.note}</div>
        </div>
      `).join('')
    : '<div class="no-data">No activity log entries.</div>';

  const evidenceHtml = (caseObj.evidence && caseObj.evidence.length > 0)
    ? caseObj.evidence.map(ev => `
        <div class="evidence-card">
          <div class="evidence-type">${ev.type}</div>
          <div class="evidence-name">${ev.name}</div>
          <div class="evidence-value">${ev.value}</div>
          <div class="evidence-footer">Added by: ${ev.added_by}</div>
        </div>
      `).join('')
    : '<div class="no-data">No evidence registered in vault.</div>';

  let playbooksHtml = '';
  if (caseObj.remediation_playbook && caseObj.remediation_playbook.length > 0) {
    playbooksHtml = caseObj.remediation_playbook.map((step, i) => `<li><strong>Step ${i+1}:</strong> ${step}</li>`).join('');
  } else {
    playbooksHtml = `
      <li><strong>Step 1: Network containment:</strong> Isolate compromised hosts (EDR) and restrict source IPs at the WAF.</li>
      <li><strong>Step 2: Credential isolation:</strong> Revoke OAuth tokens and rotate AD passwords.</li>
      <li><strong>Step 3: Malware remediation:</strong> Kill suspicious parent-child process chains and remove persistent launch items.</li>
    `;
  }

  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>NIRAVAN Core Dossier: \${caseObj.id}</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
      <style>
        :root {
          --primary: #0a0e17;
          --accent: #ffd60a;
          --accent-red: #ff2d55;
          --accent-blue: #00d4ff;
          --border: #e2e8f0;
          --bg-card: #f8fafc;
          --text-primary: #1e293b;
          --text-secondary: #475569;
          --text-muted: #64748b;
        }
        
        @media print {
          body {
            background: #fff !important;
            color: #000 !important;
            padding: 20px !important;
          }
          .no-print {
            display: none !important;
          }
          .page-break {
            page-break-before: always;
          }
        }

        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        body {
          font-family: 'Inter', sans-serif;
          background-color: #fff;
          color: var(--text-primary);
          line-height: 1.5;
          padding: 40px;
        }

        .header {
          border-bottom: 2px solid var(--primary);
          padding-bottom: 20px;
          margin-bottom: 30px;
          display: flex;
          justify-content: space-between;
          align-items: flex-end;
        }

        .header-title-area h1 {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 24px;
          font-weight: 700;
          color: var(--primary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .header-title-area .subtitle {
          font-size: 11px;
          color: var(--text-muted);
          font-family: 'Fira Code', monospace;
          margin-top: 4px;
        }

        .branding {
          text-align: right;
        }

        .branding .logo {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 20px;
          font-weight: 700;
          letter-spacing: 1.5px;
          color: var(--primary);
        }

        .branding .tagline {
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-muted);
          margin-top: 2px;
        }

        .meta-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 30px;
        }

        .meta-card {
          background-color: var(--bg-card);
          border: 1px solid var(--border);
          padding: 12px 16px;
          border-radius: 6px;
        }

        .meta-card label {
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          color: var(--text-muted);
          font-weight: 700;
          display: block;
          margin-bottom: 4px;
        }

        .meta-card span {
          font-size: 13px;
          font-weight: 600;
          color: var(--text-primary);
        }

        .badge-sec {
          display: inline-block;
          font-size: 10px;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
          text-transform: uppercase;
        }

        .badge-sec.high { background: rgba(255, 45, 85, 0.1); color: var(--accent-red); border: 1px solid rgba(255, 45, 85, 0.2); }
        .badge-sec.medium { background: rgba(255, 214, 10, 0.1); color: #b58900; border: 1px solid rgba(255, 214, 10, 0.2); }
        .badge-sec.low { background: rgba(0, 212, 255, 0.1); color: var(--accent-blue); border: 1px solid rgba(0, 212, 255, 0.2); }

        .section-title {
          font-family: 'Space Grotesk', sans-serif;
          font-size: 15px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-bottom: 1px solid var(--border);
          padding-bottom: 6px;
          margin-bottom: 15px;
          margin-top: 30px;
          color: var(--primary);
        }

        .summary-block {
          background-color: var(--bg-card);
          border-left: 4px solid var(--primary);
          padding: 16px;
          font-size: 14px;
          color: var(--text-secondary);
          line-height: 1.6;
          border-radius: 0 6px 6px 0;
          margin-bottom: 25px;
        }

        .evidence-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
          margin-bottom: 25px;
        }

        .evidence-card {
          background-color: var(--bg-card);
          border: 1px solid var(--border);
          padding: 10px 14px;
          border-radius: 6px;
        }

        .evidence-type {
          font-size: 9px;
          font-weight: 700;
          text-transform: uppercase;
          color: var(--accent-blue);
          font-family: 'Fira Code', monospace;
        }

        .evidence-name {
          font-size: 13px;
          font-weight: 600;
          color: var(--text-primary);
          margin-top: 2px;
        }

        .evidence-value {
          font-size: 12px;
          color: var(--text-secondary);
          margin-top: 1px;
          font-family: 'Fira Code', monospace;
          word-break: break-all;
        }

        .evidence-footer {
          font-size: 9px;
          color: var(--text-muted);
          margin-top: 6px;
        }

        .notes-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
          margin-bottom: 25px;
        }

        .note-row {
          border-bottom: 1px solid var(--border);
          padding-bottom: 12px;
        }

        .note-row:last-child {
          border-bottom: none;
        }

        .note-meta {
          display: flex;
          justify-content: space-between;
          font-size: 11px;
          color: var(--text-muted);
          margin-bottom: 4px;
        }

        .note-author {
          font-weight: 700;
          color: var(--text-secondary);
        }

        .note-content {
          font-size: 13px;
          color: var(--text-primary);
          line-height: 1.5;
          white-space: pre-wrap;
        }

        .playbook-list {
          padding-left: 20px;
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        .playbook-list li {
          margin-bottom: 6px;
        }

        .toolbar {
          background-color: var(--primary);
          color: #fff;
          padding: 12px 24px;
          border-radius: 6px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 30px;
        }

        .toolbar-text {
          font-size: 12px;
          font-family: 'Fira Code', monospace;
        }

        .btn-print {
          background-color: var(--accent);
          color: #000;
          border: none;
          padding: 6px 16px;
          font-size: 11px;
          font-weight: 700;
          border-radius: 4px;
          cursor: pointer;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .no-data {
          font-size: 12px;
          color: var(--text-muted);
          text-align: center;
          padding: 20px;
          background: var(--bg-card);
          border: 1px solid var(--border);
          border-radius: 6px;
        }

        footer {
          margin-top: 50px;
          border-top: 1px dashed var(--border);
          padding-top: 15px;
          text-align: center;
          font-size: 10px;
          color: var(--text-muted);
        }
      </style>
    </head>
    <body>
      <div class="toolbar no-print">
        <span class="toolbar-text">NIRAVAN Core Incident Dossier Generator</span>
        <button class="btn-print" onclick="window.print()">Print / Save PDF</button>
      </div>

      <div class="header">
        <div class="header-title-area">
          <h1>Incident Investigation Dossier</h1>
          <div class="subtitle">CASE-ID: \${caseObj.id}</div>
        </div>
        <div class="branding">
          <div class="logo">NIRAVAN</div>
          <div class="tagline">Autonomous Command Core</div>
        </div>
      </div>

      <div class="meta-grid">
        <div class="meta-card">
          <label>Severity</label>
          <span class="badge-sec \${caseObj.severity.toLowerCase()}">\${caseObj.severity}</span>
        </div>
        <div class="meta-card">
          <label>Status</label>
          <span>\${caseObj.status.toUpperCase()}</span>
        </div>
        <div class="meta-card">
          <label>Assignee</label>
          <span>\${caseObj.assignee || 'Unassigned'}</span>
        </div>
        <div class="meta-card">
          <label>Created At</label>
          <span>\${dateStr}</span>
        </div>
      </div>

      <div class="section-title">Case Title & Description</div>
      <div class="summary-block">
        <strong style="display:block; font-size: 15px; margin-bottom: 6px; font-family:'Space Grotesk',sans-serif; color:var(--primary);">\${caseObj.title}</strong>
        \${caseObj.description}
      </div>

      <div class="section-title">Suspicious Artifacts & Evidence Vault</div>
      <div class="evidence-grid">
        \${evidenceHtml}
      </div>

      <div class="page-break"></div>

      <div class="section-title">Autonomous containment playbooks (SOAR)</div>
      <ul class="playbook-list">
        \${playbooksHtml}
      </ul>

      <div class="section-title">Activity Logs & Investigation Timeline</div>
      <div class="notes-list">
        \${notesHtml}
      </div>

      <footer>
        CONFIDENTIAL - INTERNAL SECURITY OPERATIONS ONLY - GENERATED AUTONOMOUSLY BY NIRAVAN COMMAND CORE
      </footer>
    </body>
    </html>
  `);
  printWindow.document.close();
}

// Bind to window context
window.switchConsoleTab = switchConsoleTab;
window.initThreatGraph = initThreatGraph;
window.runBlastRadiusFromUI = runBlastRadiusFromUI;
window.findAttackPathFromUI = findAttackPathFromUI;
window.resetGraphView = resetGraphView;
window.closeProfileModal = closeProfileModal;
window.triggerSandboxIngestion = triggerSandboxIngestion;
window.updateRetentionPolicy = updateRetentionPolicy;
window.purgeVault = purgeVault;
window.exportCasePackage = exportCasePackage;
window.triggerCorrelationScan = triggerCorrelationScan;
window.inspectVaultEntry = inspectVaultEntry;
window.approveSOARActions = approveSOARActions;
window.dismissSOARActions = dismissSOARActions;
window.generatePDFInvestigationReport = generatePDFInvestigationReport;

// Trigger initial default console tab on load
setTimeout(() => {
  switchConsoleTab('deception');
}, 500);


/* ============================================================
   GUARDIAN MODE — Non-Technical User Interface Logic
   ============================================================ */

// Plain-English translator for technical threat types
const PLAIN_ENGLISH_MAP = {
  'brute_force':          { title: '🔐 Someone Is Trying to Guess Passwords', desc: (e) => `Someone is repeatedly trying to guess passwords on your system — ${e.technical ? e.technical.match(/(\d+) attempt/i)?.[1] || 'multiple' : 'multiple'} attempts detected from an unknown location. This is called a Brute Force Attack.`, action: 'Block IP' },
  'credential_stuffing':  { title: '🔑 Stolen Password List Being Used',      desc: (e) => `An attacker is using a list of previously stolen usernames and passwords to try to break into accounts. NIRAVAN has flagged this as high risk.`, action: 'Block IP' },
  'phishing':             { title: '📧 Suspicious Email or Link Detected',     desc: (e) => `A phishing attempt was detected — someone is trying to trick your users into revealing passwords or clicking malicious links.`, action: 'Block Source' },
  'malware':              { title: '🦠 Harmful Software Detected',             desc: (e) => `NIRAVAN detected malicious software (malware) attempting to run on ${e.host || 'a system'}. This could steal data or damage your network.`, action: 'Isolate Host' },
  'ransomware':           { title: '💀 Ransomware Attack in Progress!',        desc: (e) => `A ransomware attack has been detected on ${e.host || 'your system'}. This type of attack encrypts your data and demands payment. Immediate action required!`, action: 'Isolate Host' },
  'lateral_movement':     { title: '🕵️ Intruder Moving Through Your Network', desc: (e) => `An attacker who already has access is moving between systems inside your network, looking for sensitive data. This must be stopped immediately.`, action: 'Block Movement' },
  'data_exfiltration':    { title: '📤 Data is Being Stolen Right Now',        desc: (e) => `Sensitive data is being copied and sent to an external location. This could be student records, financial data, or staff information.`, action: 'Block Transfer' },
  'privilege_escalation': { title: '⬆️ Someone Gained Unauthorized Admin Access', desc: (e) => `An account on ${e.host || 'your system'} has gained administrator-level access it should not have. This is very dangerous.`, action: 'Revoke Access' },
  'sql_injection':        { title: '💉 Database Attack Detected',              desc: (e) => `Someone is trying to attack your database using malicious code (SQL Injection). This could expose all stored records.`, action: 'Block IP' },
  'port_scan':            { title: '🔍 Someone Is Mapping Your Network',       desc: (e) => `An external party is scanning your network to find open doors and weak points. This is usually the first step before an attack.`, action: 'Block IP' },
  'ddos':                 { title: '🌊 Your System is Being Flooded with Traffic', desc: (e) => `Someone is sending massive amounts of fake traffic to overwhelm your system and make it go offline (DDoS Attack).`, action: 'Enable Shield' },
  'insider_threat':       { title: '👤 Unusual Activity from Inside Your Organization', desc: (e) => `A user account within your organization is behaving suspiciously — accessing data outside normal working hours or downloading large amounts of files.`, action: 'Restrict Access' },
  'honeypot':             { title: '🍯 Attacker Touched a Hidden Trap',        desc: (e) => `NIRAVAN detected someone touching a digital decoy (honeypot). Only attackers and bots would access this hidden resource — this confirms a real attacker is probing your system.`, action: 'Block IP' },
};

function getPlainEnglish(evt) {
  const type = (evt.type || '').toLowerCase();
  for (const [key, val] of Object.entries(PLAIN_ENGLISH_MAP)) {
    if (type.includes(key)) return { ...val, desc: val.desc(evt) };
  }
  // Fallback: generate a readable description
  const titleMap = {
    critical: '🔴 Critical Security Alert Detected',
    high:     '🟠 High-Risk Activity Detected',
    medium:   '🟡 Suspicious Activity Detected',
    low:      '🟢 Low-Level Security Notice',
  };
  return {
    title: titleMap[evt.severity] || '⚠️ Security Event Detected',
    desc: `NIRAVAN detected a security event on ${evt.host || 'your network'}: ${evt.description}`,
    action: 'Review'
  };
}

// Guardian state
let guardianCurrentThreat = null;
let guardianActivityLog = [];
let guardianLoginBlocks  = 0;
let guardianPhishBlocks  = 0;

function renderGuardianMode() {
  updateGuardianRing();
  renderGuardianCards();
  renderGuardianActivityFeed();
  renderKnowledgeBase();
  checkForActiveThreat();
  // Start auto-refresh of activity feed if not already running
  if (!window._guardianInterval) {
    window._guardianInterval = setInterval(() => {
      if (currentPage === 'guardian') {
        checkForActiveThreat();
        renderGuardianCards();
      }
    }, 4000);
  }
}

function updateGuardianRing() {
  const qri   = window.NIRAVAN_ENGINE ? window.NIRAVAN_ENGINE.calculateQRI() : 50;
  const score = Math.max(0, 100 - qri); // flip: lower risk = higher protection
  const arc   = document.getElementById('guardian-ring-arc');
  const scoreEl = document.getElementById('guardian-ring-score');
  const labelEl = document.getElementById('guardian-ring-label');
  const statusBar = document.getElementById('guardian-status-bar');
  const statusTitle = document.getElementById('guardian-status-title');
  const statusSub   = document.getElementById('guardian-status-sub');
  const statusIcon  = document.getElementById('guardian-status-icon');
  const circumference = 2 * Math.PI * 28; // r=28

  if (arc) {
    const filled = (score / 100) * circumference;
    arc.setAttribute('stroke-dasharray', `${filled} ${circumference}`);
    if (score >= 70)      { arc.setAttribute('stroke', '#30d158'); }
    else if (score >= 45) { arc.setAttribute('stroke', '#ffd60a'); }
    else                  { arc.setAttribute('stroke', '#ff2d55'); }
  }
  if (scoreEl) scoreEl.textContent = score;

  if (score >= 70) {
    if (labelEl)     labelEl.textContent  = 'PROTECTED';
    if (statusBar)   { statusBar.classList.remove('at-risk','under-attack'); }
    if (statusTitle) statusTitle.textContent = 'Your System is Protected';
    if (statusSub)   statusSub.textContent   = 'NIRAVAN is actively monitoring all activity \u2014 no threats require your action right now.';
    if (statusIcon)  statusIcon.textContent  = '\uD83D\uDEE1\uFE0F';
  } else if (score >= 45) {
    if (labelEl)     labelEl.textContent  = 'AT RISK';
    if (statusBar)   { statusBar.classList.remove('under-attack'); statusBar.classList.add('at-risk'); }
    if (statusTitle) statusTitle.textContent = '\u26A0\uFE0F Your System Needs Attention';
    if (statusSub)   statusSub.textContent   = 'Suspicious activity has been detected. Review the alerts below and take action.';
    if (statusIcon)  statusIcon.textContent  = '\u26A0\uFE0F';
  } else {
    if (labelEl)     labelEl.textContent  = 'UNDER ATTACK';
    if (statusBar)   { statusBar.classList.remove('at-risk'); statusBar.classList.add('under-attack'); }
    if (statusTitle) statusTitle.textContent = '\uD83D\uDEA8 Active Threat \u2014 Immediate Action Required';
    if (statusSub)   statusSub.textContent   = 'A serious security threat is happening right now. Use the actions below to protect your system immediately.';
    if (statusIcon)  statusIcon.textContent  = '\uD83D\uDEA8';
  }
}

function renderGuardianCards() {
  const data = window.NIRAVAN_DATA;
  // Count login-related blocks
  const loginEvts = data.events.filter(e =>
    (e.type||'').toLowerCase().includes('brute') ||
    (e.type||'').toLowerCase().includes('credential') ||
    (e.type||'').toLowerCase().includes('auth')
  ).length;
  const phishEvts = data.events.filter(e =>
    (e.type||'').toLowerCase().includes('phish') ||
    (e.type||'').toLowerCase().includes('scan') ||
    (e.type||'').toLowerCase().includes('ddos')
  ).length;
  guardianLoginBlocks = loginEvts + data.stats.blockedEvents;
  guardianPhishBlocks = phishEvts + Math.floor(data.stats.blockedEvents * 0.4);

  animateCounter('gc-logins', guardianLoginBlocks);
  animateCounter('gc-phishing', guardianPhishBlocks);
  animateCounter('gc-data-access', data.assets ? data.assets.length : 247);
}

function checkForActiveThreat() {
  const data   = window.NIRAVAN_DATA;
  const events = data.events || [];
  // Find the most recent critical/high event not yet acknowledged
  const threat = events.find(e => e.severity === 'critical' || e.severity === 'high');
  const panel  = document.getElementById('guardian-threat-panel');
  if (!threat || !panel) return;

  guardianCurrentThreat = threat;
  const pe = getPlainEnglish(threat);

  const explainEl = document.getElementById('gtp-explain');
  const metaEl    = document.getElementById('gtp-meta');
  const timeEl    = document.getElementById('gtp-time');
  const blockBtn  = document.getElementById('gtp-block-btn');

  if (explainEl) explainEl.textContent = pe.desc;
  if (metaEl)    metaEl.innerHTML = `\uD83C\uDF10 Source IP: <strong>${threat.actor ? threat.actor.origin : 'Unknown'}</strong> &nbsp;|&nbsp; \uD83D\uDDA5\uFE0F Affected: <strong>${threat.host || 'Network'}</strong> &nbsp;|&nbsp; \u26A1 Severity: <strong style="color:${threat.severity==='critical'?'#ff2d55':'#ff6b35'}">${threat.severity.toUpperCase()}</strong>`;
  if (timeEl)    timeEl.textContent = threat.timeStr || new Date().toLocaleTimeString();
  if (blockBtn)  { blockBtn.disabled = false; blockBtn.textContent = `\uD83D\uDEAB ${pe.action} — 1 Click`; }
  panel.style.display = 'block';

  // Also add to activity feed
  addGuardianActivity(pe.title, pe.desc, threat.severity, pe.action, threat);
}

function addGuardianActivity(title, desc, severity, actionLabel, evt) {
  const feed = document.getElementById('guardian-activity-feed');
  if (!feed) return;
  const evtId = evt ? evt.id : Date.now();
  // Avoid duplicates
  if (document.getElementById(`gai-${evtId}`)) return;

  const item = document.createElement('div');
  item.className = 'guardian-activity-item';
  item.id = `gai-${evtId}`;
  item.innerHTML = `
    <div class="gai-sev ${severity}"></div>
    <div class="gai-body">
      <div class="gai-title">${title}</div>
      <div class="gai-desc">${desc.substring(0, 140)}${desc.length > 140 ? '...' : ''}</div>
    </div>
    <div class="gai-time">${new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</div>
    <button class="gai-action-btn" id="gai-btn-${evtId}" onclick="guardianQuickBlockItem(this, '${evtId}')">\uD83D\uDEAB ${actionLabel || 'Block'}</button>
  `;
  feed.insertBefore(item, feed.firstChild);
  if (feed.children.length > 8) feed.removeChild(feed.lastChild);
}

function renderGuardianActivityFeed() {
  const data = window.NIRAVAN_DATA;
  const events = (data.events || []).slice(0, 6);
  events.forEach(evt => {
    const pe = getPlainEnglish(evt);
    addGuardianActivity(pe.title, pe.desc, evt.severity, pe.action, evt);
  });
}

// ── Guardian One-Click Actions ──

function guardianBlockThreat() {
  const btn = document.getElementById('gtp-block-btn');
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = '\u2705 Blocked — System Protected';
  const panel = document.getElementById('guardian-threat-panel');

  if (guardianCurrentThreat) {
    const threatIP = guardianCurrentThreat.ip_address || (guardianCurrentThreat.technical ? (guardianCurrentThreat.technical.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) || [])[0] : '');
    const threatHost = guardianCurrentThreat.host;
    if (threatIP) {
      window.triggerMitigationBlockIP(threatIP, `Guardian Mode: Blocked active threat '${guardianCurrentThreat.title}'`);
    }
    if (threatHost) {
      window.triggerMitigationIsolateHost(threatHost, `Guardian Mode: Isolated affected host for '${guardianCurrentThreat.title}'`);
    }
  } else {
    showToast('\uD83D\uDEAB Threat blocked! NIRAVAN has automatically blocked the suspicious IP and isolated the affected system.', 'good');
    window.NIRAVAN_DATA.stats.blockedEvents++;
  }

  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_BLOCK',
    detail: `Guardian Mode: User blocked threat '${guardianCurrentThreat ? guardianCurrentThreat.title : 'active threat'}' with one-click action.`,
    ip_address: '127.0.0.1'
  });

  renderGuardianCards();

  // Hide panel after 3s
  setTimeout(() => {
    if (panel) { panel.style.display = 'none'; }
    updateGuardianRing();
  }, 3000);
}

window.toggleGuardianAdvancedView = function() {
  const el = document.getElementById('gtp-raw-log');
  if (!el) return;
  if (el.style.display === 'none') {
    el.style.display = 'block';
    if (guardianCurrentThreat) {
      el.textContent = guardianCurrentThreat.technical || JSON.stringify(guardianCurrentThreat.raw_payload || guardianCurrentThreat, null, 2);
    } else {
      el.textContent = 'No active threat details.';
    }
  } else {
    el.style.display = 'none';
  }
};

function guardianNotifyIT() {
  showToast('\uD83D\udce3 IT Team notified via email and SMS — they will respond within 15 minutes.', 'good');
  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_NOTIFY',
    detail: 'Guardian Mode: IT Team notification triggered by non-technical user.',
    ip_address: '127.0.0.1'
  });
}

function guardianMarkSafe() {
  const panel = document.getElementById('guardian-threat-panel');
  if (panel) panel.style.display = 'none';
  showToast('\u2705 Event marked as safe and added to whitelist. NIRAVAN will monitor for recurrence.', 'good');
}

function guardianBlockAllSuspicious() {
  const btn = document.getElementById('gqa-block-all');
  if (!btn || btn.classList.contains('activated')) return;
  btn.classList.add('activated');
  btn.textContent = '\u2705 All Blocked';
  const count = window.NIRAVAN_DATA.events.filter(e => e.severity === 'critical' || e.severity === 'high').length;
  window.NIRAVAN_DATA.stats.blockedEvents += count;
  showToast(`\uD83D\uDEAB ${count} suspicious IPs blocked automatically. NIRAVAN firewall rules updated.`, 'good');
  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(), timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_BLOCK_ALL', detail: `Guardian Mode: Bulk blocked ${count} suspicious IPs.`,
    ip_address: '127.0.0.1'
  });
  renderGuardianCards();
  updateGuardianRing();
}

function guardianEnablePhishing() {
  const btn = document.getElementById('gqa-phishing');
  if (!btn || btn.classList.contains('activated')) return;
  btn.classList.add('activated');
  btn.textContent = '\u2705 Phishing Shield Active';
  showToast('\uD83D\udce7 Phishing Shield enabled. All incoming connections are now screened for phishing patterns.', 'good');
  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(), timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_PHISHING_SHIELD', detail: 'Guardian Mode: Phishing Shield activated by user.',
    ip_address: '127.0.0.1'
  });
}

function guardianLockdown() {
  const btn = document.getElementById('gqa-lockdown');
  if (!btn || btn.classList.contains('activated')) return;
  btn.classList.add('activated');
  btn.textContent = '\uD83D\uDD12 System Locked';
  showToast('\uD83D\uDD12 System Lockdown activated! All external connections blocked. Only internal traffic allowed. Admin has full control.', 'critical');
  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(), timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_LOCKDOWN', detail: 'Guardian Mode: Emergency System Lockdown activated by user.',
    ip_address: '127.0.0.1'
  });
}

function guardianGenerateReport() {
  showToast('\uD83D\udcc4 Safety Report generated and sent to your email. A copy is available in Executive Reports.', 'good');
  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(), timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_REPORT', detail: 'Guardian Mode: Safety Report generated and emailed to administrator.',
    ip_address: '127.0.0.1'
  });
}

function guardianQuickBlockItem(btn, evtId) {
  if (!btn || btn.classList.contains('blocked')) return;
  btn.classList.add('blocked');
  btn.textContent = '\u2705 Blocked';
  
  if (window.NIRAVAN_DATA && window.NIRAVAN_DATA.events) {
    const evt = window.NIRAVAN_DATA.events.find(e => String(e.id) === String(evtId));
    if (evt) {
      const threatIP = evt.ip_address || (evt.technical ? (evt.technical.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) || [])[0] : '');
      const threatHost = evt.host;
      if (threatIP) window.triggerMitigationBlockIP(threatIP, `Guardian: Quick block from feed`);
      if (threatHost) window.triggerMitigationIsolateHost(threatHost, `Guardian: Quick isolate from feed`);
    } else {
      window.NIRAVAN_DATA.stats.blockedEvents++;
      showToast('\uD83D\uDEAB Blocked! The suspicious source has been blocked.', 'good');
    }
  } else {
    window.NIRAVAN_DATA.stats.blockedEvents++;
    showToast('\uD83D\uDEAB Blocked! The suspicious source has been blocked.', 'good');
  }

  window.NIRAVAN_DATA.auditLogs.unshift({
    id: Date.now(), timestamp: new Date().toISOString(),
    user_email: localStorage.getItem('niravan_user_email') || 'admin@niravan.ai',
    action: 'GUARDIAN_ITEM_BLOCK', detail: `Guardian Mode: User quick-blocked event ${evtId}.`,
    ip_address: '127.0.0.1'
  });
}

// ── Attack Knowledge Encyclopedia ──
const ATTACK_KNOWLEDGE = [
  {
    icon: '\uD83C\uDFA3',
    title: 'Phishing Attack',
    severity: 'critical',
    what: 'Attackers send fake emails or create fake websites that look real, tricking your staff into typing their passwords or downloading harmful files.',
    detect: 'NIRAVAN monitors all email patterns, suspicious link clicks, and fake login page visits in real-time.',
    action: 'Never click links in unexpected emails. NIRAVAN will block known phishing sites automatically.',
  },
  {
    icon: '\uD83D\uDD11',
    title: 'Password Guessing (Brute Force)',
    severity: 'critical',
    what: 'An attacker uses software to automatically try thousands of passwords per minute to break into accounts.',
    detect: 'NIRAVAN detects when more than 5 login failures happen in 60 seconds and immediately blocks the source.',
    action: 'Use strong passwords and enable two-factor authentication. NIRAVAN blocks the attacker\'s IP automatically.',
  },
  {
    icon: '\uD83D\uDC80',
    title: 'Ransomware',
    severity: 'critical',
    what: 'Malicious software that encrypts all your files and demands payment to unlock them. Can destroy years of data in minutes.',
    detect: 'NIRAVAN detects mass file encryption behavior and shadow copy deletion — hallmarks of ransomware — within seconds.',
    action: 'NIRAVAN will isolate the infected system immediately. Do not pay any ransom. Contact your IT team.',
  },
  {
    icon: '\uD83D\uDCE4',
    title: 'Data Theft (Exfiltration)',
    severity: 'critical',
    what: 'An attacker secretly copies your sensitive data (student records, financial data, personal information) and sends it outside your network.',
    detect: 'NIRAVAN tracks all large data transfers and flags unusual destinations — especially to foreign IP addresses.',
    action: 'Block the transfer immediately using the one-click action. Change all administrator passwords.',
  },
  {
    icon: '\u2696\uFE0F',
    title: 'Account Takeover',
    severity: 'high',
    what: 'An attacker gains access to a real user account (often through phishing or weak passwords) and pretends to be that person.',
    detect: 'NIRAVAN detects logins from unusual locations, new devices, or at unusual hours and triggers alerts instantly.',
    action: 'Force a password reset on the affected account. NIRAVAN will log all actions made under the compromised account.',
  },
  {
    icon: '\uD83E\uDDA0',
    title: 'Malware (Virus / Trojan)',
    severity: 'high',
    what: 'Harmful software secretly installed on a computer that can steal data, spy on users, or give attackers remote access to your systems.',
    detect: 'NIRAVAN monitors all running processes and file system changes, flagging known malware signatures.',
    action: 'Isolate the infected device from the network. NIRAVAN will quarantine malicious files automatically.',
  },
  {
    icon: '\uD83D\uDD0D',
    title: 'Network Scanning (Reconnaissance)',
    severity: 'medium',
    what: 'Attackers scan your network to find which systems are running, what software is installed, and which ports are open — preparing for a real attack.',
    detect: 'NIRAVAN detects port scan patterns and unusual connection attempts across your network perimeter.',
    action: 'Block the scanning IP. NIRAVAN logs all scan activity and builds an attacker profile automatically.',
  },
  {
    icon: '\uD83D\uDCBB',
    title: 'SQL Injection (Database Attack)',
    severity: 'high',
    what: 'Attackers send specially crafted input to your website or app to manipulate your database — potentially accessing all student or staff records.',
    detect: 'NIRAVAN\'s web traffic analyzer detects SQL injection patterns in all HTTP requests.',
    action: 'The malicious request is automatically blocked by NIRAVAN. Update your web application software.',
  },
  {
    icon: '\uD83C\uDF0A',
    title: 'DDoS Attack (Network Flood)',
    severity: 'high',
    what: 'Attackers send millions of fake requests to your website or server, overwhelming it and making it unavailable to real users.',
    detect: 'NIRAVAN monitors traffic volume and detects sudden floods — automatically triggering rate-limiting defenses.',
    action: 'Enable the DDoS Shield from Quick Actions above. NIRAVAN will filter malicious traffic automatically.',
  },
  {
    icon: '\uD83E\uDD47',
    title: 'Insider Threat',
    severity: 'high',
    what: 'A current or former staff member intentionally or accidentally misuses their access — downloading sensitive files, accessing unauthorized records, or sabotaging systems.',
    detect: 'NIRAVAN tracks all data access patterns and flags anomalies — like a teacher accessing financial records at midnight.',
    action: 'Restrict the suspicious account\'s access immediately. Review all recent actions in the audit trail.',
  },
  {
    icon: '\uD83C\uDF65',
    title: 'Man-in-the-Middle (Eavesdropping)',
    severity: 'medium',
    what: 'An attacker secretly intercepts the communication between your staff and your servers — reading emails, passwords, and confidential messages.',
    detect: 'NIRAVAN monitors for certificate anomalies and detects unauthorized SSL interception on your network.',
    action: 'Ensure all systems use HTTPS. NIRAVAN will flag any unencrypted sensitive data transmission.',
  },
  {
    icon: '\uD83D\uDEAA',
    title: 'Unauthorized Access',
    severity: 'medium',
    what: 'Someone accessing systems, data, or areas of your network they are not supposed to — even if they are already inside the organization.',
    detect: 'NIRAVAN\'s access control monitoring tracks who accesses what, when, and from where — flagging any policy violations.',
    action: 'Review the Access Logs in the Settings page. Revoke the unauthorized permissions immediately.',
  },
];

function renderKnowledgeBase() {
  const el = document.getElementById('guardian-knowledge-grid');
  if (!el) return;
  el.innerHTML = ATTACK_KNOWLEDGE.map(k => `
    <div class="knowledge-card">
      <div class="kc-header">
        <span class="kc-icon">${k.icon}</span>
        <span class="kc-title">${k.title}</span>
        <span class="kc-severity ${k.severity}">${k.severity.toUpperCase()}</span>
      </div>
      <div class="kc-what">${k.what}</div>
      <div class="kc-detect">🔍 How NIRAVAN detects it: ${k.detect}</div>
      <div class="kc-action">✅ What to do: ${k.action}</div>
    </div>
  `).join('');
}

// Hook into real-time engine — notify Guardian Mode when new critical event fires
const _origGenerateAndAddEvent = window.generateAndAddEvent;
const _guardianEventHook = function() {
  const data = window.NIRAVAN_DATA;
  if (data && data.events && data.events.length > 0) {
    const newest = data.events[0];
    if (newest && (newest.severity === 'critical' || newest.severity === 'high')) {
      if (currentPage === 'guardian') {
        checkForActiveThreat();
        updateGuardianRing();
        renderGuardianCards();
      }
      // Even if not on guardian page, trigger guardian notification toast
      const pe = getPlainEnglish(newest);
      if (newest.severity === 'critical') {
        showToast(`\uD83D\uDEA8 Guardian Alert: ${pe.title} \u2014 Switch to Guardian Mode to act.`, 'critical');
      }
    }
  }
};

// Patch the real-time engine to also fire guardian hooks
const _origStartRTE = startRealTimeEngine;

// Expose guardian functions globally
window.guardianBlockThreat        = guardianBlockThreat;
window.guardianNotifyIT           = guardianNotifyIT;
window.guardianMarkSafe           = guardianMarkSafe;
window.guardianBlockAllSuspicious = guardianBlockAllSuspicious;
window.guardianEnablePhishing     = guardianEnablePhishing;
window.guardianLockdown           = guardianLockdown;
window.guardianGenerateReport     = guardianGenerateReport;
window.guardianQuickBlockItem     = guardianQuickBlockItem;

// Schedule guardian background watcher (runs even when not on guardian page)
setTimeout(() => {
  setInterval(() => {
    if (window.NIRAVAN_DATA) {
      _guardianEventHook();
    }
  }, 8000);
}, 3000);

// ── Active ASM Discovery Scanning & Mitigation Actions (SOAR Upgrade) ──

window.triggerASMAScan = async function() {
  const targetInput = document.getElementById('asm-scan-target');
  if (!targetInput) return;
  const target = targetInput.value.trim();
  if (!target) {
    showToast('Please enter a target domain or IP to scan.', 'info');
    return;
  }
  
  const progressDiv = document.getElementById('asm-scan-progress');
  const statusSpan = document.getElementById('asm-progress-status');
  const scanBtn = document.getElementById('asm-scan-btn');
  
  if (progressDiv) {
    progressDiv.style.display = 'flex';
    progressDiv.style.marginTop = '10px';
    progressDiv.style.fontSize = '0.65rem';
    progressDiv.style.color = 'var(--text-muted)';
    progressDiv.style.alignItems = 'center';
    progressDiv.style.gap = '8px';
  }
  if (statusSpan) statusSpan.textContent = 'Contacting security scanner & queuing job...';
  if (scanBtn) scanBtn.disabled = true;
  
  showToast(`ASM scan queued for ${target}`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const token = localStorage.getItem('niravan_token');
      const res = await fetch(`${window.API_URL}/asm/scan-network`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ target })
      });
      if (!res.ok) throw new Error('API request failed');
      const data = await res.json();
      const jobId = data.job_id;
      
      // Start polling
      let attempts = 0;
      const interval = setInterval(async () => {
        attempts++;
        if (statusSpan) statusSpan.textContent = `Scanning in progress (Job: ${jobId}, check ${attempts})...`;
        try {
          const jobRes = await fetch(`${window.API_URL}/jobs/${jobId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          if (jobRes.ok) {
            const jobData = await jobRes.json();
            if (jobData.status === 'completed') {
              clearInterval(interval);
              if (progressDiv) progressDiv.style.display = 'none';
              if (scanBtn) scanBtn.disabled = false;
              showToast(`Scan completed for ${target}! Asset context updated.`, 'good');
              targetInput.value = '';
              
              // Force refresh dashboard/assets list
              if (window.NIRAVAN_API_ACTIVE) {
                const updatedAssetsRes = await fetch(`${window.API_URL}/assets`, {
                  headers: { 'Authorization': `Bearer ${token}` }
                });
                if (updatedAssetsRes.ok) {
                  window.NIRAVAN_DATA.assets = await updatedAssetsRes.ok ? await updatedAssetsRes.json() : window.NIRAVAN_DATA.assets;
                  if (typeof renderAttackSurface === 'function') renderAttackSurface();
                }
              }
            } else if (jobData.status === 'failed') {
              clearInterval(interval);
              if (progressDiv) progressDiv.style.display = 'none';
              if (scanBtn) scanBtn.disabled = false;
              showToast(`Scan failed: ${jobData.result?.error || 'Unknown scanner error'}`, 'critical');
            }
          }
        } catch (err) {
          console.error(err);
        }
      }, 2000);
      
    } catch (err) {
      console.error(err);
      if (progressDiv) progressDiv.style.display = 'none';
      if (scanBtn) scanBtn.disabled = false;
      showToast('Error executing scan on backend.', 'critical');
    }
  } else {
    // Offline Mock Mode fallback
    setTimeout(() => {
      if (statusSpan) statusSpan.textContent = 'Resolving DNS records and port-mapping...';
      setTimeout(() => {
        if (statusSpan) statusSpan.textContent = 'Identifying web technology fingerprint...';
        setTimeout(() => {
          if (progressDiv) progressDiv.style.display = 'none';
          if (scanBtn) scanBtn.disabled = false;
          showToast(`Mock Scan Completed: Discovered Nginx/FastAPI server on ${target}.`, 'good');
          targetInput.value = '';
          
          if (window.NIRAVAN_DATA && window.NIRAVAN_DATA.assets) {
            const newAsset = {
              id: `ast-${Math.floor(Math.random()*9000)+1000}`,
              name: target,
              ip: '192.168.10.45',
              type: 'server',
              criticality: 'high',
              riskScore: 78,
              status: 'active',
              vulnerabilities: 4,
              owner: 'Department Admin',
              os: 'Linux Ubuntu',
              services: '80,443,22'
            };
            window.NIRAVAN_DATA.assets.unshift(newAsset);
            if (typeof renderAttackSurface === 'function') {
              renderAttackSurface();
            }
          }
        }, 1200);
      }, 1200);
    }, 1000);
  }
};

window.triggerMitigationBlockIP = async function(ip, reason = 'IOC Match') {
  if (!ip) return;
  showToast(`Initiating IP block for ${ip}...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/mitigation/block-ip`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('niravan_token')}`
        },
        body: JSON.stringify({ ip, reason })
      });
      if (res.ok) {
        showToast(`🚫 IP Address ${ip} has been blocked at the network perimeter.`, 'good');
        window.NIRAVAN_DATA.stats.blockedEvents++;
        if (window.NIRAVAN_DATA.assets) {
          window.NIRAVAN_DATA.assets.forEach(a => {
            if (a.ip === ip) a.status = 'isolated';
          });
        }
        if (typeof renderAttackSurface === 'function') renderAttackSurface();
      } else {
        const err = await res.json();
        showToast(`Block IP Action Failed: ${err.detail || 'Access Denied'}`, 'critical');
      }
    } catch (e) {
      showToast('Network error during mitigation block command.', 'critical');
    }
  } else {
    showToast(`🚫 Simulated IP Block: ${ip} successfully blacklisted in WAF/Firewall.`, 'good');
    window.NIRAVAN_DATA.stats.blockedEvents++;
    if (window.NIRAVAN_DATA.assets) {
      window.NIRAVAN_DATA.assets.forEach(a => {
        if (a.ip === ip) a.status = 'isolated';
      });
    }
    window.NIRAVAN_DATA.auditLogs.unshift({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
      action: "BLOCK_IP",
      detail: `Containment action: Blocked source IP ${ip}. Reason: ${reason}.`,
      ip_address: "127.0.0.1"
    });
    if (typeof renderAttackSurface === 'function') renderAttackSurface();
  }
};

window.triggerMitigationIsolateHost = async function(host, reason = 'EDR Trigger') {
  if (!host) return;
  showToast(`Initiating host containment for ${host}...`, 'info');
  
  if (window.NIRAVAN_API_ACTIVE) {
    try {
      const res = await fetch(`${window.API_URL}/mitigation/isolate-host`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('niravan_token')}`
        },
        body: JSON.stringify({ host, reason })
      });
      if (res.ok) {
        showToast(`🔒 Host ${host} successfully isolated via EDR agent.`, 'good');
        window.NIRAVAN_DATA.stats.blockedEvents++;
        if (window.NIRAVAN_DATA.assets) {
          window.NIRAVAN_DATA.assets.forEach(a => {
            if (a.name === host) a.status = 'isolated';
          });
        }
        if (typeof renderAttackSurface === 'function') renderAttackSurface();
      } else {
        const err = await res.json();
        showToast(`Isolate Host Action Failed: ${err.detail || 'Access Denied'}`, 'critical');
      }
    } catch (e) {
      showToast('Network error during host isolation command.', 'critical');
    }
  } else {
    showToast(`🔒 Simulated Host Containment: ${host} isolated from subnets.`, 'good');
    window.NIRAVAN_DATA.stats.blockedEvents++;
    if (window.NIRAVAN_DATA.assets) {
      window.NIRAVAN_DATA.assets.forEach(a => {
        if (a.name === host) a.status = 'isolated';
      });
    }
    window.NIRAVAN_DATA.auditLogs.unshift({
      id: Date.now(),
      timestamp: new Date().toISOString(),
      user_email: localStorage.getItem('niravan_user_email') || 'analyst@niravan.ai',
      action: "ISOLATE_HOST",
      detail: `Containment action: Isolated host machine ${host}. Reason: ${reason}.`,
      ip_address: "127.0.0.1"
    });
    if (typeof renderAttackSurface === 'function') renderAttackSurface();
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Guardian Mode — OpenVAS Vulnerability Panel
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Renders a single vulnerability card in the Guardian vulnerability panel.
 */
function _renderVulnCard(v) {
  const severityColors = {
    critical: { bg: 'rgba(255,59,48,0.1)', border: 'rgba(255,59,48,0.35)', badge: '#ff3b30', icon: '🔴' },
    high:     { bg: 'rgba(255,149,0,0.1)',  border: 'rgba(255,149,0,0.35)',  badge: '#ff9500', icon: '🟠' },
    medium:   { bg: 'rgba(255,214,10,0.1)', border: 'rgba(255,214,10,0.35)', badge: '#ffd60a', icon: '🟡' },
    low:      { bg: 'rgba(48,209,88,0.1)',  border: 'rgba(48,209,88,0.35)',  badge: '#30d158', icon: '🟢' },
  };
  const sev = v.severity || 'medium';
  const colors = severityColors[sev] || severityColors.medium;
  const cvss = parseFloat(v.cvss || v.score || 0).toFixed(1);
  const name = v.name || v.cve_id || v.id || 'Unknown Vulnerability';
  const affected = v.affected || v.target || 'Unknown Asset';
  const remediation = v.remediation || 'Apply latest security patches from the vendor.';
  const fixTime = v.fix_time_minutes || 30;
  const cveId = v.cve_id || v.id || '';

  return `
    <div style="
      display: flex; align-items: flex-start; gap: 14px;
      padding: 12px 16px;
      background: ${colors.bg};
      border: 1px solid ${colors.border};
      border-radius: 10px;
      animation: fadeInUp 0.3s ease;
    ">
      <!-- CVSS Ring -->
      <div style="flex-shrink:0; text-align:center; min-width:44px;">
        <svg width="44" height="44" viewBox="0 0 44 44">
          <circle cx="22" cy="22" r="17" stroke="rgba(255,255,255,0.06)" stroke-width="5" fill="none"/>
          <circle cx="22" cy="22" r="17" stroke="${colors.badge}" stroke-width="5" fill="none"
            stroke-dasharray="${Math.round((parseFloat(cvss) / 10) * 107)} 107"
            stroke-linecap="round" transform="rotate(-90 22 22)"
            style="transition: stroke-dasharray 1s ease;"/>
          <text x="22" y="27" text-anchor="middle" fill="${colors.badge}"
            font-family="Space Grotesk" font-size="10" font-weight="700">${cvss}</text>
        </svg>
        <div style="font-size:0.55rem; color: var(--text-muted); margin-top: 2px;">${colors.icon} ${sev.toUpperCase()}</div>
      </div>

      <!-- Content -->
      <div style="flex:1; min-width:0;">
        <div style="display:flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap:wrap;">
          <span style="font-size: 0.8rem; font-weight: 700; color: #f0f4ff; line-clamp: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 350px;">${name}</span>
          ${cveId ? `<span style="font-size:0.6rem; font-family:monospace; background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius:4px; color: var(--text-muted); white-space:nowrap;">${cveId}</span>` : ''}
        </div>
        <div style="font-size:0.72rem; color: var(--text-secondary); margin-bottom: 6px;">
          📍 <strong style="color:#f0f4ff;">${affected}</strong>
        </div>
        <div style="font-size: 0.7rem; color: var(--text-muted); line-height:1.4; margin-bottom: 6px;">
          <strong style="color: var(--text-secondary);">Fix:</strong> ${remediation}
        </div>
        <div style="display:flex; align-items: center; gap: 10px; flex-wrap:wrap;">
          <span style="font-size:0.6rem; background: rgba(255,255,255,0.05); padding: 2px 8px; border-radius:6px; color:var(--text-muted);">
            ⏱ ~${fixTime} min to fix
          </span>
          ${v.mitre ? `<span style="font-size:0.6rem; background: rgba(88,86,214,0.15); padding: 2px 8px; border-radius:6px; color:#9f7aea;">${v.mitre}</span>` : ''}
          <span style="font-size:0.6rem; background: rgba(255,255,255,0.04); padding: 2px 8px; border-radius:6px; color:var(--text-muted);">
            🔎 ${v.source === 'openvas' || v.source === 'openvas_mock' ? 'OpenVAS Scanner' : 'CISA KEV'}
          </span>
        </div>
      </div>
    </div>
  `;
}

/**
 * Loads vulnerabilities from the backend and renders them in the Guardian panel.
 */
async function loadGuardianVulnerabilities() {
  const feed = document.getElementById('guardian-vuln-feed');
  const critBadge = document.getElementById('guardian-vuln-critical-badge');
  const highBadge = document.getElementById('guardian-vuln-high-badge');
  if (!feed) return;

  const token = localStorage.getItem('niravan_jwt_token');
  if (!token) {
    feed.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">🔒 Log in to view vulnerability scan results</div>`;
    return;
  }

  try {
    const res = await fetch('http://127.0.0.1:8000/api/v1/vulnerabilities', {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const vulns = (data.vulnerabilities || []).slice(0, 20); // Show top 20

    if (critBadge && data.critical_count > 0) {
      critBadge.style.display = 'inline-block';
      critBadge.textContent = `● ${data.critical_count} CRITICAL`;
    }
    if (highBadge && data.high_count > 0) {
      highBadge.style.display = 'inline-block';
      highBadge.textContent = `● ${data.high_count} HIGH`;
    }

    if (vulns.length === 0) {
      feed.innerHTML = `
        <div style="text-align:center; padding:30px; color:var(--text-muted);">
          <div style="font-size:2rem; margin-bottom:8px;">✅</div>
          <div style="font-size:0.9rem; font-weight:600; color:#30d158;">No vulnerabilities found</div>
          <div style="font-size:0.75rem; margin-top:6px; opacity:0.7;">Your infrastructure is clean. Click Scan Again to re-verify.</div>
        </div>`;
      return;
    }

    feed.innerHTML = vulns.map(_renderVulnCard).join('');

  } catch (e) {
    // Backend offline — show mock data based on NIRAVAN_DATA
    const mockVulns = (window.NIRAVAN_DATA?.cves || []).slice(0, 8).map(c => ({
      cve_id: c.id,
      cvss: c.score || 7.5,
      severity: c.severity || 'high',
      name: c.id,
      description: c.desc || '',
      affected: c.affected || 'Unknown Asset',
      remediation: 'Apply latest security patches from the vendor.',
      fix_time_minutes: 30,
      source: 'cisa_kev',
    }));

    if (mockVulns.length > 0) {
      feed.innerHTML = mockVulns.map(_renderVulnCard).join('');
    } else {
      feed.innerHTML = `
        <div style="text-align:center; padding:20px; color:var(--text-muted);">
          <div style="font-size:1.5rem; margin-bottom:8px;">⚠️</div>
          <div style="font-size:0.8rem;">Backend offline — showing cached data</div>
          <div style="font-size:0.7rem; margin-top:4px; opacity:0.6;">Start the backend server to see live OpenVAS results</div>
        </div>`;
    }
  }
}

/**
 * Triggers a new OpenVAS vulnerability scan for a selected asset and refreshes the panel.
 */
window.guardianRunVulnScan = async function() {
  const feed = document.getElementById('guardian-vuln-feed');
  if (feed) {
    feed.innerHTML = `
      <div style="text-align:center; padding:30px; color:var(--text-muted);">
        <div style="font-size:2rem; margin-bottom:8px; animation: pulse 1.5s infinite;">🔎</div>
        <div style="font-size:0.9rem; font-weight:600;">Running OpenVAS scan...</div>
        <div style="font-size:0.72rem; margin-top:6px; opacity:0.7;">This will take a few seconds. Please wait.</div>
      </div>`;
  }

  const token = localStorage.getItem('niravan_jwt_token');
  // Pick the highest-risk asset as scan target, or use a default
  const topAsset = window.NIRAVAN_DATA?.assets?.[0];
  const target = topAsset?.name || 'web-server.tn.gov.in';

  try {
    const scanRes = await fetch(`http://127.0.0.1:8000/api/v1/vulnerabilities/scan?target=${encodeURIComponent(target)}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (scanRes.ok) {
      const { scan_id } = await scanRes.json();
      showToast(`🔎 OpenVAS scan started for ${target} (ID: ${scan_id})`, 'good');
      // Poll for completion then reload
      let polls = 0;
      const poll = setInterval(async () => {
        polls++;
        const statusRes = await fetch(`http://127.0.0.1:8000/api/v1/vulnerabilities/scan/${scan_id}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (statusRes.ok) {
          const { status } = await statusRes.json();
          if (status === 'completed' || polls > 15) {
            clearInterval(poll);
            showToast(`✅ OpenVAS scan complete. Refreshing findings...`, 'good');
            await loadGuardianVulnerabilities();
          }
        } else {
          clearInterval(poll);
          await loadGuardianVulnerabilities();
        }
      }, 1000);
    }
  } catch (e) {
    showToast('OpenVAS scan failed — backend may be offline', 'warning');
    await loadGuardianVulnerabilities();
  }
};

// ── Feedback, Self-Evaluation, and Defense Memory Frontend Hooks ──

window.submitThreatFeedback = async function(feedbackType) {
  if (!guardianCurrentThreat) {
    showToast("No active threat selected to submit feedback.", "warning");
    return;
  }
  
  const incidentId = guardianCurrentThreat.id;
  showToast(`Submitting feedback: ${feedbackType === 'false_positive' ? 'False Positive' : 'True Positive'}...`, 'info');
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    headers['Content-Type'] = 'application/json';
    
    const res = await fetch(`${window.API_URL || '/api/v1'}/incidents/${incidentId}/feedback`, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ feedback_type: feedbackType, comments: `User marked threat as ${feedbackType}` })
    });
    
    if (res.ok) {
      showToast(`✅ Feedback recorded. Incident ${feedbackType === 'false_positive' ? 'suppressed' : 'confirmed'}.`, 'good');
      // Hide threat panel if false positive
      if (feedbackType === 'false_positive') {
        const panel = document.getElementById('guardian-threat-panel');
        if (panel) panel.style.display = 'none';
        guardianCurrentThreat = null;
      }
      // Refresh sync
      if (window.syncFromBackend) {
        await window.syncFromBackend();
      }
      renderGuardianCards();
      updateGuardianRing();
      loadGuardianMetrics();
    } else {
      showToast("Failed to submit feedback to server.", "bad");
    }
  } catch(err) {
    console.error("Error submitting feedback:", err);
    showToast("Network error submitting feedback.", "bad");
  }
};

async function loadGuardianMetrics() {
  const precisionEl = document.getElementById('metric-precision');
  const recallEl = document.getElementById('metric-recall');
  const successEl = document.getElementById('metric-success-rate');
  const mttdEl = document.getElementById('metric-mttd');
  const mttrEl = document.getElementById('metric-mttr');
  const memoryFeed = document.getElementById('defense-memory-feed');
  const memoryCount = document.getElementById('defense-memory-count');
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/self-evaluation/metrics`, {
      headers: headers
    });
    if (res.ok) {
      const data = await res.json();
      const lat = data.latest;
      if (precisionEl) precisionEl.textContent = `${lat.precision}%`;
      if (recallEl) recallEl.textContent = `${lat.recall}%`;
      if (mttdEl) mttdEl.textContent = lat.mttd_minutes.toString();
      if (mttrEl) mttrEl.textContent = lat.mttr_minutes.toString();
    }
  } catch (err) {
    console.error("Error loading self-evaluation metrics:", err);
  }
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/defense-memory`, {
      headers: headers
    });
    if (res.ok) {
      const data = await res.json();
      if (successEl) successEl.textContent = `${data.success_rate}%`;
      if (memoryCount) memoryCount.textContent = `${data.total_actions} records`;
      
      if (memoryFeed) {
        if (!data.history || data.history.length === 0) {
          memoryFeed.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding: 10px;">No mitigations recorded yet</div>`;
        } else {
          memoryFeed.innerHTML = data.history.slice(0, 5).map(m => {
            const outcomeClass = m.result === 'successful' ? 'color:#30d158;' : 'color:#ff3b30;';
            const time = m.timestamp.split('T')[1].substring(0,8);
            return `<div style="display:flex; justify-content:space-between; margin-bottom:2px; opacity:0.8;">
              <span>🛡️ [${m.action.toUpperCase()}] on pattern "${m.pattern}"</span>
              <span style="${outcomeClass} font-weight:600;">${m.result.toUpperCase()} (${time})</span>
            </div>`;
          }).join('');
        }
      }
    }
  } catch (err) {
    console.error("Error loading defense memory:", err);
  }
  
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/reputation/scores`, {
      headers: headers
    });
    if (res.ok) {
      const data = await res.json();
      
      const assetsList = document.getElementById('reputation-assets-list');
      if (assetsList) {
        if (!data.assets || data.assets.length === 0) {
          assetsList.innerHTML = `<div style="color:var(--text-muted); font-size:0.6rem; text-align:center;">No assets found</div>`;
        } else {
          assetsList.innerHTML = data.assets.map(a => {
            const scoreColor = a.reputation_score >= 80 ? '#30d158' : (a.reputation_score >= 50 ? '#ffd60a' : '#ff3b30');
            return `<div style="display:flex; justify-content:space-between; align-items:center; font-size:0.65rem; padding: 2px 0;">
              <span>🖥️ ${a.name} (${a.ip})</span>
              <span style="color:${scoreColor}; font-weight:700;">${a.reputation_score}</span>
            </div>`;
          }).join('');
        }
      }
      
      const usersList = document.getElementById('reputation-users-list');
      if (usersList) {
        if (!data.users || data.users.length === 0) {
          usersList.innerHTML = `<div style="color:var(--text-muted); font-size:0.6rem; text-align:center;">No users found</div>`;
        } else {
          usersList.innerHTML = data.users.map(u => {
            const scoreColor = u.reputation_score >= 80 ? '#30d158' : (u.reputation_score >= 50 ? '#ffd60a' : '#ff3b30');
            return `<div style="display:flex; justify-content:space-between; align-items:center; font-size:0.65rem; padding: 2px 0;">
              <span>👤 ${u.email.split('@')[0]} [${u.role}]</span>
              <span style="color:${scoreColor}; font-weight:700;">${u.reputation_score}</span>
            </div>`;
          }).join('');
        }
      }
    }
  } catch (err) {
    console.error("Error loading reputation scores:", err);
  }
}

window.runSelfEvaluation = async function() {
  showToast("Running Cyber OS self-evaluation...", "info");
  try {
    const headers = window.getHeaders ? window.getHeaders() : {};
    const res = await fetch(`${window.API_URL || '/api/v1'}/self-evaluation`, {
      method: 'POST',
      headers: headers
    });
    if (res.ok) {
      showToast("✅ Self-evaluation complete. Metrics updated.", "good");
      await loadGuardianMetrics();
    } else {
      showToast("Failed to run self-evaluation on server.", "bad");
    }
  } catch (err) {
    console.error("Error running self-evaluation:", err);
    showToast("Network error during self-evaluation.", "bad");
  }
};

// Auto-load vulnerability and metrics panels when guardian page is visited
const _origShowPage = window.showPage || null;
window.showPage = function(pageId) {
  if (_origShowPage) _origShowPage(pageId);
  if (pageId === 'guardian') {
    setTimeout(() => {
      loadGuardianVulnerabilities();
      loadGuardianMetrics();
    }, 400);
  }
};

// Also load on page load if guardian is the initial page
document.addEventListener('DOMContentLoaded', () => {
  const activePage = document.querySelector('.page.active')?.id;
  if (activePage === 'page-guardian') {
    setTimeout(() => {
      loadGuardianVulnerabilities();
      loadGuardianMetrics();
    }, 1200);
  }
  // Also hook into nav clicks
  document.querySelectorAll('[data-page="guardian"], .nav-item[onclick*="guardian"]').forEach(el => {
    el.addEventListener('click', () => {
      setTimeout(() => {
        loadGuardianVulnerabilities();
        loadGuardianMetrics();
      }, 500);
    });
  });
});
