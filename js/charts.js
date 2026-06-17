/* ============================================================
   NIRAVAN – Chart Rendering Module
   All Chart.js configurations for the dashboard
   ============================================================ */

// ── Chart.js Global Defaults ──
Chart.defaults.color = '#8899bb';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size   = 11;

const CHART_COLORS = {
  critical: '#ff2d55',
  high:     '#ff6b35',
  medium:   '#ffd60a',
  low:      '#30d158',
  blue:     '#00d4ff',
  purple:   '#bf5af2',
  pink:     '#ff2d80',
};

let chartInstances = {};

// ── Destroy existing chart ──
function destroyChart(id) {
  if(chartInstances[id]) {
    chartInstances[id].destroy();
    delete chartInstances[id];
  }
}

// ── Threat Velocity Trend Chart (Line) ──
function renderTrendChart() {
  const ctx = document.getElementById('trend-chart');
  if(!ctx) return;
  destroyChart('trend');

  const { labels, data } = getTrendData();

  chartInstances.trend = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Threats',
        data,
        borderColor: CHART_COLORS.critical,
        backgroundColor: 'rgba(255,45,85,0.08)',
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 5,
        pointBackgroundColor: CHART_COLORS.critical,
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(5,9,20,0.95)',
          borderColor: 'rgba(255,45,85,0.3)',
          borderWidth: 1,
          callbacks: {
            title: (items) => items[0].label,
            label: (item)  => ` ${item.raw} threats detected`
          }
        }
      },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: {size:9} } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font:{size:9} }, beginAtZero: true }
      },
      animation: { duration: 1000, easing: 'easeInOutQuart' }
    }
  });
}

// ── Attack Vector Doughnut Chart ──
function renderVectorChart() {
  const ctx = document.getElementById('vector-chart');
  if(!ctx) return;
  destroyChart('vector');

  chartInstances.vector = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: VECTOR_DATA.labels,
      datasets: [{
        data: VECTOR_DATA.data,
        backgroundColor: [
          'rgba(255,45,85,0.75)',
          'rgba(255,107,53,0.75)',
          'rgba(191,90,242,0.75)',
          'rgba(255,214,10,0.75)',
          'rgba(0,212,255,0.75)',
          'rgba(48,209,88,0.75)',
          'rgba(255,45,128,0.75)',
          'rgba(100,160,255,0.75)',
        ],
        borderColor: 'rgba(3,7,18,0.8)',
        borderWidth: 2,
        hoverBorderColor: '#fff',
        hoverBorderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: { boxWidth: 8, padding: 8, font: {size: 9} }
        },
        tooltip: {
          backgroundColor: 'rgba(5,9,20,0.95)',
          borderColor: 'rgba(0,212,255,0.3)',
          borderWidth: 1,
          callbacks: {
            label: (item) => ` ${item.label}: ${item.raw}%`
          }
        }
      },
      animation: { animateRotate: true, duration: 1200 }
    }
  });
}

// ── Geographic Attack Origin Bar Chart ──
function renderGeoChart() {
  const ctx = document.getElementById('geo-chart');
  if(!ctx) return;
  destroyChart('geo');

  chartInstances.geo = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: GEO_DATA.labels,
      datasets: [{
        label: 'Attack Events',
        data: GEO_DATA.data,
        backgroundColor: [
          'rgba(255,45,85,0.6)',
          'rgba(255,107,53,0.6)',
          'rgba(255,214,10,0.6)',
          'rgba(191,90,242,0.6)',
          'rgba(0,212,255,0.6)',
          'rgba(48,209,88,0.6)',
          'rgba(255,45,128,0.6)',
          'rgba(100,160,255,0.6)',
        ],
        borderColor: 'transparent',
        borderRadius: 4,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(5,9,20,0.95)',
          borderColor: 'rgba(0,212,255,0.3)',
          borderWidth: 1,
        }
      },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { font:{size:9} } },
        y: { grid: { display: false }, ticks: { font:{size:10} } }
      },
      animation: { duration: 1000 }
    }
  });
}

// ── Risk Domain Radar Chart ──
function renderRadarChart() {
  const ctx = document.getElementById('radar-chart');
  if(!ctx) return;
  destroyChart('radar');

  chartInstances.radar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: ['Network', 'Endpoint', 'Identity', 'Cloud', 'Application', 'Data', 'Physical'],
      datasets: [
        {
          label: 'Current Risk',
          data: [82, 65, 71, 58, 74, 88, 30],
          borderColor: 'rgba(255,45,85,0.8)',
          backgroundColor: 'rgba(255,45,85,0.1)',
          borderWidth: 2,
          pointBackgroundColor: '#ff2d55',
          pointRadius: 3,
        },
        {
          label: 'Baseline',
          data: [40, 35, 45, 38, 42, 50, 20],
          borderColor: 'rgba(0,212,255,0.5)',
          backgroundColor: 'rgba(0,212,255,0.05)',
          borderWidth: 1.5,
          pointBackgroundColor: '#00d4ff',
          pointRadius: 2,
          borderDash: [4,4],
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { boxWidth: 8, padding: 8, font: {size:9} }
        }
      },
      scales: {
        r: {
          min: 0, max: 100,
          ticks: { stepSize: 25, font:{size:8}, backdropColor:'transparent' },
          grid: { color: 'rgba(255,255,255,0.08)' },
          angleLines: { color: 'rgba(255,255,255,0.06)' },
          pointLabels: { font:{size:9}, color:'#8899bb' }
        }
      },
      animation: { duration: 1200 }
    }
  });
}

// ── Live update: add new data point to trend chart ──
function updateTrendChart() {
  const chart = chartInstances.trend;
  if(!chart) return;
  chart.data.labels.push(new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'}));
  chart.data.labels.shift();
  const newVal = randomInt(5, 60);
  chart.data.datasets[0].data.push(newVal);
  chart.data.datasets[0].data.shift();
  chart.update('none');
}

// ── World Map Threat Visualization ──
let mapAnimations = [];

function renderWorldMap() {
  const canvas = document.getElementById('world-map-canvas');
  if(!canvas) return;
  
  // Guard: wait for layout if canvas has no size
  const rect = canvas.getBoundingClientRect();
  if(rect.width < 10) {
    setTimeout(renderWorldMap, 250);
    return;
  }

  // Stop any previous animation
  window._mapRunning = false;
  setTimeout(() => {
    window._mapRunning = true;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width  = rect.width  * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width;
    const H = rect.height || 240;
    window._mapCtx  = ctx;
    window._mapW    = W;
    window._mapH    = H;
    window._mapArcs = [];
    drawWorldMapBase(ctx, W, H);
    animateMap();
  }, 0);
}

function drawWorldMapBase(ctx, W, H) {
  // Background
  ctx.fillStyle = 'rgba(3,7,18,0.4)';
  ctx.fillRect(0, 0, W, H);

  // Draw grid lines
  ctx.strokeStyle = 'rgba(0,212,255,0.06)';
  ctx.lineWidth = 0.5;
  // Latitude lines
  for(let i = 0; i <= 6; i++) {
    ctx.beginPath();
    ctx.moveTo(0, H/6 * i);
    ctx.lineTo(W, H/6 * i);
    ctx.stroke();
  }
  // Longitude lines
  for(let i = 0; i <= 12; i++) {
    ctx.beginPath();
    ctx.moveTo(W/12 * i, 0);
    ctx.lineTo(W/12 * i, H);
    ctx.stroke();
  }

  // Draw continents as approximate shapes
  drawContinents(ctx, W, H);

  // Draw fixed city dots (targets)
  const targets = ATTACK_TARGETS;
  targets.forEach(t => {
    const x = t.x * W;
    const y = t.y * H;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(0,212,255,0.6)';
    ctx.fill();
    // Pulse ring
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(0,212,255,0.2)';
    ctx.lineWidth = 1;
    ctx.stroke();
  });
}

function drawContinents(ctx, W, H) {
  ctx.strokeStyle = 'rgba(0,212,255,0.15)';
  ctx.lineWidth = 1;
  ctx.fillStyle = 'rgba(0,212,255,0.04)';

  // North America (approximate)
  ctx.beginPath();
  ctx.moveTo(W*0.08, H*0.15); ctx.lineTo(W*0.08, H*0.18); ctx.lineTo(W*0.1, H*0.2);
  ctx.lineTo(W*0.15, H*0.18); ctx.lineTo(W*0.22, H*0.22); ctx.lineTo(W*0.32, H*0.22);
  ctx.lineTo(W*0.32, H*0.25); ctx.lineTo(W*0.28, H*0.42); ctx.lineTo(W*0.25, H*0.52);
  ctx.lineTo(W*0.22, H*0.55); ctx.lineTo(W*0.20, H*0.52); ctx.lineTo(W*0.16, H*0.45);
  ctx.lineTo(W*0.10, H*0.38); ctx.lineTo(W*0.07, H*0.30); ctx.lineTo(W*0.05, H*0.25);
  ctx.lineTo(W*0.08, H*0.15);
  ctx.fill(); ctx.stroke();

  // South America
  ctx.beginPath();
  ctx.moveTo(W*0.22, H*0.55); ctx.lineTo(W*0.28, H*0.55);
  ctx.lineTo(W*0.34, H*0.60); ctx.lineTo(W*0.36, H*0.70);
  ctx.lineTo(W*0.32, H*0.80); ctx.lineTo(W*0.26, H*0.85);
  ctx.lineTo(W*0.22, H*0.82); ctx.lineTo(W*0.18, H*0.75);
  ctx.lineTo(W*0.18, H*0.65); ctx.lineTo(W*0.20, H*0.58);
  ctx.lineTo(W*0.22, H*0.55);
  ctx.fill(); ctx.stroke();

  // Europe
  ctx.beginPath();
  ctx.moveTo(W*0.45, H*0.15); ctx.lineTo(W*0.58, H*0.15);
  ctx.lineTo(W*0.60, H*0.20); ctx.lineTo(W*0.56, H*0.30);
  ctx.lineTo(W*0.52, H*0.35); ctx.lineTo(W*0.50, H*0.38);
  ctx.lineTo(W*0.46, H*0.36); ctx.lineTo(W*0.44, H*0.28);
  ctx.lineTo(W*0.45, H*0.15);
  ctx.fill(); ctx.stroke();

  // Africa
  ctx.beginPath();
  ctx.moveTo(W*0.46, H*0.38); ctx.lineTo(W*0.56, H*0.35);
  ctx.lineTo(W*0.60, H*0.40); ctx.lineTo(W*0.62, H*0.50);
  ctx.lineTo(W*0.58, H*0.65); ctx.lineTo(W*0.54, H*0.75);
  ctx.lineTo(W*0.50, H*0.76); ctx.lineTo(W*0.46, H*0.68);
  ctx.lineTo(W*0.44, H*0.55); ctx.lineTo(W*0.44, H*0.45);
  ctx.lineTo(W*0.46, H*0.38);
  ctx.fill(); ctx.stroke();

  // Asia
  ctx.beginPath();
  ctx.moveTo(W*0.58, H*0.15); ctx.lineTo(W*0.88, H*0.12);
  ctx.lineTo(W*0.92, H*0.18); ctx.lineTo(W*0.90, H*0.28);
  ctx.lineTo(W*0.88, H*0.35); ctx.lineTo(W*0.82, H*0.42);
  ctx.lineTo(W*0.76, H*0.48); ctx.lineTo(W*0.70, H*0.48);
  ctx.lineTo(W*0.65, H*0.45); ctx.lineTo(W*0.60, H*0.40);
  ctx.lineTo(W*0.58, H*0.30); ctx.lineTo(W*0.58, H*0.15);
  ctx.fill(); ctx.stroke();

  // Australia
  ctx.beginPath();
  ctx.moveTo(W*0.76, H*0.58); ctx.lineTo(W*0.90, H*0.55);
  ctx.lineTo(W*0.95, H*0.62); ctx.lineTo(W*0.92, H*0.70);
  ctx.lineTo(W*0.84, H*0.72); ctx.lineTo(W*0.76, H*0.68);
  ctx.lineTo(W*0.76, H*0.58);
  ctx.fill(); ctx.stroke();
}

// ── World Map Animation Loop ──
function animateMap() {
  if(!window._mapRunning) return;
  const canvas = document.getElementById('world-map-canvas');
  if(!canvas) return;
  const ctx    = window._mapCtx;
  const W      = window._mapW;
  const H      = window._mapH;
  if(!ctx || !W || !H) return;

  // Occasionally add new arc
  if(Math.random() < 0.05 && window._mapArcs.length < 8) {
    const origin  = randomItem(ATTACK_ORIGINS);
    const target  = randomItem(ATTACK_TARGETS);
    const sev     = randomItem(['critical','critical','high','high','medium']);
    const color   = sev === 'critical' ? '#ff2d55' : sev === 'high' ? '#ff6b35' : '#ffd60a';
    window._mapArcs.push({
      ox: origin.x * W, oy: origin.y * H,
      tx: target.x * W, ty: target.y * H,
      progress: 0, speed: 0.01 + Math.random() * 0.015,
      color, sev, alpha: 1
    });
  }

  // Redraw base
  ctx.clearRect(0, 0, W, H);
  drawWorldMapBase(ctx, W, H);

  // Draw and update arcs
  window._mapArcs = window._mapArcs.filter(arc => arc.alpha > 0);
  window._mapArcs.forEach(arc => {
    arc.progress = Math.min(1, arc.progress + arc.speed);

    // Bezier curve for arc
    const cpx = (arc.ox + arc.tx) / 2;
    const cpy = Math.min(arc.oy, arc.ty) - W * 0.12;

    const t   = arc.progress;
    const px  = (1-t)*(1-t)*arc.ox + 2*(1-t)*t*cpx + t*t*arc.tx;
    const py  = (1-t)*(1-t)*arc.oy + 2*(1-t)*t*cpy + t*t*arc.ty;

    // Draw arc path up to current progress
    ctx.beginPath();
    const steps = Math.floor(t * 50);
    for(let i = 0; i <= steps; i++) {
      const ti = i / 50;
      const xi = (1-ti)*(1-ti)*arc.ox + 2*(1-ti)*ti*cpx + ti*ti*arc.tx;
      const yi = (1-ti)*(1-ti)*arc.oy + 2*(1-ti)*ti*cpy + ti*ti*arc.ty;
      if(i===0) ctx.moveTo(xi,yi);
      else ctx.lineTo(xi,yi);
    }
    ctx.strokeStyle = arc.color + 'aa';
    ctx.lineWidth   = 1.5;
    ctx.stroke();

    // Draw moving dot
    ctx.beginPath();
    ctx.arc(px, py, 3, 0, Math.PI * 2);
    ctx.fillStyle = arc.color;
    ctx.fill();
    ctx.shadowBlur = 10;
    ctx.shadowColor = arc.color;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Origin dot
    ctx.beginPath();
    ctx.arc(arc.ox, arc.oy, 4, 0, Math.PI * 2);
    ctx.fillStyle = arc.color;
    ctx.fill();

    if(arc.progress >= 1) {
      arc.alpha -= 0.02;
      // Impact flash at target
      ctx.beginPath();
      ctx.arc(arc.tx, arc.ty, (1 - arc.alpha) * 15, 0, Math.PI * 2);
      ctx.strokeStyle = arc.color + Math.floor(arc.alpha * 255).toString(16).padStart(2,'0');
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  });

  requestAnimationFrame(animateMap);
}

// ── Attack Path Canvas ──
function renderAttackPathCanvas() {
  const canvas = document.getElementById('attack-path-canvas');
  if(!canvas) return;

  // Guard: retry if canvas has no size yet
  const rect = canvas.getBoundingClientRect();
  if(rect.width < 10) { setTimeout(renderAttackPathCanvas, 300); return; }

  const paths = window.NIRAVAN_ENGINE.ATTACK_PATHS;
  if(!paths || !paths.length) return;
  const path = paths[0];

  const ctx  = canvas.getContext('2d');
  const dpr  = window.devicePixelRatio || 1;
  const W    = rect.width;
  const H    = Math.max(rect.height, 180);

  canvas.style.height = H + 'px';
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  ctx.scale(dpr, dpr);

  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = 'rgba(3,7,18,0.6)';
  ctx.fillRect(0, 0, W, H);

  // Draw connections
  const nodes = path.nodes;
  for(let i = 0; i < nodes.length - 1; i++) {
    const a = nodes[i];
    const b = nodes[i+1];
    ctx.beginPath();
    ctx.setLineDash([6,4]);
    ctx.moveTo(a.x * W, a.y * H);
    ctx.lineTo(b.x * W, b.y * H);
    ctx.strokeStyle = 'rgba(255,45,85,0.4)';
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.setLineDash([]);

    // Arrow
    const angle = Math.atan2((b.y - a.y)*H, (b.x - a.x)*W);
    const mx = (a.x + b.x)/2 * W;
    const my = (a.y + b.y)/2 * H;
    ctx.save();
    ctx.translate(mx, my);
    ctx.rotate(angle);
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(-8, -4);
    ctx.lineTo(-8, 4);
    ctx.closePath();
    ctx.fillStyle = 'rgba(255,45,85,0.6)';
    ctx.fill();
    ctx.restore();
  }

  // Draw nodes
  nodes.forEach((node, i) => {
    const x = node.x * W;
    const y = node.y * H;

    // Glow
    const grd = ctx.createRadialGradient(x,y,0,x,y,20);
    grd.addColorStop(0, node.color + '40');
    grd.addColorStop(1, 'transparent');
    ctx.fillStyle = grd;
    ctx.beginPath();
    ctx.arc(x, y, 20, 0, Math.PI * 2);
    ctx.fill();

    // Node circle
    ctx.beginPath();
    ctx.arc(x, y, i === 0 ? 8 : 6, 0, Math.PI * 2);
    ctx.fillStyle = node.color;
    ctx.fill();
    ctx.strokeStyle = 'rgba(3,7,18,0.8)';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Label
    ctx.fillStyle = '#f0f4ff';
    ctx.font = 'bold 10px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, x, y + 20);
  });
}

console.log('[NIRAVAN] Charts module initialized');
