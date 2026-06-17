/**
 * NIRAVAN – Tamil Nadu Interactive District Threat Map
 * Styled, responsive SVG-based geo-intelligence overlay for TN State SOC
 */

window.TN_DISTRICTS = [
  { id: "chennai", name: "Chennai", x: 410, y: 70, threat: "critical", incidents: 142, type: "Phishing & Ransomware" },
  { id: "tiruvallur", name: "Tiruvallur", x: 370, y: 50, threat: "high", incidents: 53, type: "Brute Force" },
  { id: "kancheepuram", name: "Kancheepuram", x: 360, y: 100, threat: "medium", incidents: 28, type: "SQL Injection" },
  { id: "chengalpattu", name: "Chengalpattu", x: 390, y: 120, threat: "high", incidents: 64, type: "DDoS Attack" },
  { id: "ranipet", name: "Ranipet", x: 320, y: 80, threat: "low", incidents: 12, type: "None" },
  { id: "vellore", name: "Vellore", x: 280, y: 90, threat: "medium", incidents: 22, type: "Unauthorized Access" },
  { id: "tirupathur", name: "Tirupathur", x: 250, y: 110, threat: "low", incidents: 8, type: "None" },
  { id: "krishnagiri", name: "Krishnagiri", x: 190, y: 120, threat: "low", incidents: 15, type: "Malware Cleaned" },
  { id: "dharmapuri", name: "Dharmapuri", x: 210, y: 170, threat: "low", incidents: 9, type: "None" },
  { id: "tiruvannamalai", name: "Tiruvannamalai", x: 300, y: 150, threat: "medium", incidents: 19, type: "Credential Stuffing" },
  { id: "kallakurichi", name: "Kallakurichi", x: 280, y: 210, threat: "low", incidents: 7, type: "None" },
  { id: "viluppuram", name: "Viluppuram", x: 330, y: 180, threat: "medium", incidents: 24, type: "Phishing Link Clicked" },
  { id: "cuddalore", name: "Cuddalore", x: 360, y: 220, threat: "high", incidents: 41, type: "Ransomware Attempt" },
  { id: "salem", name: "Salem", x: 230, y: 220, threat: "high", incidents: 48, type: "DDoS Targeting Treasury" },
  { id: "namakkal", name: "Namakkal", x: 220, y: 280, threat: "medium", incidents: 16, type: "Malicious Document" },
  { id: "erode", name: "Erode", x: 170, y: 250, threat: "medium", incidents: 21, type: "SSH Brute Force" },
  { id: "nilgiris", name: "Nilgiris", x: 80, y: 240, threat: "low", incidents: 4, type: "None" },
  { id: "coimbatore", name: "Coimbatore", x: 100, y: 300, threat: "critical", incidents: 98, type: "Data Leak Attempt" },
  { id: "tiruppur", name: "Tiruppur", x: 140, y: 310, threat: "medium", incidents: 33, type: "Malware Spreading" },
  { id: "karur", name: "Karur", x: 200, y: 320, threat: "low", incidents: 11, type: "None" },
  { id: "trichy", name: "Tiruchirappalli", x: 250, y: 330, threat: "high", incidents: 57, type: "API Exploits" },
  { id: "perambalur", name: "Perambalur", x: 270, y: 290, threat: "low", incidents: 5, type: "None" },
  { id: "ariyalur", name: "Ariyalur", x: 290, y: 300, threat: "low", incidents: 6, type: "None" },
  { id: "mayiladuthurai", name: "Mayiladuthurai", x: 360, y: 280, threat: "low", incidents: 10, type: "None" },
  { id: "nagapattinam", name: "Nagapattinam", x: 370, y: 320, threat: "medium", incidents: 18, type: "Port Scanning" },
  { id: "tiruvarur", name: "Tiruvarur", x: 340, y: 330, threat: "low", incidents: 9, type: "None" },
  { id: "thanjavur", name: "Thanjavur", x: 300, y: 340, threat: "medium", incidents: 25, type: "Account Takeover" },
  { id: "pudukkottai", name: "Pudukkottai", x: 280, y: 380, threat: "low", incidents: 13, type: "None" },
  { id: "dindigul", name: "Dindigul", x: 180, y: 380, threat: "medium", incidents: 20, type: "Botnet Telemetry" },
  { id: "theni", name: "Theni", x: 120, y: 430, threat: "low", incidents: 8, type: "None" },
  { id: "madurai", name: "Madurai", x: 190, y: 430, threat: "high", incidents: 71, type: "Database Scraping" },
  { id: "sivaganga", name: "Sivaganga", x: 240, y: 430, threat: "low", incidents: 12, type: "None" },
  { id: "ramanathapuram", name: "Ramanathapuram", x: 290, y: 480, threat: "medium", incidents: 17, type: "None" },
  { id: "virudhunagar", name: "Virudhunagar", x: 170, y: 480, threat: "medium", incidents: 23, type: "Phishing Attempt" },
  { id: "tenkasi", name: "Tenkasi", x: 100, y: 530, threat: "low", incidents: 6, type: "None" },
  { id: "thoothukudi", name: "Thoothukudi", x: 180, y: 560, threat: "medium", incidents: 30, type: "Brute Force" },
  { id: "tirunelveli", name: "Tirunelveli", x: 130, y: 580, threat: "high", incidents: 45, type: "Command & Control" },
  { id: "kanyakumari", name: "Kanyakumari", x: 100, y: 640, threat: "medium", incidents: 19, type: "DNS Tunneling" }
];

window.initTNMap = function(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  // Clear previous content
  container.innerHTML = "";

  // Create SVG element
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 500 700");
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "100%");
  svg.style.background = "radial-gradient(circle at 50% 50%, rgba(10,18,40,0.6) 0%, rgba(3,7,18,0.95) 100%)";
  svg.style.borderRadius = "12px";
  svg.style.border = "1px solid var(--border-glass)";

  // Add grid overlay in background
  const gridGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
  gridGroup.setAttribute("opacity", "0.05");
  for (let i = 0; i <= 500; i += 40) {
    const lineX = document.createElementNS("http://www.w3.org/2000/svg", "line");
    lineX.setAttribute("x1", i); lineX.setAttribute("y1", 0);
    lineX.setAttribute("x2", i); lineX.setAttribute("y2", 700);
    lineX.setAttribute("stroke", "#00d4ff");
    lineX.setAttribute("stroke-width", "1");
    gridGroup.appendChild(lineX);
  }
  for (let j = 0; j <= 700; j += 40) {
    const lineY = document.createElementNS("http://www.w3.org/2000/svg", "line");
    lineY.setAttribute("x1", 0); lineY.setAttribute("y1", j);
    lineY.setAttribute("x2", 500); lineY.setAttribute("y2", j);
    lineY.setAttribute("stroke", "#00d4ff");
    lineY.setAttribute("stroke-width", "1");
    gridGroup.appendChild(lineY);
  }
  svg.appendChild(gridGroup);

  // Connection paths to Chennai (Central Command Center hub)
  const linksGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
  const chennaiNode = window.TN_DISTRICTS.find(d => d.id === "chennai");

  window.TN_DISTRICTS.forEach(dist => {
    if (dist.id === "chennai") return;
    
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", chennaiNode.x);
    line.setAttribute("y1", chennaiNode.y);
    line.setAttribute("x2", dist.x);
    line.setAttribute("y2", dist.y);
    line.setAttribute("stroke", getThreatColorHex(dist.threat));
    line.setAttribute("stroke-width", "0.75");
    line.setAttribute("opacity", "0.25");
    line.setAttribute("stroke-dasharray", "4,4");
    line.innerHTML = `<animate attributeName="stroke-dashoffset" values="40;0" dur="4s" repeatCount="indefinite" />`;
    linksGroup.appendChild(line);
  });
  svg.appendChild(linksGroup);

  // Create nodes group
  const nodesGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");

  window.TN_DISTRICTS.forEach(dist => {
    const color = getThreatColorHex(dist.threat);

    // Node group
    const nodeG = document.createElementNS("http://www.w3.org/2000/svg", "g");
    nodeG.setAttribute("class", "map-district-node");
    nodeG.setAttribute("cursor", "pointer");
    nodeG.setAttribute("id", `map-node-${dist.id}`);

    // Outer glow pulse
    if (dist.threat === "critical" || dist.threat === "high") {
      const pulseCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      pulseCircle.setAttribute("cx", dist.x);
      pulseCircle.setAttribute("cy", dist.y);
      pulseCircle.setAttribute("r", "16");
      pulseCircle.setAttribute("fill", color);
      pulseCircle.setAttribute("opacity", "0.15");
      pulseCircle.innerHTML = `
        <animate attributeName="r" values="8;24" dur="2.5s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.4;0" dur="2.5s" repeatCount="indefinite" />
      `;
      nodeG.appendChild(pulseCircle);
    }

    // Main circle
    const mainCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    mainCircle.setAttribute("cx", dist.x);
    mainCircle.setAttribute("cy", dist.y);
    mainCircle.setAttribute("r", dist.id === "chennai" ? "10" : "6");
    mainCircle.setAttribute("fill", color);
    mainCircle.setAttribute("stroke", "#fff");
    mainCircle.setAttribute("stroke-width", "1");
    nodeG.appendChild(mainCircle);

    // Label for larger nodes
    if (dist.id === "chennai" || dist.id === "coimbatore" || dist.id === "madurai" || dist.id === "trichy" || dist.id === "salem") {
      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", dist.x + 12);
      text.setAttribute("y", dist.y + 4);
      text.setAttribute("fill", "#e0e6ed");
      text.setAttribute("font-family", "var(--font-display)");
      text.setAttribute("font-size", "10px");
      text.setAttribute("font-weight", "600");
      text.textContent = dist.name;
      nodeG.appendChild(text);
    }

    // Event listeners
    nodeG.addEventListener("mouseenter", (e) => {
      mainCircle.setAttribute("r", dist.id === "chennai" ? "14" : "10");
      mainCircle.setAttribute("stroke-width", "2");
      showMapTooltip(dist, e);
    });

    nodeG.addEventListener("mouseleave", () => {
      mainCircle.setAttribute("r", dist.id === "chennai" ? "10" : "6");
      mainCircle.setAttribute("stroke-width", "1");
      hideMapTooltip();
    });

    nodeG.addEventListener("click", () => {
      selectMapDistrict(dist);
    });

    nodesGroup.appendChild(nodeG);
  });
  
  svg.appendChild(nodesGroup);
  container.appendChild(svg);
};

function getThreatColorHex(threat) {
  switch (threat) {
    case "critical": return "#ff2d55";
    case "high": return "#ff6b35";
    case "medium": return "#ffd60a";
    default: return "#30d158";
  }
}

// Tooltip HTML element creation helper
let tooltipEl = null;
function showMapTooltip(dist, event) {
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.style.position = "absolute";
    tooltipEl.style.background = "rgba(10, 20, 40, 0.95)";
    tooltipEl.style.border = "1px solid var(--border-glass)";
    tooltipEl.style.borderRadius = "8px";
    tooltipEl.style.padding = "10px 14px";
    tooltipEl.style.color = "#fff";
    tooltipEl.style.fontSize = "0.85rem";
    tooltipEl.style.pointerEvents = "none";
    tooltipEl.style.zIndex = "1000";
    tooltipEl.style.boxShadow = "0 8px 32px rgba(0,0,0,0.8)";
    tooltipEl.style.fontFamily = "var(--font-body)";
    document.body.appendChild(tooltipEl);
  }

  const rect = event.currentTarget.getBoundingClientRect();
  const stateColor = getThreatColorHex(dist.threat);

  tooltipEl.innerHTML = `
    <div style="font-family:var(--font-display); font-weight:700; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:4px; margin-bottom:6px;">
      ${dist.name} District
    </div>
    <div>Threat Level: <span style="color:${stateColor}; font-weight:700;">${dist.threat.toUpperCase()}</span></div>
    <div>Active Incidents: <strong>${dist.incidents}</strong></div>
    <div>Primary Attack: <strong>${dist.type}</strong></div>
  `;

  tooltipEl.style.display = "block";
  tooltipEl.style.left = (window.scrollX + rect.left + 20) + "px";
  tooltipEl.style.top = (window.scrollY + rect.top - 20) + "px";
}

function hideMapTooltip() {
  if (tooltipEl) tooltipEl.style.display = "none";
}

function selectMapDistrict(dist) {
  // Update a details card if present in DOM
  const titleEl = document.getElementById("tn-district-title");
  const countEl = document.getElementById("tn-district-incidents");
  const typeEl = document.getElementById("tn-district-threat");
  const presetEl = document.getElementById("tn-district-preset");

  if (titleEl) titleEl.innerText = `${dist.name} District Security Dossier`;
  if (countEl) countEl.innerText = dist.incidents;
  if (typeEl) {
    typeEl.innerText = dist.type;
    typeEl.style.color = getThreatColorHex(dist.threat);
  }

  // Populate simulated onboarded systems
  if (presetEl) {
    let presets = "";
    if (dist.incidents > 50) {
      presets = `
        <div class="district-sys-badge critical">🏫 University Portal (Critical Risk)</div>
        <div class="district-sys-badge high">🏥 Civil Hospital System (DDoS target)</div>
        <div class="district-sys-badge medium">🏛️ District Collectorate Network</div>
      `;
    } else {
      presets = `
        <div class="district-sys-badge low">🏛️ District Collectorate Network</div>
        <div class="district-sys-badge low">🚔 CCTNS Police Station Link</div>
      `;
    }
    presetEl.innerHTML = presets;
  }

  // Highlight selected node
  document.querySelectorAll(".map-district-node circle").forEach(c => {
    c.setAttribute("stroke", "#fff");
    c.setAttribute("stroke-width", "1");
  });
  
  const selectedNode = document.querySelector(`#map-node-${dist.id} circle`);
  if (selectedNode) {
    selectedNode.setAttribute("stroke", "#00d4ff");
    selectedNode.setAttribute("stroke-width", "3");
  }
}
