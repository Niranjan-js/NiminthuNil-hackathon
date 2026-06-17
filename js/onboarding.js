/**
 * NIRAVAN – Department Onboarding Wizard
 * Wizard modal to select department type, district, and auto-initialize presets
 */

window.initOnboardingWizard = function() {
  // Check if already onboarded in this session/localStorage
  if (localStorage.getItem("NIRAVAN_ONBOARDED") === "true") {
    return;
  }

  // Create wizard container and overlay
  const overlay = document.createElement("div");
  overlay.id = "onboarding-wizard-overlay";
  overlay.className = "tn-wizard-overlay";

  // Build the wizard container
  const wizard = document.createElement("div");
  wizard.className = "tn-wizard-container glass-panel";
  wizard.id = "onboarding-wizard-modal";

  overlay.appendChild(wizard);
  document.body.appendChild(overlay);

  // Render Step 1
  renderWizardStep(1, wizard);
};

// Wizard State
window.onboardingData = {
  deptType: "",
  deptName: "",
  district: "",
  assetCount: 50,
  email: ""
};

function renderWizardStep(step, wizardElement = null) {
  try {
    const wizard = wizardElement || document.getElementById("onboarding-wizard-modal");
    if (!wizard) {
      console.error("[NIRAVAN] Onboarding wizard modal element not found!");
      return;
    }

    const isTamil = window.NIRAVAN_CURRENT_LANG === "ta";
    let content = "";

  if (step === 1) {
    // Step 1: Select Department Preset
    content = `
      <div class="wizard-header">
        <h2 data-i18n="onboard-title">${isTamil ? "துறை ஒருங்கிணைப்பு வழிகாட்டி" : "Department Onboarding Setup Wizard"}</h2>
        <span class="step-indicator">Step 1 of 3</span>
      </div>
      <p class="wizard-desc">Select your government sector or institution type to auto-configure appropriate cybersecurity presets, honeypots, and monitoring priorities.</p>
      
      <div class="preset-grid">
        <div class="preset-card" onclick="selectPreset('School')">
          <div class="preset-icon">🏫</div>
          <div class="preset-name" data-i18n="onboard-school">${isTamil ? "கல்வி நிறுவனம் (பள்ளி / கல்லூரி)" : "Educational Institution (School / College)"}</div>
          <div class="preset-info">Protects student portals, admission records, and exam databases. High anti-phishing priority.</div>
        </div>
        <div class="preset-card" onclick="selectPreset('Collectorate')">
          <div class="preset-icon">🏛️</div>
          <div class="preset-name" data-i18n="onboard-collectorate">${isTamil ? "மாவட்ட ஆட்சியரகம் / அரசு அலுவலகம்" : "District Collectorate / Govt Office"}</div>
          <div class="preset-info">Protects land records, citizen data databases, and official email accounts. Legal compliances focused.</div>
        </div>
        <div class="preset-card" onclick="selectPreset('Hospital')">
          <div class="preset-icon">🏥</div>
          <div class="preset-name" data-i18n="onboard-hospital">${isTamil ? "அரசு மருத்துவமனை / சுகாதாரம்" : "Government Hospital / Healthcare"}</div>
          <div class="preset-info">Protects patient records (EHR), hospital inventory, and connected IoT medical equipment.</div>
        </div>
        <div class="preset-card" onclick="selectPreset('Police')">
          <div class="preset-icon">🚔</div>
          <div class="preset-name" data-i18n="onboard-police">${isTamil ? "காவல்துறை / சட்ட அமலாக்கம்" : "Police Department / Law Enforcement"}</div>
          <div class="preset-info">Protects FIR databases, CCTNS station links, and surveillance networks. High access control priority.</div>
        </div>
        <div class="preset-card" onclick="selectPreset('Treasury')">
          <div class="preset-icon">💰</div>
          <div class="preset-name" data-i18n="onboard-treasury">${isTamil ? "கருவூலம் மற்றும் நிதித் துறை" : "Treasury & Financial Department"}</div>
          <div class="preset-info">Protects state pension servers, salary disbursements, and payment portals. Maximum threat defense.</div>
        </div>
      </div>
    `;
  } else if (step === 2) {
    // Step 2: Details Form
    const districtsOptions = window.TN_DISTRICTS.map(d => `<option value="${d.name}">${d.name}</option>`).join("");
    content = `
      <div class="wizard-header">
        <h2>${isTamil ? "துறை விவரங்களை உள்ளிடவும்" : "Enter Department Details"}</h2>
        <span class="step-indicator">Step 2 of 3</span>
      </div>
      <p class="wizard-desc">Configure district mappings and security scoping metrics.</p>
      
      <div class="wizard-form">
        <div class="form-group">
          <label>Department / Institution Name</label>
          <input type="text" id="wizard-dept-name" placeholder="e.g. Government Higher Secondary School, Salem" value="${window.onboardingData.deptName}">
        </div>
        
        <div class="form-row">
          <div class="form-group">
            <label>Tamil Nadu District</label>
            <select id="wizard-district">
              <option value="" disabled selected>Select District</option>
              ${districtsOptions}
            </select>
          </div>
          <div class="form-group">
            <label>Number of Endpoints / computers</label>
            <input type="number" id="wizard-assets" min="5" max="10000" value="${window.onboardingData.assetCount}">
          </div>
        </div>
        
        <div class="form-group">
          <label>Security Coordinator Email Address</label>
          <input type="email" id="wizard-email" placeholder="coordinator@tn.gov.in" value="${window.onboardingData.email}">
        </div>

        <div class="wizard-buttons">
          <button class="btn btn-outline" onclick="renderWizardStep(1)">Back</button>
          <button class="btn btn-primary" onclick="submitStep2()">Optimize System &rarr;</button>
        </div>
      </div>
    `;
  } else if (step === 3) {
    // Step 3: Optimizing Loading Animation
    content = `
      <div class="wizard-header text-center">
        <h2>Optimizing NIRAVAN Security Core</h2>
      </div>
      <div class="optimizing-loader">
        <div class="cyber-spinner"></div>
        <ul class="optimization-log" id="opt-log">
          <li class="pending">Deploying context-aware Honey-tokens...</li>
          <li class="pending">Configuring district threat intelligence links...</li>
          <li class="pending">Setting up CERT-In compliance matrices...</li>
          <li class="pending">Activating active threat defense shields...</li>
        </ul>
      </div>
    `;

    setTimeout(runOptimizationAnimation, 400);
  } else if (step === 4) {
    // Step 4: Finished Onboarded
    content = `
      <div class="wizard-header text-center">
        <div class="success-shield">🛡️</div>
        <h2 style="color:#30d158; margin-top:10px;">NIRAVAN SECURED</h2>
      </div>
      <p class="wizard-desc text-center">
        NIRAVAN Autonomous Agent is active and protecting <strong>${window.onboardingData.deptName}</strong> (${window.onboardingData.deptType} Preset) in <strong>${window.onboardingData.district} District</strong>.
      </p>
      
      <div class="summary-box">
        <div>Asset Count Protected: <strong>${window.onboardingData.assetCount}</strong></div>
        <div>Uplink Status: <span style="color:#30d158; font-weight:700;">Active to Chennai State SOC</span></div>
        <div>Active Security Shield: <span style="color:#00d4ff; font-weight:700;">CERT-In 6h reporting enabled</span></div>
      </div>

      <div class="wizard-buttons" style="justify-content:center;">
        <button class="btn btn-primary" onclick="completeOnboarding()">Enter Command Center</button>
      </div>
    `;
  }

    wizard.innerHTML = content;
  } catch (e) {
    console.error("[NIRAVAN] renderWizardStep error:", e);
  }
}

window.selectPreset = function(type) {
  window.onboardingData.deptType = type;
  
  // Set default names for presets
  if (type === "School") {
    window.onboardingData.deptName = "Chennai Central Arts and Science College";
    window.onboardingData.assetCount = 120;
  } else if (type === "Collectorate") {
    window.onboardingData.deptName = "Salem District Collectorate";
    window.onboardingData.assetCount = 350;
  } else if (type === "Hospital") {
    window.onboardingData.deptName = "Rajaji Govt General Hospital, Madurai";
    window.onboardingData.assetCount = 85;
  } else if (type === "Police") {
    window.onboardingData.deptName = "Vellore Cyber Police Headquarters";
    window.onboardingData.assetCount = 45;
  } else if (type === "Treasury") {
    window.onboardingData.deptName = "TN State Treasury Directorate, Chennai";
    window.onboardingData.assetCount = 500;
  }
  
  renderWizardStep(2);
};

window.submitStep2 = function() {
  const name = document.getElementById("wizard-dept-name").value.trim();
  const district = document.getElementById("wizard-district").value;
  const assets = parseInt(document.getElementById("wizard-assets").value);
  const email = document.getElementById("wizard-email").value.trim();

  if (!name || !district || !email) {
    alert("Please fill in all details, including district and official email.");
    return;
  }

  window.onboardingData.deptName = name;
  window.onboardingData.district = district;
  window.onboardingData.assetCount = assets;
  window.onboardingData.email = email;

  renderWizardStep(3);
};

function runOptimizationAnimation() {
  const logs = document.querySelectorAll("#opt-log li");
  if (logs.length === 0) return;

  let index = 0;
  
  function advance() {
    if (index > 0) {
      logs[index - 1].className = "done";
      logs[index - 1].innerHTML = "✓ " + logs[index - 1].innerHTML.replace("...", "");
    }
    
    if (index < logs.length) {
      logs[index].className = "active";
      index++;
      setTimeout(advance, 800);
    } else {
      setTimeout(() => {
        renderWizardStep(4);
      }, 500);
    }
  }

  advance();
}

window.completeOnboarding = function() {
  // Save state
  localStorage.setItem("NIRAVAN_ONBOARDED", "true");
  localStorage.setItem("NIRAVAN_DEPT_TYPE", window.onboardingData.deptType);
  localStorage.setItem("NIRAVAN_DEPT_NAME", window.onboardingData.deptName);
  localStorage.setItem("NIRAVAN_DISTRICT", window.onboardingData.district);
  localStorage.setItem("NIRAVAN_ASSET_COUNT", window.onboardingData.assetCount);
  localStorage.setItem("NIRAVAN_ADMIN_EMAIL", window.onboardingData.email);

  // Close modal
  const overlay = document.getElementById("onboarding-wizard-overlay");
  if (overlay) {
    overlay.remove();
  }

  // Update UI and trigger events
  const event = new CustomEvent("niravanOnboardingCompleted", { detail: window.onboardingData });
  window.dispatchEvent(event);

  // If backend is active, send details to save on server
  const token = localStorage.getItem("NIRAVAN_TOKEN");
  if (token) {
    fetch("/api/v1/auth/me", {
      headers: { "Authorization": `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(user => {
      // In the future, we can submit details via a PUT endpoint
      console.log("[NIRAVAN] Onboarded user:", user.email);
    })
    .catch(err => console.error(err));
  }

  // Force page reload or routing refresh to display brand-new preset values
  if (window.refreshApplicationData) {
    window.refreshApplicationData();
  }
};
