// scanner.js — connects to the live GateKeeper API
// API: https://gatekeeper-api-tp3a.onrender.com

const API_URL = "https://gatekeeper-api-tp3a.onrender.com";

// ── Preset attack vectors ──
const PRESETS = {
  typosquat: `# Typosquatting attack vector demonstration
reqeusts==2.31.0
coloramaa==0.4.6
urllib4==1.26.5
flask==3.0.0
django==4.2.0`,

  malicious: `# Known malicious packages (removed from PyPI)
ctx==0.1.2
pygrata==0.1.0
loglib-modules==0.1.0
requests==2.31.0
numpy==1.26.4`,

  clean: `# Clean production build
requests==2.31.0
flask==3.0.2
numpy==1.26.4
pandas==2.2.1
boto3==1.34.0`
};

// ── Parse requirements.txt into package list ──
function parseRequirements(text) {
  return text
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"));
}

// ── Severity → colour mapping ──
function severityColor(sev) {
  switch (sev) {
    case "CRITICAL": return "#ff3b3b";
    case "HIGH":     return "#ffcc00";
    case "MEDIUM":   return "#0088ff";
    default:         return "#00e87a";
  }
}

function actionColor(action) {
  switch (action) {
    case "BLOCK": return "#ff3b3b";
    case "WARN":  return "#ffcc00";
    default:      return "#00e87a";
  }
}

// ── Render a single package result row ──
function renderRow(result, index) {
  const color  = severityColor(result.severity);
  const acolor = actionColor(result.build_action);
  const delay  = index * 80;

  const findings = result.findings.length > 0
    ? result.findings.join(" · ")
    : "No threats detected";

  const scorePercent = result.combined_score;

  return `
    <div class="result-row" style="
      border-left: 3px solid ${color};
      background: rgba(${result.severity === 'CRITICAL' ? '255,59,59' :
                        result.severity === 'HIGH'     ? '255,204,0' :
                        result.severity === 'MEDIUM'   ? '0,136,255' :
                                                         '0,232,122'}, 0.04);
      padding: 14px 16px;
      margin-bottom: 8px;
      animation: rowSlide 0.35s ease ${delay}ms backwards;
      display: grid;
      grid-template-columns: 1.5fr 80px 2fr 100px 70px;
      gap: 12px;
      align-items: center;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      transition: background 0.2s;
      cursor: default;
    "
    onmouseover="this.style.background='rgba(255,255,255,0.03)'"
    onmouseout="this.style.background='rgba(${result.severity === 'CRITICAL' ? '255,59,59' :
                                              result.severity === 'HIGH'     ? '255,204,0' :
                                              result.severity === 'MEDIUM'   ? '0,136,255' :
                                                                               '0,232,122'}, 0.04)'"
    >
      <div style="font-family:'Space Mono',monospace; font-size:12px; color:#fff; font-weight:700;">
        ${result.name}${result.pinned_version
          ? `<span style="color:rgba(255,255,255,0.25);font-weight:400">==` +
            result.pinned_version + `</span>`
          : ''}
      </div>
      <div>
        <span style="
          font-family:'Space Mono',monospace;
          font-size:9px; letter-spacing:1px;
          padding:3px 7px; border:1px solid ${color};
          color:${color}; text-transform:uppercase;
        ">${result.severity}</span>
      </div>
      <div style="font-family:'Space Mono',monospace; font-size:10px;
                  color:rgba(200,216,224,0.5); line-height:1.5;">
        ${findings}
      </div>
      <div>
        <div style="font-family:'Space Mono',monospace; font-size:10px;
                    color:rgba(200,216,224,0.6); margin-bottom:4px;">
          ${result.combined_score}/100
        </div>
        <div style="height:2px; background:rgba(255,255,255,0.06); overflow:hidden;">
          <div style="height:100%; width:${scorePercent}%;
                      background:${color};
                      transition:width 0.8s cubic-bezier(0.25,0.46,0.45,0.94);">
          </div>
        </div>
      </div>
      <div>
        <span style="
          font-family:'Space Mono',monospace; font-size:9px;
          letter-spacing:1px; padding:4px 8px; border:1px solid ${acolor};
          color:${acolor}; text-transform:uppercase;
          ${result.build_action === 'BLOCK'
            ? 'animation:badgePulse 2s ease-in-out infinite;' : ''}
        ">${result.build_action}</span>
      </div>
    </div>`;
}

// ── Render summary header after scan ──
function renderSummary(data) {
  const statusColor = data.build_blocked ? "#ff3b3b" : "#00e87a";
  const statusText  = data.build_blocked
    ? "⚠ BUILD BLOCKED — CRITICAL FINDINGS DETECTED"
    : "✓ BUILD PASSED — ALL PACKAGES CLEARED";

  return `
    <div style="
      font-family:'Space Mono',monospace;
      font-size:11px; letter-spacing:2px;
      padding:12px 16px; margin-bottom:16px;
      border:1px solid ${statusColor};
      color:${statusColor};
      background:rgba(${data.build_blocked ? '255,59,59' : '0,232,122'},0.06);
      text-transform:uppercase;
    ">${statusText}</div>

    <div style="
      display:grid; grid-template-columns:repeat(4,1fr);
      gap:8px; margin-bottom:20px;
    ">
      ${[
        ['SCANNED',  data.total,    '#c8d8e0'],
        ['CRITICAL', data.critical, '#ff3b3b'],
        ['HIGH',     data.high,     '#ffcc00'],
        ['CLEAN',    data.clean,    '#00e87a'],
      ].map(([label, val, col]) => `
        <div style="
          background:rgba(255,255,255,0.03);
          border:1px solid rgba(255,255,255,0.07);
          padding:12px; text-align:center;
        ">
          <div style="font-size:24px; font-weight:700;
                      font-family:'Space Mono',monospace;
                      color:${col}; margin-bottom:4px;">${val}</div>
          <div style="font-size:9px; letter-spacing:2px;
                      color:rgba(200,216,224,0.4);">${label}</div>
        </div>`).join('')}
    </div>

    <div style="
      display:grid;
      grid-template-columns:1.5fr 80px 2fr 100px 70px;
      gap:12px; padding:8px 16px; margin-bottom:4px;
      font-family:'Space Mono',monospace; font-size:9px;
      letter-spacing:2px; color:rgba(200,216,224,0.3);
      text-transform:uppercase; border-bottom:1px solid rgba(255,255,255,0.06);
    ">
      <span>Package</span>
      <span>Severity</span>
      <span>Finding</span>
      <span>Score</span>
      <span>Action</span>
    </div>`;
}

// ── Scanning overlay ──
function showScanning(container, packageCount) {
  container.innerHTML = `
    <div style="
      display:flex; flex-direction:column;
      align-items:center; justify-content:center;
      min-height:200px; gap:20px;
    ">
      <div style="
        width:60px; height:60px;
        border:1px solid rgba(0,232,122,0.2);
        border-top:1px solid #00e87a;
        border-radius:50%;
        animation:spinRing 1s linear infinite;
      "></div>
      <div style="
        font-family:'Space Mono',monospace;
        font-size:11px; letter-spacing:4px;
        color:#00e87a; animation:blink 1s ease-in-out infinite;
      ">SCANNING ${packageCount} PACKAGE${packageCount !== 1 ? 'S' : ''}...</div>
      <div style="
        font-family:'Space Mono',monospace;
        font-size:10px; color:rgba(200,216,224,0.3);
      ">Calling live GateKeeper API</div>
    </div>`;
}

// ── Error display ──
function showError(container, message) {
  container.innerHTML = `
    <div style="
      font-family:'Space Mono',monospace;
      font-size:11px; color:#ff3b3b;
      padding:20px; border:1px solid rgba(255,59,59,0.3);
      background:rgba(255,59,59,0.05); letter-spacing:1px;
    ">
      <div style="margin-bottom:8px; letter-spacing:3px;">⚠ API ERROR</div>
      <div style="color:rgba(200,216,224,0.5); font-size:10px;">${message}</div>
      <div style="color:rgba(200,216,224,0.3); font-size:9px; margin-top:12px;">
        Note: Render free tier sleeps after 15 min inactivity.<br>
        First request may take 30–50 seconds to wake up. Try again.
      </div>
    </div>`;
}

// ── MAIN SCAN FUNCTION ──
async function runScan() {
  const editor    = document.getElementById("codeEditor");
  const container = document.getElementById("resultsContainer");
  const btn       = document.getElementById("btnScan");

  const raw      = editor.value.trim();
  const packages = parseRequirements(raw);

  if (!packages.length) {
    showError(container, "No packages found. Add at least one package to scan.");
    return;
  }

  // Show loading state
  btn.disabled    = true;
  btn.textContent = "Scanning...";
  showScanning(container, packages.length);

  try {
    const response = await fetch(`${API_URL}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packages })
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    // Render results
    container.innerHTML =
      renderSummary(data) +
      data.results.map((r, i) => renderRow(r, i)).join("");

  } catch (err) {
    showError(container, err.message || "Could not reach the GateKeeper API.");
  } finally {
    btn.disabled    = false;
    btn.innerHTML   = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Run GateKeeper Scan`;
  }
}

// ── Inject required CSS animations ──
const style = document.createElement("style");
style.textContent = `
  @keyframes rowSlide {
    from { opacity:0; transform:translateX(16px); }
    to   { opacity:1; transform:translateX(0); }
  }
  @keyframes spinRing {
    to { transform: rotate(360deg); }
  }
  @keyframes blink {
    0%,100% { opacity:1; } 50% { opacity:0.3; }
  }
  @keyframes badgePulse {
    0%,100% { opacity:1; } 50% { opacity:0.4; }
  }
`;
document.head.appendChild(style);