// scanner.js — live GateKeeper API client + result rendering
// Connects to the local GateKeeper FastAPI backend so the UI remains exact while
// the data comes from the real detection engine in this project.

const API_URL = (() => {
  const meta = document.querySelector('meta[name="gatekeeper-api-url"]');
  const metaUrl = meta ? meta.getAttribute("content") : "";
  const configured = window.GATEKEEPER_API_URL || metaUrl || "http://localhost:8000";
  return String(configured).replace(/\/$/, "");
})();

// ── Preset attack vectors ────────────────────────────────────────────
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

// ── Severity → paper-surface colour ──────────────────────────────────
// These are the DARK variants from the design system. The bright panel
// values (#FF6A4D etc.) fail contrast on the bone background — do not
// substitute them here.
const SEVERITY_COLOR = {
  CRITICAL: "var(--sev-critical)",
  HIGH:     "var(--sev-high)",
  MEDIUM:   "var(--sev-low)",
  LOW:      "var(--sev-safe)",
  NONE:     "var(--sev-safe)"
};

const ACTION_COLOR = {
  BLOCK: "var(--sev-critical)",
  WARN:  "var(--sev-high)",
  PASS:  "var(--sev-safe)",
  ALLOW: "var(--sev-safe)"
};

function normalizeSeverity(raw) {
  const value = String(raw || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH" || value === "MEDIUM") return value;
  if (value === "LOW" || value === "CLEAN" || value === "NONE") return "LOW";
  return "LOW";
}

function normalizeAction(raw) {
  const value = String(raw || "").toUpperCase();
  if (value === "BLOCK" || value === "WARN" || value === "PASS") return value;
  if (value === "LOG") return "PASS";
  if (value === "ALLOW") return "PASS";
  return "PASS";
}

function severityColor(sev) {
  return SEVERITY_COLOR[String(normalizeSeverity(sev)).toUpperCase()] || "var(--sev-safe)";
}

function actionColor(action) {
  return ACTION_COLOR[String(normalizeAction(action)).toUpperCase()] || "var(--sev-safe)";
}

function escapeHtml(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ── Parse requirements.txt into a package list ───────────────────────
function parseRequirements(text) {
  return text
    .split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"));
}

// ── Result row ───────────────────────────────────────────────────────
function renderRow(result, index) {
  const severity = normalizeSeverity(result.severity);
  const action = normalizeAction(result.build_action);
  const color   = severityColor(severity);
  const acolor  = actionColor(action);
  const score   = Number(result.combined_score) || 0;
  const version = result.pinned_version
    ? `<span class="res-version">==${escapeHtml(result.pinned_version)}</span>`
    : "";
  const findings = (result.findings && result.findings.length)
    ? result.findings.map(escapeHtml).join(" · ")
    : "No threats detected";

  return `
    <div class="res-row" style="animation-delay:${index * 45}ms">
      <div>
        <div class="res-name">${escapeHtml(result.name)}${version}</div>
        <div class="res-track"><div class="res-fill" style="width:${score}%; background:${color}"></div></div>
        <div class="res-why">${escapeHtml(severity)} · ${findings}</div>
      </div>
      <div class="res-score" style="color:${color}">${score}</div>
      <div class="res-action" style="color:${acolor}">${escapeHtml(action)}</div>
    </div>`;
}

// ── Verdict banner + tally + table head ──────────────────────────────
function renderSummary(data) {
  const blocked = !!data.build_blocked;

  const verdict = `
    <div class="verdict ${blocked ? "verdict--block" : "verdict--pass"}">
      <div class="verdict-label">BUILD DECISION</div>
      <div class="verdict-value">${blocked ? "BUILD BLOCKED · EXIT 1" : "BUILD PASSED · EXIT 0"}</div>
    </div>`;

  const cells = [
    ["SCANNED",  data.total,    "var(--ink)"],
    ["CRITICAL", data.critical, "var(--sev-critical)"],
    ["HIGH",     data.high,     "var(--sev-high)"],
    ["CLEAN",    data.clean,    "var(--sev-safe)"]
  ].map(([label, val, col]) => `
    <div class="tally-cell">
      <div class="tally-num" style="color:${col}">${Number(val) || 0}</div>
      <div class="tally-label">${label}</div>
    </div>`).join("");

  return `
    ${verdict}
    <div class="tally">${cells}</div>
    <div class="res-head"><span>PACKAGE · SEVERITY · FINDING</span><span>SCORE</span><span>ACTION</span></div>`;
}

// ── States ───────────────────────────────────────────────────────────
function showScanning(container, count) {
  container.innerHTML = `
    <div class="scan-busy">
      <div class="scan-ring"></div>
      <div class="scan-blink">SCANNING ${count} PACKAGE${count !== 1 ? "S" : ""}…</div>
    </div>`;
}

function showError(container, message) {
  container.innerHTML = `
    <div class="scan-error">
      <div class="scan-error-head">⚠ API ERROR</div>
      <div>${escapeHtml(message)}</div>
      <div class="scan-error-hint">
        Free-tier hosting sleeps after 15 minutes of inactivity.<br />
        A cold first request can take 30–50 seconds. Try again.
      </div>
    </div>`;
}

// ── Main ─────────────────────────────────────────────────────────────
async function runScan() {
  const editor    = document.getElementById("codeEditor");
  const container = document.getElementById("resultsContainer");
  const btn       = document.getElementById("btnScan");
  const state     = document.getElementById("scanState");

  const packages = parseRequirements(editor.value.trim());

  if (!packages.length) {
    if (state) state.textContent = "NO INPUT";
    showError(container, "No packages found. Add at least one requirement line to scan.");
    return;
  }

  btn.disabled = true;
  btn.textContent = "SCANNING…";
  if (state) state.textContent = "RUNNING";
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
    const rows = (data.results || []).map(renderRow).join("");
    container.innerHTML = renderSummary(data) + rows;

    if (state) state.textContent = `${data.total || packages.length} EVALUATED`;
  } catch (err) {
    if (state) state.textContent = "ERROR";
    showError(container, err.message || "Could not reach the GateKeeper API.");
  } finally {
    btn.disabled = false;
    btn.textContent = "RUN GATEKEEPER SCAN";
  }
}
