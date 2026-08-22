// app.js — presets, YAML sync, copy, nav state, line counter

document.addEventListener("DOMContentLoaded", () => {

  const editor = document.getElementById("codeEditor");
  const lineCount = document.getElementById("lineCount");

  // ── Line counter ──
  function updateLineCount() {
    if (!editor || !lineCount) return;
    const n = editor.value.split("\n")
      .map(l => l.trim())
      .filter(l => l && !l.startsWith("#")).length;
    lineCount.textContent = `${n} PACKAGE${n === 1 ? "" : "S"}`;
  }

  // ── Presets ──
  document.querySelectorAll(".preset-btn[data-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn[data-preset]")
        .forEach(b => b.classList.remove("is-active"));
      btn.classList.add("is-active");
      if (editor) {
        editor.value = PRESETS[btn.dataset.preset] || "";
        updateLineCount();
      }
    });
  });

  if (editor) {
    editor.value = PRESETS.typosquat;
    editor.addEventListener("input", updateLineCount);
    updateLineCount();
  }

  // ── Scan ──
  const scanBtn = document.getElementById("btnScan");
  if (scanBtn) scanBtn.addEventListener("click", runScan);

  // ── Policy selects rewrite the YAML sample ──
  const sevSelect  = document.getElementById("inputFailSeverity");
  const sandSelect = document.getElementById("inputSkipSandbox");
  const yamlEl     = document.getElementById("yamlContent");

  function renderYaml() {
    if (!yamlEl) return;
    const sev  = sevSelect  ? sevSelect.value  : "CRITICAL";
    const skip = sandSelect ? sandSelect.value : "true";
    yamlEl.textContent =
`name: Security Audit Pipeline
on: [push, pull_request]

jobs:
  gatekeeper-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: GateKeeper Supply Chain Scan
        uses: Swan/gatekeeper@v1
        with:
          requirements-file: 'requirements.txt'
          fail-on-severity: '${sev}'
          skip-sandbox: '${skip}'`;
  }

  if (sevSelect)  sevSelect.addEventListener("change", renderYaml);
  if (sandSelect) sandSelect.addEventListener("change", renderYaml);
  renderYaml();

  // ── Copy YAML ──
  const copyBtn = document.getElementById("btnCopyYaml");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(yamlEl.textContent).then(() => {
        copyBtn.textContent = "COPIED";
        setTimeout(() => (copyBtn.textContent = "COPY"), 1600);
      });
    });
  }

  // ── Nav active state on scroll ──
  const sections = ["scanner", "architecture", "cicd", "attacks"]
    .map(id => document.getElementById(id))
    .filter(Boolean);
  const navLinks = Array.from(document.querySelectorAll(".nav-link"));

  if ("IntersectionObserver" in window && sections.length) {
    const io = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        navLinks.forEach(a => {
          a.classList.toggle("is-active", a.getAttribute("href") === `#${entry.target.id}`);
        });
      });
    }, { rootMargin: "-40% 0px -55% 0px" });
    sections.forEach(s => io.observe(s));
  }

  // NOTE: anchor navigation uses native CSS scroll-behavior (see styles.css).
  // Do not add a scrollIntoView handler — it fights the sticky nav offset.
});
