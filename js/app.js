// app.js — handles presets, copy button, navbar scroll

document.addEventListener("DOMContentLoaded", () => {

  // ── Preset buttons ──
  document.querySelectorAll(".preset-btn[data-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn[data-preset]")
        .forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("codeEditor").value =
        PRESETS[btn.dataset.preset] || "";
    });
  });

  // ── Scan button ──
  document.getElementById("btnScan")
    .addEventListener("click", runScan);

  // ── Copy YAML button ──
  const copyBtn = document.getElementById("btnCopyYaml");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const yaml = document.getElementById("yamlContent").textContent;
      navigator.clipboard.writeText(yaml).then(() => {
        copyBtn.textContent = "Copied!";
        setTimeout(() => copyBtn.textContent = "Copy YAML", 2000);
      });
    });
  }

  // ── Navbar scroll effect ──
  window.addEventListener("scroll", () => {
    const nav = document.getElementById("navbar");
    if (nav) {
      nav.style.background = window.scrollY > 40
        ? "rgba(8,7,6,0.95)"
        : "rgba(8,7,6,0.7)";
    }
  });

  // ── Smooth scroll for nav links ──
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener("click", e => {
      const target = document.querySelector(a.getAttribute("href"));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: "smooth" });
      }
    });
  });

});