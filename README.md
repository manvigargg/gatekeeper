# GateKeeper 🔒
### Supply Chain Attack Detector for CI/CD Pipelines

GateKeeper is an open-source security tool that monitors Python dependencies
for supply chain attacks — the same attack vector behind SolarWinds, Codecov,
and the XZ Utils backdoor.

---

## What it detects

| Attack Type | How |
|---|---|
| Typosquatting | Levenshtein edit-distance against top 50 PyPI packages |
| Malicious install scripts | AST static analysis for network calls, shell execution, credential theft |
| Suspicious metadata | New packages, low downloads, missing homepages |
| Dependency confusion | Public package hijacking private internal names |

---

## Project Structure
gatekeeper/
├── phase1/   PyPI metadata checker
├── phase2/   Typosquatting detector
├── phase3/   AST-based static analyser
├── phase4/   Docker sandboxed execution      [coming soon]
└── phase5/   GitHub Actions + SLSA reporting [coming soon]

---

## Usage

**Phase 1 — Metadata check:**
```bash
cd phase1
python pypi_checker.py requirements.txt
```

**Phase 2 — Typosquatting scan:**
```bash
cd phase2
python typosquat_checker.py requirements.txt
```

**Phase 3 — AST analysis:**
```bash
cd phase3
python ast_analyzer.py fake_malicious_setup.py
```

---

## Tech Stack
Python · PyPI API · GitHub API · Levenshtein Distance · AST Analysis · Docker · GitHub Actions · SLSA

---

## Real-world attacks this catches
- **SolarWinds (2020)** — compromised build pipeline injected malware into signed updates
- **Codecov (2021)** — malicious bash script exfiltrated CI environment variables
- **XZ Utils (2024)** — backdoor hidden in build scripts, nearly compromised millions of Linux systems