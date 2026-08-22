# 🔒 GateKeeper

### Supply Chain Attack Detector for CI/CD Pipelines

GateKeeper is an open-source Python security tool that scans Python dependencies for supply chain attacks before they enter your build pipeline. It detects typosquatting, suspicious package metadata, malicious install scripts, and anomalous runtime behaviour — the same attack vectors behind SolarWinds, Codecov, and the XZ Utils backdoor.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0088ff?style=flat-square)](https://manvigargg.github.io/gatekeeper)
[![API](https://img.shields.io/badge/API-Render-00e87a?style=flat-square)](https://gatekeeper-api-tp3a.onrender.com)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions)](https://github.com/manvigargg/gatekeeper/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-amber?style=flat-square)](LICENSE)

---

## What is GateKeeper?

GateKeeper monitors every Python dependency in your `requirements.txt` and runs it through a multi-phase detection engine before `pip install` executes. If a package is suspicious, GateKeeper flags it with a risk score, a severity level, and a build action (PASS / WARN / BLOCK) — and can automatically block a pull request from merging via GitHub Actions.

The tool addresses a fundamental gap in most CI/CD pipelines: dependencies are trusted by default. GateKeeper removes that implicit trust.

---

## Why Supply Chain Security Matters

Supply chain attacks target the software you depend on, not the software you write:

| Attack | Year | Method | Impact |
|---|---|---|---|
| **SolarWinds** | 2020 | Compromised build pipeline injected malware into signed updates | 18,000+ organisations affected |
| **Codecov** | 2021 | Modified bash uploader silently exfiltrated CI environment variables | Twitch, Hashicorp, Atlassian breached |
| **XZ Utils** | 2024 | Obfuscated backdoor hidden in build scripts, targeting SSH authentication | Nearly compromised millions of Linux systems |

GateKeeper is designed to catch attacks in this category before they reach your production environment.

---

## Key Features

- **PyPI metadata analysis** — checks download counts, package age, version validity, and homepage presence
- **Levenshtein typosquatting detection** — dynamic programming edit-distance algorithm against the top 50 PyPI packages
- **AST static analysis** — parses install scripts as Abstract Syntax Trees and flags network calls, shell execution, credential theft, and base64 obfuscation
- **Docker sandbox execution** — runs packages in isolated containers with strace syscall monitoring
- **Unified risk scoring** — weighted combination of all phases into a single 0–100 score with severity classification
- **GitHub Actions integration** — automatically blocks PR merges on CRITICAL findings
- **Live REST API** — FastAPI backend deployed on Render, callable from any CI/CD system
- **Interactive web dashboard** — static frontend with 3D Three.js visualisation, live scanner, and real-time API results
- **Benchmarked detection** — validated against the Backstabber malicious package dataset

---

## How GateKeeper Works

```
requirements.txt
      ↓
┌─────────────────────────────────────────────┐
│              GateKeeper Engine              │
│                                             │
│  Phase 1: PyPI metadata check (weight 20%) │
│  Phase 2: Typosquatting detection (30%)    │
│  Phase 4: Docker sandbox runtime (50%)     │
│                                             │
│  Combined risk score → severity → action   │
└─────────────────────────────────────────────┘
      ↓
PASS / WARN / BLOCK
```

Each phase produces a score from 0–100. The unified scanner combines them using weighted averaging, with the sandbox carrying the most weight because runtime behaviour is the hardest evidence to fake.

| Score | Severity | Build action |
|---|---|---|
| 75–100 | CRITICAL | BLOCK |
| 45–74 | HIGH | WARN |
| 20–44 | MEDIUM | LOG |
| 0–19 | CLEAN | PASS |

---

## Architecture

```
gatekeeper/
├── phase1/              # PyPI metadata checker
│   ├── pypi_checker.py
│   └── requirements.txt
├── phase2/              # Typosquatting detector
│   ├── popular_packages.py
│   ├── typosquat_checker.py
│   └── requirements.txt
├── phase3/              # AST static analyser
│   ├── suspicious_patterns.py
│   ├── ast_analyzer.py
│   └── fake_malicious_setup.py
├── phase4/              # Docker sandbox
│   ├── Dockerfile
│   ├── monitor.py
│   ├── sandbox_runner.py
│   └── reports/
├── phase5/              # Unified scanner
│   └── gatekeeper.py
├── phase6/              # Benchmark runner
│   └── benchmark.py
├── phase8/              # FastAPI backend
│   ├── main.py
│   └── requirements.txt
├── .github/
│   └── workflows/
│       └── gatekeeper.yml   # GitHub Actions workflow
├── action.yml               # Reusable GitHub Action definition
├── index.html               # Frontend dashboard
├── css/styles.css
├── js/
│   ├── app.js
│   ├── scanner.js
│   └── gate-3d.js           # Three.js 3D visualisation
├── assets/
│   └── gatekeeper-shield.png
├── Procfile                 # Render deployment
└── requirements.txt         # Root — scanned by GitHub Actions
```

---

## Detection Phases

### Phase 1 — PyPI Metadata Analysis

Calls the public PyPI JSON API (`https://pypi.org/pypi/{package}/json`) for every dependency and checks:

- Does the package exist on PyPI? (404 = immediate flag)
- Does the pinned version exist in the release list?
- Weekly download count (below 1,000 = suspicious)
- Package age (published within 30 days = suspicious)
- Presence of homepage or project URL
- Meaningful package description

### Phase 2 — Typosquatting Detection

Computes Levenshtein edit distance between every scanned package name and the top 50 most-downloaded PyPI packages. Uses dynamic programming (O(m×n) time) for efficiency.

- Edit distance 1 → CRITICAL (one character off)
- Edit distance 2 → HIGH (two edits away)
- Exact match → safe, immediately returns clean

Example:
```
numppy  vs  numpy   → distance 1 → CRITICAL (extra 'p' inserted)
requets vs  requests → distance 1 → CRITICAL (missing 't')
djago   vs  django  → distance 1 → CRITICAL (missing 'n')
```

### Phase 3 — AST Static Analysis

Parses Python install scripts (`setup.py`, `__init__.py`) into Abstract Syntax Trees using Python's built-in `ast` module. Walks every node in the tree and matches against a ruleset of suspicious patterns:

| Category | Severity | Examples |
|---|---|---|
| Network calls | CRITICAL | `socket.connect()`, `urllib.request.urlopen()`, `requests.get()` |
| Shell execution | CRITICAL | `os.system()`, `subprocess.run()`, `subprocess.Popen()` |
| Dynamic execution | CRITICAL | `eval()`, `exec()`, `compile()` |
| Obfuscation | HIGH | `base64.b64decode()`, `codecs.decode()` |
| Credential theft | CRITICAL | `os.getenv()` reading `AWS_*`, `GITHUB_TOKEN` |
| Sensitive file access | CRITICAL | Reading `.ssh/`, `.aws/`, `id_rsa` |

AST analysis catches patterns that text search and regex cannot — the tree walker sees what code *does* regardless of how it is formatted or obfuscated.

### Phase 4 — Docker Sandboxed Execution

Installs the target package inside an isolated Docker container with strace monitoring all system calls. The container:

- Has no access to the host filesystem
- Runs as a non-root user
- Is memory and CPU limited
- Logs every `connect()`, `openat()`, and `execve()` syscall

A whitelist filters out normal pip behaviour (Fastly CDN connections, OS detection calls, SSL certificate reads). Everything remaining is genuine suspicious activity.

Findings are categorised as:
- **Network calls** to non-PyPI IPs
- **Sensitive file access** (`.ssh`, `.aws`, `/etc/passwd`, etc.)
- **Unexpected subprocess spawning**

### Phase 5 — Unified Scanner

Wires all phases into a single command:

```bash
python gatekeeper.py requests flask numppy
python gatekeeper.py --file requirements.txt
```

Produces a combined weighted risk score, per-phase breakdown, and a JSON report saved to `reports/`.

---

## Benchmark Results

Validated against the [Backstabber's Knife Collection](https://github.com/lxyeternal/pypi-malregistry) dataset of real malicious PyPI packages:

| Metric | Result |
|---|---|
| Overall detection rate | **95.0%** (19/20 malicious packages caught) |
| False positive rate | **0.0%** (0/15 clean packages wrongly flagged) |
| Typosquatting catch rate | **100%** (10/10) |
| Credential theft catch rate | **100%** (2/2) |
| Malicious code catch rate | **100%** (5/5) |
| Dependency confusion catch rate | **50%** (1/2) |

The one missed category is pure dependency confusion with a plausible internal package name — this requires knowledge of the organisation's private package registry to catch reliably.

---

## Frontend

The frontend is a static HTML/CSS/JavaScript dashboard hosted on GitHub Pages. It is the presentation and interaction layer for the GateKeeper detection engine — it does not perform detection itself.

**Live URL:** `https://manvigargg.github.io/gatekeeper`

### Features

- **3D GateKeeper shield** — Three.js visualisation with orbit rings, scan pulse animations, and mouse parallax
- **Interactive scanner** — paste any `requirements.txt` and scan against the live API
- **Real scan results** — severity badges, risk score bars, BLOCK/WARN/PASS verdicts rendered from actual backend responses
- **Preset attack vectors** — one-click load of typosquatting, known malicious, and clean package examples
- **Architecture documentation** — all four detection phases explained inline
- **CI/CD integration guide** — copyable GitHub Actions YAML

### API Connection

The frontend calls the live backend directly:

```javascript
const response = await fetch("https://gatekeeper-api-tp3a.onrender.com/api/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ packages })
});
```

All scan results shown in the dashboard are real — returned by the actual detection engine, not hardcoded.

---

## Backend API

**Base URL:** `https://gatekeeper-api-tp3a.onrender.com`

Built with FastAPI and deployed on Render. Source: `phase8/main.py`.

### GET /

Health check.

```json
{
  "status": "online",
  "tool": "GateKeeper",
  "version": "0.5.0",
  "time": "2026-07-29T04:21:44Z"
}
```

### POST /api/scan

Scan a list of packages. Accepts up to 30 packages per request.

**Request:**
```json
{
  "packages": [
    "requests==2.31.0",
    "numppy==1.0.0",
    "flask==3.0.2"
  ]
}
```

**Response:**
```json
{
  "scanned_at": "2026-07-29T04:21:44Z",
  "total": 3,
  "critical": 1,
  "high": 0,
  "clean": 2,
  "build_blocked": true,
  "results": [
    {
      "name": "requests",
      "pinned_version": "2.31.0",
      "severity": "CLEAN",
      "combined_score": 0,
      "build_action": "PASS",
      "findings": [],
      "phases": {
        "phase1": { "score": 0, "findings": [] },
        "phase2": { "score": 0, "findings": [] }
      },
      "scan_time_ms": 2203
    },
    {
      "name": "numppy",
      "pinned_version": "1.0.0",
      "severity": "CRITICAL",
      "combined_score": 90,
      "build_action": "BLOCK",
      "findings": [
        "Package 'numppy' NOT FOUND on PyPI",
        "Looks like 'numpy' (edit distance: 1)"
      ],
      "phases": {
        "phase1": { "score": 90, "findings": ["Package 'numppy' NOT FOUND on PyPI"] },
        "phase2": { "score": 90, "findings": ["Looks like 'numpy' (edit distance: 1)"] }
      },
      "scan_time_ms": 675
    }
  ]
}
```

### GET /api/stats

Returns benchmark statistics.

```json
{
  "benchmark": "backstabber-knife-collection",
  "detection_rate": 95.0,
  "false_positive_rate": 0.0,
  "total_malicious_tested": 20,
  "caught": 19,
  "total_clean_tested": 15,
  "false_positives": 0,
  "attack_categories": {
    "typosquatting": "100%",
    "dependency_confusion": "50%",
    "credential_theft": "100%",
    "data_exfiltration": "100%",
    "malicious_code": "100%"
  }
}
```

---

## Example Detection: Typosquatting

A developer accidentally types `numppy` instead of `numpy` in their `requirements.txt`. Without GateKeeper, pip would silently install whatever is published under that name on PyPI — potentially a package uploaded by an attacker specifically to exploit this typo.

With GateKeeper:

```bash
$ python gatekeeper.py numppy==1.0.0

Scanning numppy...

────────────────────────────────────────────────────────────────
  numppy  [CRITICAL]  Score: 90/100  →  BLOCK

  Phase 1 — Metadata  (weight 20%)  score: 90
    → Package 'numppy' NOT FOUND on PyPI

  Phase 2 — Typosquatting  (weight 30%)  score: 90
    → Looks like 'numpy' (edit distance: 1)

  Phase 4 — Sandbox  (weight 50%)  score: 0
    ✓ No suspicious runtime behaviour

⚠  BUILD BLOCKED — CRITICAL findings detected
```

The build is blocked before `pip install` runs.

---

## Installation

### Prerequisites

- Python 3.11+
- Docker Desktop (for Phase 4 sandbox)
- Git

### Clone the repository

```bash
git clone https://github.com/manvigargg/gatekeeper.git
cd gatekeeper
```

### Install dependencies

```bash
pip install fastapi uvicorn python-multipart requests
```

---

## Running Locally

### Phase 1 — PyPI metadata check

```bash
cd phase1
python pypi_checker.py requirements.txt
```

### Phase 2 — Typosquatting detection

```bash
cd phase2
python typosquat_checker.py requirements.txt
```

### Phase 3 — AST static analysis

```bash
cd phase3
python ast_analyzer.py fake_malicious_setup.py
```

### Phase 4 — Docker sandbox (requires Docker Desktop running)

```bash
cd phase4
python sandbox_runner.py requests
python sandbox_runner.py requests flask numpy
```

### Phase 5 — Unified scanner

```bash
cd phase5
python gatekeeper.py requests flask numppy
python gatekeeper.py --file requirements.txt
```

### Phase 6 — Benchmark

```bash
cd phase6
python benchmark.py
```

### Phase 8 — FastAPI backend

```bash
cd phase8
uvicorn main:app --reload --port 8000
```

API explorer available at `http://localhost:8000/docs`

---

## CI/CD Integration

GateKeeper runs automatically on every push and pull request via GitHub Actions. To add it to your own repository:

```yaml
name: GateKeeper Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
    paths:
      - 'requirements*.txt'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run GateKeeper
        uses: manvigargg/gatekeeper@main
        with:
          requirements-file: 'requirements.txt'
          fail-on-severity: 'CRITICAL'
          skip-sandbox: 'true'
```

GateKeeper exits with code `1` if any CRITICAL findings are detected — GitHub Actions interprets this as a failed check and blocks the merge.

---

## Technology Stack

| Component | Technology |
|---|---|
| Detection engine | Python 3.11 |
| Metadata analysis | PyPI JSON API, pypistats.org API |
| Typosquatting | Levenshtein distance (dynamic programming, stdlib only) |
| AST analysis | Python built-in `ast` module |
| Sandbox | Docker, strace |
| Backend API | FastAPI, Uvicorn, Pydantic |
| Deployment | Render (free tier) |
| Frontend | HTML, CSS, vanilla JavaScript |
| 3D visualisation | Three.js |
| Frontend hosting | GitHub Pages |
| CI/CD | GitHub Actions |

No AI or machine learning is used. All detection is rule-based and algorithmic.

---

## Limitations and Current Scope

- **Phase 4 sandbox requires Docker Desktop** — not available in all CI environments on the free tier
- **API rate limits** — PyPI and pypistats APIs have rate limits; scanning large `requirements.txt` files adds delays due to polite request spacing
- **Dependency confusion** — 50% catch rate on the benchmark; detecting internal package name conflicts requires knowledge of your private registry
- **Render free tier cold starts** — the first API request after 15 minutes of inactivity may take 30–50 seconds
- **npm/PyPI only** — only Python packages (PyPI) are currently supported; npm, Cargo, Maven are not implemented
- **Phase 3 (AST analysis) is not wired into the API** — the unified scanner and API currently run Phase 1 and Phase 2 only; Phase 3 is available as a standalone CLI tool
- **No authentication on the API** — the `/api/scan` endpoint is public

---

## Planned Improvements

- Wire Phase 3 AST analysis into the unified scanner and API
- Add npm package scanning support
- Implement dependency confusion detection using private registry integration
- Add SLSA Level 2 provenance generation using `slsa-framework/slsa-github-generator`
- Persistent scan history and a database-backed report store
- GitHub Action published on the marketplace
- Rate limiting and API key authentication on the backend

---

## Project Structure Summary

```
gatekeeper/
├── phase1/          PyPI metadata checker
├── phase2/          Typosquatting detector (Levenshtein)
├── phase3/          AST static analyser
├── phase4/          Docker sandboxed execution + strace
├── phase5/          Unified scanner (phases 1, 2, 4)
├── phase6/          Backstabber benchmark runner
├── phase8/          FastAPI REST API
├── .github/         GitHub Actions workflow
├── action.yml       Reusable GitHub Action definition
├── index.html       Frontend dashboard entry point
├── css/             Stylesheet
├── js/              Scanner logic, UI interactions, Three.js 3D
├── assets/          Shield image
└── Procfile         Render deployment command
```

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feat/my-feature`)
5. Open a pull request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*GateKeeper is an open-source portfolio project. It is not a production-grade security product and should not be used as the sole security control in a production environment.*
