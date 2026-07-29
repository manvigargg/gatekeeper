"""
main.py — Phase 8: FastAPI Backend
------------------------------------
Serves GateKeeper scan results over HTTP.
Wires directly into the Phase 1 + Phase 2 detection engines.

Endpoints:
    GET  /              → health check
    POST /api/scan      → scan a list of packages
    GET  /api/stats     → benchmark stats

Run with:
    cd phase8
    uvicorn main:app --reload --port 8000
"""

import sys
import os
import time
import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── point to phase1 and phase2 ──
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "phase1"))
sys.path.insert(0, os.path.join(ROOT, "phase2"))

from pypi_checker import fetch_pypi_data, fetch_download_stats, analyse_package
from typosquat_checker import check_typosquatting

# ── app ──
app = FastAPI(
    title="GateKeeper API",
    description="Supply chain attack detector",
    version="0.5.0"
)

# ── CORS — allow frontend to call this ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── models ──
class ScanRequest(BaseModel):
    packages: List[str]


class PackageResult(BaseModel):
    name: str
    pinned_version: Optional[str]
    severity: str
    combined_score: int
    build_action: str
    findings: List[str]
    phases: dict
    scan_time_ms: int


class ScanResponse(BaseModel):
    scanned_at: str
    total: int
    critical: int
    high: int
    clean: int
    build_blocked: bool
    results: List[dict]


# ── helpers ──
def parse_package_line(line: str):
    """Parse 'requests==2.31.0' → ('requests', '2.31.0')"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None
    line = line.split("#")[0].strip()
    for sep in ["==", ">=", "<=", "~=", "!=", ">"]:
        if sep in line:
            name, version = line.split(sep, 1)
            return name.strip().lower(), version.strip()
    return line.lower(), None


def score_to_severity(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "CLEAN"


def score_to_action(score: int) -> str:
    if score >= 75: return "BLOCK"
    if score >= 45: return "WARN"
    if score >= 20: return "LOG"
    return "PASS"


def run_phase1(name: str, pinned_version: str):
    """PyPI metadata check."""
    try:
        pypi_data = fetch_pypi_data(name)
        if pypi_data is None:
            return 90, [f"Package '{name}' NOT FOUND on PyPI"]
        weekly = fetch_download_stats(name)
        warnings = analyse_package(name, pinned_version, pypi_data, weekly)
        score = min(len(warnings) * 25, 100)
        return score, warnings
    except Exception as e:
        return 0, [f"Phase 1 error: {str(e)}"]


def run_phase2(name: str):
    """Typosquatting detection."""
    try:
        matches = check_typosquatting(name)
        if not matches:
            return 0, []
        top = matches[0]
        score = 90 if top["distance"] == 1 else 50
        findings = [
            f"Looks like '{m['matched_package']}' (edit distance: {m['distance']})"
            for m in matches
        ]
        return score, findings
    except Exception as e:
        return 0, [f"Phase 2 error: {str(e)}"]


def scan_package(name: str, pinned_version: str) -> dict:
    """Run all phases on one package."""
    t0 = time.time()

    p1_score, p1_findings = run_phase1(name, pinned_version)
    time.sleep(0.3)   # polite API delay

    p2_score, p2_findings = run_phase2(name)

    # weighted combination
    combined = round(
        p1_score * 0.40 +
        p2_score * 0.60
    )
    combined = min(combined, 100)

    severity = score_to_severity(combined)
    action   = score_to_action(combined)

    all_findings = p1_findings + p2_findings

    elapsed_ms = round((time.time() - t0) * 1000)

    return {
        "name":           name,
        "pinned_version": pinned_version,
        "severity":       severity,
        "combined_score": combined,
        "build_action":   action,
        "findings":       all_findings,
        "phases": {
            "phase1": {"score": p1_score, "findings": p1_findings},
            "phase2": {"score": p2_score, "findings": p2_findings},
        },
        "scan_time_ms": elapsed_ms,
    }


# ── routes ──
@app.get("/")
def health():
    return {
        "status": "online",
        "tool":    "GateKeeper",
        "version": "0.5.0",
        "time":    datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", response_model=ScanResponse)
def scan(body: ScanRequest):
    if not body.packages:
        raise HTTPException(status_code=400, detail="No packages provided")

    if len(body.packages) > 30:
        raise HTTPException(status_code=400, detail="Max 30 packages per scan")

    results = []
    critical = high = clean = 0

    for line in body.packages:
        name, version = parse_package_line(line)
        if not name:
            continue

        result = scan_package(name, version)
        results.append(result)

        sev = result["severity"]
        if sev == "CRITICAL":  critical += 1
        elif sev == "HIGH":    high += 1
        else:                  clean += 1

    return {
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
        "total":         len(results),
        "critical":      critical,
        "high":          high,
        "clean":         clean,
        "build_blocked": critical > 0,
        "results":       results,
    }


@app.get("/api/stats")
def stats():
    """Return benchmark stats — these come from Phase 6."""
    return {
        "benchmark":          "backstabber-knife-collection",
        "detection_rate":     95.0,
        "false_positive_rate": 0.0,
        "total_malicious_tested": 20,
        "caught":             19,
        "total_clean_tested": 15,
        "false_positives":    0,
        "attack_categories": {
            "typosquatting":       "100%",
            "dependency_confusion": "50%",
            "credential_theft":    "100%",
            "data_exfiltration":   "100%",
            "malicious_code":      "100%",
        }
    }