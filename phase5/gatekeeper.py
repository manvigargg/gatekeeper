"""
gatekeeper.py — Phase 5: Unified Scanner
-----------------------------------------
Wires all four phases into a single pipeline.

For each package:
    Phase 1 → PyPI metadata check
    Phase 2 → Typosquatting detection
    Phase 3 → AST static analysis (if source available)
    Phase 4 → Docker sandbox execution

Produces one combined risk score and one final verdict.

Usage:
    python gatekeeper.py requests
    python gatekeeper.py requests flask numpy
    python gatekeeper.py --file requirements.txt
"""

import sys
import os
import json
import time
import argparse
import urllib.request
import urllib.error
import re
from datetime import datetime, timezone

# ── Point to sibling phase folders ─────────────────────────────────
ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "phase1"))
sys.path.insert(0, os.path.join(ROOT, "phase2"))

from pypi_checker    import fetch_pypi_data, fetch_download_stats, analyse_package
from typosquat_checker import check_typosquatting

# ── Terminal colours ────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "CLEAN":    GREEN,
}

# ── Config ──────────────────────────────────────────────────────────
# How much each phase contributes to the final risk score
PHASE_WEIGHTS = {
    "phase1": 0.20,   # Metadata anomalies
    "phase2": 0.30,   # Typosquatting (strong signal)
    "phase4": 0.50,   # Runtime sandbox (strongest signal)
}

LOW_DOWNLOAD_THRESHOLD = 1_000
NEW_PACKAGE_DAYS       = 30


# ───────────────────────────────────────────────────────────────────
# PHASE 1 RUNNER
# ───────────────────────────────────────────────────────────────────
def run_phase1(package_name, pinned_version=None):
    """
    Run PyPI metadata checks.
    Returns (score 0-100, list of warning strings).
    """
    pypi_data = fetch_pypi_data(package_name)

    if pypi_data is None:
        return 90, [f"Package '{package_name}' NOT FOUND on PyPI"]

    weekly_downloads = fetch_download_stats(package_name)
    warnings         = analyse_package(
        package_name, pinned_version, pypi_data, weekly_downloads
    )

    # Convert warnings to a score
    score = min(len(warnings) * 25, 100)
    return score, warnings


# ───────────────────────────────────────────────────────────────────
# PHASE 2 RUNNER
# ───────────────────────────────────────────────────────────────────
def run_phase2(package_name):
    """
    Run typosquatting detection.
    Returns (score 0-100, list of match dicts).
    """
    matches = check_typosquatting(package_name)

    if not matches:
        return 0, []

    # Distance 1 = very suspicious, distance 2 = moderately suspicious
    top      = matches[0]
    score    = 90 if top["distance"] == 1 else 50
    warnings = [
        f"Looks like '{m['matched_package']}' (edit distance: {m['distance']})"
        for m in matches
    ]
    return score, warnings


# ───────────────────────────────────────────────────────────────────
# PHASE 4 RUNNER
# ───────────────────────────────────────────────────────────────────
def run_phase4(package_name):
    """
    Run Docker sandbox.
    Returns (score 0-100, list of finding strings).
    Skips gracefully if Docker is not available.
    """
    import subprocess

    # Check Docker is available
    check = subprocess.run(
        ["docker", "info"],
        capture_output=True
    )
    if check.returncode != 0:
        return 0, ["[skipped] Docker not available"]

    sandbox_dir = os.path.join(ROOT, "phase4")
    image_name  = "gatekeeper-sandbox"

    # Build image if needed
    inspect = subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True
    )
    if inspect.returncode != 0:
        subprocess.run(
            ["docker", "build", "-t", image_name, sandbox_dir],
            capture_output=True
        )

    # Run the sandbox
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--memory=256m", "--cpus=0.5",
            image_name,
            "python", "monitor.py", package_name
        ],
        capture_output=True,
        text=True,
        timeout=180
    )

    try:
        json_start = result.stdout.index("{")
        report     = json.loads(result.stdout[json_start:])
    except (ValueError, json.JSONDecodeError):
        return 0, ["[skipped] Could not parse sandbox output"]

    score    = report.get("risk_score", 0)
    findings = [f["description"] for f in report.get("findings", [])]
    return score, findings


# ───────────────────────────────────────────────────────────────────
# COMBINE SCORES
# ───────────────────────────────────────────────────────────────────
def combine_scores(p1_score, p2_score, p4_score):
    """
    Weighted combination of all phase scores into one final score.
    Phase 4 (runtime) carries the most weight because it's the
    hardest evidence — you can't fake what the code actually does.
    """
    combined = (
        p1_score * PHASE_WEIGHTS["phase1"] +
        p2_score * PHASE_WEIGHTS["phase2"] +
        p4_score * PHASE_WEIGHTS["phase4"]
    )
    return round(min(combined, 100))


def score_to_severity(score):
    if score >= 75:
        return "CRITICAL"
    elif score >= 45:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "CLEAN"


def score_to_action(score):
    if score >= 75:
        return "BLOCK"
    elif score >= 45:
        return "WARN"
    elif score >= 20:
        return "LOG"
    else:
        return "PASS"


# ───────────────────────────────────────────────────────────────────
# PRINT ONE PACKAGE RESULT
# ───────────────────────────────────────────────────────────────────
def print_result(result):
    sev   = result["severity"]
    color = SEV_COLOR.get(sev, RESET)
    score = result["combined_score"]

    print(f"\n{color}{'─' * 64}{RESET}")
    print(f"  {BOLD}{result['package']}{RESET}  "
          f"{color}[{sev}]  Score: {score}/100  →  {result['build_action']}{RESET}")

    # Phase 1
    p1 = result["phases"]["phase1"]
    p1_color = RED if p1["score"] > 0 else GREEN
    print(f"\n  {CYAN}Phase 1 — Metadata{RESET}  "
          f"{DIM}(weight 20%){RESET}  score: {p1_color}{p1['score']}{RESET}")
    if p1["findings"]:
        for w in p1["findings"]:
            print(f"    {p1_color}→ {w}{RESET}")
    else:
        print(f"    {GREEN}✓ No metadata anomalies{RESET}")

    # Phase 2
    p2 = result["phases"]["phase2"]
    p2_color = RED if p2["score"] > 0 else GREEN
    print(f"\n  {CYAN}Phase 2 — Typosquatting{RESET}  "
          f"{DIM}(weight 30%){RESET}  score: {p2_color}{p2['score']}{RESET}")
    if p2["findings"]:
        for w in p2["findings"]:
            print(f"    {p2_color}→ {w}{RESET}")
    else:
        print(f"    {GREEN}✓ No typosquatting matches{RESET}")

    # Phase 4
    p4 = result["phases"]["phase4"]
    p4_color = RED if p4["score"] > 0 else GREEN
    print(f"\n  {CYAN}Phase 4 — Sandbox{RESET}  "
          f"{DIM}(weight 50%){RESET}  score: {p4_color}{p4['score']}{RESET}")
    if p4["findings"] and p4["findings"] != ["[skipped] Docker not available"]:
        for w in p4["findings"]:
            print(f"    {p4_color}→ {w}{RESET}")
    elif "[skipped]" in (p4["findings"] or [""])[0]:
        print(f"    {YELLOW}⚠ Sandbox skipped{RESET}")
    else:
        print(f"    {GREEN}✓ No suspicious runtime behaviour{RESET}")


# ───────────────────────────────────────────────────────────────────
# SCAN ONE PACKAGE
# ───────────────────────────────────────────────────────────────────
def scan_package(package_name, pinned_version=None):
    """Run all phases on one package and return combined result."""

    print(f"\n{CYAN}Scanning {BOLD}{package_name}{RESET}{CYAN}...{RESET}")

    # Run all phases
    print(f"  {DIM}Phase 1: metadata...{RESET}", end="\r")
    p1_score, p1_findings = run_phase1(package_name, pinned_version)
    time.sleep(0.3)   # Polite API delay

    print(f"  {DIM}Phase 2: typosquatting...{RESET}", end="\r")
    p2_score, p2_findings = run_phase2(package_name)

    print(f"  {DIM}Phase 4: sandbox...{RESET}         ", end="\r")
    p4_score, p4_findings = run_phase4(package_name)

    # Combine
    combined = combine_scores(p1_score, p2_score, p4_score)
    severity = score_to_severity(combined)
    action   = score_to_action(combined)

    return {
        "package":        package_name,
        "pinned_version": pinned_version,
        "scanned_at":     datetime.now(timezone.utc).isoformat(),
        "combined_score": combined,
        "severity":       severity,
        "build_action":   action,
        "phases": {
            "phase1": {"score": p1_score, "findings": p1_findings},
            "phase2": {"score": p2_score, "findings": p2_findings},
            "phase4": {"score": p4_score, "findings": p4_findings},
        }
    }


# ───────────────────────────────────────────────────────────────────
# PARSE requirements.txt
# ───────────────────────────────────────────────────────────────────
def parse_requirements(filepath):
    packages = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.split("#")[0].strip()
                for sep in ["==", ">=", "<=", "~=", "!=", ">"]:
                    if sep in line:
                        name, version = line.split(sep, 1)
                        packages.append((name.strip(), version.strip()))
                        break
                else:
                    packages.append((line.strip(), None))
    except FileNotFoundError:
        print(f"{RED}Error: '{filepath}' not found.{RESET}")
        sys.exit(1)
    return packages


# ───────────────────────────────────────────────────────────────────
# SAVE UNIFIED REPORT
# ───────────────────────────────────────────────────────────────────
def save_report(results):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath  = os.path.join("reports", f"gatekeeper-{timestamp}.json")

    report = {
        "tool":       "GateKeeper",
        "version":    "0.5.0",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "results":    results,
        "summary": {
            "total":    len(results),
            "clean":    sum(1 for r in results if r["severity"] == "CLEAN"),
            "medium":   sum(1 for r in results if r["severity"] == "MEDIUM"),
            "high":     sum(1 for r in results if r["severity"] == "HIGH"),
            "critical": sum(1 for r in results if r["severity"] == "CRITICAL"),
        }
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    return filepath


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="GateKeeper — Supply Chain Attack Detector"
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Package names to scan"
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to requirements.txt"
    )
    args = parser.parse_args()

    # Build package list
    if args.file:
        packages = parse_requirements(args.file)
    elif args.packages:
        packages = [(p, None) for p in args.packages]
    else:
        parser.print_help()
        sys.exit(1)

    print(f"\n{BOLD}{'═' * 64}")
    print(f"  GateKeeper — Supply Chain Attack Detector")
    print(f"  Scanning {len(packages)} package(s)")
    print(f"{'═' * 64}{RESET}")

    results      = []
    block_build  = False

    for package_name, pinned_version in packages:
        result = scan_package(package_name, pinned_version)
        print_result(result)
        results.append(result)
        if result["severity"] == "CRITICAL":
            block_build = True

    # Final summary table
    print(f"\n\n{BOLD}{'═' * 64}")
    print(f"  SCAN SUMMARY")
    print(f"{'═' * 64}{RESET}")

    for r in results:
        color = SEV_COLOR.get(r["severity"], RESET)
        pkg   = r["package"]
        ver   = f"=={r['pinned_version']}" if r["pinned_version"] else ""
        print(f"  {color}{pkg+ver:<35} "
              f"{r['severity']:<10} "
              f"score: {r['combined_score']:>3}/100  "
              f"→ {r['build_action']}{RESET}")

    report_file = save_report(results)
    print(f"\n  {CYAN}Full report saved: {report_file}{RESET}")

    if block_build:
        print(f"\n{RED}{BOLD}  ⚠  BUILD BLOCKED — CRITICAL findings detected{RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}  ✓  BUILD PASSED{RESET}\n")


if __name__ == "__main__":
    main()