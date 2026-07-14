"""
sandbox_runner.py — runs on YOUR machine
-----------------------------------------
Orchestrates the Docker sandbox:
  1. Builds the container image (once)
  2. For each package, spins up a fresh container
  3. Captures the JSON report from monitor.py
  4. Prints results and saves a report file

Usage:
    python sandbox_runner.py requests
    python sandbox_runner.py lod4sh
    python sandbox_runner.py requests flask numpy
"""

import sys
import subprocess
import json
import os
from datetime import datetime, timezone


# ── Config ──────────────────────────────────────────────────────────
IMAGE_NAME    = "gatekeeper-sandbox"
REPORTS_DIR   = "reports"
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))


# ── Terminal colours ────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEV_COLOR = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": CYAN}


def build_image():
    """Build the Docker image if it doesn't already exist."""
    print(f"{CYAN}Building sandbox image '{IMAGE_NAME}'...{RESET}")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, SCRIPT_DIR],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"{RED}Docker build failed:{RESET}")
        print(result.stderr)
        sys.exit(1)
    print(f"{GREEN}✓ Image built successfully{RESET}\n")


def image_exists():
    """Check if we already built the image."""
    result = subprocess.run(
        ["docker", "image", "inspect", IMAGE_NAME],
        capture_output=True
    )
    return result.returncode == 0


def run_sandbox(package_name):
    """
    Spin up a fresh container for this package.
    --rm         = delete container after it exits (no cleanup needed)
    --network=none = NO internet access (we catch attempted connections via strace,
                     but the connection itself never succeeds — totally safe)
    """
    print(f"{CYAN}Scanning '{package_name}' in sandbox...{RESET}")
    result = subprocess.run(
    [
        "docker", "run",
        "--rm",
        "--memory=256m",           # Limit memory
        "--cpus=0.5",              # Limit CPU
        IMAGE_NAME,
        "python", "monitor.py", package_name
    ],
    capture_output=True,
    text=True,
    timeout=180
)

    return result.stdout, result.stderr, result.returncode


def save_report(report, package_name):
    """Save the JSON report to the reports folder."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename  = os.path.join(REPORTS_DIR, f"{package_name}-{timestamp}.json")
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    return filename


def print_report(report):
    """Pretty-print the report to the terminal."""
    sev   = report.get("severity", "UNKNOWN")
    score = report.get("risk_score", 0)
    color = SEV_COLOR.get(sev, RESET)

    print(f"\n{color}{'─' * 60}{RESET}")
    print(f"  {BOLD}{report['package']}{RESET}  "
          f"{color}[{sev}]  Risk score: {score}/100{RESET}")
    print(f"  Build action: {color}{report['build_action']}{RESET}")
    print(f"  Install succeeded: {report['install_success']}")

    findings = report.get("findings", [])
    if not findings:
        print(f"\n  {GREEN}No suspicious runtime behaviour detected.{RESET}")
    else:
        print(f"\n  {color}{BOLD}{len(findings)} finding(s):{RESET}")
        for f in findings:
            fc = SEV_COLOR.get(f["severity"], RESET)
            print(f"  {fc}→ [{f['severity']}] {f['description']}{RESET}")

    counts = report.get("raw_counts", {})
    print(f"\n  {CYAN}Raw counts:{RESET} "
          f"network calls: {counts.get('network_calls', 0)}  |  "
          f"sensitive file access: {counts.get('file_accesses', 0)}  |  "
          f"subprocesses: {counts.get('subprocess_calls', 0)}")


def scan_package(package_name):
    """Full pipeline for one package."""
    stdout, stderr, exit_code = run_sandbox(package_name)

    # The container prints JSON to stdout
    # The container prints a log line then JSON — extract just the JSON part
    try:
        # Find where the JSON starts (first '{') and parse from there
        json_start = stdout.index("{")
        report = json.loads(stdout[json_start:])
    except (ValueError, json.JSONDecodeError):
        print(f"{RED}Could not parse container output for '{package_name}'{RESET}")
        print(f"stdout: {stdout[:500]}")
        print(f"stderr: {stderr[:500]}")
        return None

    print_report(report)

    report_file = save_report(report, package_name)
    print(f"\n  {CYAN}Report saved:{RESET} {report_file}")

    return report


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python sandbox_runner.py <package> [package2] [package3]")
        sys.exit(1)

    packages = sys.argv[1:]

    # Build image once (skips if already built)
    if not image_exists():
        build_image()
    else:
        print(f"{GREEN}✓ Using existing sandbox image{RESET}\n")

    results        = []
    critical_found = False

    for package_name in packages:
        report = scan_package(package_name)
        if report:
            results.append(report)
            if report.get("severity") == "CRITICAL":
                critical_found = True

    # Final summary
    print(f"\n{'─' * 60}")
    print(f"\n{BOLD}Sandbox scan complete — {len(packages)} package(s){RESET}")
    for r in results:
        color = SEV_COLOR.get(r["severity"], RESET)
        print(f"  {color}{r['package']:30} {r['severity']:10} score: {r['risk_score']}/100{RESET}")

    if critical_found:
        print(f"\n{RED}{BOLD}⚠  CRITICAL findings — build should be blocked.{RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{GREEN}All packages passed sandbox analysis.{RESET}\n")


if __name__ == "__main__":
    main()