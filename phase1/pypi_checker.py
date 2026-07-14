"""
pypi_checker.py — Phase 1 of the Supply Chain Attack Detector
--------------------------------------------------------------
Reads a requirements.txt file, calls the PyPI API for each package,
and prints metadata + a basic suspicion flag.

Usage:
    python pypi_checker.py requirements.txt
"""

import sys
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


# ── Config ─────────────────────────────────────────────────────────
LOW_DOWNLOAD_THRESHOLD = 1_000      # weekly downloads below this = suspicious
NEW_PACKAGE_DAYS       = 30        # published less than this = suspicious
PYPI_API               = "https://pypi.org/pypi/{package}/json"
PYPI_STATS_API         = "https://pypistats.org/api/packages/{package}/recent"


# ── Terminal colours ────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def parse_requirements(filepath):
    """
    Read requirements.txt and return a list of (package_name, pinned_version) tuples.
    """
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
        print(f"{RED}Error: File '{filepath}' not found.{RESET}")
        sys.exit(1)
    return packages


def fetch_pypi_data(package_name):
    """
    Call the PyPI JSON API for one package.
    Returns the parsed JSON, or None if not found.
    """
    url = PYPI_API.format(package=package_name)
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception as e:
        print(f"  {YELLOW}Warning: Could not fetch {package_name}: {e}{RESET}")
        return None


def fetch_download_stats(package_name):
    """
    Get weekly download count from pypistats.org.
    Returns an integer, or None if unavailable.
    """
    url = PYPI_STATS_API.format(package=package_name.lower())
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "supply-chain-detector/0.1"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            for entry in data.get("data", []):
                if entry.get("category") == "week":
                    return entry.get("downloads", 0)
    except Exception:
        pass
    return None


def days_since(iso_date_string):
    """
    How many days ago was this ISO date?
    """
    try:
        clean = iso_date_string.replace("Z", "+00:00")
        published = datetime.fromisoformat(clean)
        now = datetime.now(timezone.utc)
        return (now - published).days
    except Exception:
        return None


def analyse_package(name, pinned_version, pypi_data, weekly_downloads):
    """
    Run suspicion checks. Returns a list of warning strings.
    """
    warnings = []
    info = pypi_data["info"]

    # Check 1: Pinned version doesn't exist on PyPI
    if pinned_version:
        available = list(pypi_data.get("releases", {}).keys())
        if pinned_version not in available:
            warnings.append(
                f"Pinned version {pinned_version} does NOT exist on PyPI!"
            )

    # Check 2: Very low weekly downloads
    if weekly_downloads is not None and weekly_downloads < LOW_DOWNLOAD_THRESHOLD:
        warnings.append(
            f"Very low weekly downloads: {weekly_downloads:,} "
            f"(threshold: {LOW_DOWNLOAD_THRESHOLD:,})"
        )

    # Check 3: Brand-new package
    upload_times = pypi_data.get("urls", [])
    if upload_times:
        first_upload = upload_times[0].get("upload_time_iso_8601", "")
        age_days = days_since(first_upload)
        if age_days is not None and age_days < NEW_PACKAGE_DAYS:
            warnings.append(
                f"Package is only {age_days} day(s) old — "
                f"published {first_upload[:10]}"
            )

    # Check 4: No homepage or project URLs
    home_page    = info.get("home_page") or ""
    project_urls = info.get("project_urls") or {}
    if not home_page and not project_urls:
        warnings.append("No homepage or project URL listed")

    # Check 5: No meaningful description
    summary = info.get("summary") or ""
    if len(summary.strip()) < 10:
        warnings.append("Package has no meaningful description")

    return warnings


def print_result(name, pinned_version, pypi_data, weekly_downloads, warnings):
    """Pretty-print one package result."""
    info    = pypi_data["info"]
    latest  = info.get("version", "?")
    author  = info.get("author") or info.get("maintainer") or "unknown"
    summary = (info.get("summary") or "No description")[:80]

    if warnings:
        status = f"{RED}⚠  SUSPICIOUS{RESET}"
        color  = RED
    else:
        status = f"{GREEN}✓  OK{RESET}"
        color  = GREEN

    print(f"\n{color}{'─' * 60}{RESET}")
    print(f"  {BOLD}{name}{RESET}  {status}")
    print(f"  {CYAN}Pinned:{RESET}    {pinned_version or '(not pinned)'}   "
          f"{CYAN}Latest:{RESET} {latest}")
    if weekly_downloads is not None:
        print(f"  {CYAN}Downloads:{RESET} {weekly_downloads:,} / week")
    else:
        print(f"  {CYAN}Downloads:{RESET} unavailable")
    print(f"  {CYAN}Author:{RESET}    {author}")
    print(f"  {CYAN}Summary:{RESET}   {summary}")

    if warnings:
        print(f"\n  {RED}{BOLD}Warnings:{RESET}")
        for w in warnings:
            print(f"    {RED}→ {w}{RESET}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python pypi_checker.py requirements.txt")
        sys.exit(1)

    filepath = sys.argv[1]
    packages = parse_requirements(filepath)

    if not packages:
        print("No packages found.")
        sys.exit(0)

    print(f"\n{BOLD}Supply Chain Checker — scanning {len(packages)} package(s){RESET}")
    print(f"Source: {filepath}\n")

    suspicious_count = 0

    for name, pinned_version in packages:
        print(f"  Fetching {name}...", end="", flush=True)

        pypi_data = fetch_pypi_data(name)

        if pypi_data is None:
            print(f"\r  {RED}⚠  {name}: NOT FOUND on PyPI — high risk!{RESET}")
            suspicious_count += 1
            continue

        weekly_downloads = fetch_download_stats(name)
        warnings = analyse_package(name, pinned_version, pypi_data, weekly_downloads)

        print("\r", end="")
        print_result(name, pinned_version, pypi_data, weekly_downloads, warnings)

        if warnings:
            suspicious_count += 1

        time.sleep(0.5)   # be polite to the API

    # Summary
    total = len(packages)
    clean = total - suspicious_count
    print(f"\n{'─' * 60}")
    print(f"\n{BOLD}Scan complete.{RESET}  "
          f"{GREEN}{clean} clean{RESET}  |  "
          f"{RED}{suspicious_count} suspicious{RESET}  |  "
          f"{total} total\n")

    # This exit code is what will eventually block a CI build
    if suspicious_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()