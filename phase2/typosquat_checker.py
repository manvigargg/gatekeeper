"""
typosquat_checker.py — Phase 2 of the Supply Chain Attack Detector
------------------------------------------------------------------
Checks every package in a requirements.txt against a list of
top PyPI packages using Levenshtein (edit) distance.

If a package name is very close (but not identical) to a popular
package — it's likely a typosquatting attempt.

Usage:
    python typosquat_checker.py requirements.txt
"""

import sys
from popular_packages import TOP_PYPI_PACKAGES


# ── Config ──────────────────────────────────────────────────────────
# Distance of 1 = one typo away (most dangerous)
# Distance of 2 = two edits away (still suspicious)
TYPOSQUAT_DISTANCE_THRESHOLD = 2


# ── Terminal colours ────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ───────────────────────────────────────────────────────────────────
# THE CORE ALGORITHM — Levenshtein Distance
# ───────────────────────────────────────────────────────────────────
def levenshtein_distance(s1, s2):
    """
    Calculate the minimum number of single-character edits
    (insertions, deletions, substitutions) to turn s1 into s2.

    Example:
        levenshtein_distance("numpy", "numppy") → 1  (one insertion)
        levenshtein_distance("requests", "requets") → 1  (one deletion)
        levenshtein_distance("flask", "flash") → 1  (one substitution)

    How it works (dynamic programming):
        We build a 2D grid where grid[i][j] = minimum edits
        to convert s1[:i] into s2[:j].
        We fill it row by row, and the answer is in the bottom-right cell.
    """
    # If either string is empty, distance = length of the other
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    # Create a grid of size (len(s1)+1) x (len(s2)+1)
    rows = len(s1) + 1
    cols = len(s2) + 1
    grid = [[0] * cols for _ in range(rows)]

    # First column: cost of deleting all chars of s1
    for i in range(rows):
        grid[i][0] = i

    # First row: cost of inserting all chars of s2
    for j in range(cols):
        grid[0][j] = j

    # Fill in the rest of the grid
    for i in range(1, rows):
        for j in range(1, cols):
            if s1[i - 1] == s2[j - 1]:
                # Characters match — no extra cost
                cost = 0
            else:
                # Characters differ — costs 1 substitution
                cost = 1

            grid[i][j] = min(
                grid[i - 1][j] + 1,        # deletion
                grid[i][j - 1] + 1,        # insertion
                grid[i - 1][j - 1] + cost  # substitution
            )

    return grid[rows - 1][cols - 1]


# ───────────────────────────────────────────────────────────────────
# CHECK ONE PACKAGE NAME AGAINST ALL POPULAR PACKAGES
# ───────────────────────────────────────────────────────────────────
def check_typosquatting(package_name):
    """
    Compare package_name against every package in TOP_PYPI_PACKAGES.

    Returns a list of dicts, each containing:
        - matched_package: the popular package it looks like
        - distance: how many edits apart they are
        - severity: "CRITICAL" (distance 1) or "HIGH" (distance 2)

    Returns an empty list if no suspicious matches found.
    """
    name_lower = package_name.lower()
    suspicious_matches = []

    for popular in TOP_PYPI_PACKAGES:
        # Skip if it's the exact same package — that's fine
        if name_lower == popular.lower():
            return []   # Exact match with a real package, nothing to flag

        distance = levenshtein_distance(name_lower, popular.lower())

        if distance <= TYPOSQUAT_DISTANCE_THRESHOLD:
            severity = "CRITICAL" if distance == 1 else "HIGH"
            suspicious_matches.append({
                "matched_package": popular,
                "distance": distance,
                "severity": severity,
            })

    # Sort by distance so closest match appears first
    suspicious_matches.sort(key=lambda x: x["distance"])
    return suspicious_matches


# ───────────────────────────────────────────────────────────────────
# READ requirements.txt
# ───────────────────────────────────────────────────────────────────
def parse_requirements(filepath):
    """Read requirements.txt and return list of package names."""
    packages = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.split("#")[0].strip()
                # Extract just the package name (ignore version)
                for sep in ["==", ">=", "<=", "~=", "!=", ">"]:
                    if sep in line:
                        name = line.split(sep, 1)[0].strip()
                        packages.append(name)
                        break
                else:
                    packages.append(line)
    except FileNotFoundError:
        print(f"{RED}Error: '{filepath}' not found.{RESET}")
        sys.exit(1)
    return packages


# ───────────────────────────────────────────────────────────────────
# PRINT RESULTS
# ───────────────────────────────────────────────────────────────────
def print_result(package_name, matches):
    if not matches:
        print(f"  {GREEN}✓  {package_name}{RESET}")
        return

    top = matches[0]  # The closest / most suspicious match
    sev_color = RED if top["severity"] == "CRITICAL" else YELLOW

    print(f"\n{sev_color}{'─' * 60}{RESET}")
    print(f"  {BOLD}{package_name}{RESET}  "
          f"{sev_color}⚠  {top['severity']} — possible typosquatting{RESET}")

    for m in matches:
        c = RED if m["severity"] == "CRITICAL" else YELLOW
        print(f"  {c}→ Looks like '{m['matched_package']}' "
              f"(edit distance: {m['distance']}){RESET}")


# ───────────────────────────────────────────────────────────────────
# ALSO: a small demo to explain how the algorithm works
# ───────────────────────────────────────────────────────────────────
def print_algorithm_demo():
    print(f"\n{CYAN}{BOLD}How Levenshtein distance works:{RESET}")
    examples = [
        ("numppy",    "numpy",    "extra 'p' inserted"),
        ("requets",   "requests", "missing 's'"),
        ("lod4sh",    "lodash",   "'4' substituted for 'a'"),
        ("flask",     "flask",    "identical — safe"),
    ]
    for fake, real, explanation in examples:
        dist = levenshtein_distance(fake, real)
        flag = f"{RED}suspicious{RESET}" if dist <= 2 and fake != real else f"{GREEN}safe{RESET}"
        print(f"  '{fake}' vs '{real}' → distance {dist} → {flag}  ({explanation})")
    print()


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python typosquat_checker.py requirements.txt")
        sys.exit(1)

    # Always show the algorithm demo first — helps you understand what's happening
    print_algorithm_demo()

    filepath = sys.argv[1]
    packages = parse_requirements(filepath)

    if not packages:
        print("No packages found.")
        sys.exit(0)

    print(f"{BOLD}Typosquatting scan — {len(packages)} package(s){RESET}\n")

    flagged = []

    for name in packages:
        matches = check_typosquatting(name)
        print_result(name, matches)
        if matches:
            flagged.append((name, matches))

    # Summary
    print(f"\n{'─' * 60}")
    clean = len(packages) - len(flagged)
    print(f"\n{BOLD}Scan complete.{RESET}  "
          f"{GREEN}{clean} clean{RESET}  |  "
          f"{RED}{len(flagged)} flagged{RESET}  |  "
          f"{len(packages)} total\n")

    if flagged:
        sys.exit(1)


if __name__ == "__main__":
    main()