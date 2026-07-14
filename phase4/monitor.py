"""
monitor.py — runs INSIDE the Docker container
---------------------------------------------
Installs a package and monitors everything it does at runtime.
Includes whitelists to filter out normal pip/PyPI behaviour
so we only flag genuinely suspicious activity.
"""

import sys
import os
import subprocess
import json
import re
from datetime import datetime, timezone


# ── Whitelists — known safe behaviour during a normal pip install ───

# PyPI's CDN (Fastly) IP ranges — pip needs these to download packages
SAFE_IP_PREFIXES = [
    "151.101.",     # Fastly CDN — PyPI's content delivery network
    "199.232.",     # Fastly CDN alternate range
    "146.75.",      # Fastly CDN alternate range
    "192.168.",     # Internal Docker/host networking (DNS resolver etc.)
    "172.17.",      # Docker bridge network
    "172.18.",      # Docker bridge network alternate
    "10.",          # Internal network ranges
    "127.",         # Localhost
]

# Port 53 = DNS, port 443 = HTTPS (normal pip download), port 80 = HTTP
SAFE_PORTS = {"53", "443", "80"}

# These processes are spawned by pip itself during a normal install
SAFE_PROCESSES = [
    "pip", "python", "python3",
    "setup.py", "easy_install",
    "gcc", "cc", "c++", "g++",    # Compiling C extensions
    "lsb_release", "uname",        # OS detection by pip
    "ldconfig", "objdump",         # Linker tools for C extensions
    "sh", "/bin/sh", "/bin/bash",
    "tar", "unzip", "gzip",        # Archive extraction
]

# File paths that pip legitimately accesses
SAFE_FILE_PATTERNS = [
    "pip",
    "pypi",
    "python",
    "site-packages",
    "dist-info",
    "setuptools",
    "wheel",
    "certifi",          # pip's SSL certificates
    "INSTALLER",
    "METADATA",
    "RECORD",
    "WHEEL",
    "tokenize",         # Python's tokenize module (not an auth token)
    "token.py",         # Python stdlib token module
    "_tokenize",
]


def is_safe_connection(ip, port):
    """Return True if this network connection is normal pip behaviour."""
    if port in SAFE_PORTS:
        for prefix in SAFE_IP_PREFIXES:
            if ip.startswith(prefix):
                return True
    return False


def is_safe_process(command):
    """Return True if this subprocess is spawned by pip itself."""
    cmd_lower = command.lower()
    return any(safe in cmd_lower for safe in SAFE_PROCESSES)


def is_safe_file_access(raw_line):
    """Return True if this file access is normal pip/Python behaviour."""
    line_lower = raw_line.lower()
    return any(pattern in line_lower for pattern in SAFE_FILE_PATTERNS)


def run_with_strace(package_name):
    """Install the package under strace so every system call is logged."""
    strace_log = "/tmp/strace_output.log"

    print(f"[monitor] Installing {package_name} under strace...", file=sys.stderr)

    result = subprocess.run(
        [
            "strace",
            "-f",
            "-e", "trace=network,file,process",
            "-o", strace_log,
            "pip", "install",
            "--no-deps",
            "--quiet",
            package_name
        ],
        capture_output=True,
        text=True,
        timeout=120
    )

    return strace_log, result.returncode


def parse_network_calls(strace_log):
    """Extract outbound network connections, filtering out normal pip traffic."""
    connections = []
    seen = set()   # Deduplicate repeated connections to same IP:port

    ip_pattern   = re.compile(r'sin_addr=inet_addr\("([^"]+)"\)')
    port_pattern = re.compile(r'sin_port=htons\((\d+)\)')

    try:
        with open(strace_log, "r", errors="ignore") as f:
            for line in f:
                if "connect(" not in line:
                    continue
                ip_match   = ip_pattern.search(line)
                port_match = port_pattern.search(line)
                if not ip_match:
                    continue
                ip   = ip_match.group(1)
                port = port_match.group(1) if port_match else "unknown"

                # Skip safe connections
                if is_safe_connection(ip, port):
                    continue

                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)

                connections.append({"ip": ip, "port": port})
    except FileNotFoundError:
        pass

    return connections


def parse_sensitive_file_access(strace_log):
    """Find access to sensitive files, filtering out normal pip file access."""
    sensitive_paths = [
        ".ssh", ".aws", "id_rsa", "id_ed25519",
        ".bash_history", ".zsh_history",
        "/etc/passwd", "/etc/shadow",
        ".npmrc", ".pypirc",
        "credentials",
    ]

    found = []
    seen  = set()

    try:
        with open(strace_log, "r", errors="ignore") as f:
            for line in f:
                if 'openat(' not in line and 'open(' not in line:
                    continue

                # Skip known safe file access patterns
                if is_safe_file_access(line):
                    continue

                line_lower = line.lower()
                for path in sensitive_paths:
                    if path in line_lower and path not in seen:
                        seen.add(path)
                        found.append({"path": path})
                        break
    except FileNotFoundError:
        pass

    return found


def parse_subprocess_calls(strace_log):
    """Find external processes spawned, filtering out normal pip processes."""
    processes = []
    seen      = set()
    pattern   = re.compile(r'execve\("([^"]+)"')

    try:
        with open(strace_log, "r", errors="ignore") as f:
            for line in f:
                if "execve(" not in line:
                    continue
                match = pattern.search(line)
                if not match:
                    continue
                cmd = match.group(1)

                if is_safe_process(cmd):
                    continue
                if cmd in seen:
                    continue
                seen.add(cmd)

                processes.append({"command": cmd})
    except FileNotFoundError:
        pass

    return processes


def build_report(package_name, network_calls, file_accesses,
                 subprocess_calls, install_exit_code):
    """Combine findings into a structured report."""
    findings   = []
    risk_score = 0

    for conn in network_calls:
        findings.append({
            "severity":    "CRITICAL",
            "category":    "network_call",
            "description": f"Outbound connection to {conn['ip']}:{conn['port']}",
        })
        risk_score += 40

    for fa in file_accesses:
        findings.append({
            "severity":    "CRITICAL",
            "category":    "sensitive_file_access",
            "description": f"Accessed sensitive path: '{fa['path']}'",
        })
        risk_score += 35

    for sp in subprocess_calls:
        findings.append({
            "severity":    "HIGH",
            "category":    "subprocess_execution",
            "description": f"Spawned unexpected process: {sp['command']}",
        })
        risk_score += 25

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        severity     = "CRITICAL"
        build_action = "BLOCK"
    elif risk_score >= 40:
        severity     = "HIGH"
        build_action = "WARN"
    elif risk_score > 0:
        severity     = "MEDIUM"
        build_action = "LOG"
    else:
        severity     = "CLEAN"
        build_action = "PASS"

    return {
        "package":         package_name,
        "scanned_at":      datetime.now(timezone.utc).isoformat(),
        "install_success": install_exit_code == 0,
        "risk_score":      risk_score,
        "severity":        severity,
        "build_action":    build_action,
        "findings":        findings,
        "raw_counts": {
            "network_calls":   len(network_calls),
            "file_accesses":   len(file_accesses),
            "subprocess_calls": len(subprocess_calls),
        }
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python monitor.py <package-name>")
        sys.exit(1)

    package_name = sys.argv[1]

    strace_log, exit_code = run_with_strace(package_name)

    network_calls    = parse_network_calls(strace_log)
    file_accesses    = parse_sensitive_file_access(strace_log)
    subprocess_calls = parse_subprocess_calls(strace_log)

    report = build_report(
        package_name, network_calls,
        file_accesses, subprocess_calls, exit_code
    )

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()