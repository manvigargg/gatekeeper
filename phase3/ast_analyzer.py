"""
ast_analyzer.py — Phase 3 of the Supply Chain Attack Detector
-------------------------------------------------------------
Parses Python install scripts (setup.py / __init__.py) using
Python's built-in AST module and flags suspicious behaviour.

Usage:
    python ast_analyzer.py path/to/setup.py
    python ast_analyzer.py path/to/package_folder/

How it works:
    1. Parse the Python file into an AST (Abstract Syntax Tree)
    2. Walk every node in the tree
    3. For each function call found, check if it matches a
       suspicious pattern from suspicious_patterns.py
    4. Report findings with severity and exact line numbers
"""

import ast
import sys
import os
from suspicious_patterns import SUSPICIOUS_PATTERNS


# ── Terminal colours ────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
}


# ───────────────────────────────────────────────────────────────────
# CORE: Walk the AST and collect all function calls
# ───────────────────────────────────────────────────────────────────
def extract_calls(tree):
    """
    Walk every node in the AST and return a list of all function calls found.

    Each call is returned as a dict:
        {
            "type":        "attribute" or "builtin",
            "module":      "socket"         (if attribute call like socket.connect)
            "function":    "connect",
            "line":        42,              (line number in source file)
            "raw":         "socket.connect" (string representation)
        }
    """
    calls = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        line = getattr(node, "lineno", 0)

        # Case 1: module.function() — e.g. socket.connect(), os.system()
        if isinstance(node.func, ast.Attribute):
            function_name = node.func.attr

            # Get the module name (handles simple cases like socket.connect)
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                calls.append({
                    "type":     "attribute",
                    "module":   module_name,
                    "function": function_name,
                    "line":     line,
                    "raw":      f"{module_name}.{function_name}",
                })

        # Case 2: bare function() — e.g. eval(), exec(), __import__()
        elif isinstance(node.func, ast.Name):
            function_name = node.func.id
            calls.append({
                "type":     "builtin",
                "module":   "",
                "function": function_name,
                "line":     line,
                "raw":      function_name,
            })

    return calls


# ───────────────────────────────────────────────────────────────────
# MATCH calls against suspicious patterns
# ───────────────────────────────────────────────────────────────────
def find_suspicious_calls(calls):
    """
    Compare extracted calls against every pattern in SUSPICIOUS_PATTERNS.
    Returns a list of findings, each containing the call + the pattern it matched.
    """
    findings = []

    for call in calls:
        for pattern in SUSPICIOUS_PATTERNS:

            matched = False

            # Match attribute calls: module.function()
            if call["type"] == "attribute":
                module_match   = call["module"]   in pattern["modules"]
                function_match = call["function"] in pattern["functions"]
                if module_match and function_match:
                    matched = True

            # Match builtin calls: eval(), exec(), etc.
            elif call["type"] == "builtin":
                if call["function"] in pattern["functions"] and not pattern["modules"]:
                    matched = True

            if matched:
                findings.append({
                    "call":    call,
                    "pattern": pattern,
                })

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: severity_order.get(f["pattern"]["severity"], 3))

    return findings


# ───────────────────────────────────────────────────────────────────
# ANALYSE a single Python file
# ───────────────────────────────────────────────────────────────────
def analyse_file(filepath):
    """
    Parse one Python file and return its findings.
    Returns (findings, error_message).
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except Exception as e:
        return [], f"Could not read file: {e}"

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [], f"Could not parse file (syntax error): {e}"

    calls    = extract_calls(tree)
    findings = find_suspicious_calls(calls)
    return findings, None


# ───────────────────────────────────────────────────────────────────
# COLLECT files to analyse from a path (file or folder)
# ───────────────────────────────────────────────────────────────────
def collect_python_files(path):
    """
    If path is a .py file, return just that.
    If path is a folder, return all .py files inside it
    (prioritising setup.py and __init__.py since those run on install).
    """
    if os.path.isfile(path):
        return [path]

    py_files = []
    priority = []   # setup.py and __init__.py go first

    for root, dirs, files in os.walk(path):
        # Skip hidden folders and common non-code directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for fname in files:
            if fname.endswith(".py"):
                full = os.path.join(root, fname)
                if fname in ("setup.py", "__init__.py", "install.py"):
                    priority.append(full)
                else:
                    py_files.append(full)

    return priority + py_files


# ───────────────────────────────────────────────────────────────────
# PRINT results for one file
# ───────────────────────────────────────────────────────────────────
def print_file_results(filepath, findings, error):
    short = os.path.basename(filepath)

    if error:
        print(f"\n  {YELLOW}⚠  {short}: {error}{RESET}")
        return

    if not findings:
        print(f"  {GREEN}✓  {short} — no suspicious patterns found{RESET}")
        return

    print(f"\n{RED}{'─' * 60}{RESET}")
    print(f"  {BOLD}{short}{RESET}  {RED}⚠  {len(findings)} suspicious pattern(s) found{RESET}")
    print(f"  {CYAN}Full path: {filepath}{RESET}\n")

    for f in findings:
        call    = f["call"]
        pattern = f["pattern"]
        color   = SEV_COLOR.get(pattern["severity"], RESET)

        print(f"  {color}{BOLD}[{pattern['severity']}]{RESET}  "
              f"Line {call['line']:>4}  —  {color}{call['raw']}(){RESET}")
        print(f"           {pattern['description']}")
        print(f"           Category: {pattern['category']}\n")


# ───────────────────────────────────────────────────────────────────
# DEMO: show the AST of a tiny example so you can see what it looks like
# ───────────────────────────────────────────────────────────────────
def print_ast_demo():
    demo_code = """
import socket
socket.connect("185.220.101.42", 443)
result = eval(base64.b64decode("aW1wb3J0IG9z"))
"""
    print(f"\n{CYAN}{BOLD}What an AST looks like for malicious code:{RESET}")
    print(f"{CYAN}Source code:{RESET}")
    for line in demo_code.strip().splitlines():
        print(f"  {line}")

    print(f"\n{CYAN}Parsed AST (simplified):{RESET}")
    tree = ast.parse(demo_code)
    print(ast.dump(tree, indent=2)[:800])   # Show first 800 chars
    print("  ... (truncated)\n")


# ───────────────────────────────────────────────────────────────────
# MAIN
# ───────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python ast_analyzer.py path/to/setup.py")
        print(f"       python ast_analyzer.py path/to/package_folder/")
        sys.exit(1)

    # Always show the AST demo first
    print_ast_demo()

    target = sys.argv[1]
    files  = collect_python_files(target)

    if not files:
        print(f"{YELLOW}No Python files found at: {target}{RESET}")
        sys.exit(0)

    print(f"{BOLD}AST Analysis — scanning {len(files)} file(s){RESET}\n")

    total_findings = 0

    for filepath in files:
        findings, error = analyse_file(filepath)
        print_file_results(filepath, findings, error)
        total_findings += len(findings)

    # Summary
    print(f"\n{'─' * 60}")
    if total_findings == 0:
        print(f"\n{GREEN}{BOLD}All clear — no suspicious patterns detected.{RESET}\n")
    else:
        print(f"\n{RED}{BOLD}⚠  {total_findings} suspicious pattern(s) found "
              f"across {len(files)} file(s).{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()