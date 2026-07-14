"""
suspicious_patterns.py
----------------------
Defines what counts as suspicious behaviour in an install script.

Each pattern has:
    - category:    what kind of attack this is
    - severity:    CRITICAL / HIGH / MEDIUM
    - description: human-readable explanation
    - nodes:       which AST node types to look for
    - names:       the specific function/module names that trigger it

This is your detection ruleset — the "brain" of Phase 3.
In a real security tool, this list would have hundreds of entries
and be updated as new attack patterns are discovered.
"""

SUSPICIOUS_PATTERNS = [

    # ── Network calls ────────────────────────────────────────────────
    {
        "category":    "network_call",
        "severity":    "CRITICAL",
        "description": "Outbound network connection during install",
        "modules":     ["socket", "http.client", "httplib"],
        "functions":   ["connect", "create_connection"],
    },
    {
        "category":    "network_call",
        "severity":    "CRITICAL",
        "description": "HTTP request during install (data exfiltration risk)",
        "modules":     ["urllib", "urllib.request", "urllib2", "requests", "httpx", "aiohttp"],
        "functions":   ["urlopen", "get", "post", "put", "request", "fetch"],
    },
    {
        "category":    "network_call",
        "severity":    "HIGH",
        "description": "DNS lookup during install",
        "modules":     ["socket"],
        "functions":   ["gethostbyname", "getaddrinfo", "getnameinfo"],
    },

    # ── System/shell execution ────────────────────────────────────────
    {
        "category":    "shell_execution",
        "severity":    "CRITICAL",
        "description": "Shell command execution during install",
        "modules":     ["os", "subprocess"],
        "functions":   ["system", "popen", "call", "run", "Popen", "check_output"],
    },
    {
        "category":    "shell_execution",
        "severity":    "CRITICAL",
        "description": "eval() or exec() — dynamic code execution",
        "modules":     [],   # These are builtins, not module calls
        "functions":   ["eval", "exec", "compile", "__import__"],
    },

    # ── File system access ────────────────────────────────────────────
    {
        "category":    "file_access",
        "severity":    "HIGH",
        "description": "Reading sensitive system files",
        "modules":     ["os", "os.path"],
        "functions":   ["getenv", "environ"],
    },
    {
        "category":    "file_access",
        "severity":    "CRITICAL",
        "description": "Writing files outside the package directory",
        "modules":     ["shutil"],
        "functions":   ["copy", "move", "copyfile"],
    },

    # ── Encoding / obfuscation ────────────────────────────────────────
    {
        "category":    "obfuscation",
        "severity":    "HIGH",
        "description": "Base64 decoding — common obfuscation technique",
        "modules":     ["base64"],
        "functions":   ["b64decode", "decodebytes", "decodestring"],
    },
    {
        "category":    "obfuscation",
        "severity":    "HIGH",
        "description": "Encoding/decoding — possible payload hiding",
        "modules":     ["codecs"],
        "functions":   ["decode", "encode"],
    },

    # ── Credential theft ─────────────────────────────────────────────
    {
        "category":    "credential_theft",
        "severity":    "CRITICAL",
        "description": "Accessing environment variables (API keys, tokens, passwords)",
        "modules":     ["os"],
        "functions":   ["getenv"],
    },
    {
        "category":    "credential_theft",
        "severity":    "CRITICAL",
        "description": "Reading SSH keys or AWS credentials from filesystem",
        "modules":     ["pathlib"],
        "functions":   ["read_text", "read_bytes", "open"],
    },
]