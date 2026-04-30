"""String analysis AI tools for firmware reverse engineering."""

import asyncio
import logging
import math
import os
import re
from collections import Counter

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.utils.sandbox import safe_walk, validate_path

logger = logging.getLogger(__name__)

MAX_STRINGS = 200
MAX_GREP_RESULTS = 100
MAX_CRED_RESULTS = 100

# Hash type identification for /etc/shadow analysis
_HASH_TYPES = {
    "$1$": ("MD5", "WEAK"),
    "$2a$": ("Blowfish", "OK"),
    "$2b$": ("Blowfish", "OK"),
    "$2y$": ("Blowfish", "OK"),
    "$5$": ("SHA-256", "OK"),
    "$6$": ("SHA-512", "OK"),
    "$y$": ("yescrypt", "OK"),
}

# Common default passwords found in embedded firmware
_COMMON_PASSWORDS = [
    "admin", "root", "password", "1234", "12345", "123456",
    "default", "changeme", "toor", "pass", "guest", "user",
    "test", "administrator", "support",
]

# Patterns for string categorisation
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_FILEPATH_RE = re.compile(r"(?:/[\w._-]+){2,}")
_CRED_RE = re.compile(
    r"(?:password|passwd|secret|api_key|token|credential)\s*[=:]\s*\S+",
    re.IGNORECASE,
)

# Crypto file extensions
_CRYPTO_EXTENSIONS = {
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".pub",
}

# SSH key filenames
_SSH_KEY_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
}

# PEM header patterns
_PEM_HEADER_RE = re.compile(
    r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?(PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----"
)

# Credential patterns for find_hardcoded_credentials
_CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"passwd\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"secret\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"api_key\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"token\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"credential\s*[=:]\s*(\S+)", re.IGNORECASE),
]

# Hex-string patterns for binary rodata scanning. Embedded firmware secrets
# (app_id, app_secret, AES keys, signing keys) are commonly stored as ASCII
# hex strings of these well-known lengths:
#   32 hex chars → MD5 / 128-bit key / UUID without dashes / app_id
#   40 hex chars → SHA-1 / 160-bit key
#   64 hex chars → SHA-256 / 256-bit key
# We deliberately don't match shorter widths (too noisy) or longer (rare).
_HEX_SECRET_PATTERNS = (
    (re.compile(r"^[0-9a-fA-F]{32}$"), "32-hex (MD5/128-bit key/app_id-shaped)"),
    (re.compile(r"^[0-9a-fA-F]{40}$"), "40-hex (SHA-1/160-bit key)"),
    (re.compile(r"^[0-9a-fA-F]{64}$"), "64-hex (SHA-256/256-bit key)"),
)

# Strings to exclude even if they match a secret pattern. These appear in
# ELF metadata (build IDs, debug info) and are not exploitable secrets.
_HEX_FALSE_POSITIVE_STRINGS = frozenset({
    "0" * 32, "0" * 40, "0" * 64,
    "f" * 32, "f" * 40, "f" * 64,
    "F" * 32, "F" * 40, "F" * 64,
})

# Magic-looking ALL-CAPS prefixes followed by digits — embedded vendors often
# use these as keys (e.g. ``_MEARI56565099`` is a Wyze AES key). High false-
# positive rate, so we tag findings as medium confidence and require length>=12.
_MAGIC_KEY_RE = re.compile(r"^_?[A-Z][A-Z0-9_]{4,}\d{4,}$")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


async def _run_subprocess(
    args: list[str], cwd: str, timeout: int = 30
) -> tuple[str, str]:
    """Run a subprocess asynchronously with timeout.

    Returns (stdout, stderr) as strings.
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"Command timed out after {timeout}s: {args[0]}")
    return stdout.decode("utf-8", errors="replace"), stderr.decode(
        "utf-8", errors="replace"
    )


def _categorize_strings(lines: list[str]) -> dict[str, list[str]]:
    """Categorize extracted strings into meaningful groups."""
    categories: dict[str, list[str]] = {
        "urls": [],
        "ip_addresses": [],
        "email_addresses": [],
        "file_paths": [],
        "potential_credentials": [],
        "other": [],
    }
    seen: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)

        categorized = False
        if _URL_RE.search(line):
            categories["urls"].append(line)
            categorized = True
        if _IP_RE.search(line):
            categories["ip_addresses"].append(line)
            categorized = True
        if _EMAIL_RE.search(line):
            categories["email_addresses"].append(line)
            categorized = True
        if _CRED_RE.search(line):
            categories["potential_credentials"].append(line)
            categorized = True
        if _FILEPATH_RE.search(line) and not categorized:
            categories["file_paths"].append(line)
            categorized = True
        if not categorized:
            categories["other"].append(line)

    return categories


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_text_file(path: str) -> bool:
    """Check if a file is likely text by scanning for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" not in chunk
    except (OSError, PermissionError):
        return False


def _is_elf_file(path: str) -> bool:
    """Check if a file is an ELF binary by magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


async def _extract_data_strings(path: str, min_length: int = 8) -> list[str]:
    """Run ``strings -d -n <min_length>`` against an ELF binary.

    ``-d`` restricts extraction to data sections (.rodata, .data) which is
    where secrets typically live. This avoids matching against symbol-table
    junk and code-section strings, lowering the false-positive rate.

    Returns a list of strings (deduplicated, in extraction order).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "strings", "-d", "-n", str(min_length), path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
    except (OSError, asyncio.TimeoutError):
        return []

    seen: set[str] = set()
    out: list[str] = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _classify_binary_string(s: str) -> tuple[str, str] | None:
    """Identify a string as a likely secret. Returns (category, label) or None.

    *category* is ``"high"`` for fixed-shape hex secrets and ``"medium"`` for
    magic-key-shaped strings (false-positive prone but worth flagging).
    """
    if s in _HEX_FALSE_POSITIVE_STRINGS:
        return None
    for pat, label in _HEX_SECRET_PATTERNS:
        if pat.match(s):
            return ("high", label)
    if len(s) >= 12 and _MAGIC_KEY_RE.match(s):
        return ("medium", "magic-key-shaped (uppercase prefix + digits)")
    return None


async def _scan_binary_for_credentials(
    abs_path: str, virtual_path: str, results: list[dict[str, str]]
) -> None:
    """Extract ELF rodata strings and flag anything secret-shaped.

    Appends findings to *results* in place. Mutates nothing else.
    """
    strings = await _extract_data_strings(abs_path, min_length=8)
    for s in strings:
        if len(results) >= MAX_CRED_RESULTS:
            return
        classification = _classify_binary_string(s)
        if classification is None:
            continue
        confidence, label = classification
        results.append({
            "file": virtual_path,
            "line": "rodata",
            "match": f"{s}  [{label}]",
            "entropy": f"{_shannon_entropy(s):.2f}",
            "category": f"binary_secret_{confidence}",
        })


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_extract_strings(input: dict, context: ToolContext) -> str:
    """Extract and categorize interesting strings from a file."""
    path = context.resolve_path(input["path"])
    min_length = input.get("min_length", 6)

    if not os.path.isfile(path):
        return f"Error: '{input['path']}' is not a file."

    stdout, _ = await _run_subprocess(
        ["strings", "-n", str(min_length), path],
        cwd=context.extracted_path,
    )

    lines = stdout.splitlines()
    total_count = len(lines)
    categories = _categorize_strings(lines)

    # Build output
    parts: list[str] = [
        f"Extracted strings from {input['path']} ({total_count} total, min length {min_length}):",
        "",
    ]

    shown = 0
    for cat_name, cat_items in categories.items():
        if not cat_items:
            continue
        label = cat_name.replace("_", " ").title()
        parts.append(f"## {label} ({len(cat_items)} found)")
        for item in cat_items:
            if shown >= MAX_STRINGS:
                break
            parts.append(f"  {item}")
            shown += 1
        parts.append("")
        if shown >= MAX_STRINGS:
            parts.append(f"... [truncated: showing {MAX_STRINGS} of {total_count} strings]")
            break

    return "\n".join(parts)


async def _handle_search_strings(input: dict, context: ToolContext) -> str:
    """Search for a regex pattern across firmware filesystem files."""
    pattern = input["pattern"]
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)

    try:
        stdout, _ = await _run_subprocess(
            [
                "grep", "-rn",
                "--binary-files=without-match",
                "--max-count=100",
                "-E", pattern,
                search_path,
            ],
            cwd=context.extracted_path,
            timeout=30,
        )
    except TimeoutError:
        return f"Search timed out after 30s. Try a more specific pattern or path."

    if not stdout.strip():
        return f"No matches found for pattern '{pattern}'."

    lines = stdout.strip().splitlines()

    # Convert absolute paths to firmware-relative paths
    results: list[str] = []
    for line in lines[:MAX_GREP_RESULTS]:
        if line.startswith(real_root):
            line = line[len(real_root):]
            if not line.startswith("/"):
                line = "/" + line
        results.append(line)

    header = f"Found {len(results)} match(es) for '{pattern}'"
    if len(lines) > MAX_GREP_RESULTS:
        header += f" (showing first {MAX_GREP_RESULTS})"
    header += ":\n"

    return header + "\n".join(results)


async def _handle_find_crypto_material(input: dict, context: ToolContext) -> str:
    """Find cryptographic keys, certificates, and related files."""
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)

    findings: dict[str, list[str]] = {
        "private_keys": [],
        "certificates": [],
        "public_keys": [],
        "ssh_keys": [],
        "crypto_files": [],
    }

    for dirpath, _dirs, files in safe_walk(search_path):
        for name in files:
            abs_path = os.path.join(dirpath, name)
            rel_path = "/" + os.path.relpath(abs_path, real_root)

            _, ext = os.path.splitext(name)
            ext = ext.lower()

            # Check SSH key filenames
            if name in _SSH_KEY_NAMES:
                findings["ssh_keys"].append(rel_path)
                continue

            # Try PEM header detection for text files
            pem_matched = False
            if os.path.isfile(abs_path) and os.path.getsize(abs_path) <= 1_000_000:
                if _is_text_file(abs_path):
                    try:
                        with open(abs_path, "r", errors="replace") as f:
                            header = f.read(4096)
                        match = _PEM_HEADER_RE.search(header)
                        if match:
                            pem_matched = True
                            kind = match.group(2)
                            if "PRIVATE" in kind:
                                findings["private_keys"].append(rel_path)
                            elif "CERTIFICATE" in kind:
                                findings["certificates"].append(rel_path)
                            elif "PUBLIC" in kind:
                                findings["public_keys"].append(rel_path)
                    except (OSError, PermissionError):
                        pass

            # Fall back to extension-based detection
            if not pem_matched and ext in _CRYPTO_EXTENSIONS:
                findings["crypto_files"].append(f"{rel_path} ({ext})")

    # Build output
    total = sum(len(v) for v in findings.values())
    if total == 0:
        return "No cryptographic material found."

    parts: list[str] = [f"Found {total} crypto-related file(s):", ""]
    for cat_name, items in findings.items():
        if not items:
            continue
        label = cat_name.replace("_", " ").title()
        parts.append(f"## {label} ({len(items)})")
        for item in items:
            parts.append(f"  {item}")
        parts.append("")

    return "\n".join(parts)


def _identify_hash_type(pw_hash: str) -> tuple[str, str]:
    """Identify password hash type and strength. Returns (type_name, strength)."""
    if not pw_hash or pw_hash in ("!", "*", "!!", "x", "NP", "LK"):
        return ("locked/disabled", "N/A")
    for prefix, (name, strength) in _HASH_TYPES.items():
        if pw_hash.startswith(prefix):
            return (name, strength)
    # No known prefix — likely DES (traditional crypt, 13 chars)
    if len(pw_hash) == 13 and pw_hash.isascii():
        return ("DES", "WEAK")
    return ("unknown", "UNKNOWN")


def _try_common_passwords(pw_hash: str) -> str | None:
    """Try cracking a hash against common default passwords."""
    try:
        import crypt
    except ImportError:
        return None

    for password in _COMMON_PASSWORDS:
        try:
            if crypt.crypt(password, pw_hash) == pw_hash:
                return password
        except Exception:
            continue
    return None


def _analyze_shadow_file(
    shadow_path: str, display_path: str, results: list[dict[str, str]],
) -> list[str]:
    """Analyze a shadow file for password security issues. Returns issue lines."""
    issues: list[str] = []
    try:
        with open(shadow_path, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                user = parts[0]
                pw_hash = parts[1]

                if not pw_hash or pw_hash in ("", "!"):
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}' has empty/disabled password hash: '{pw_hash}'",
                        "entropy": "n/a",
                        "category": "shadow",
                    })
                    if pw_hash == "":
                        issues.append(
                            f"  [CRITICAL] {display_path}:{line_num}: "
                            f"User '{user}' has NO password (empty hash)"
                        )
                    continue

                if pw_hash in ("*", "!!", "x", "NP", "LK"):
                    continue  # Properly locked account

                hash_type, strength = _identify_hash_type(pw_hash)

                if strength == "WEAK":
                    issues.append(
                        f"  [HIGH] {display_path}:{line_num}: "
                        f"User '{user}' uses weak {hash_type} password hash"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}': weak {hash_type} hash",
                        "entropy": "n/a",
                        "category": "shadow_weak_hash",
                    })

                # Try common passwords
                cracked = _try_common_passwords(pw_hash)
                if cracked:
                    issues.append(
                        f"  [CRITICAL] {display_path}:{line_num}: "
                        f"User '{user}' has default password: '{cracked}' "
                        f"(hash type: {hash_type})"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"User '{user}': default password '{cracked}' ({hash_type})",
                        "entropy": "n/a",
                        "category": "shadow_cracked",
                    })
    except (OSError, PermissionError):
        pass
    return issues


def _analyze_passwd_file(
    passwd_path: str, display_path: str, results: list[dict[str, str]],
) -> list[str]:
    """Analyze a passwd file for security issues. Returns issue lines."""
    issues: list[str] = []
    try:
        with open(passwd_path, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user = parts[0]
                pw_field = parts[1]
                uid = parts[2]
                shell = parts[6]

                # Flag uid=0 non-root accounts
                if uid == "0" and user != "root":
                    issues.append(
                        f"  [HIGH] {display_path}:{line_num}: "
                        f"Non-root account '{user}' has UID 0 (root-equivalent)"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"UID 0 non-root account: {user}",
                        "entropy": "n/a",
                        "category": "passwd_uid0",
                    })

                # Flag empty password field with login shell
                no_login_shells = {
                    "/bin/false", "/usr/bin/false", "/sbin/nologin",
                    "/usr/sbin/nologin", "/bin/sync",
                }
                if pw_field == "" and shell.strip() not in no_login_shells:
                    issues.append(
                        f"  [CRITICAL] {display_path}:{line_num}: "
                        f"User '{user}' has empty password field with login shell '{shell.strip()}'"
                    )
                    results.append({
                        "file": display_path,
                        "line": str(line_num),
                        "match": f"Empty password with shell: {user} ({shell.strip()})",
                        "entropy": "n/a",
                        "category": "passwd_empty",
                    })
    except (OSError, PermissionError):
        pass
    return issues


async def _handle_find_hardcoded_credentials(
    input: dict, context: ToolContext
) -> str:
    """Find hardcoded passwords, API keys, tokens, and other credentials."""
    input_path = input.get("path", "/")
    search_path = context.resolve_path(input_path)
    real_root = context.real_root_for(input_path)

    results: list[dict[str, str]] = []
    auth_issues: list[str] = []

    # Check /etc/shadow and /etc_ro/shadow for password security
    for shadow_rel in ["etc/shadow", "etc_ro/shadow"]:
        shadow_path = os.path.join(real_root, shadow_rel)
        if os.path.isfile(shadow_path):
            issues = _analyze_shadow_file(shadow_path, f"/{shadow_rel}", results)
            auth_issues.extend(issues)

    # Check /etc/passwd and /etc_ro/passwd for account issues
    for passwd_rel in ["etc/passwd", "etc_ro/passwd"]:
        passwd_path = os.path.join(real_root, passwd_rel)
        if os.path.isfile(passwd_path):
            issues = _analyze_passwd_file(passwd_path, f"/{passwd_rel}", results)
            auth_issues.extend(issues)

    # Walk filesystem for credential patterns. Two passes per file:
    #   - text files: line-by-line regex match against _CREDENTIAL_PATTERNS
    #   - ELF binaries: rodata-strings scan for secret-shaped tokens
    # The binary pass is the important one for embedded firmware where the
    # interesting credentials live in compiled-in literals, not /etc/.
    binaries_to_scan: list[tuple[str, str]] = []  # (abs_path, virtual_path)

    for dirpath, _dirs, files in safe_walk(search_path):
        if len(results) >= MAX_CRED_RESULTS:
            break
        for name in files:
            if len(results) >= MAX_CRED_RESULTS:
                break

            abs_path = os.path.join(dirpath, name)
            if not os.path.isfile(abs_path):
                continue
            if os.path.getsize(abs_path) > 50_000_000:  # 50MB hard cap
                continue

            virtual_path = context.to_virtual_path(abs_path)
            if virtual_path is None:
                continue

            if _is_elf_file(abs_path):
                binaries_to_scan.append((abs_path, virtual_path))
                continue

            if os.path.getsize(abs_path) > 1_000_000:
                continue
            if not _is_text_file(abs_path):
                continue

            try:
                with open(abs_path, "r", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if len(results) >= MAX_CRED_RESULTS:
                            break
                        for pat in _CREDENTIAL_PATTERNS:
                            m = pat.search(line)
                            if m:
                                value = m.group(1)
                                entropy = _shannon_entropy(value)
                                results.append({
                                    "file": virtual_path,
                                    "line": str(line_num),
                                    "match": line.strip()[:200],
                                    "entropy": f"{entropy:.2f}",
                                    "category": "credential_pattern",
                                })
                                break  # one match per line
            except (OSError, PermissionError):
                continue

    # Pass 2: ELF binary rodata. Run after text scan so that the result budget
    # leaves room for binary findings even when text matches are noisy.
    for abs_path, virtual_path in binaries_to_scan:
        if len(results) >= MAX_CRED_RESULTS:
            break
        await _scan_binary_for_credentials(abs_path, virtual_path, results)

    if not results and not auth_issues:
        return "No hardcoded credentials found."

    # Build output
    parts: list[str] = [f"Found {len(results)} potential credential(s):", ""]

    # Authentication issues section (shadow/passwd analysis)
    if auth_issues:
        parts.append(f"## Authentication Issues ({len(auth_issues)})")
        parts.extend(auth_issues)
        parts.append("")

    # ELF rodata findings — these are the high-signal hits for embedded firmware,
    # so render them before the noisier text-pattern matches.
    binary_high = [r for r in results if r.get("category") == "binary_secret_high"]
    binary_medium = [r for r in results if r.get("category") == "binary_secret_medium"]

    if binary_high:
        parts.append(
            f"## Hardcoded Secrets in Binary rodata (high confidence) — {len(binary_high)}"
        )
        for r in binary_high:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        parts.append("")

    if binary_medium:
        parts.append(
            f"## Suspected Secrets in Binary rodata (medium confidence) — {len(binary_medium)}"
        )
        parts.append(
            "  These match magic-key heuristics (uppercase prefix + digits). "
            "Verify with decompilation before treating as real secrets."
        )
        for r in binary_medium:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        parts.append("")

    # Separate remaining text-pattern results by entropy
    pattern_results = [r for r in results if r.get("category") == "credential_pattern"]

    high_entropy: list[dict[str, str]] = []
    low_entropy: list[dict[str, str]] = []
    for r in pattern_results:
        if r["entropy"] == "n/a" or float(r["entropy"]) > 4.0:
            high_entropy.append(r)
        else:
            low_entropy.append(r)

    if high_entropy:
        parts.append(f"## Likely Real Secrets in Text Files (high entropy >4.0 bits) — {len(high_entropy)}")
        for r in high_entropy:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        parts.append("")

    if low_entropy:
        parts.append(f"## Possible Credentials in Text Files (lower entropy) — {len(low_entropy)}")
        for r in low_entropy:
            parts.append(f"  {r['file']}:{r['line']}  entropy={r['entropy']}")
            parts.append(f"    {r['match']}")
        parts.append("")

    if len(results) >= MAX_CRED_RESULTS:
        parts.append(f"... [truncated: showing first {MAX_CRED_RESULTS} results]")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_string_tools(registry: ToolRegistry) -> None:
    """Register all string analysis tools with the given registry."""

    registry.register(
        name="extract_strings",
        description=(
            "Extract and categorize interesting strings from a file (binary or text). "
            "Strings are categorized into: URLs, IP addresses, email addresses, "
            "file paths, potential credentials, and other. "
            "Max 200 strings returned."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to extract strings from",
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length (default: 6)",
                },
            },
            "required": ["path"],
        },
        handler=_handle_extract_strings,
    )

    registry.register(
        name="search_strings",
        description=(
            "Search for a regex pattern across all text files in the firmware filesystem "
            "(like grep -rn). Returns matching lines with file paths and line numbers. "
            "Max 100 results. Timeout: 30 seconds."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (extended regex syntax)",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": ["pattern"],
        },
        handler=_handle_search_strings,
    )

    registry.register(
        name="find_crypto_material",
        description=(
            "Scan the firmware filesystem for cryptographic material: "
            "private keys, certificates, public keys, SSH keys, "
            "and files with crypto-related extensions (.pem, .key, .crt, etc.). "
            "Also checks file contents for PEM headers."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": [],
        },
        handler=_handle_find_crypto_material,
    )

    registry.register(
        name="find_hardcoded_credentials",
        description=(
            "Search firmware for hardcoded passwords, API keys, tokens, and "
            "other credentials. Coverage:\n"
            "- /etc/shadow & /etc_ro/shadow: hash type identification (DES, MD5, "
            "SHA-256, SHA-512), weak hash flagging, and cracking against 15 common "
            "default passwords (admin, root, password, 1234, etc.)\n"
            "- /etc/passwd & /etc_ro/passwd: UID-0 non-root accounts, empty password "
            "fields with login shells\n"
            "- Text files: password/secret/token assignments via regex patterns, "
            "ranked by Shannon entropy.\n"
            "- ELF binary rodata: 32/40/64-hex-character strings (MD5/SHA-1/SHA-256, "
            "API keys, app secrets) and magic-key-shaped tokens (uppercase prefix + "
            "digits). The binary scan is what surfaces the kind of compiled-in "
            "credentials embedded firmware typically uses — flagship binary apps "
            "rarely keep their keys in /etc/.\n"
            "Max 100 results."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory to search in (default: '/')",
                },
            },
            "required": [],
        },
        handler=_handle_find_hardcoded_credentials,
    )
