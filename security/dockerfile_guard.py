"""Static checks for hardening Dockerfiles and container configuration.

Every public helper accepts either a single Dockerfile line, a whole
Dockerfile, or (for configuration helpers) a small mapping such as a
Compose service block.  The helpers are deliberately conservative: when
something cannot be proven safe, the unsafe answer is returned.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

__all__ = [
    "parse_instructions",
    "is_non_root",
    "base_digest",
    "has_secret_arg",
    "is_safe_install",
    "capabilities_ok",
    "dockerignore_ok",
    "entry_permissions",
]


# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

_INSTRUCTION_RE = re.compile(r"^\s*([A-Za-z]+)\b\s*(.*)$")
_COMMENT_RE = re.compile(r"^\s*#")


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations and drop comments/blank lines."""
    lines: list[str] = []
    buffer: list[str] = []

    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if _COMMENT_RE.match(raw):
            continue
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].strip())
            continue
        if buffer:
            buffer.append(stripped.strip())
            lines.append(" ".join(part for part in buffer if part))
            buffer = []
        elif stripped.strip():
            lines.append(stripped.strip())

    if buffer:
        lines.append(" ".join(part for part in buffer if part))
    return lines


def _split_instructions(text: str) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for line in _logical_lines(text):
        match = _INSTRUCTION_RE.match(line)
        if match:
            parsed.append((match.group(1).upper(), match.group(2).strip()))
    return parsed


def parse_instructions(text: str) -> dict[str, Any]:
    """Parse a Dockerfile into a summary of its instructions.

    The returned mapping has one truthy entry per instruction found in the
    file plus a ``stages`` key holding the number of ``FROM`` instructions.
    ``HEALTHCHECK NONE`` is reported as ``False`` because it disables the
    check.  An empty (or comment-only) Dockerfile yields ``{}``.
    """
    if not isinstance(text, str) or not text.strip():
        return {}

    instructions: dict[str, Any] = {}
    stages = 0

    for instruction, argument in _split_instructions(text):
        if instruction == "FROM":
            stages += 1
            instructions["FROM"] = True
        elif instruction == "HEALTHCHECK":
            instructions["HEALTHCHECK"] = not argument.upper().startswith("NONE")
        else:
            instructions[instruction] = True

    if not instructions:
        return {}

    instructions["stages"] = stages
    return instructions


# ---------------------------------------------------------------------------
# USER / non-root execution
# ---------------------------------------------------------------------------

_ROOT_NAMES = {"root", "0", "root:root", "0:0"}


def _last_instruction(text: str, name: str) -> str | None:
    """Return the argument of the last occurrence of ``name``."""
    found = None
    for instruction, argument in _split_instructions(text):
        if instruction == name:
            found = argument
    return found


def is_non_root(text: str) -> bool:
    """Return ``True`` only when the container's final ``USER`` is non-root.

    A Dockerfile without a ``USER`` instruction runs as root, so it is not
    considered non-root.  Numeric UIDs other than ``0`` are accepted.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    user = _last_instruction(text, "USER")
    if user is None:
        return False

    # Ignore trailing comments such as ``USER app # runtime user``.
    user = user.split("#", 1)[0].strip()
    if not user:
        return False

    identity = user.rsplit(" ", 1)[-1].strip().lower()
    if identity in _ROOT_NAMES or identity.startswith("root:"):
        return False

    # ``USER 0:1000`` is still the root user.
    if identity.startswith("0:") or identity == "0":
        return False

    return True


# ---------------------------------------------------------------------------
# Base image pinning
# ---------------------------------------------------------------------------

_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]+$")


def _from_references(argument: str) -> list[str]:
    """Extract image references from the argument of a FROM instruction."""
    references: list[str] = []
    for part in argument.split():
        if part.startswith("--"):  # e.g. --platform=linux/amd64
            continue
        if part.upper() == "AS":
            break
        if part.startswith("$"):  # build-arg driven reference, cannot verify
            references.append(part)
            continue
        references.append(part)
        break
    return references


def base_digest(text: str) -> bool:
    """Return ``True`` when every base image is pinned by a sha256 digest.

    ``scratch`` is immutable by definition and needs no digest.  Any image
    referenced only by tag (including ``latest``) or by build argument is
    reported as unpinned.
    """
    if isinstance(text, str) and text.strip():
        pairs = _split_instructions(text)
    else:
        return False

    references: list[str] = []
    for instruction, argument in pairs:
        if instruction == "FROM":
            references.extend(_from_references(argument))

    if not references:
        return False

    for reference in references:
        if reference.lower() == "scratch":
            continue
        if reference.startswith("$"):
            return False
        if not _DIGEST_RE.search(reference):
            return False
    return True


# ---------------------------------------------------------------------------
# Build-time secrets
# ---------------------------------------------------------------------------

_SECRET_TOKENS = {
    "SECRET",
    "SECRETS",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "CREDENTIAL",
    "CREDENTIALS",
    "PRIVATE",
    "AUTH",
    "APIKEY",
    "ACCESSKEY",
}
_SECRET_COMPOUNDS = (
    "APIKEY",
    "ACCESSKEY",
    "SECRETKEY",
    "PRIVATEKEY",
    "AUTHTOKEN",
    "ACCESSTOKEN",
)


def _is_secret_name(name: str) -> bool:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if not cleaned:
        return False
    compact = cleaned.replace("_", "")
    if any(compound in compact for compound in _SECRET_COMPOUNDS):
        return True
    return any(token in _SECRET_TOKENS for token in cleaned.split("_"))


def has_secret_arg(text: str) -> bool:
    """Return ``True`` when an ``ARG`` carries a secret-looking value.

    Secrets passed as build arguments are baked into image layers and are
    therefore never acceptable; BuildKit secret mounts are the safe path.
    Both ``ARG API_KEY=x`` and ``ARG API_KEY`` (value supplied at build
    time) are flagged.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    for instruction, argument in _split_instructions(text):
        if instruction != "ARG":
            continue
        # ``ARG NAME=value`` or ``ARG NAME``; ignore a trailing comment.
        declaration = argument.split("#", 1)[0].strip()
        if not declaration:
            continue
        name = declaration.split("=", 1)[0].strip()
        if _is_secret_name(name):
            return True
    return False


# ---------------------------------------------------------------------------
# Install / RUN command hygiene
# ---------------------------------------------------------------------------

_PIPE_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?"
    r"(?:ba|z|da|k|fi)?sh\b",
    re.IGNORECASE,
)
_PIPE_INTERPRETER_RE = re.compile(
    r"(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?"
    r"(?:python|python3|perl|ruby|node)\b",
    re.IGNORECASE,
)
_PROCESS_SUB_RE = re.compile(
    r"\b(?:ba|z|da|k)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)
_SETUID_RE = re.compile(
    r"\bchmod\b[^;&|\n]*\s(?:u\+s|g\+s|\+s|0?[24][0-7]{3})\b",
    re.IGNORECASE,
)
_APT_CACHE_RE = re.compile(r"/var/lib/apt/lists")
_APK_CACHE_RE = re.compile(r"/var/cache/apk")
_YUM_CACHE_RE = re.compile(r"\b(?:yum|dnf)\s+clean\s+all\b", re.IGNORECASE)


def is_safe_install(text: str) -> bool:
    """Check a ``RUN`` instruction for unsafe installation practices.

    The command is rejected when it executes a downloaded script through a
    shell/interpreter, sets the setuid/setgid bit, or installs packages
    without removing the corresponding package cache.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    command = text.strip()
    if command.upper().startswith("RUN "):
        command = command[4:].strip()

    if _PIPE_SHELL_RE.search(command) or _PIPE_INTERPRETER_RE.search(command):
        return False
    if _PROCESS_SUB_RE.search(command):
        return False
    if _SETUID_RE.search(command):
        return False

    lowered = command.lower()
    if "apt-get" in lowered and "install" in lowered:
        if not _APT_CACHE_RE.search(command):
            return False
    if "apk" in lowered and " add" in lowered:
        if "--no-cache" not in lowered and not _APK_CACHE_RE.search(command):
            return False
    if ("yum" in lowered or "dnf" in lowered) and "install" in lowered:
        if not _YUM_CACHE_RE.search(command):
            return False

    return True


# ---------------------------------------------------------------------------
# Linux capabilities
# ---------------------------------------------------------------------------

# Capabilities that grant broad host-level power; adding them back defeats
# the point of dropping the default capability set.
_DANGEROUS_CAPS = {
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_TIME",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYSLOG",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "NET_ADMIN",
    "NET_RAW",
    "SETUID",
    "SETGID",
    "AUDIT_CONTROL",
    "AUDIT_READ",
    "AUDIT_WRITE",
    "BPF",
    "PERFMON",
    "MKNOD",
    "CHROOT",
}


def _normalize_caps(values: Any) -> list[str]:
    if isinstance(values, str):
        values = re.split(r"[\s,]+", values)
    if not isinstance(values, Iterable) or isinstance(values, Mapping):
        return []
    caps: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        name = value.strip().upper()
        if name.startswith("CAP_"):
            name = name[4:]
        if name:
            caps.append(name)
    return caps


def capabilities_ok(config: Mapping[str, Any]) -> bool:
    """Return ``True`` for a least-privilege capability configuration.

    A container is rejected when it runs privileged, adds ``ALL`` or any
    high-risk capability, or adds capabilities without first dropping all of
    the defaults (``cap_drop: [ALL]``).
    """
    if not isinstance(config, Mapping):
        return False
    if config.get("privileged"):
        return False

    added = _normalize_caps(config.get("cap_add", []))
    dropped = set(_normalize_caps(config.get("cap_drop", [])))

    if any(cap in _DANGEROUS_CAPS for cap in added):
        return False

    if added and "ALL" not in dropped:
        return False

    # An explicit ``no-new-privileges`` option is a plus, never a problem.
    return True


# ---------------------------------------------------------------------------
# Build-context hygiene (.dockerignore)
# ---------------------------------------------------------------------------

_SENSITIVE_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".env",
    ".env.local",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".npmrc",
    ".netrc",
    ".pgpass",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
}
_SENSITIVE_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keystore",
    ".pyc",
    ".pyo",
    ".swp",
)
_SENSITIVE_NAME_RE = re.compile(
    r"(?:^|[._-])(?:secret|secrets|credential|credentials|password|passwd|token)(?:[._-]|$)",
    re.IGNORECASE,
)


def _path_is_sensitive(entry: str) -> bool:
    cleaned = entry.strip().strip("\"'")
    if not cleaned or cleaned in {".", "./", "*"}:
        return False
    # A .dockerignore entry is a pattern; strip leading ``!``/``/`` and
    # wildcards so the underlying path can be inspected.
    cleaned = cleaned.lstrip("!")
    if cleaned.startswith("/"):
        cleaned = cleaned[1:]
    cleaned = cleaned.rstrip("/")
    if not cleaned:
        return False

    lowered = cleaned.lower()
    if _SENSITIVE_NAME_RE.search(lowered):
        return True
    if lowered.endswith(_SENSITIVE_SUFFIXES):
        return True

    for part in re.split(r"[/\\]+", lowered):
        if part in _SENSITIVE_PARTS:
            return True
    return False


def _strip_glob(entry: str) -> str:
    return entry.replace("*", "").replace("?", "")


def dockerignore_ok(entry: Any) -> bool:
    """Return ``True`` when a build-context entry is safe to include.

    ``entry`` is a path (or iterable of paths/patterns) considered for the
    build context; sensitive material such as ``.git``, ``.env``, SSH keys
    and secrets must be excluded via ``.dockerignore``, so those entries are
    reported as not ok.  A multi-line string is treated as a set of paths.
    """
    if isinstance(entry, str):
        entries: list[str] = [
            line.strip() for line in entry.splitlines() if line.strip()
        ]
    elif isinstance(entry, Iterable) and not isinstance(entry, Mapping):
        entries = [item for item in entry if isinstance(item, str)]
    else:
        return False

    if not entries:
        return False

    for item in entries:
        if _path_is_sensitive(item):
            return False
        # ``*.pem``-style globs must still reveal their suffix.
        if _path_is_sensitive(_strip_glob(item)):
            return False
    return True


# ---------------------------------------------------------------------------
# Entrypoint script permissions
# ---------------------------------------------------------------------------

_SYMBOLIC_PERM_RE = re.compile(r"^[-dlbcps]?([r-][w-][xsStT-]){3}$")


def _symbolic_to_mode(spec: str) -> int | None:
    if not _SYMBOLIC_PERM_RE.match(spec):
        return None
    bits = spec[-9:]
    # Permission bit for each character position, owner/group/other.
    weights = (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)
    mode = 0
    for index, (char, weight) in enumerate(zip(bits, weights)):
        if char in "rwx":
            mode |= weight
        elif char in "sS":
            # ``s`` also implies the execute bit; ``S`` does not.
            if char == "s":
                mode |= weight
            mode |= 0o4000 if index < 3 else 0o2000
        elif char in "tT":
            if char == "t":
                mode |= weight
            mode |= 0o1000
    return mode


def _coerce_mode(mode: Any) -> int | None:
    if isinstance(mode, bool):
        return None
    if isinstance(mode, int):
        # Tests and callers frequently write modes as bare digits ("755").
        # Re-interpret such values as octal when every digit is octal.
        digits = str(mode)
        if mode > 0o777 and len(digits) <= 4 and set(digits) <= set("01234567"):
            return int(digits, 8)
        return mode
    if isinstance(mode, str):
        text = mode.strip().lower()
        if not text:
            return None
        if text.startswith("0o"):
            try:
                return int(text, 8)
            except ValueError:
                return None
        if set(text) <= set("01234567") and len(text) <= 4:
            return int(text, 8)
        symbolic = _symbolic_to_mode(mode.strip())
        if symbolic is not None:
            return symbolic
        try:
            return int(text, 8)
        except ValueError:
            return None
    return None


def entry_permissions(mode: Any) -> bool:
    """Validate the permissions of a container entrypoint script.

    ``mode`` may be an int (``755`` or ``0o755``), an octal string, or a
    symbolic string such as ``-rwx------``.  The script must be executable
    by its owner, must not be writable by anyone else, must not expose any
    permission to ``other``, and must not carry setuid/setgid/sticky bits.
    """
    value = _coerce_mode(mode)
    if value is None or value < 0:
        return False

    # Reject setuid/setgid/sticky and any access granted to "other".
    if value & 0o7000:
        return False
    if value & 0o007:
        return False
    # Group must not be able to modify the script.
    if value & 0o020:
        return False
    # The owner must be able to execute it.
    if not value & 0o100:
        return False

    return True
