"""Mandatory output redaction, config secret masking, and output truncation."""

from __future__ import annotations

import re
from typing import Iterable

from .config import ServerProfile

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
SSH_RSH_ECHO_RE = re.compile(r"""(?:-e|--rsh)[=\s]+['"]?ssh\b[^'"\n]*['"]?""")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
DSN_CREDS_RE = re.compile(
    r"\b((?:mysql|postgres|postgresql|redis|rediss|mongodb(?:\+srv)?|amqp)://[^:\s/@]+:)([^@\s/]+)(@)"
)
# Matches valid IPv4 octets 0-255 not prefixed by 'v' (reduces version false positives)
IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?![A-Za-z0-9_.])"
)
PLACEHOLDER_RE = re.compile(r"\{\{REDACTED_SECRET_(\d+)\}\}")


class SecretPlaceholderError(ValueError):
    """Raised when a drafted config tampers with or corrupts secret placeholders."""


class Redactor:
    """Scrubs all credentials, hosts, users, paths, IPs, and secrets before output leaves opsd."""

    def __init__(self, all_profiles: dict[str, ServerProfile]) -> None:
        self._all_profiles = all_profiles

    def redact(
        self,
        text: str,
        *,
        active_profile: ServerProfile | None = None,
        extra_literals: Iterable[tuple[str, str]] = (),
    ) -> str:
        if not text:
            return text

        # 1. Scrub private key blocks & ssh rsh command echoes first
        out = PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
        out = SSH_RSH_ECHO_RE.sub("[REDACTED_SSH_CMD]", out)

        # 2. Exact literal replacements (longest first to prevent partial leaks)
        replacements: list[tuple[str, str]] = []
        for literal, tag in extra_literals:
            if literal:
                replacements.append((literal, tag))

        profiles_to_scrub: list[ServerProfile] = list(self._all_profiles.values())
        if active_profile is not None and active_profile not in profiles_to_scrub:
            profiles_to_scrub.append(active_profile)

        for prof in profiles_to_scrub:
            replacements.append((f"{prof.user}@{prof.host}", "[REDACTED_USER]@[REDACTED_HOST]"))
            replacements.append((str(prof.key_file), "[REDACTED_KEY]"))
            if prof.sync_key_file:
                replacements.append((str(prof.sync_key_file), "[REDACTED_KEY]"))
            replacements.append((prof.host, "[REDACTED_HOST]"))
            # Avoid replacing single-character usernames indiscriminately
            if len(prof.user) >= 2:
                replacements.append((prof.user, "[REDACTED_USER]"))

        replacements.sort(key=lambda item: len(item[0]), reverse=True)
        for literal, tag in replacements:
            if literal:
                out = out.replace(literal, tag)

        # 3. Pattern-based fallback scrubbing
        out = AWS_KEY_RE.sub("[REDACTED_SECRET]", out)
        out = BEARER_RE.sub("Bearer [REDACTED_SECRET]", out)
        out = DSN_CREDS_RE.sub(r"\1[REDACTED_SECRET]\3", out)
        out = IPV4_RE.sub("[REDACTED_IP]", out)
        return out


def mask_config_secrets(
    content: str,
    redact_patterns: Iterable[str],
) -> tuple[str, dict[str, str]]:
    """Replace matched secret values in config content with deterministic placeholders.

    Returns (masked_content, secret_map) where secret_map maps
    '{{REDACTED_SECRET_N}}' -> original matched substring.
    """
    compiled = [re.compile(p) for p in redact_patterns]
    if not compiled:
        return content, {}

    secret_map: dict[str, str] = {}
    counter = 0

    def mask_line(line: str) -> str:
        nonlocal counter
        result = line
        for regex in compiled:
            def _repl(match: re.Match[str]) -> str:
                nonlocal counter
                full = match.group(0)
                if PLACEHOLDER_RE.search(full):
                    return full
                counter += 1
                placeholder = f"{{{{REDACTED_SECRET_{counter}}}}}"
                secret_map[placeholder] = full
                return placeholder

            result = regex.sub(_repl, result)
        return result

    masked_lines = [mask_line(line) for line in content.splitlines(keepends=True)]
    return "".join(masked_lines), secret_map


def unmask_config_secrets(draft_content: str, secret_map: dict[str, str]) -> str:
    """Restore masked secret placeholders back to their real values in memory.

    Rejects drafts that invent unknown placeholders or drop/alter existing secret placeholders.
    """
    found_placeholders = {f"{{{{REDACTED_SECRET_{m.group(1)}}}}}" for m in PLACEHOLDER_RE.finditer(draft_content)}
    expected_placeholders = set(secret_map.keys())

    unknown = found_placeholders - expected_placeholders
    if unknown:
        raise SecretPlaceholderError(
            f"Draft contains unknown secret placeholder(s): {', '.join(sorted(unknown))}"
        )

    missing = expected_placeholders - found_placeholders
    if missing:
        raise SecretPlaceholderError(
            f"Draft removed or modified protected secret placeholder(s): {', '.join(sorted(missing))}"
        )

    restored = draft_content
    for placeholder, real_val in secret_map.items():
        if restored.count(placeholder) != 1:
            raise SecretPlaceholderError(
                f"Placeholder {placeholder} must appear exactly once in draft."
            )
        restored = restored.replace(placeholder, real_val)
    return restored


def truncate_output(text: str, max_bytes: int) -> str:
    """Truncate text cleanly to max_bytes in UTF-8."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    suffix = "\n... [OUTPUT TRUNCATED]\n"
    budget = max(0, max_bytes - len(suffix.encode("utf-8")))
    cut = raw[:budget].decode("utf-8", errors="ignore")
    return cut + suffix
