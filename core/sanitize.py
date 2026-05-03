# core/sanitize.py
"""
Shared sanitization utilities used across all PHANTOM modules.

Centralises filename and domain validation to prevent path traversal (C-2)
and command injection (C-3) vulnerabilities identified during security audit.
"""

from __future__ import annotations

import re

# Strict domain regex — RFC 1123 compliant label format
_DOMAIN_RE: re.Pattern = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def safe_filename(value: str) -> str:
    """
    Sanitize any user-controlled string into a filesystem-safe filename.

    Strips all characters except alphanumerics, dots, hyphens, and underscores.
    Prevents path traversal via ``../`` or absolute paths in target names.

    Used by every module's ``_save_results()`` to build output file names
    from ``result.target``.

    Returns:
        A non-empty sanitized string suitable for use in file paths.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return cleaned or "target"


def validate_target(target: str) -> str:
    """
    Validates that a target string is a legitimate domain name.

    Prevents injection of shell metacharacters or path traversal sequences
    into subprocess calls and filesystem operations.

    Args:
        target: Raw target string from CLI input.

    Returns:
        Lowercase, stripped domain string.

    Raises:
        ValueError: If the target does not match a valid domain pattern.
    """
    cleaned = target.strip().lower()
    if not _DOMAIN_RE.match(cleaned):
        raise ValueError(
            f"Invalid target domain: {target!r} — "
            "expected format: example.com or sub.example.com"
        )
    return cleaned
