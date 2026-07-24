"""Deterministic redaction for externally visible text."""

from __future__ import annotations

import re

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{12,}\b", re.IGNORECASE)
_TOKEN_KV = re.compile(
    r"\b(token|api[_-]?key|apikey|secret|password|passwd|pwd)"
    r"\s*[:=]\s*([\"']?)[^\s,;]{8,}\2",
    re.IGNORECASE,
)
_SECRET_KEY = re.compile(
    r"\b(?:sk-(?:live|test|proj|prod)-|gh[pousr]_)[A-Za-z0-9_-]{12,}\b",
    re.IGNORECASE,
)
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^<>:\"/\\|?*\r\n]+\\)*[^<>:\"/\\|?*\r\n]*\b")
_UNIX_PATH = re.compile(r"(?<![\w:])/(?:[A-Za-z0-9._-]+/){1,}[A-Za-z0-9._-]+")


def redact_text(value: str, *, max_length: int = 240) -> str:
    """Redact common secrets, email addresses, and local paths."""
    text = str(value or "")
    text = _EMAIL.sub("[REDACTED_EMAIL]", text)
    text = _BEARER.sub("Bearer [REDACTED_TOKEN]", text)
    text = _TOKEN_KV.sub(lambda match: f"{match.group(1)}=[REDACTED_TOKEN]", text)
    text = _SECRET_KEY.sub("[REDACTED_TOKEN]", text)
    text = _WINDOWS_PATH.sub("[REDACTED_PATH]", text)
    text = _UNIX_PATH.sub("[REDACTED_PATH]", text)
    return text[:max_length]

