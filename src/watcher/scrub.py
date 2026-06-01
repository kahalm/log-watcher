"""PII-/Secret-Redaction (Feature 19) — bevor Daten an LLM/Mail/ES gehen."""
from __future__ import annotations

import re

_JWT = re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_URLCRED = re.compile(r"(://[^/\s:@]+:)[^@/\s]+(@)")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_LONGTOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")  # API-Keys / Hashes / Secrets


def scrub(text: str) -> str:
    if not text:
        return text
    s = _JWT.sub("<jwt>", text)
    s = _BEARER.sub("bearer <token>", s)
    s = _URLCRED.sub(r"\1<pw>\2", s)
    s = _EMAIL.sub("<email>", s)
    s = _IPV4.sub("<ip>", s)
    s = _LONGTOKEN.sub("<token>", s)
    return s


def scrub_messages(messages: dict) -> dict:
    """Scrubbt die Keys (Message-Templates) eines {message: count}-Dicts; summiert bei Kollision."""
    out: dict = {}
    for msg, count in messages.items():
        key = scrub(str(msg))
        out[key] = out.get(key, 0) + count
    return out
