"""PII-/Secret-Redaction (Feature 19) — bevor Daten an LLM/Mail/ES gehen."""
from __future__ import annotations

import re

_JWT = re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_URLCRED = re.compile(r"(://[^/\s:@]+:)[^@/\s]+(@)")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# IPv6 bewusst eng gefasst: nur die volle 8-Gruppen-Form oder Formen MIT "::".
# Ein laxes "Gruppen durch Doppelpunkte" würde Uhrzeiten (12:34:56) und MAC-Adressen
# mitreißen und jede Logzeile mit Zeitstempel unlesbar machen.
_IPV6 = re.compile(
    r"(?<![0-9A-Za-z:.])("
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                                 # volle Form
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"   # komprimiert (a::b)
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"                            # führendes :: (::1)
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                                             # abschließendes :: (fe80::)
    r")(?:%[0-9A-Za-z._-]+)?(?![0-9A-Za-z.])"
)
_LONGTOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")  # API-Keys / Hashes / Secrets


def scrub(text: str) -> str:
    if not text:
        return text
    s = _JWT.sub("<jwt>", text)
    s = _BEARER.sub("bearer <token>", s)
    s = _URLCRED.sub(r"\1<pw>\2", s)
    s = _EMAIL.sub("<email>", s)
    s = _IPV4.sub("<ip>", s)
    s = _IPV6.sub("<ip>", s)
    s = _LONGTOKEN.sub("<token>", s)
    return s


def scrub_signals(signals) -> list:
    """Redigiert die `detail`-Texte von Signalen IN PLACE.

    Muss zentral passieren, bevor Signale irgendwohin gehen: security.py/linux.py bauen die
    Details aus Roh-Client-IPs bzw. Hostnamen, und LLM-Prompt, Mail, Discord und das
    ES-Alert-Dokument rendern `detail` wörtlich — scrub_messages deckt nur die
    Message-Templates ab, nicht die Signale selbst.
    """
    for s in signals:
        s.detail = scrub(s.detail)
    return signals


def scrub_messages(messages: dict) -> dict:
    """Scrubbt die Keys (Message-Templates) eines {message: count}-Dicts; summiert bei Kollision."""
    out: dict = {}
    for msg, count in messages.items():
        key = scrub(str(msg))
        out[key] = out.get(key, 0) + count
    return out
