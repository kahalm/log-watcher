"""PII-/Secret-Redaction (Feature 19) — bevor Daten an LLM/Mail/ES gehen."""
from __future__ import annotations

import ipaddress
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

# IPv4-mapped IPv6 (::ffff:a.b.c.d) VOR den Einzel-Mustern behandeln: die IPv6-Regex kann
# den Dotted-Quad-Schwanz nicht als Ganzes fassen und würde sonst "::ffff" separat mangeln
# ("<ip>:<ip>" bzw. halb redigierte Reste).
_IPV4MAPPED = re.compile(r"(?<![0-9A-Za-z:.])::[fF]{4}:(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z.])")


def _is_internal(addr: str) -> bool:
    """Privat/loopback/link-local? Solche Adressen identifizieren keinen externen Nutzer,
    sind aber fuer die Diagnose Gold wert (Fall 09.09.2026: der PII-Scrub machte aus dem
    eigenen Docker-Gateway ::ffff:172.28.0.1 ein nichtssagendes "<ip>:<ip>" — der
    hausgemachte Sweep sah dadurch wie ein externer Scanner aus). Nicht Parsebares gilt
    als extern -> wird redigiert (sicherer Default)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def scrub(text: str) -> str:
    if not text:
        return text
    s = _JWT.sub("<jwt>", text)
    s = _BEARER.sub("bearer <token>", s)
    s = _URLCRED.sub(r"\1<pw>\2", s)
    s = _EMAIL.sub("<email>", s)

    # Behaltene (interne) Adressen hinter Platzhalter verstecken, sonst mangeln die
    # Folge-Regexes sie erneut an: die IPv6-Regex wuerde z.B. das "::ffff" einer soeben
    # behaltenen mapped-Adresse "::ffff:172.28.0.1" nachtraeglich zu "<ip>" machen.
    kept: "list[str]" = []

    def _keep_or_redact(m: "re.Match", addr: str) -> str:
        if not _is_internal(addr):
            return "<ip>"
        kept.append(m.group(0))
        return f"\x00K{len(kept) - 1}\x00"

    s = _IPV4MAPPED.sub(lambda m: _keep_or_redact(m, m.group(1)), s)
    s = _IPV4.sub(lambda m: _keep_or_redact(m, m.group(0)), s)
    # Zone-ID (%eth0) steckt nur im Gesamt-Match (group 0), geparst wird die Adresse (group 1).
    s = _IPV6.sub(lambda m: _keep_or_redact(m, m.group(1)), s)
    s = _LONGTOKEN.sub("<token>", s)
    for i, val in enumerate(kept):
        s = s.replace(f"\x00K{i}\x00", val)
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
