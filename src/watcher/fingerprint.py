"""Normalisiert Log-Messages zu einer stabilen Signatur (Feature 8).

So gruppieren z.B. "timeout after 30s" und "timeout after 45s" zur selben
Signatur — variable Teile (Zahlen, Hex/GUIDs, Strings in Quotes) werden ersetzt.
"""
from __future__ import annotations

import re

_GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{8,}\b")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_NUM = re.compile(r"\d+")


def fingerprint(msg: str) -> str:
    s = _GUID.sub("<id>", msg)        # zuerst GUID (enthält Hex)
    s = _HEX.sub("<hex>", s)
    s = _QUOTED.sub("<str>", s)
    s = _NUM.sub("<n>", s)            # restliche Zahlen
    return " ".join(s.split())        # Whitespace normalisieren
