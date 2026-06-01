"""Dedupe/Cooldown-State, atomar persistiert (best-effort)."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile


def signature(signals) -> str:
    """Stabile Signatur über Art + Detail der Signale.

    Dadurch durchbricht ein NEUES Problem (andere Details) den Cooldown, während
    dasselbe wiederkehrende Problem unterdrückt wird.
    """
    parts = sorted(f"{s.kind}:{s.detail}" for s in signals)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def save_state(path: str, state: dict) -> None:
    d = os.path.dirname(path) or "."
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, path)
    except OSError:
        # State ist best-effort; ein Schreibfehler darf den Watcher nicht killen.
        pass


def in_cooldown(state: dict, sig: str, cooldown_seconds: float, now: float) -> bool:
    last = state.get("alerts", {}).get(sig)
    return last is not None and (now - last) < cooldown_seconds


def record(state: dict, sig: str, now: float) -> dict:
    alerts = state.setdefault("alerts", {})
    alerts[sig] = now
    # Einträge älter als 30 Tage aufräumen, damit der State nicht unbegrenzt wächst.
    cutoff = now - 30 * 86400
    state["alerts"] = {k: v for k, v in alerts.items() if v >= cutoff}
    return state
