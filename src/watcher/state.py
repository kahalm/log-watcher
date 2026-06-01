"""Persistenter State (atomar, best-effort):

- pro Target: Cooldown-Alerts, First-seen-Fingerprints, Verdict-Cache
- global: LLM-Tagesbudget, Digest-Marker
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile

_SEEN_RETENTION = 180 * 86400
_VERDICT_RETENTION = 7 * 86400
_ALERT_RETENTION = 30 * 86400


def signature(signals) -> str:
    """Stabile Signatur über Art + Detail der Signale."""
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
        pass  # best-effort


def _target(state: dict, name: str) -> dict:
    return state.setdefault("targets", {}).setdefault(name, {})


# --- Cooldown / Dedupe ---
def in_cooldown(state: dict, target: str, sig: str, cooldown_seconds: float, now: float) -> bool:
    last = _target(state, target).get("alerts", {}).get(sig)
    return last is not None and (now - last) < cooldown_seconds


def record_alert(state: dict, target: str, sig: str, now: float) -> dict:
    t = _target(state, target)
    alerts = t.setdefault("alerts", {})
    alerts[sig] = now
    t["alerts"] = {k: v for k, v in alerts.items() if v >= now - _ALERT_RETENTION}
    return state


# --- First-seen-Fingerprints (Feature 9) ---
def known_fingerprints(state: dict, target: str) -> set:
    """Bereits jemals gesehene Fingerprints (für 'wirklich neu, nicht nur seit Vorfenster')."""
    return set(_target(state, target).get("seen", {}).keys())


def record_fingerprints(state: dict, target: str, fps, now: float) -> dict:
    """Merkt die aktuellen Fingerprints als gesehen (mit Retention-Aufräumen)."""
    t = _target(state, target)
    seen = t.setdefault("seen", {})
    for fp in fps:
        seen[fp] = now
    t["seen"] = {k: v for k, v in seen.items() if v >= now - _SEEN_RETENTION}
    return state


# --- Verdict-Cache (Feature 12) ---
def get_cached_verdict(state: dict, target: str, sig: str, ttl_seconds: float, now: float):
    v = _target(state, target).get("verdicts", {}).get(sig)
    if v and (now - v.get("ts", 0)) < ttl_seconds:
        return v.get("assessment")
    return None


def put_verdict(state: dict, target: str, sig: str, assessment: dict, now: float) -> dict:
    t = _target(state, target)
    vs = t.setdefault("verdicts", {})
    vs[sig] = {"assessment": assessment, "ts": now}
    t["verdicts"] = {k: val for k, val in vs.items() if val.get("ts", 0) >= now - _VERDICT_RETENTION}
    return state


# --- LLM-Tagesbudget (Feature 11), global ---
def llm_calls_remaining(state: dict, day: str, max_calls: int) -> int:
    b = state.get("llm_budget", {})
    used = b.get("calls", 0) if b.get("day") == day else 0
    return max(0, max_calls - used)


def record_llm_call(state: dict, day: str, tokens: int = 0) -> dict:
    b = state.get("llm_budget", {})
    if b.get("day") != day:
        b = {"day": day, "calls": 0, "tokens": 0}
    b["calls"] += 1
    b["tokens"] += int(tokens or 0)
    state["llm_budget"] = b
    return state
