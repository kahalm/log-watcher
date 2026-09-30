"""Heartbeat für den Docker-Healthcheck (atomar; Schreibfehler: einmal ERROR + Zähler)."""
from __future__ import annotations

import time

from .state import atomic_write


def write_heartbeat(path: str, now: "float | None" = None) -> bool:
    now = time.time() if now is None else now
    return atomic_write(path, str(now), "HEARTBEAT_FILE")


def read_heartbeat(path: str) -> "float | None":
    try:
        with open(path) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def is_fresh(path: str, max_stale_seconds: float, now: "float | None" = None) -> bool:
    now = time.time() if now is None else now
    ts = read_heartbeat(path)
    return ts is not None and (now - ts) < max_stale_seconds
