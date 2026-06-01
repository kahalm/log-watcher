"""Heartbeat für den Docker-Healthcheck (best-effort, atomar)."""
from __future__ import annotations

import os
import tempfile
import time


def write_heartbeat(path: str, now: "float | None" = None) -> None:
    now = time.time() if now is None else now
    d = os.path.dirname(path) or "."
    try:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            f.write(str(now))
        os.replace(tmp, path)
    except OSError:
        pass


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
