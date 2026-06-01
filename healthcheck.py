#!/usr/bin/env python3
"""Docker-Healthcheck: prüft, ob der Heartbeat aktuell ist. Exit 0 = gesund."""
import os
import sys

sys.path.insert(0, "/app/src")
from watcher.health import is_fresh  # noqa: E402

path = os.environ.get("HEARTBEAT_FILE", "/data/heartbeat")
max_stale = float(os.environ.get("HEALTH_MAX_STALENESS_SECONDS", "180"))
sys.exit(0 if is_fresh(path, max_stale) else 1)
