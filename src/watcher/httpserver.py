"""Kleiner HTTP-Server: /healthz, /status, /metrics (Features 15 + 16)."""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import health
from .metrics import METRICS

log = logging.getLogger("log-watcher")


def route(path: str, heartbeat_file: str, max_stale: float):
    """Reine Routing-Logik (ohne Socket) -> (status_code, content_type, body). Testbar."""
    if path.startswith("/healthz"):
        ok = health.is_fresh(heartbeat_file, max_stale)
        return (200 if ok else 503, "text/plain; charset=utf-8", "ok" if ok else "stale")
    if path.startswith("/status"):
        return (200, "application/json", json.dumps(METRICS.status()))
    if path.startswith("/metrics"):
        return (200, "text/plain; version=0.0.4; charset=utf-8", METRICS.prometheus())
    return (404, "text/plain; charset=utf-8", "not found")


def start_http_server(cfg):
    """Startet den Server in einem Daemon-Thread (oder None, wenn HTTP_PORT<=0)."""
    port = cfg.http_port
    if not port or port <= 0:
        return None
    hb_file, max_stale = cfg.heartbeat_file, cfg.health_max_staleness

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # nicht jede Anfrage loggen

        def do_GET(self):
            code, ctype, body = route(self.path, hb_file, max_stale)
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="http").start()
    log.info("HTTP-Server auf :%s (/healthz /status /metrics)", port)
    return srv
