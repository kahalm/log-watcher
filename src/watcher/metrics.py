"""Laufzeit-Metriken (Feature 15) — Prometheus-Text + /status-JSON."""
from __future__ import annotations

import threading


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.started_ts = 0.0
        self.cycles_total = 0
        self.alerts_total = 0
        self.suppressed_total = 0
        self.llm_calls_total = 0
        self.llm_tokens_total = 0
        self.es_errors_total = 0
        self.signals_total: dict = {}
        self.last_cycle_ts = 0.0
        self.last_cycle_signals: list = []

    def start(self, ts):
        with self._lock:
            self.started_ts = ts

    def inc(self, attr, n=1):
        with self._lock:
            setattr(self, attr, getattr(self, attr) + n)

    def add_signals(self, kinds):
        with self._lock:
            self.last_cycle_signals = list(kinds)
            for k in kinds:
                self.signals_total[k] = self.signals_total.get(k, 0) + 1

    def mark_cycle(self, ts):
        with self._lock:
            self.cycles_total += 1
            self.last_cycle_ts = ts

    def status(self) -> dict:
        with self._lock:
            return {
                "started_ts": self.started_ts,
                "cycles_total": self.cycles_total,
                "alerts_total": self.alerts_total,
                "suppressed_total": self.suppressed_total,
                "llm_calls_total": self.llm_calls_total,
                "llm_tokens_total": self.llm_tokens_total,
                "es_errors_total": self.es_errors_total,
                "signals_total": dict(self.signals_total),
                "last_cycle_ts": self.last_cycle_ts,
                "last_cycle_signals": list(self.last_cycle_signals),
            }

    def prometheus(self) -> str:
        s = self.status()
        out = []

        def counter(name, val, help_):
            out.append(f"# HELP {name} {help_}")
            out.append(f"# TYPE {name} counter")
            out.append(f"{name} {val}")

        counter("log_watcher_cycles_total", s["cycles_total"], "Anzahl Pruefzyklen")
        counter("log_watcher_alerts_total", s["alerts_total"], "Gesendete Alerts")
        counter("log_watcher_suppressed_total", s["suppressed_total"], "Durch Cooldown unterdrueckte Alerts")
        counter("log_watcher_llm_calls_total", s["llm_calls_total"], "LLM-Aufrufe")
        counter("log_watcher_llm_tokens_total", s["llm_tokens_total"], "LLM-Tokens (in+out)")
        counter("log_watcher_es_errors_total", s["es_errors_total"], "ES-Fehler")
        out.append("# HELP log_watcher_signals_total Ausgeloeste Signale nach Art")
        out.append("# TYPE log_watcher_signals_total counter")
        for k, v in s["signals_total"].items():
            kk = str(k).replace('\\', '').replace('"', '')
            out.append(f'log_watcher_signals_total{{kind="{kk}"}} {v}')
        out.append("# HELP log_watcher_last_cycle_timestamp_seconds Zeitpunkt des letzten Zyklus")
        out.append("# TYPE log_watcher_last_cycle_timestamp_seconds gauge")
        out.append(f"log_watcher_last_cycle_timestamp_seconds {int(s['last_cycle_ts'])}")
        return "\n".join(out) + "\n"


# Prozessweiter Singleton (Loop schreibt, HTTP-Server liest).
METRICS = Metrics()
