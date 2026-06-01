"""Billiges, deterministisches Regel-Gate VOR dem (teuren) LLM-Aufruf.

Nur wenn hier mindestens ein Signal feuert, wird überhaupt der LLM bemüht.
Das hält die Kosten niedrig und reduziert False Positives.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Signal:
    kind: str            # error_spike | fatal | new_errors | ingestion_stopped
    severity_hint: str   # low | medium | high
    detail: str


def _count_levels(levels: dict, names) -> int:
    return sum(levels.get(n, 0) for n in names)


def evaluate(current: dict, baseline: dict, cfg) -> "list[Signal]":
    signals: list[Signal] = []
    cur_err = _count_levels(current["levels"], cfg.error_levels)
    base_err = _count_levels(baseline["levels"], cfg.error_levels)

    # 1) Fehler-Spike: genug Fehler UND deutlich mehr als im Vorfenster.
    if cur_err >= cfg.min_errors and cur_err >= base_err * cfg.error_spike_factor:
        signals.append(Signal(
            "error_spike", "medium",
            f"{cur_err} Fehler im Fenster (Vorfenster: {base_err}, Schwelle Faktor {cfg.error_spike_factor})."))

    # 1b) Warn-Spike: separat, mit höherer Mindestmenge (Warnungen sind lauter).
    if cfg.alert_on_warn_spike:
        cur_warn = _count_levels(current["levels"], cfg.warn_levels)
        base_warn = _count_levels(baseline["levels"], cfg.warn_levels)
        if cur_warn >= cfg.min_warnings and cur_warn >= base_warn * cfg.warn_spike_factor:
            signals.append(Signal(
                "warn_spike", "low",
                f"{cur_warn} Warnungen im Fenster (Vorfenster: {base_warn}, Schwelle Faktor {cfg.warn_spike_factor})."))

    # 2) Fatal/Critical immer melden.
    fatal_levels = [l for l in cfg.error_levels if l.lower() in ("fatal", "critical")]
    fatal = _count_levels(current["levels"], fatal_levels)
    if fatal > 0:
        signals.append(Signal("fatal", "high", f"{fatal} Fatal/Critical-Eintrag(e) im Fenster."))

    # 3) Neue Fehler-Signaturen (Messages, die im Vorfenster nicht vorkamen).
    if cfg.alert_on_new_signatures:
        new = sorted(set(current["error_messages"]) - set(baseline["error_messages"]))
        if new:
            preview = "; ".join(new[:5])
            signals.append(Signal("new_errors", "medium",
                                  f"{len(new)} neue Fehler-Signatur(en): {preview}"))

    # 4) Ingestion-Stopp: vorher Logs, jetzt nichts -> evtl. Log-Pipeline tot.
    if cfg.ingestion_drop_check and baseline["total"] >= cfg.min_errors and current["total"] == 0:
        signals.append(Signal("ingestion_stopped", "high",
                              f"Keine Logs im aktuellen Fenster (Vorfenster: {baseline['total']}). Ingestion gestoppt?"))

    return signals


def overall_severity(signals: "list[Signal]") -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return max((s.severity_hint for s in signals), key=lambda s: order.get(s, 0), default="low")
