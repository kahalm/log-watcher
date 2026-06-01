"""Billiges, deterministisches Regel-Gate VOR dem (teuren) LLM-Aufruf.

Nur wenn hier mindestens ein Signal feuert, wird überhaupt der LLM bemüht.
Das hält die Kosten niedrig und reduziert False Positives.
"""
from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import fingerprint


@dataclass
class Signal:
    kind: str            # error_spike | warn_spike | fatal | new_errors | ingestion_stopped | index_silent
    severity_hint: str   # low | medium | high
    detail: str


def _count_levels(levels: dict, names) -> int:
    return sum(levels.get(n, 0) for n in names)


def evaluate(current: dict, baseline: dict, cfg, known_fingerprints=None) -> "list[Signal]":
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

    # 3) Neue Fehler-Signaturen: per Fingerprint gruppiert (Feature 8), und – falls
    #    known_fingerprints übergeben – nur wirklich erstmalig gesehene (Feature 9),
    #    nicht bloß "fehlt im Vorfenster".
    if cfg.alert_on_new_signatures:
        cur_fps = {fingerprint(m) for m in current.get("error_messages", {})}
        base_fps = {fingerprint(m) for m in baseline.get("error_messages", {})}
        new_fps = cur_fps - base_fps
        if known_fingerprints is not None:
            new_fps -= set(known_fingerprints)
        if new_fps:
            preview = "; ".join(sorted(new_fps)[:5])
            signals.append(Signal("new_errors", "medium",
                                  f"{len(new_fps)} neue Fehler-Signatur(en): {preview}"))

    # 4) Ingestion-Stopp (gesamt): vorher Logs, jetzt nichts -> Pipeline evtl. tot.
    if cfg.ingestion_drop_check and baseline["total"] >= cfg.min_errors and current["total"] == 0:
        signals.append(Signal("ingestion_stopped", "high",
                              f"Keine Logs im aktuellen Fenster (Vorfenster: {baseline['total']}). Ingestion gestoppt?"))

    # 4b) Per-Index-Stille (Feature 10): ein Index verstummt, während andere weiterloggen.
    if cfg.ingestion_drop_check and current["total"] > 0:
        cur_idx = current.get("per_index", {})
        for idx, base_cnt in baseline.get("per_index", {}).items():
            if base_cnt >= cfg.min_errors and cur_idx.get(idx, 0) == 0:
                signals.append(Signal("index_silent", "high",
                                      f"Index '{idx}': 0 Logs im Fenster (Vorfenster: {base_cnt})."))

    return signals


def overall_severity(signals: "list[Signal]") -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return max((s.severity_hint for s in signals), key=lambda s: order.get(s, 0), default="low")
