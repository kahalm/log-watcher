"""Billiges, deterministisches Regel-Gate VOR dem (teuren) LLM-Aufruf.

Nur wenn hier mindestens ein Signal feuert, wird überhaupt der LLM bemüht.
Das hält die Kosten niedrig und reduziert False Positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .fingerprint import fingerprint

# Backing-Index eines Data-Streams: ".ds-<stream>-<yyyy.MM.dd>-<NNNNNN>".
# Beim Rollover wird das vorherige Backing stumm, der Stream als Ganzes lebt aber
# weiter -> wir kollabieren alle Backing-Indizes auf ihren Stream-Namen.
_DS_BACKING = re.compile(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$")


def _collapse_datastreams(counts: dict) -> dict:
    """Fasst Data-Stream-Backing-Indizes (.ds-…) unter ihrem Stream-Namen zusammen
    und summiert die Counts. Klassische Indizes bleiben unverändert. So zählt für die
    Stille-Prüfung der Data-Stream als EINE Einheit — ein Rollover (altes Backing → 0,
    neues Backing aktiv) löst keinen Fehlalarm mehr aus."""
    collapsed: dict = {}
    for idx, cnt in counts.items():
        m = _DS_BACKING.match(idx)
        key = m.group(1) if m else idx
        collapsed[key] = collapsed.get(key, 0) + cnt
    return collapsed


@dataclass
class Signal:
    kind: str            # error_spike | warn_spike | fatal | new_errors | ingestion_stopped | index_silent | heartbeat_missing
    severity_hint: str   # low | medium | high
    detail: str


def _count_levels(levels: dict, names) -> int:
    return sum(levels.get(n, 0) for n in names)


def _ignore_patterns(cfg) -> "list[str]":
    """`warn_spike_ignore` als kleingeschriebene Teilstring-Liste (oder leer)."""
    return [p.lower() for p in (getattr(cfg, "warn_spike_ignore", None) or [])]


def _is_ignored(msg: str, pats: "list[str]") -> bool:
    low = str(msg).lower()
    return any(p in low for p in pats)


def _ignored_warn_count(window: dict, cfg) -> int:
    """Summe der Warnungen, deren Message/Template einen der konfigurierten
    `warn_spike_ignore`-Teilstrings enthält (case-insensitiv). Diese gelten als
    by-design-Rauschen und werden vom warn_spike-Count abgezogen.

    Quelle ist `error_messages` (Top-Templates über Error+Warning). Die Ignore-Liste
    ist für WARNUNGS-Templates gedacht; der Abzug wird beim Aufrufer auf den Warn-Count
    und auf >=0 begrenzt, damit ein versehentlich passendes Fehler-Template nicht in den
    Negativbereich rutscht."""
    pats = _ignore_patterns(cfg)
    if not pats:
        return 0
    return sum(cnt for msg, cnt in window.get("error_messages", {}).items() if _is_ignored(msg, pats))


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
        # by-design-Rauschen (z.B. softFail-Retries) vor der Schwellenprüfung abziehen.
        ignored_cur = _ignored_warn_count(current, cfg)
        ignored_base = _ignored_warn_count(baseline, cfg)
        cur_warn = max(0, cur_warn - ignored_cur)
        base_warn = max(0, base_warn - ignored_base)
        if cur_warn >= cfg.min_warnings and cur_warn >= base_warn * cfg.warn_spike_factor:
            detail = (f"{cur_warn} Warnungen im Fenster (Vorfenster: {base_warn}, "
                      f"Schwelle Faktor {cfg.warn_spike_factor}).")
            if ignored_cur:
                detail += f" ({ignored_cur} ignorierte Warnung(en) bereits abgezogen.)"
            signals.append(Signal("warn_spike", "low", detail))

    # 2) Fatal/Critical immer melden.
    fatal_levels = [l for l in cfg.error_levels if l.lower() in ("fatal", "critical")]
    fatal = _count_levels(current["levels"], fatal_levels)
    if fatal > 0:
        signals.append(Signal("fatal", "high", f"{fatal} Fatal/Critical-Eintrag(e) im Fenster."))

    # 3) Neue Fehler-Signaturen: per Fingerprint gruppiert (Feature 8), und – falls
    #    known_fingerprints übergeben – nur wirklich erstmalig gesehene (Feature 9),
    #    nicht bloß "fehlt im Vorfenster".
    if cfg.alert_on_new_signatures:
        # Explizit ignorierte Templates (warn_spike_ignore) sind by-design-Rauschen und
        # dürfen AUCH new_errors nicht auslösen — sonst verschiebt der message_field-Fix
        # das Rauschen nur vom warn_spike- ins new_errors-Signal.
        pats = _ignore_patterns(cfg)
        cur_fps = {fingerprint(m) for m in current.get("error_messages", {}) if not _is_ignored(m, pats)}
        base_fps = {fingerprint(m) for m in baseline.get("error_messages", {}) if not _is_ignored(m, pats)}
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

    return signals


def evaluate_index_silence(cur_index: dict, base_index: dict, cfg, window_hours: float | None = None) -> "list[Signal]":
    """Per-Index-Stille (Feature 10): ein Index verstummt, während andere weiterloggen.

    Läuft über ein eigenes (i.d.R. größeres) Fenster als die Spike-/Fehler-Regeln, damit
    bursty, aktivitätsgetriebene Low-Volume-Indizes (z.B. crawler-logs) bei normalen
    Leerlaufphasen keinen Fehlalarm auslösen. `cur_index`/`base_index` = {index: count}.
    """
    signals: list[Signal] = []
    if not cfg.ingestion_drop_check:
        return signals
    # Data-Stream-Backing-Indizes auf ihren Stream-Namen kollabieren, damit ein
    # Rollover (altes .ds-…-000001 → 0, neues -000002 aktiv) keinen Fehlalarm auslöst.
    cur_index = _collapse_datastreams(cur_index)
    base_index = _collapse_datastreams(base_index)
    # Ganze Pipeline still? -> das ist „ingestion_stopped", nicht „index_silent".
    if sum(cur_index.values()) <= 0:
        return signals
    wtxt = f"{window_hours:g}h-" if window_hours else ""
    for idx, base_cnt in base_index.items():
        if base_cnt >= cfg.min_errors and cur_index.get(idx, 0) == 0:
            signals.append(Signal("index_silent", "high",
                                  f"Index '{idx}': 0 Logs im {wtxt}Fenster (Vorfenster: {base_cnt})."))
    return signals


def evaluate_heartbeats(hb_counts: dict, cfg) -> "list[Signal]":
    """Heartbeat-Überwachung: pro erwartetem Dienst prüfen, ob in den letzten N Minuten ein
    Lebenszeichen ankam. `hb_counts` = {service_name: count}. Count 0 → Dienst vermutlich tot.

    Anders als die Index-Stille greift das PRO DIENST (z.B. API tot, während der Bot weiter in
    denselben Index heartbeatet → Index nicht still, dieser Check aber schlägt an).
    """
    signals: list[Signal] = []
    window = cfg.heartbeat_max_staleness_minutes
    for name, count in hb_counts.items():
        if count == 0:
            signals.append(Signal(
                "heartbeat_missing", "high",
                f"Kein Heartbeat von '{name}' in den letzten {window:g} min — Dienst vermutlich tot/hängend."))
    return signals


def overall_severity(signals: "list[Signal]") -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return max((s.severity_hint for s in signals), key=lambda s: order.get(s, 0), default="low")
