"""log-watcher: ES-Aggregate -> Regel-Gate -> (LLM) -> E-Mail. Hybrid, alle X h."""
from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from .config import Config
from .es_client import ESClient, ESError
from . import rules, analyzer, notifier, state, health, alerts, scrub
from . import fingerprint as fp

log = logging.getLogger("log-watcher")

_stop = threading.Event()


def _handle_signal(signum, _frame):
    log.info("Signal %s empfangen — fahre nach dem aktuellen Schritt sauber herunter.", signum)
    _stop.set()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _baseline_window(cfg: Config, now: datetime, win: timedelta):
    """Vergleichsfenster je nach BASELINE_MODE (Feature 7)."""
    if cfg.baseline_mode == "yesterday":
        end = now - timedelta(hours=24)
        return end - win, end
    if cfg.baseline_mode == "last_week":
        end = now - timedelta(days=7)
        return end - win, end
    # previous (Default): unmittelbares Vorfenster
    return now - 2 * win, now - win


def run_cycle(cfg: Config, es: ESClient, now: datetime) -> None:
    win = timedelta(hours=cfg.window_hours)
    base_start, base_end = _baseline_window(cfg, now, win)
    current = es.aggregate_window(_iso(now - win), _iso(now))
    baseline = es.aggregate_window(_iso(base_start), _iso(base_end))

    # PII/Secrets aus den Message-Templates entfernen, bevor sie in LLM/Mail/ES gehen (Feature 19).
    if cfg.scrub_pii:
        current["error_messages"] = scrub.scrub_messages(current.get("error_messages", {}))
        baseline["error_messages"] = scrub.scrub_messages(baseline.get("error_messages", {}))

    log.info("Fenster: total=%s levels=%s | Baseline(%s): total=%s",
             current["total"], current["levels"], cfg.baseline_mode, baseline["total"])

    st = state.load_state(cfg.state_file)
    now_ts = now.timestamp()
    known = state.known_fingerprints(st, cfg.name)
    signals = rules.evaluate(current, baseline, cfg, known_fingerprints=known)

    # Aktuelle Fehler-Fingerprints als gesehen merken (Feature 9).
    state.record_fingerprints(st, cfg.name, {fp.fingerprint(m) for m in current.get("error_messages", {})}, now_ts)

    if not signals:
        state.save_state(cfg.state_file, st)
        log.info("Keine Auffälligkeit (Regel-Gate leer).")
        return

    log.info("Regel-Gate ausgelöst: %s", [s.kind for s in signals])
    sig = state.signature(signals)
    if state.in_cooldown(st, cfg.name, sig, cfg.cooldown_hours * 3600, now_ts):
        state.save_state(cfg.state_file, st)
        log.info("Unterdrückt (Cooldown aktiv für Signatur %s).", sig)
        return

    # Verdict-Cache (12): identische Signatur innerhalb der TTL nicht erneut (teuer) bewerten.
    ttl = cfg.llm_verdict_ttl_hours * 3600
    assessment = state.get_cached_verdict(st, cfg.name, sig, ttl, now_ts)
    if assessment is not None:
        log.info("Verdict-Cache-Treffer für Signatur %s.", sig)
    else:
        day = now.strftime("%Y-%m-%d")
        use_llm = bool(cfg.anthropic_api_key) and state.llm_calls_remaining(st, day, cfg.llm_max_calls_per_day) > 0
        if cfg.anthropic_api_key and not use_llm:
            log.warning("LLM-Tagesbudget (%s) erschöpft -> regelbasiert.", cfg.llm_max_calls_per_day)
        # Beispiel-Logzeilen nur holen, wenn der LLM wirklich läuft (Feature 14), dann redigieren (19).
        samples = []
        if use_llm and cfg.include_samples:
            samples = es.fetch_samples(_iso(now - win), _iso(now), cfg.sample_size, cfg.sample_field)
            if cfg.scrub_pii:
                samples = [scrub.scrub(s) for s in samples]
        assessment = analyzer.assess(cfg, current, baseline, signals, samples=samples, use_llm=use_llm)
        if assessment.get("llm_used"):
            state.record_llm_call(st, day, assessment.get("llm_tokens", 0))
        state.put_verdict(st, cfg.name, sig, assessment, now_ts)

    log.info("Beurteilung: anomalous=%s severity=%s llm=%s",
             assessment.get("anomalous"), assessment.get("severity"), assessment.get("llm_used"))

    if not assessment.get("anomalous"):
        # Auch "nicht auffällig" merken -> kein erneuter LLM-Call für dasselbe Muster im Cooldown.
        state.save_state(cfg.state_file, state.record_alert(st, cfg.name, sig, now_ts))
        return

    severity = assessment.get("severity", rules.overall_severity(signals))
    subject = f"[log-watcher][{severity.upper()}] Auffälligkeit in {', '.join(cfg.es_indices)}"
    text_body = notifier.build_email_body(assessment, signals, current, baseline, cfg)
    html_body = notifier.build_email_html(assessment, signals, current, baseline, cfg)

    emailed = False
    if cfg.dry_run:
        log.warning("DRY_RUN: würde E-Mail senden:\n--- %s ---\n%s", subject, text_body)
    else:
        try:
            notifier.send_email(cfg, subject, text_body, html_body)
            emailed = True
            log.info("E-Mail (HTML+Text) gesendet an %s", cfg.smtp_to)
        except Exception as e:  # noqa: BLE001 — Mail-Fehler darf Indizierung/State nicht verhindern
            log.error("E-Mail-Versand fehlgeschlagen: %s", e)

        # Alert für die Kibana-Historie zurück nach ES (best-effort, auch wenn die Mail scheiterte).
        if cfg.index_alerts:
            try:
                idx = alerts.alert_index_name(cfg.alert_index_prefix, now)
                doc = alerts.build_alert_doc(assessment, signals, current, baseline, cfg,
                                             _iso(now), sig, emailed)
                es.index_alert(doc, idx)
                log.info("Alert in ES indiziert (%s)", idx)
            except ESError as e:
                log.warning("Alert-Indizierung fehlgeschlagen: %s", e)

    state.save_state(cfg.state_file, state.record_alert(st, cfg.name, sig, now_ts))


def startup_probe(cfg: Config, es: ESClient, now: datetime) -> None:
    """Einmalige Diagnose beim Start: ES erreichbar? Logs/Felder plausibel?"""
    try:
        win = timedelta(hours=cfg.window_hours)
        sample = es.aggregate_window(_iso(now - win), _iso(now))
        if sample["total"] == 0:
            log.warning("Startup-Probe: 0 Dokumente im letzten Fenster — ES_URL/ES_INDICES/Zeitfeld prüfen?")
        elif not sample["levels"]:
            log.warning("Startup-Probe: %s Dokumente, aber keine Level-Buckets — ES_LEVEL_FIELD '%s' prüfen?",
                        sample["total"], cfg.level_field)
        else:
            log.info("Startup-Probe ok: total=%s levels=%s", sample["total"], sample["levels"])
    except ESError as e:
        log.error("Startup-Probe: ES nicht erreichbar (%s) — versuche es im Loop weiter.", e)


def selftest(cfg: Config, es: ESClient, now: datetime) -> int:
    """Konfig-Check: Aggregate + Signale anzeigen, keine Mail. Beendet danach."""
    log.info("SELFTEST: einmaliger Trockenlauf (keine Mail wird gesendet).")
    startup_probe(cfg, es, now)
    forced = Config()
    forced.__dict__.update(cfg.__dict__)
    forced.dry_run = True
    try:
        run_cycle(forced, es, now)
    except ESError as e:
        log.error("SELFTEST: ES-Fehler: %s", e)
        return 1
    return 0


def _sleep_with_heartbeat(cfg: Config, seconds: float) -> None:
    """In Häppchen schlafen, dabei Heartbeat aktualisieren und auf Stop-Signal reagieren."""
    deadline = time.monotonic() + seconds
    while not _stop.is_set():
        health.write_heartbeat(cfg.heartbeat_file)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        _stop.wait(min(cfg.heartbeat_interval, remaining))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    cfg = Config()
    errs = cfg.validate()
    if errs:
        for e in errs:
            log.error("Config-Fehler: %s", e)
        return 1

    es = ESClient(cfg)
    now = datetime.now(timezone.utc)

    if cfg.selftest:
        return selftest(cfg, es, now)

    log.info("log-watcher gestartet (intervall=%ss, fenster=%sh, indices=%s, dry_run=%s)",
             cfg.interval_seconds, cfg.window_hours, cfg.es_indices, cfg.dry_run)
    health.write_heartbeat(cfg.heartbeat_file)
    startup_probe(cfg, es, now)

    if cfg.index_alerts and not cfg.dry_run:
        try:
            es.ensure_alert_template(cfg.alert_index_prefix)
        except ESError as e:
            log.warning("Alert-Index-Template konnte nicht angelegt werden: %s", e)

    if cfg.notify_on_start and not cfg.dry_run:
        try:
            notifier.send_email(cfg, "[log-watcher] gestartet",
                                f"log-watcher läuft. Intervall {cfg.window_hours}h, Indices {cfg.es_indices}.")
        except Exception as e:  # noqa: BLE001 — Start-Mail darf den Start nicht verhindern
            log.warning("Start-Mail fehlgeschlagen: %s", e)

    while not _stop.is_set():
        try:
            run_cycle(cfg, es, datetime.now(timezone.utc))
        except ESError as e:
            log.error("ES-Fehler: %s", e)
        except Exception:
            log.exception("Unerwarteter Fehler im Zyklus")
        health.write_heartbeat(cfg.heartbeat_file)
        if cfg.run_once:
            return 0
        _sleep_with_heartbeat(cfg, cfg.interval_seconds)

    log.info("Sauber beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
