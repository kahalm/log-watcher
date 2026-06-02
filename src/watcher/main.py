"""log-watcher: ES-Aggregate -> Regel-Gate -> (LLM) -> E-Mail. Hybrid, alle X h."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from datetime import date, datetime, timedelta, timezone

from . import __version__
from .config import Config, load_targets
from .es_client import ESClient, ESError
from . import rules, analyzer, notifier, state, health, alerts, scrub, httpserver, digest, discord_notify
from . import fingerprint as fp
from .metrics import METRICS

log = logging.getLogger("log-watcher")

_stop = threading.Event()


def _handle_signal(signum, _frame):
    log.info("Signal %s empfangen — fahre nach dem aktuellen Schritt sauber herunter.", signum)
    _stop.set()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _build_time_str() -> str:
    raw = os.environ.get("LOGWATCHER_BUILD_TIME", "")
    if not raw or raw == "unknown":
        return "unbekannt"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%H:%M am %d.%m.%Y") + " UTC"
    except ValueError:
        return raw


def _startup_message(targets) -> str:
    return (f"🟢 log-watcher online — v{__version__}, "
            f"Image gebaut um {_build_time_str()}. "
            f"Targets: {[c.name for c in targets]}")


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

    # Per-Index-Stille über ein eigenes (größeres) Fenster prüfen — vermeidet Fehlalarme
    # bei bursty, aktivitätsgetriebenen Indizes (z.B. crawler-logs hat normale Leerlaufphasen).
    if cfg.ingestion_drop_check and cfg.index_silent_window_hours > 0:
        isw = timedelta(hours=cfg.index_silent_window_hours)
        try:
            cur_idx = es.per_index_counts(_iso(now - isw), _iso(now))
            base_idx = es.per_index_counts(_iso(now - 2 * isw), _iso(now - isw))
            signals += rules.evaluate_index_silence(cur_idx, base_idx, cfg, cfg.index_silent_window_hours)
        except ESError as e:
            log.warning("Index-Stille-Prüfung übersprungen: %s", e)

    METRICS.add_signals([s.kind for s in signals])

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
        METRICS.inc("suppressed_total")
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
            METRICS.inc("llm_calls_total")
            METRICS.inc("llm_tokens_total", assessment.get("llm_tokens", 0))
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
        log.warning("DRY_RUN: würde alarmieren:\n--- %s ---\n%s", subject, text_body)
    else:
        if cfg.smtp_host:
            try:
                notifier.send_email(cfg, subject, text_body, html_body)
                emailed = True
                log.info("E-Mail (HTML+Text) gesendet an %s", cfg.smtp_to)
            except Exception as e:  # noqa: BLE001 — Kanal-Fehler darf Indizierung/State nicht verhindern
                log.error("E-Mail-Versand fehlgeschlagen: %s", e)
        if cfg.discord_webhook_url:
            try:
                discord_notify.post(cfg.discord_webhook_url,
                                    discord_notify.build_alert_payload(subject, assessment, signals, current, baseline, cfg))
                log.info("Discord-Alert gesendet.")
            except Exception as e:  # noqa: BLE001
                log.error("Discord-Versand fehlgeschlagen: %s", e)

        # Alert für die Kibana-Historie zurück nach ES (best-effort, auch wenn ein Kanal scheiterte).
        if cfg.index_alerts:
            try:
                idx = alerts.alert_index_name(cfg.alert_index_prefix, now)
                doc = alerts.build_alert_doc(assessment, signals, current, baseline, cfg,
                                             _iso(now), sig, emailed)
                es.index_alert(doc, idx)
                log.info("Alert in ES indiziert (%s)", idx)
            except ESError as e:
                log.warning("Alert-Indizierung fehlgeschlagen: %s", e)

    METRICS.inc("alerts_total")
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


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def replay(cfg: Config, es: ESClient, start_dt: datetime, end_dt: datetime) -> int:
    """Regeln über einen vergangenen Zeitraum testen (Feature 18): pro Fenster die
    Signale loggen — ohne LLM, Mail, ES-Schreiben oder State."""
    win = timedelta(hours=cfg.window_hours)
    log.info("REPLAY [%s]: %s .. %s (Fenster %sh)", cfg.name, _iso(start_dt), _iso(end_dt), cfg.window_hours)
    cursor = start_dt + win
    fired = 0
    while cursor <= end_dt and not _stop.is_set():
        try:
            current = es.aggregate_window(_iso(cursor - win), _iso(cursor))
            b_start, b_end = _baseline_window(cfg, cursor, win)
            baseline = es.aggregate_window(_iso(b_start), _iso(b_end))
        except ESError as e:
            log.error("REPLAY: ES-Fehler: %s", e)
            return 1
        if cfg.scrub_pii:
            current["error_messages"] = scrub.scrub_messages(current.get("error_messages", {}))
            baseline["error_messages"] = scrub.scrub_messages(baseline.get("error_messages", {}))
        signals = rules.evaluate(current, baseline, cfg)
        if cfg.ingestion_drop_check and cfg.index_silent_window_hours > 0:
            isw = timedelta(hours=cfg.index_silent_window_hours)
            try:
                cur_idx = es.per_index_counts(_iso(cursor - isw), _iso(cursor))
                base_idx = es.per_index_counts(_iso(cursor - 2 * isw), _iso(cursor - isw))
                signals += rules.evaluate_index_silence(cur_idx, base_idx, cfg, cfg.index_silent_window_hours)
            except ESError as e:
                log.warning("REPLAY: Index-Stille-Prüfung übersprungen: %s", e)
        if signals:
            fired += 1
            log.info("REPLAY %s: %s", _iso(cursor), " | ".join(f"{s.kind}: {s.detail}" for s in signals))
        cursor += win
    log.info("REPLAY [%s] fertig: %d Fenster mit Signalen.", cfg.name, fired)
    return 0


def _maybe_digest(glob: Config, clients, st: dict, now: datetime) -> None:
    """Sendet einmal pro Periode (nach DIGEST_HOUR_UTC) eine Zusammenfassung (Feature 4)."""
    if not glob.digest_enabled:
        return
    last = st.get("last_digest")
    if last is not None:
        try:
            if (now.date() - date.fromisoformat(last)).days < glob.digest_period_days:
                return
        except ValueError:
            pass
    if now.hour < glob.digest_hour:
        return
    summaries = [digest.target_summary(cfg, es, glob.digest_period_days * 86400, now, _iso)
                 for cfg, es in clients]
    subject, text_body, html_body = digest.build(summaries, glob.digest_period_days)
    if glob.dry_run:
        log.warning("DRY_RUN: würde Digest senden:\n--- %s ---\n%s", subject, text_body)
    else:
        if glob.smtp_host:
            try:
                notifier.send_email(glob, subject, text_body, html_body)
                log.info("Digest-Mail gesendet an %s", glob.smtp_to)
            except Exception as e:  # noqa: BLE001
                log.error("Digest-Mail fehlgeschlagen: %s", e)
        if glob.discord_webhook_url:
            try:
                discord_notify.post_text(glob.discord_webhook_url, f"**{subject}**\n```\n{text_body[:1800]}\n```")
                log.info("Digest an Discord gesendet.")
            except Exception as e:  # noqa: BLE001
                log.error("Digest-Discord fehlgeschlagen: %s", e)
    st["last_digest"] = now.date().isoformat()
    state.save_state(glob.state_file, st)


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

    targets = load_targets()
    glob = targets[0]  # globale Loop-Settings (Intervall/Heartbeat/HTTP/State/Digest/Modi)

    bad = False
    for cfg in targets:
        for e in cfg.validate():
            log.error("Config-Fehler [%s]: %s", cfg.name, e)
            bad = True
    if bad:
        return 1

    now = datetime.now(timezone.utc)
    clients = [(cfg, ESClient(cfg)) for cfg in targets]

    # Replay-Modus (Feature 18): über alle Targets, dann beenden.
    if glob.replay_from:
        end_dt = _parse_iso(glob.replay_to) if glob.replay_to else now
        rc = 0
        for cfg, es in clients:
            rc |= replay(cfg, es, _parse_iso(glob.replay_from), end_dt)
        return rc

    if glob.selftest:
        rc = 0
        for cfg, es in clients:
            rc |= selftest(cfg, es, now)
        return rc

    log.info("log-watcher gestartet (targets=%s, intervall=%ss, fenster=%sh, dry_run=%s)",
             [c.name for c in targets], glob.interval_seconds, glob.window_hours, glob.dry_run)
    METRICS.start(now.timestamp())
    httpserver.start_http_server(glob)
    health.write_heartbeat(glob.heartbeat_file)

    for cfg, es in clients:
        startup_probe(cfg, es, now)
        if cfg.index_alerts and not cfg.dry_run:
            try:
                es.ensure_alert_template(cfg.alert_index_prefix)
            except ESError as e:
                log.warning("Alert-Index-Template [%s]: %s", cfg.name, e)

    if glob.notify_on_start and not glob.dry_run:
        start_msg = _startup_message(targets)
        log.info("Start-Meldung: %s", start_msg)
        if glob.smtp_host:
            try:
                notifier.send_email(glob, "[log-watcher] gestartet", start_msg)
            except Exception as e:  # noqa: BLE001 — Start-Meldung darf den Start nicht verhindern
                log.warning("Start-Mail fehlgeschlagen: %s", e)
        if glob.discord_webhook_url:
            try:
                discord_notify.post_text(glob.discord_webhook_url, start_msg)
            except Exception as e:  # noqa: BLE001
                log.warning("Start-Discord fehlgeschlagen: %s", e)

    while not _stop.is_set():
        cycle_now = datetime.now(timezone.utc)
        for cfg, es in clients:
            try:
                run_cycle(cfg, es, cycle_now)
            except ESError as e:
                METRICS.inc("es_errors_total")
                log.error("ES-Fehler [%s]: %s", cfg.name, e)
            except Exception:
                log.exception("Unerwarteter Fehler im Zyklus [%s]", cfg.name)
        try:
            _maybe_digest(glob, clients, state.load_state(glob.state_file), cycle_now)
        except Exception:
            log.exception("Digest fehlgeschlagen")
        METRICS.mark_cycle(time.time())
        health.write_heartbeat(glob.heartbeat_file)
        if glob.run_once:
            return 0
        _sleep_with_heartbeat(glob, glob.interval_seconds)

    log.info("Sauber beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
