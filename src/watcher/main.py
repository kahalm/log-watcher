"""log-watcher: ES-Aggregate -> Regel-Gate -> (LLM) -> E-Mail. Hybrid, alle X h."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from datetime import date, datetime, timedelta, timezone

import requests

from . import __version__
from .config import Config, load_targets
from .es_client import ESClient, ESError
from . import rules, analyzer, notifier, state, health, alerts, scrub, httpserver, digest, discord_notify, security, linux
from . import fingerprint as fp
from .metrics import METRICS

log = logging.getLogger("log-watcher")

_stop = threading.Event()


def _handle_signal(signum, _frame):
    log.info("Signal %s empfangen — fahre nach dem aktuellen Schritt sauber herunter.", signum)
    _stop.set()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


_legacy_heartbeat_warned: set = set()


def _heartbeat_counts(cfg: Config, es: ESClient, now: datetime) -> dict:
    """Pro erwartetem Dienst (cfg.heartbeat_checks) zählen, wie viele passende Heartbeats in den
    letzten heartbeat_max_staleness_minutes ankamen. {name: count}.

    "name=index": Zeilen mit heartbeat_service_field == name (strukturiert, nicht fälschbar über
    Freitext). "name=index=phrase": Altform, match_phrase gegen das gerenderte heartbeat_field."""
    counts: dict = {}
    window_min = cfg.heartbeat_max_staleness_minutes
    if window_min <= 0 or not cfg.heartbeat_checks:
        return counts
    rng = {"range": {cfg.timestamp_field: {"gte": _iso(now - timedelta(minutes=window_min)), "lt": _iso(now)}}}
    for spec in cfg.heartbeat_checks:
        parts = [p.strip() for p in spec.split("=", 2)]
        if len(parts) not in (2, 3) or not all(parts):
            log.warning("Ungültige HEARTBEAT_CHECKS-Angabe übersprungen: %r", spec)
            continue
        name, index = parts[0], parts[1]
        if len(parts) == 2:
            match = {"term": {cfg.heartbeat_service_field: name}}
        else:
            if spec not in _legacy_heartbeat_warned:
                _legacy_heartbeat_warned.add(spec)
                log.warning("HEARTBEAT_CHECKS %r prüft Freitext (fälschbar über jede Logzeile mit "
                            "diesem Text) — auf %r umstellen (Feld %s).",
                            spec, f"{name}={index}", cfg.heartbeat_service_field)
            match = {"match_phrase": {cfg.heartbeat_field: parts[2]}}
        query = {"bool": {"must": [match, rng]}}
        counts[name] = es.count(index, query)
    return counts


def _build_time_str() -> str:
    raw = os.environ.get("LOGWATCHER_BUILD_TIME", "")
    if not raw or raw == "unknown":
        return "unbekannt"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%H:%M am %d.%m.%Y") + " UTC"
    except ValueError:
        return raw


def _report_build_to_rookhub() -> None:
    """Meldet die laufende Build-SHA/Ref an rookhubs Admin-CI (Push-Modell) — rookhub kann log-watcher
    nicht per HTTP erreichen (eigenes Docker-Netz), also meldet log-watcher aktiv. Best-effort:
    ohne ROOKHUB_BUILD_REPORT_URL/CI_BUILD_REPORT_SECRET passiert nichts, Fehler werden nur geloggt."""
    url = os.environ.get("ROOKHUB_BUILD_REPORT_URL", "").strip()
    secret = os.environ.get("CI_BUILD_REPORT_SECRET", "").strip()
    if not url or not secret:
        return
    import requests
    payload = {
        "repo": os.environ.get("BUILD_REPORT_REPO", "log-watcher"),
        "sha": os.environ.get("GIT_SHA", ""),
        "ref": os.environ.get("GIT_REF", ""),
    }
    try:
        resp = requests.post(url, json=payload, headers={"X-Build-Report-Key": secret}, timeout=5)
        if resp.status_code >= 300:
            log.warning("Build-Report an rookhub: HTTP %s", resp.status_code)
    except Exception as e:  # noqa: BLE001 — darf den Start/Zyklus nie stören
        log.warning("Build-Report an rookhub fehlgeschlagen: %s", e)


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


def _notify(glob: Config, label: str, text: str = "", *, payload=None, mail=None,
            dry_level: int = logging.INFO) -> set:
    """Eine Meldung an die konfigurierten Kanäle — der einzige Versandweg (Alert, Digest,
    Warnungen, Entwarnungen, All-is-well, Start-Meldung).

    text:    Discord-Text (post_text), zugleich die DRY_RUN-Vorschau, wenn keine Mail dabei ist.
    payload: Discord-Payload (post) statt text; ein Callable wird erst hier gebaut, ein Fehler
             darin zählt als Kanal-Fehler.
    mail:    (subject, text_body, html_body) -> zusätzlich per E-Mail, sofern SMTP_HOST gesetzt ist.

    Liefert die Kanäle, die zugestellt haben ({"email", "discord"}, im DRY_RUN {"dry_run"}). Leer
    heißt: niemand wurde benachrichtigt — dann KEINEN Marker/State fortschreiben, der nächste
    Zyklus versucht es erneut. Wirft nie wegen eines Kanal-Fehlers.
    """
    if glob.dry_run:
        preview = f"\n--- {mail[0]} ---\n{mail[1]}" if mail else text
        log.log(dry_level, "DRY_RUN: %s: %s", label, preview)
        return {"dry_run"}
    sent = set()
    if mail is not None and glob.smtp_host:
        try:
            notifier.send_email(glob, *mail)
            sent.add("email")
            log.info("%s: E-Mail gesendet an %s", label, glob.smtp_to)
        except Exception as e:  # noqa: BLE001 — Kanal-Fehler darf State/andere Kanäle nicht verhindern
            log.error("%s: E-Mail fehlgeschlagen: %s", label, e)
    if glob.discord_webhook_url and (payload is not None or text):
        try:
            if payload is None:
                discord_notify.post_text(glob.discord_webhook_url, text)
            else:
                discord_notify.post(glob.discord_webhook_url, payload() if callable(payload) else payload)
            sent.add("discord")
            log.info("%s an Discord gesendet.", label)
        except Exception as e:  # noqa: BLE001
            log.error("%s an Discord fehlgeschlagen: %s", label, e)
    return sent


def run_cycle(cfg: Config, es: ESClient, now: datetime) -> None:
    win = timedelta(hours=cfg.window_hours)
    base_start, base_end = _baseline_window(cfg, now, win)
    current = es.aggregate_window(_iso(now - win), _iso(now))
    baseline = es.aggregate_window(_iso(base_start), _iso(base_end))
    rules.warn_if_templates_missing(current, cfg)

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

    # Heartbeat-Überwachung: fehlt das Lebenszeichen eines Dienstes → vermutlich tot. Greift
    # pro Dienst (genauer als die Index-Stille) und macht „Stille" verlässlich auswertbar,
    # da gesunde Dienste alle 60 s einen Heartbeat schreiben.
    if cfg.heartbeat_max_staleness_minutes > 0 and cfg.heartbeat_checks:
        try:
            signals += rules.evaluate_heartbeats(_heartbeat_counts(cfg, es, now), cfg)
        except ESError as e:
            log.warning("Heartbeat-Prüfung übersprungen: %s", e)

    # Security-Heuristik: systematisches API-Abklopfen (Scanner-Pfade, Pfad-Enumeration,
    # Auth-Brute-Force) über die HTTP-Zugriffslogs desselben Fensters erkennen.
    if cfg.security_check:
        try:
            sec = es.security_window(_iso(now - win), _iso(now))
            signals += security.evaluate_security(sec, cfg)
        except ESError as e:
            log.warning("Security-Prüfung übersprungen: %s", e)

    # Linux-System-Heuristik: SSH-Brute-Force, OOM, Disk-Fehler, Unit-Failures und
    # verstummte Hosts über die Filebeat-/journald-Logs (eigene Indizes).
    if cfg.linux_check and cfg.linux_indices:
        try:
            lin = es.linux_window(_iso(now - win), _iso(now), _iso(now - 2 * win))
            signals += linux.evaluate_linux(lin, cfg)
        except ESError as e:
            log.warning("Linux-Prüfung übersprungen: %s", e)

    # Signatur aus den ROHEN Details bilden — VOR dem Redigieren. Sonst kollabieren
    # verschiedene Angreifer-IPs auf dieselbe Signatur (beide werden zu "<ip>") und der
    # zweite Angreifer läuft still in den 12h-Cooldown des ersten, inklusive dessen
    # gecachtem LLM-Verdict.
    raw_signature = state.signature(signals)

    # Signal-Details erst hier redigieren — danach geht nichts mehr an LLM/Mail/Discord/ES
    # vorbei. Ohne das gingen die Roh-Client-IPs aus security.py trotz SCRUB_PII=true raus.
    if cfg.scrub_pii:
        scrub.scrub_signals(signals)

    METRICS.add_signals([s.kind for s in signals])

    # Aktuelle Fehler-Fingerprints als gesehen merken (Feature 9).
    state.record_fingerprints(st, cfg.name, {fp.fingerprint(m) for m in current.get("error_messages", {})}, now_ts)

    if not signals:
        state.save_state(cfg.state_file, st)
        log.info("Keine Auffälligkeit (Regel-Gate leer).")
        return

    log.info("Regel-Gate ausgelöst: %s", [s.kind for s in signals])
    sig = raw_signature
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
            samples = es.fetch_samples(_iso(now - win), _iso(now), cfg.sample_size,
                                       cfg.sample_field or cfg.message_field)
            if cfg.scrub_pii:
                samples = [scrub.scrub(s) for s in samples]
        assessment = analyzer.assess(cfg, current, baseline, signals, samples=samples, use_llm=use_llm)
        if assessment.get("llm_used"):
            state.record_llm_call(st, day, assessment.get("llm_tokens", 0))
            METRICS.inc("llm_calls_total")
            METRICS.inc("llm_tokens_total", assessment.get("llm_tokens", 0))
            ended = state.clear_llm_outage(st)
            if ended is not None and ended.get("notified_at") is not None:
                # Nur entwarnen, wenn auch gewarnt wurde — sonst meldet der Waechter eine
                # Stoerung, die nie jemand zu sehen bekam.
                st["llm_recovered"] = {"kind": ended.get("kind"), "reason": ended.get("reason"),
                                       "since": ended.get("since"), "at": now_ts}
        if assessment.get("llm_error"):
            # Ausfall festhalten (die Warnung geht in der Hauptschleife raus) und das degradierte
            # Urteil NICHT in den Verdict-Cache legen: sonst gilt die Notbewertung noch Stunden
            # weiter, nachdem das Guthaben wieder da ist.
            state.set_llm_outage(st, assessment.get("llm_error_kind", "sonstiges"),
                                 assessment["llm_error"], now_ts)
            METRICS.inc("llm_errors_total")
        else:
            state.put_verdict(st, cfg.name, sig, assessment, now_ts)

    # Bestätigte Security-Signale sind immer eine „große Warnung": der LLM darf einen
    # erkannten Scan/Brute-Force nicht zu „nicht auffällig" herabstufen.
    security_signals = [s for s in signals
                        if s.kind in security.SECURITY_KINDS or s.kind in linux.FORCED_KINDS]
    if security_signals:
        assessment["anomalous"] = True
        assessment["severity"] = "high"
        if not assessment.get("summary"):
            assessment["summary"] = ("🚨 Sicherheitsrelevante Auffälligkeit: "
                                     + " ".join(s.detail for s in security_signals))

    log.info("Beurteilung: anomalous=%s severity=%s llm=%s",
             assessment.get("anomalous"), assessment.get("severity"), assessment.get("llm_used"))

    if not assessment.get("anomalous"):
        # Auch "nicht auffällig" merken -> kein erneuter LLM-Call für dasselbe Muster im Cooldown.
        state.save_state(cfg.state_file, state.record_alert(st, cfg.name, sig, now_ts))
        return

    severity = assessment.get("severity", rules.overall_severity(signals))
    # Target-Name in den Betreff/Titel: bei mehreren ES-Instanzen mit identischen Index-Namen
    # (z.B. rookhub-prod vs. rookhub-dev, beide rookhub-logs-*) sonst nicht auseinanderzuhalten.
    if security_signals:
        subject = f"[log-watcher][{cfg.name}][{severity.upper()}] 🚨 Sicherheits-Alarm in {', '.join(cfg.es_indices)}"
    else:
        subject = f"[log-watcher][{cfg.name}][{severity.upper()}] Auffälligkeit in {', '.join(cfg.es_indices)}"
    text_body = notifier.build_email_body(assessment, signals, current, baseline, cfg)
    html_body = notifier.build_email_html(assessment, signals, current, baseline, cfg)

    # Im Trockenlauf gilt der Alert als zugestellt: der Cooldown soll wie im Echtbetrieb greifen.
    sent = _notify(cfg, "Alert", mail=(subject, text_body, html_body), dry_level=logging.WARNING,
                   payload=lambda: discord_notify.build_alert_payload(subject, assessment, signals,
                                                                      current, baseline, cfg))
    emailed = "email" in sent
    delivered = bool(sent)
    if not cfg.dry_run:
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
    # Cooldown nur stempeln, wenn wirklich jemand benachrichtigt wurde. Sonst würde ein
    # transienter SMTP-/Webhook-Ausfall den Alarm für COOLDOWN_HOURS still verschlucken —
    # bei stabilem Detail (heartbeat_missing) auch in allen Folgezyklen.
    if delivered:
        state.record_alert(st, cfg.name, sig, now_ts)
    else:
        log.error("Kein Alert-Kanal erfolgreich — Cooldown NICHT gesetzt, nächster Zyklus versucht es erneut.")
    state.save_state(cfg.state_file, st)


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
            rules.warn_if_templates_missing(sample, cfg, "Startup-Probe: ")
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
        if cfg.security_check:
            try:
                signals += security.evaluate_security(es.security_window(_iso(cursor - win), _iso(cursor)), cfg)
            except ESError as e:
                log.warning("REPLAY: Security-Prüfung übersprungen: %s", e)
        if cfg.linux_check and cfg.linux_indices:
            try:
                signals += linux.evaluate_linux(
                    es.linux_window(_iso(cursor - win), _iso(cursor), _iso(cursor - 2 * win)), cfg)
            except ESError as e:
                log.warning("REPLAY: Linux-Prüfung übersprungen: %s", e)
        if signals:
            fired += 1
            if cfg.scrub_pii:
                scrub.scrub_signals(signals)  # Replay-Log landet selbst wieder in ES/stdout
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
    try:
        summaries = [digest.target_summary(cfg, es, glob.digest_period_days * 86400, now, _iso)
                     for cfg, es in clients]
    except ESError as e:
        # Marker bleibt stehen -> nächster Zyklus versucht es erneut, statt einen Digest
        # mit stillen 0-Werten zu verschicken. All-is-well soll davon unberührt bleiben.
        log.warning("Digest übersprungen (ES-Fehler): %s", e)
        return
    subject, text_body, html_body = digest.build(summaries, glob.digest_period_days)
    # Backticks raus: die Top-Fehlermeldungen kommen roh aus ES — ein ``` darin würde
    # den Code-Zaun sprengen und den Rest als Markdown rendern. Mentions (@everyone)
    # entschärft discord_notify.post zentral via allowed_mentions {parse: []}.
    fenced = text_body[:1800].replace("`", "'")
    delivered = _notify(glob, "Digest", f"**{subject}**\n```\n{fenced}\n```",
                        mail=(subject, text_body, html_body), dry_level=logging.WARNING)
    # Periodenmarker nur bei erfolgreichem Versand fortschreiben — sonst fällt der Digest
    # wegen eines kurzen Kanal-Ausfalls für die ganze Periode aus.
    if not delivered:
        log.error("Digest an keinen Kanal zugestellt — Marker nicht gesetzt, nächster Zyklus versucht es erneut.")
        return
    st["last_digest"] = now.date().isoformat()
    state.save_state(glob.state_file, st)


_ALLISWELL_QUOTE = (
    '"As they saw it, their purpose was to walk down the street chanting '
    "'Two o'clock and all's well', and if all wasn't well, they found another street.\""
    "\n— *Night Watch*, Terry Pratchett"
)


def _any_recent_alert(st: dict, targets, since_ts: float) -> bool:
    """True wenn irgendeines der Targets in den letzten Stunden einen Alert gesendet hat."""
    for cfg in targets:
        alerts = st.get("targets", {}).get(cfg.name, {}).get("alerts", {})
        if any(ts >= since_ts for ts in alerts.values()):
            return True
    return False


def _outage_age(outage: dict, now: datetime) -> str:
    """Dauer des Ausfalls in Klartext („seit 3 h 20 min“)."""
    since = outage.get("since")
    if not isinstance(since, (int, float)):
        return "unbekannt lange"
    minutes = max(0, int((now.timestamp() - since) // 60))
    if minutes < 60:
        return f"seit {minutes} min"
    return f"seit {minutes // 60} h {minutes % 60:02d} min"


def _maybe_llm_outage_warning(glob: Config, st: dict, now: datetime) -> None:
    """Warnt, solange die LLM-Bewertung nicht laeuft — statt Stille oder „alles in Ordnung“.

    Der Fall, der das ausgeloest hat: leeres Anthropic-Guthaben. Der Wachhund lief weiter,
    schrieb 84-mal einen Traceback ins eigene Log und meldete nach Discord nichts — waehrend
    das Regel-Gate mehrfach angeschlagen hatte. Wer nichts hoert, schliesst auf Ruhe; genau
    das darf ein Ausfall des Bewerters nicht bedeuten.
    """
    if not glob.discord_webhook_url:
        return

    recovered = st.get("llm_recovered")
    if isinstance(recovered, dict):
        msg = ("✅ **Log-Wächter bewertet wieder vollständig.**\n"
               f"> {recovered.get('reason', 'LLM-Aufruf')} — behoben.")
        # Erst nach dem Versand austragen: scheitert Discord, bliebe sonst die Ausfall-Warnung
        # die letzte Meldung im Kanal — der nächste Zyklus versucht die Entwarnung erneut.
        if _notify(glob, "LLM-Entwarnung", msg):
            st.pop("llm_recovered", None)
            state.save_state(glob.state_file, st)

    if not state.llm_outage_needs_notice(st, now.timestamp(), glob.llm_outage_notice_hours * 3600):
        return
    outage = state.llm_outage(st)
    assert outage is not None  # llm_outage_needs_notice hat es schon geprueft

    todo = {
        "guthaben": "Guthaben aufladen (Anthropic Console → Plans & Billing).",
        "schluessel": "ANTHROPIC_API_KEY im Stack ersetzen.",
        "drosselung": "Meist von selbst vorbei — haelt es an, Intervall oder Modell pruefen.",
    }.get(outage.get("kind"), "Log des Waechters ansehen: `docker logs log-watcher`.")

    msg = ("⚠️ **Log-Wächter arbeitet nur noch regelbasiert.**\n"
           f"> {outage.get('reason', 'LLM-Aufruf scheitert')} ({_outage_age(outage, now)})\n\n"
           "Regel-Alarme (Sicherheit, Fehler-Ausschläge, Systemmeldungen) laufen weiter — "
           "die **Bewertung und Einordnung fehlt**, und die tägliche Alles-in-Ordnung-Meldung "
           "bleibt aus, solange das so ist.\n"
           f"→ {todo}")

    if not _notify(glob, f"LLM-Ausfall-Warnung ({outage.get('kind')})", msg, dry_level=logging.WARNING):
        return   # nicht als gemeldet verbuchen, dann greift der naechste Zyklus
    state.record_llm_outage_notice(st, now.timestamp())
    state.save_state(glob.state_file, st)


# Ab so vielen gescheiterten Zyklen in Folge warnt der Wächter: ein einzelner ES-Schluckauf
# (Neustart, kurzer Timeout) ist im nächsten Zyklus vorbei und soll kein Warnung/Entwarnung-Paar
# nach Discord schicken. Die All-is-well-Sperre greift dagegen schon beim ersten Fehlschlag.
_OUTAGE_MIN_CYCLES = 2


def _cycle_failure_reason(e: BaseException) -> str:
    """Grund eines gescheiterten Zyklus für State und Discord-Warnung — ohne Host, Port, URL.

    str(ESError) trägt bei einem Verbindungsfehler die requests-Meldung samt
    ``HTTPConnectionPool(host='<ES-IP>', port=9200) … url: /<indizes>/_search``; die interne
    ES-Adresse hat im Discord-Kanal (Drittanbieter) nichts verloren. Der volle Text steht im Log.
    """
    if isinstance(e, ESError):
        if e.status is not None:
            return f"ES HTTP {e.status}"
        cause = e.__cause__
        if cause is None:
            return "ES nicht erreichbar"   # ESError-Vertrag: status None = Verbindungsfehler
        if isinstance(cause, requests.RequestException):
            return f"ES nicht erreichbar ({type(cause).__name__})"
        return f"ES-Fehler ({type(cause).__name__})"
    return f"Unerwarteter Fehler: {type(e).__name__}"


def _run_cycles(clients, now: datetime) -> dict:
    """Ein Zyklus je Target. Liefert {target: None (geprüft) | Grund (gescheitert)}.

    Der Grund landet im State und in der Discord-Warnung, darum ohne ES-Adresse
    (_cycle_failure_reason); die volle Fehlermeldung geht nur ins Log.
    """
    results: dict = {}
    for cfg, es in clients:
        try:
            run_cycle(cfg, es, now)
            results[cfg.name] = None
        except ESError as e:
            METRICS.inc("es_errors_total")
            log.error("ES-Fehler [%s]: %s", cfg.name, e)
            results[cfg.name] = _cycle_failure_reason(e)
        except Exception as e:  # noqa: BLE001 — ein kaputtes Target darf die anderen nicht stoppen
            log.exception("Unerwarteter Fehler im Zyklus [%s]", cfg.name)
            results[cfg.name] = _cycle_failure_reason(e)
    return results


def _record_cycle_results(glob: Config, st: dict, results: dict, now: datetime) -> None:
    """Zyklus-Erfolg/-Fehlschlag je Target im Zustand festhalten (für Warnung und All-is-well)."""
    now_ts = now.timestamp()
    recovered = []
    for name, reason in results.items():
        if reason is None:
            ended = state.record_cycle_ok(st, name, now_ts)
            # Nur entwarnen, wenn auch gewarnt wurde.
            if ended is not None and ended.get("notified_at") is not None:
                recovered.append(name)
        else:
            state.record_cycle_failure(st, name, reason, now_ts)
    if recovered:
        prev = st.get("cycle_recovered")
        st["cycle_recovered"] = (prev if isinstance(prev, list) else []) + recovered
    state.save_state(glob.state_file, st)


def _blind_targets(st: dict, targets, since_ts: float) -> list:
    """Targets, die seit `since_ts` nicht erfolgreich geprüft wurden oder gerade scheitern."""
    blind = []
    for cfg in targets:
        last_ok = state.last_cycle_ok(st, cfg.name)
        if state.cycle_outage(st, cfg.name) is not None or last_ok is None or last_ok < since_ts:
            blind.append(cfg.name)
    return blind


def _names_md(names) -> str:
    """Target-Namen kommagetrennt, Markdown-escapt (Namen stammen aus der config.yaml)."""
    return ", ".join(discord_notify.escape_markdown(str(n)) for n in names)


def _maybe_cycle_outage_warning(glob: Config, targets, st: dict, now: datetime) -> None:
    """Warnt, solange Targets nicht geprüft werden können (ES weg, Zyklus scheitert).

    Eine Sammelmeldung mit einer Zeile je Elasticsearch statt einer Meldung je Target — hängen
    acht Targets an derselben ES, wären acht Warnungen genau der Lärm, der echte übertönt.
    """
    if not glob.discord_webhook_url:
        return

    recovered = st.get("cycle_recovered")
    if isinstance(recovered, list) and recovered:
        msg = ("✅ **Log-Wächter prüft wieder:** "
               + _names_md(sorted(set(str(n) for n in recovered))) + ".")
        # Wie bei der LLM-Entwarnung: erst nach erfolgreichem Versand austragen.
        if _notify(glob, "Zyklus-Entwarnung", msg):
            st.pop("cycle_recovered", None)
            state.save_state(glob.state_file, st)

    now_ts = now.timestamp()
    every = glob.es_outage_notice_hours * 3600
    groups: dict = {}   # es_url -> [(name, outage)]
    for cfg in targets:
        outage = state.cycle_outage(st, cfg.name)
        if outage is None or int(outage.get("cycles", 0) or 0) < _OUTAGE_MIN_CYCLES:
            continue
        last = outage.get("notified_at")
        if isinstance(last, (int, float)) and (now_ts - last) < every:
            continue
        groups.setdefault(cfg.es_url, []).append((cfg.name, outage))
    if not groups:
        return

    lines = []
    for members in groups.values():
        names = _names_md([n for n, _ in members])
        oldest = min(members, key=lambda m: m[1].get("since", now_ts))[1]
        newest = max(members, key=lambda m: m[1].get("last_seen", 0))[1]
        reason = discord_notify.escape_markdown(str(newest.get("reason", "Zyklus scheitert"))[:200])
        lines.append(f"> **{names}** ({_outage_age(oldest, now)}): {reason}")
    msg = ("⚠️ **Log-Wächter blind: Prüfzyklus scheitert.**\n"
           + "\n".join(lines) + "\n\n"
           "Diese Targets werden gerade **nicht geprüft** — kein Alarm heißt hier nicht „alles ruhig“, "
           "und die tägliche Alles-in-Ordnung-Meldung bleibt aus, solange das so ist.\n"
           "→ Elasticsearch prüfen, dann `docker logs log-watcher`.")

    names = [n for members in groups.values() for n, _ in members]
    if not _notify(glob, f"Zyklus-Ausfall-Warnung ({names})", msg, dry_level=logging.WARNING):
        return   # nicht als gemeldet verbuchen, dann greift der naechste Zyklus
    for members in groups.values():
        for _, outage in members:
            outage["notified_at"] = now_ts
    state.save_state(glob.state_file, st)


def _maybe_alliswell(glob: Config, targets, st: dict, now: datetime) -> None:
    if not glob.alliswell_enabled or not glob.discord_webhook_url:
        return
    # Kein „alles in Ordnung“, wenn der Bewerter nicht arbeitet: die Meldung sagt „ich habe
    # nachgesehen und nichts gefunden“, und genau das stimmt dann nicht. Gewarnt hat
    # _maybe_llm_outage_warning bereits.
    if state.llm_outage(st) is not None:
        log.info("All-is-well unterdrueckt: LLM-Bewertung ausgefallen.")
        return
    last = st.get("last_alliswell")
    if last is not None:
        try:
            if now.date() == date.fromisoformat(last):
                return
        except ValueError:
            pass
    if now.hour < glob.alliswell_hour:
        return
    if _any_recent_alert(st, targets, now.timestamp() - 86400):
        return
    # Kein „alles in Ordnung“, wenn ein Target in den letzten 24 h nicht erfolgreich geprüft
    # wurde oder gerade scheitert (ES weg): dann hat der Wächter nicht nachgesehen. Gewarnt
    # hat _maybe_cycle_outage_warning; der Tag bleibt offen, nach der Erholung kommt die Meldung.
    blind = _blind_targets(st, targets, now.timestamp() - 86400)
    if blind:
        log.info("All-is-well unterdrueckt: nicht geprueft: %s", blind)
        return
    msg = f"🕗 Zwei Uhr und alles in Ordnung!\n> {_ALLISWELL_QUOTE}\n\n✅ Keine Auffälligkeiten in den letzten 24 h."
    # Tagesmarker nur nach Zustellung: scheitert Discord um 08:00 kurz, versucht es der nächste
    # Zyklus erneut, statt den Tag stumm abzuhaken (der Wächter wirkte sonst tot).
    if not _notify(glob, "All-is-well-Meldung", msg):
        return
    st["last_alliswell"] = now.date().isoformat()
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

    # Schreibprobe vor dem Loop: ist /data nicht beschreibbar (Rechte nach USER-Umstellung, Platte
    # voll, nur lesbar eingehängt), liefen Cooldown, Verdict-Cache, LLM-Tagesbudget und Tagesmarker
    # still ins Leere — derselbe Alarm alle INTERVAL_SECONDS. Dann lieber gar nicht starten.
    paths = {("STATE_FILE", c.state_file) for c in targets} | {("HEARTBEAT_FILE", glob.heartbeat_file)}
    for what, path in sorted(paths):
        err = state.check_writable(path)
        if err:
            log.error("%s %s nicht schreibbar (%s) — Start abgebrochen. Rechte/Eigentümer des "
                      "Verzeichnisses (Volume /data) und freien Platz prüfen.", what, path, err)
            return 1

    log.info("log-watcher gestartet (targets=%s, intervall=%ss, fenster=%sh, dry_run=%s)",
             [c.name for c in targets], glob.interval_seconds, glob.window_hours, glob.dry_run)
    METRICS.start(now.timestamp())
    httpserver.start_http_server(glob)
    health.write_heartbeat(glob.heartbeat_file)
    _report_build_to_rookhub()   # laufendes Image an rookhubs Admin-CI melden (Push)

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
        # zustandslos: ein Fehlschlag wird nur geloggt und verhindert den Start nicht
        _notify(glob, "Start-Meldung", start_msg, mail=("[log-watcher] gestartet", start_msg, None))

    while not _stop.is_set():
        cycle_now = datetime.now(timezone.utc)
        _report_build_to_rookhub()   # je Zyklus erneut melden (überlebt rookhub-api-Neustarts)
        results = _run_cycles(clients, cycle_now)
        try:
            shared_st = state.load_state(glob.state_file)
            _record_cycle_results(glob, shared_st, results, cycle_now)
            _maybe_digest(glob, clients, shared_st, cycle_now)
            _maybe_llm_outage_warning(glob, shared_st, cycle_now)
            _maybe_cycle_outage_warning(glob, [cfg for cfg, _ in clients], shared_st, cycle_now)
            _maybe_alliswell(glob, [cfg for cfg, _ in clients], shared_st, cycle_now)
        except Exception:
            log.exception("Digest/All-is-well fehlgeschlagen")
        METRICS.mark_cycle(time.time())
        health.write_heartbeat(glob.heartbeat_file)
        if glob.run_once:
            return 0
        _sleep_with_heartbeat(glob, glob.interval_seconds)

    log.info("Sauber beendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
