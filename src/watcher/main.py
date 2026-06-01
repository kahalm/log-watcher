"""log-watcher: ES-Aggregate -> Regel-Gate -> (LLM) -> E-Mail. Hybrid, alle X h."""
from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from .config import Config
from .es_client import ESClient, ESError
from . import rules, analyzer, notifier, state

log = logging.getLogger("log-watcher")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def run_cycle(cfg: Config, es: ESClient, now: datetime) -> None:
    win = timedelta(hours=cfg.window_hours)
    end, start, base_start = now, now - win, now - 2 * win
    current = es.aggregate_window(_iso(start), _iso(end))
    baseline = es.aggregate_window(_iso(base_start), _iso(start))
    log.info("Fenster: total=%s levels=%s | Baseline: total=%s",
             current["total"], current["levels"], baseline["total"])

    signals = rules.evaluate(current, baseline, cfg)
    if not signals:
        log.info("Keine Auffälligkeit (Regel-Gate leer).")
        return

    log.info("Regel-Gate ausgelöst: %s", [s.kind for s in signals])
    sig = state.signature(signals)
    st = state.load_state(cfg.state_file)
    now_ts = now.timestamp()
    if state.in_cooldown(st, sig, cfg.cooldown_hours * 3600, now_ts):
        log.info("Unterdrückt (Cooldown aktiv für Signatur %s).", sig)
        return

    assessment = analyzer.assess(cfg, current, baseline, signals)
    log.info("Beurteilung: anomalous=%s severity=%s llm=%s",
             assessment.get("anomalous"), assessment.get("severity"), assessment.get("llm_used"))

    if not assessment.get("anomalous"):
        # Auch "nicht auffällig" merken -> kein erneuter LLM-Call für dasselbe Muster im Cooldown.
        state.save_state(cfg.state_file, state.record(st, sig, now_ts))
        return

    severity = assessment.get("severity", rules.overall_severity(signals))
    subject = f"[log-watcher][{severity.upper()}] Auffälligkeit in {', '.join(cfg.es_indices)}"
    body = notifier.build_email_body(assessment, signals, current, baseline, cfg)
    if cfg.dry_run:
        log.warning("DRY_RUN: würde E-Mail senden:\n--- %s ---\n%s", subject, body)
    else:
        notifier.send_email(cfg, subject, body)
        log.info("E-Mail gesendet an %s", cfg.smtp_to)
    state.save_state(cfg.state_file, state.record(st, sig, now_ts))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config()
    errs = cfg.validate()
    if errs:
        for e in errs:
            log.error("Config-Fehler: %s", e)
        return 1

    es = ESClient(cfg)
    log.info("log-watcher gestartet (intervall=%ss, fenster=%sh, indices=%s, dry_run=%s)",
             cfg.interval_seconds, cfg.window_hours, cfg.es_indices, cfg.dry_run)

    while True:
        try:
            run_cycle(cfg, es, datetime.now(timezone.utc))
        except ESError as e:
            log.error("ES-Fehler: %s", e)
        except Exception:
            log.exception("Unerwarteter Fehler im Zyklus")
        if cfg.run_once:
            return 0
        time.sleep(cfg.interval_seconds)


if __name__ == "__main__":
    sys.exit(main())
