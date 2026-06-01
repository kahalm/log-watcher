"""Konfiguration aus Umgebungsvariablen (12-Factor). Alles per ENV überschreibbar."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _str(key, default=None):
    v = os.environ.get(key)
    return v if v not in (None, "") else default


def _int(key, default):
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


def _float(key, default):
    try:
        return float(os.environ[key])
    except (KeyError, ValueError):
        return default


def _bool(key, default=False):
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _list(key, default):
    raw = os.environ.get(key)
    if raw is None:
        raw = default
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass
class Config:
    # --- Elasticsearch (nur lesend) ---
    es_url: str = field(default_factory=lambda: _str("ES_URL", "http://elasticsearch:9200"))
    es_indices: list = field(default_factory=lambda: _list("ES_INDICES", "rookhub-logs-*,crawler-logs-*"))
    es_api_key: "str | None" = field(default_factory=lambda: _str("ES_API_KEY"))
    es_user: "str | None" = field(default_factory=lambda: _str("ES_USER"))
    es_pass: "str | None" = field(default_factory=lambda: _str("ES_PASSWORD"))
    timestamp_field: str = field(default_factory=lambda: _str("ES_TIMESTAMP_FIELD", "@timestamp"))
    level_field: str = field(default_factory=lambda: _str("ES_LEVEL_FIELD", "level"))
    message_field: str = field(default_factory=lambda: _str("ES_MESSAGE_FIELD", "messageTemplate.keyword"))
    error_levels: list = field(default_factory=lambda: _list("ES_ERROR_LEVELS", "Error,Fatal"))
    warn_levels: list = field(default_factory=lambda: _list("ES_WARN_LEVELS", "Warning"))
    # Alerts zur Kibana-Historie zurück nach ES schreiben:
    index_alerts: bool = field(default_factory=lambda: _bool("ES_INDEX_ALERTS", True))
    alert_index_prefix: str = field(default_factory=lambda: _str("ES_ALERT_INDEX_PREFIX", "log-watcher-alerts"))

    # --- Fenster / Intervall ---
    window_hours: float = field(default_factory=lambda: _float("WINDOW_HOURS", 6.0))
    interval_seconds: int = field(default_factory=lambda: _int("INTERVAL_SECONDS", 6 * 3600))
    run_once: bool = field(default_factory=lambda: _bool("RUN_ONCE", False))

    # --- Cheap-Rules (billiges, deterministisches Gate vor dem LLM) ---
    min_errors: int = field(default_factory=lambda: _int("MIN_ERRORS", 5))
    error_spike_factor: float = field(default_factory=lambda: _float("ERROR_SPIKE_FACTOR", 3.0))
    # Warnungen sind lauter als Fehler -> höhere Mindestmenge, eigener Faktor, abschaltbar.
    min_warnings: int = field(default_factory=lambda: _int("MIN_WARNINGS", 20))
    warn_spike_factor: float = field(default_factory=lambda: _float("WARN_SPIKE_FACTOR", 3.0))
    alert_on_warn_spike: bool = field(default_factory=lambda: _bool("ALERT_ON_WARN_SPIKE", True))
    alert_on_new_signatures: bool = field(default_factory=lambda: _bool("ALERT_ON_NEW_SIGNATURES", True))
    ingestion_drop_check: bool = field(default_factory=lambda: _bool("INGESTION_DROP_CHECK", True))

    # --- LLM (Anthropic) ---
    anthropic_api_key: "str | None" = field(default_factory=lambda: _str("ANTHROPIC_API_KEY"))
    model: str = field(default_factory=lambda: _str("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"))
    max_tokens: int = field(default_factory=lambda: _int("ANTHROPIC_MAX_TOKENS", 1024))

    # --- SMTP ---
    smtp_host: "str | None" = field(default_factory=lambda: _str("SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _int("SMTP_PORT", 587))
    smtp_user: "str | None" = field(default_factory=lambda: _str("SMTP_USER"))
    smtp_pass: "str | None" = field(default_factory=lambda: _str("SMTP_PASSWORD"))
    smtp_from: "str | None" = field(default_factory=lambda: _str("SMTP_FROM"))
    smtp_to: list = field(default_factory=lambda: _list("SMTP_TO", ""))
    smtp_tls: bool = field(default_factory=lambda: _bool("SMTP_TLS", True))

    # --- State / Dedupe ---
    state_file: str = field(default_factory=lambda: _str("STATE_FILE", "/data/state.json"))
    cooldown_hours: float = field(default_factory=lambda: _float("COOLDOWN_HOURS", 12.0))

    # --- Health / Heartbeat ---
    heartbeat_file: str = field(default_factory=lambda: _str("HEARTBEAT_FILE", "/data/heartbeat"))
    heartbeat_interval: int = field(default_factory=lambda: _int("HEARTBEAT_INTERVAL_SECONDS", 60))

    # --- Sonstiges ---
    dry_run: bool = field(default_factory=lambda: _bool("DRY_RUN", False))
    notify_on_start: bool = field(default_factory=lambda: _bool("NOTIFY_ON_START", False))
    selftest: bool = field(default_factory=lambda: _bool("SELFTEST", False))

    @property
    def window_seconds(self) -> float:
        return self.window_hours * 3600

    def validate(self) -> "list[str]":
        errs = []
        if not self.es_url:
            errs.append("ES_URL fehlt")
        if not self.es_indices:
            errs.append("ES_INDICES fehlt")
        if not self.dry_run:
            if not self.smtp_host:
                errs.append("SMTP_HOST fehlt (oder DRY_RUN=true setzen)")
            if not self.smtp_from:
                errs.append("SMTP_FROM fehlt")
            if not self.smtp_to:
                errs.append("SMTP_TO fehlt")
        return errs
