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
    # --- Identität / Baseline ---
    name: str = field(default_factory=lambda: _str("TARGET_NAME", "default"))
    # Baseline-Vergleichsfenster: previous (Vorfenster) | yesterday (-24h) | last_week (-7d)
    baseline_mode: str = field(default_factory=lambda: _str("BASELINE_MODE", "previous"))

    # --- Elasticsearch (nur lesend) ---
    es_url: str = field(default_factory=lambda: _str("ES_URL", "http://elasticsearch:9200"))
    es_indices: list = field(default_factory=lambda: _list("ES_INDICES", "rookhub-logs-*,crawler-logs-*"))
    es_api_key: "str | None" = field(default_factory=lambda: _str("ES_API_KEY"))
    es_user: "str | None" = field(default_factory=lambda: _str("ES_USER"))
    es_pass: "str | None" = field(default_factory=lambda: _str("ES_PASSWORD"))
    timestamp_field: str = field(default_factory=lambda: _str("ES_TIMESTAMP_FIELD", "@timestamp"))
    level_field: str = field(default_factory=lambda: _str("ES_LEVEL_FIELD", "level.keyword"))
    message_field: str = field(default_factory=lambda: _str("ES_MESSAGE_FIELD", "messageTemplate.keyword"))
    error_levels: list = field(default_factory=lambda: _list("ES_ERROR_LEVELS", "Error,Fatal"))
    warn_levels: list = field(default_factory=lambda: _list("ES_WARN_LEVELS", "Warning"))
    # Alerts zur Kibana-Historie zurück nach ES schreiben:
    index_alerts: bool = field(default_factory=lambda: _bool("ES_INDEX_ALERTS", True))
    alert_index_prefix: str = field(default_factory=lambda: _str("ES_ALERT_INDEX_PREFIX", "log-watcher-alerts"))

    # --- Fenster / Intervall ---
    window_hours: float = field(default_factory=lambda: _float("WINDOW_HOURS", 6.0))
    # Eigenes (größeres) Fenster nur für die Per-Index-Stille-Prüfung. Bursty/aktivitäts-
    # getriebene Low-Volume-Indizes (z.B. crawler-logs) haben normale Leerlaufphasen — ein
    # größeres Fenster verhindert Fehlalarme. 0 = Index-Stille-Prüfung aus.
    index_silent_window_hours: float = field(default_factory=lambda: _float("INDEX_SILENT_WINDOW_HOURS", 24.0))
    # Heartbeat-Überwachung: erwartete Lebenszeichen pro Dienst als "name=index=phrase"-Tripel
    # (komma-separiert). Kam in den letzten HEARTBEAT_MAX_STALENESS_MINUTES kein passender
    # Heartbeat → Signal "heartbeat_missing" (Dienst vermutlich tot). 0 min = aus.
    # phrase wird per match_phrase gegen das gerenderte Message-Feld (sample_field) geprüft.
    heartbeat_checks: list = field(default_factory=lambda: _list(
        "HEARTBEAT_CHECKS",
        "rookhub-api=rookhub-logs-*=Heartbeat: rookhub-api,"
        "rookhub-crawler=crawler-logs-*=Heartbeat: rookhub-crawler,"
        "schach-bot=rookhub-logs-*=ClientLog heartbeat_bot"))
    heartbeat_max_staleness_minutes: float = field(default_factory=lambda: _float("HEARTBEAT_MAX_STALENESS_MINUTES", 5.0))
    interval_seconds: int = field(default_factory=lambda: _int("INTERVAL_SECONDS", 6 * 3600))
    run_once: bool = field(default_factory=lambda: _bool("RUN_ONCE", False))

    # --- Cheap-Rules (billiges, deterministisches Gate vor dem LLM) ---
    min_errors: int = field(default_factory=lambda: _int("MIN_ERRORS", 5))
    error_spike_factor: float = field(default_factory=lambda: _float("ERROR_SPIKE_FACTOR", 3.0))
    # Warnungen sind lauter als Fehler -> höhere Mindestmenge, eigener Faktor, abschaltbar.
    min_warnings: int = field(default_factory=lambda: _int("MIN_WARNINGS", 20))
    warn_spike_factor: float = field(default_factory=lambda: _float("WARN_SPIKE_FACTOR", 3.0))
    alert_on_warn_spike: bool = field(default_factory=lambda: _bool("ALERT_ON_WARN_SPIKE", True))
    # Warnungs-Templates, die NICHT zum warn_spike zählen: by-design-Rauschen, das als
    # Warnung geloggt wird, aber kein Vorfall ist (z.B. piratechess softFail-Retries
    # "curl exited with code …" bei wackeligem VPN-Exit). Case-insensitiver Teilstring-
    # Match gegen das Message/Template-Feld; passende Warnungen werden vom warn_spike-
    # Count (aktuell UND Vorfenster) abgezogen. Erfordert ein korrekt aggregierbares
    # message_field (bei ECS-Logs: labels.MessageTemplate). Leer = nichts ignorieren.
    warn_spike_ignore: list = field(default_factory=lambda: _list("WARN_SPIKE_IGNORE", ""))
    alert_on_new_signatures: bool = field(default_factory=lambda: _bool("ALERT_ON_NEW_SIGNATURES", True))
    ingestion_drop_check: bool = field(default_factory=lambda: _bool("INGESTION_DROP_CHECK", True))

    # --- Security-Heuristik (systematisches API-Abklopfen durch Clients erkennen) ---
    # Wertet HTTP-Zugriffslogs (Requests mit Statuscode) des Fensters aus. Feuert „große
    # Warnungen" (high) bei Scanner-/Exploit-Pfaden, Pfad-Enumeration und Auth-Brute-Force.
    security_check: bool = field(default_factory=lambda: _bool("SECURITY_CHECK", True))
    # Mindestzahl Treffer auf verdächtige Pfade (s. security_path_tokens), ab der gewarnt wird.
    security_min_suspicious: int = field(default_factory=lambda: _int("SECURITY_MIN_SUSPICIOUS", 3))
    # Pfad-Enumeration: ab so vielen 4xx UND so vielen VERSCHIEDENEN Pfaden je Quell-IP.
    # (Hohe Pfad-Vielfalt unterscheidet einen Scan von legitimen, wiederholten 404 auf wenige Endpunkte.)
    security_scan_min_4xx: int = field(default_factory=lambda: _int("SECURITY_SCAN_MIN_4XX", 40))
    security_scan_min_paths: int = field(default_factory=lambda: _int("SECURITY_SCAN_MIN_PATHS", 15))
    # Auth-Brute-Force: ab so vielen abgelehnten Auth-Antworten (401/403) je Quell-IP.
    security_auth_fail_threshold: int = field(default_factory=lambda: _int("SECURITY_AUTH_FAIL_THRESHOLD", 25))
    # Felder der Zugriffslogs (Serilog/ECS-Defaults; alle direkt aggregierbar).
    security_status_field: str = field(default_factory=lambda: _str("SECURITY_STATUS_FIELD", "http.response.status_code"))
    security_path_field: str = field(default_factory=lambda: _str("SECURITY_PATH_FIELD", "url.path"))
    security_ip_field: str = field(default_factory=lambda: _str("SECURITY_IP_FIELD", "labels.IpAddress"))
    # Wie viele Quell-IPs (Top nach Request-Zahl) je Fenster auf Enumeration/Brute-Force geprüft werden.
    security_top_ips: int = field(default_factory=lambda: _int("SECURITY_TOP_IPS", 20))
    # Verdächtige Pfad-Substrings (case-insensitiv); leer = Default-Liste aus security.py.
    security_path_tokens: list = field(default_factory=lambda: _list("SECURITY_PATH_TOKENS", ""))

    # --- Linux-System-Heuristik (Filebeat/journald-Logs von Host + VMs) ---
    # Aktiv, sobald linux_indices gesetzt ist (z.B. [filebeat-*]). Feuert je Host bei
    # SSH-Brute-Force, OOM-Kills, Disk-/FS-Fehlern, systemd-Unit-Fehlschlägen und
    # verstummten Hosts (Filebeat/VM tot).
    linux_check: bool = field(default_factory=lambda: _bool("LINUX_CHECK", True))
    linux_indices: list = field(default_factory=lambda: _list("LINUX_INDICES", ""))
    # Fehlgeschlagene SSH-Logins je Host im Fenster, ab denen gewarnt wird.
    linux_ssh_fail_threshold: int = field(default_factory=lambda: _int("LINUX_SSH_FAIL_THRESHOLD", 20))
    # OOM-Kill- bzw. Disk-Fehler-Meldungen je Host: schon 1 ist meldenswert.
    linux_oom_threshold: int = field(default_factory=lambda: _int("LINUX_OOM_THRESHOLD", 1))
    linux_disk_error_threshold: int = field(default_factory=lambda: _int("LINUX_DISK_ERROR_THRESHOLD", 1))
    # systemd-Unit-Fehlschlag-Meldungen je Host (Restart-Schleifen erzeugen viele).
    linux_unit_fail_threshold: int = field(default_factory=lambda: _int("LINUX_UNIT_FAIL_THRESHOLD", 10))
    # Verstummte Hosts melden (im Vorfenster >= min_baseline Docs, aktuell 0).
    linux_host_silent_check: bool = field(default_factory=lambda: _bool("LINUX_HOST_SILENT_CHECK", True))
    linux_host_silent_min_baseline: int = field(default_factory=lambda: _int("LINUX_HOST_SILENT_MIN_BASELINE", 10))
    # Felder der Filebeat-Docs.
    linux_host_field: str = field(default_factory=lambda: _str("LINUX_HOST_FIELD", "host.hostname"))
    linux_message_field: str = field(default_factory=lambda: _str("LINUX_MESSAGE_FIELD", "message"))
    # Wie viele Hosts (Top nach Log-Volumen) je Fenster geprüft werden.
    linux_top_hosts: int = field(default_factory=lambda: _int("LINUX_TOP_HOSTS", 50))

    # --- LLM (Anthropic) ---
    anthropic_api_key: "str | None" = field(default_factory=lambda: _str("ANTHROPIC_API_KEY"))
    model: str = field(default_factory=lambda: _str("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"))
    max_tokens: int = field(default_factory=lambda: _int("ANTHROPIC_MAX_TOKENS", 1024))
    llm_max_calls_per_day: int = field(default_factory=lambda: _int("LLM_MAX_CALLS_PER_DAY", 50))   # Budget (11)
    llm_verdict_ttl_hours: float = field(default_factory=lambda: _float("LLM_VERDICT_TTL_HOURS", 12.0))  # Cache (12)
    include_samples: bool = field(default_factory=lambda: _bool("LLM_INCLUDE_SAMPLES", True))       # (14)
    sample_size: int = field(default_factory=lambda: _int("LLM_SAMPLE_SIZE", 5))
    sample_field: str = field(default_factory=lambda: _str("LLM_SAMPLE_FIELD", "message"))
    scrub_pii: bool = field(default_factory=lambda: _bool("SCRUB_PII", True))                        # (19)

    # --- SMTP ---
    smtp_host: "str | None" = field(default_factory=lambda: _str("SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _int("SMTP_PORT", 587))
    smtp_user: "str | None" = field(default_factory=lambda: _str("SMTP_USER"))
    smtp_pass: "str | None" = field(default_factory=lambda: _str("SMTP_PASSWORD"))
    smtp_from: "str | None" = field(default_factory=lambda: _str("SMTP_FROM"))
    smtp_to: list = field(default_factory=lambda: _list("SMTP_TO", ""))
    smtp_tls: bool = field(default_factory=lambda: _bool("SMTP_TLS", True))

    # --- Discord-Webhook (zusätzlicher/alternativer Kanal) ---
    discord_webhook_url: "str | None" = field(default_factory=lambda: _str("DISCORD_WEBHOOK_URL"))

    # --- State / Dedupe ---
    state_file: str = field(default_factory=lambda: _str("STATE_FILE", "/data/state.json"))
    cooldown_hours: float = field(default_factory=lambda: _float("COOLDOWN_HOURS", 12.0))

    # --- Health / Heartbeat / HTTP ---
    heartbeat_file: str = field(default_factory=lambda: _str("HEARTBEAT_FILE", "/data/heartbeat"))
    heartbeat_interval: int = field(default_factory=lambda: _int("HEARTBEAT_INTERVAL_SECONDS", 60))
    health_max_staleness: float = field(default_factory=lambda: _float("HEALTH_MAX_STALENESS_SECONDS", 180.0))
    http_port: int = field(default_factory=lambda: _int("HTTP_PORT", 0))  # 0 = aus (Features 15/16)

    # --- Replay (Feature 18) ---
    replay_from: "str | None" = field(default_factory=lambda: _str("REPLAY_FROM"))  # ISO, z.B. 2026-05-01T00:00:00
    replay_to: "str | None" = field(default_factory=lambda: _str("REPLAY_TO"))

    # --- Digest (Feature 4) ---
    digest_enabled: bool = field(default_factory=lambda: _bool("DIGEST_ENABLED", False))
    digest_hour: int = field(default_factory=lambda: _int("DIGEST_HOUR_UTC", 7))
    digest_period_days: int = field(default_factory=lambda: _int("DIGEST_PERIOD_DAYS", 1))

    # --- All-is-well (tägliche Wächter-Meldung) ---
    alliswell_enabled: bool = field(default_factory=lambda: _bool("ALLISWELL_ENABLED", True))
    alliswell_hour: int = field(default_factory=lambda: _int("ALLISWELL_HOUR_UTC", 8))

    # --- Sonstiges ---
    dry_run: bool = field(default_factory=lambda: _bool("DRY_RUN", False))
    notify_on_start: bool = field(default_factory=lambda: _bool("NOTIFY_ON_START", False))
    selftest: bool = field(default_factory=lambda: _bool("SELFTEST", False))

    @property
    def window_seconds(self) -> float:
        return self.window_hours * 3600

    def with_overrides(self, overrides: dict) -> "Config":
        """Setzt bekannte Felder aus einem Dict (YAML) — unbekannte Keys werden ignoriert."""
        import logging
        for k, v in (overrides or {}).items():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                logging.getLogger("log-watcher").warning("Unbekannter Config-Key ignoriert: %s", k)
        return self

    def validate(self) -> "list[str]":
        errs = []
        if not self.es_url:
            errs.append("ES_URL fehlt")
        if not self.es_indices:
            errs.append("ES_INDICES fehlt")
        if not self.dry_run:
            has_email = bool(self.smtp_host and self.smtp_from and self.smtp_to)
            has_discord = bool(self.discord_webhook_url)
            if not has_email and not has_discord:
                errs.append("Kein Alert-Kanal: SMTP_HOST/SMTP_FROM/SMTP_TO oder DISCORD_WEBHOOK_URL setzen (oder DRY_RUN=true).")
            elif self.smtp_host and not (self.smtp_from and self.smtp_to):
                errs.append("SMTP_HOST gesetzt, aber SMTP_FROM/SMTP_TO fehlen.")
        return errs


def load_targets() -> "list[Config]":
    """Eine oder mehrere Ziel-Konfigurationen (Feature 17).

    Ohne CONFIG_FILE: genau ein Target aus den ENV-Defaults.
    Mit CONFIG_FILE (YAML): `defaults` werden auf jedes Target angewandt, dann die
    target-spezifischen Keys. Jedes Target erbt zunächst die ENV-Defaults.
    """
    path = _str("CONFIG_FILE")
    if not path:
        return [Config()]
    import yaml
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    defaults = doc.get("defaults", {}) or {}
    targets = doc.get("targets") or [{}]
    out = []
    for t in targets:
        out.append(Config().with_overrides(defaults).with_overrides(t))
    return out

