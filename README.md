# log-watcher

Wächter-Container, der periodisch (Default **alle 6 h**) die Elasticsearch-Logs prüft und bei
echten Auffälligkeiten eine **E-Mail** schickt. **Hybrid-Ansatz:** ein billiges, deterministisches
Regel-Gate entscheidet zuerst, ob überhaupt etwas Verdächtiges vorliegt — nur dann wird der
**Anthropic-LLM** zur Beurteilung + Klartext-Zusammenfassung bemüht. Das hält Kosten und
False-Positives niedrig.

```
        alle X h
           │
           ▼
   ┌──────────────────┐   Aggregate (size=0)   ┌──────────────┐
   │  ES-Aggregat-Query├───────────────────────►│ Elasticsearch│
   │  Fenster+Baseline │                        └──────────────┘
   └────────┬─────────┘
            ▼
   ┌──────────────────┐  kein Signal → fertig (kein LLM, keine Mail)
   │  Regel-Gate       │
   │  (Spike/Fatal/    │  Signal(e)
   │   neue Sig./Stop) │────────────┐
   └──────────────────┘            ▼
                          ┌──────────────────┐  anomalous=false → fertig
                          │  LLM-Beurteilung  │
                          │  (Anthropic,      │  anomalous=true
                          │  structured)      │────────────┐
                          └──────────────────┘            ▼
                                                ┌──────────────────┐
                                                │ Dedupe/Cooldown   │ neu → E-Mail (SMTP)
                                                └──────────────────┘
```

## Warum hybrid (und nicht „LLM liest alle Logs")
- **Kosten/Token:** Es werden nur **Aggregate** (Zähler je Level, Top-Message-Templates, Doc-Volumen)
  des aktuellen Fensters und des Vorfensters an den LLM gegeben — niemals Rohlogs.
- **Wenig False-Positives:** Der LLM läuft nur, wenn das Regel-Gate (Spike/Fatal/neue Signatur/
  Ingestion-Stopp) anschlägt — und urteilt dann konservativ.
- **Privacy:** Nur Aggregate + Message-Templates verlassen den Host, keine Rohlogs/PII.
- **Degradiert sauber:** Ohne `ANTHROPIC_API_KEY` meldet der Watcher rein **regelbasiert**.

## Signale (Regel-Gate)
| Signal | Schwere | Bedeutung |
|--------|---------|-----------|
| `error_spike` | medium | `Error/Fatal`-Anzahl ≥ `MIN_ERRORS` **und** ≥ `ERROR_SPIKE_FACTOR` × Vorfenster |
| `warn_spike` | low | `Warning`-Anzahl ≥ `MIN_WARNINGS` **und** ≥ `WARN_SPIKE_FACTOR` × Vorfenster (lauter → höhere Schwelle, via `ALERT_ON_WARN_SPIKE` abschaltbar) |
| `fatal` | high | mind. ein `Fatal`/`Critical`-Eintrag |
| `new_errors` | medium | per Fingerprint gruppierte Fehler, die *erstmalig* (nicht nur seit Vorfenster) auftreten |
| `ingestion_stopped` | high | gesamt 0 Logs → Pipeline evtl. tot |
| `index_silent` | high | ein Index verstummt, während andere weiterloggen (Teil-Ausfall) |

Die Alarm-Mail wird als **HTML** (mit farbigen Severity-Badges + Level-Tabelle Aktuell-vs-Baseline) **plus Plaintext-Fallback** verschickt.

**Kanäle:** E-Mail (SMTP) und/oder **Discord** (`DISCORD_WEBHOOK_URL` → farbiges Embed). Mindestens
ein Kanal muss konfiguriert sein (außer `DRY_RUN=true`); Discord reicht auch allein. Alerts, Digest
und die optionale Start-Meldung gehen an alle konfigurierten Kanäle.

### Alert-Historie in Kibana
Jeder ausgelöste Alarm wird zusätzlich als Dokument nach ES geschrieben (Index
`log-watcher-alerts-YYYY.MM`, via `ES_INDEX_ALERTS`/`ES_ALERT_INDEX_PREFIX`), sodass du in
Kibana eine durchsuchbare Historie + Dashboards bauen kannst. Felder u.a.: `@timestamp`,
`severity`, `summary`, `suspected_cause`, `recommended_action`, `llm_used`, `emailed`,
`signals[]`, `window.levels`, `window.top_error_messages[] {message,count}`, `baseline`.
Beim Start legt der Watcher ein Index-Template mit `number_of_replicas=0` an (Single-Node → green).
Top-Fehler-Messages werden als **Array** indiziert (nicht als Objekt mit Message-Text als Feldname),
um Mapping-Explosionen zu vermeiden.

Ein fertiges **Kibana-Dashboard** (Data View + Visualisierungen + Suche + Dashboard) liegt unter
[`kibana/log-watcher-dashboard.ndjson`](kibana/) — importierbar via *Stack Management → Saved Objects → Import* (Kibana 8.17).

## Konfiguration (ENV)
Siehe `.env.example`. Wichtigste Werte:

| Variable | Default | Zweck |
|----------|---------|-------|
| `ES_URL` | `http://elasticsearch:9200` | Elasticsearch |
| `ES_INDICES` | `rookhub-logs-*,crawler-logs-*` | überwachte Index-Pattern |
| `WINDOW_HOURS` / `INTERVAL_SECONDS` | `6` / `21600` | Fenstergröße / Prüfintervall |
| `INDEX_SILENT_WINDOW_HOURS` | `24` | eigenes (größeres) Fenster nur für die Per-Index-Stille-Prüfung; vermeidet Fehlalarme bei bursty Low-Volume-Indizes (z.B. crawler-logs). `0` = aus |
| `MIN_ERRORS` / `ERROR_SPIKE_FACTOR` | `5` / `3.0` | Spike-Schwellen |
| `ANTHROPIC_API_KEY` | – | optional; ohne → rein regelbasiert |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5-20251001` | günstiges Monitoring-Modell |
| `SMTP_*` | – | Mailversand (Pflicht außer `DRY_RUN=true`) |
| `COOLDOWN_HOURS` | `12` | gleiche Auffälligkeit nicht öfter melden |
| `DRY_RUN` | `false` | keine Mail, nur loggen (zum Einrichten) |
| `SELFTEST` | `false` | einmaliger Konfig-Check (Probe + Trockenlauf), dann beenden |
| `NOTIFY_ON_START` | `false` | einmalige „gestartet"-Mail (Verkabelung testen) |
| `HEARTBEAT_INTERVAL_SECONDS` / `HEALTH_MAX_STALENESS_SECONDS` | `60` / `180` | Docker-Healthcheck |

> Hinweis rookhub: Der ES läuft mit `xpack.security.enabled=false` → **keine** `ES_API_KEY`
> nötig. Für gesicherte Cluster `ES_API_KEY` **oder** `ES_USER`/`ES_PASSWORD` setzen.

## Lokal testen
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
PYTHONPATH=src pytest -q

# Konfig-Check gegen einen echten ES (Probe + Trockenlauf, keine Mail):
ES_URL=http://localhost:9200 SELFTEST=true PYTHONPATH=src python -m watcher.main
```

## Betrieb
- **Robustheit:** Stimmt ein Feldname nicht (z.B. `ES_MESSAGE_FIELD`), reduziert sich die
  Aggregation automatisch (volle Aggregation → nur Levels → nur Total) statt auszufallen;
  beim Start läuft eine **Probe**, die fehlende Logs/Felder sofort als WARN meldet.
- **Healthcheck:** Der Loop schreibt regelmäßig einen Heartbeat; der Docker-Healthcheck
  (`healthcheck.py`) meldet `unhealthy`, wenn der Heartbeat veraltet ist.
- **Sauberes Herunterfahren:** `SIGTERM`/`SIGINT` brechen den langen Schlaf sofort ab
  (kein Warten bis zum nächsten Intervall).
- **Kostentransparenz:** Bei LLM-Aufrufen wird der Token-Verbrauch geloggt.

## CI / Deploy (tag-gated, wie die übrigen Repos)
- Push auf `main` → Build `:dev`. Git-Tag `vX.Y.Z` → Build `:latest` + `:X.Y.Z` (Watchtower zieht `:latest`).
- Tests laufen via GitHub Actions (`.github/workflows/test.yml`).
- Image: `ghcr.io/kahalm/log-watcher`.

## Deploy (Docker, Homelab — turnkey)
**Eigenständiger Stack** (eigenes Bridge-Netz, kein gemeinsames Netz mit anderen Stacks). ES wird
über den **Host** erreicht: der ES-Container publisht `:9200`, und `compose.yaml` mappt
`host.docker.internal` (host-gateway) → `ES_URL=http://host.docker.internal:9200`.

Eine fertige `.env` liegt bei (`HTTP_PORT=8080`, **`DRY_RUN=true`** für sicheren Start). Nur einen **Alert-Kanal** eintragen:
```ini
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/…   # und/oder SMTP_*
# ANTHROPIC_API_KEY=sk-ant-…   # optional; ohne -> rein regelbasiert
```
1. **Beobachten (kein Versand):** so wie geliefert starten und Logs prüfen:
   ```bash
   docker compose up -d && docker compose logs -f
   ```
2. **Scharf schalten:** in `.env` `DRY_RUN=false` → `docker compose up -d`.

`compose.yaml` zieht das CI-gebaute Image `ghcr.io/kahalm/log-watcher:latest` (kein lokaler Build nötig;
für lokal die `build:`-Zeile einkommentieren). **Tag-gated wie die übrigen Repos:** Tag `vX.Y.Z` → CI baut
`:latest` → Watchtower deployt. Health/Metrics: `:8080/healthz`, `/status`, `/metrics`.

## Weitere Features
- **Fingerprinting (8):** variable Teile (Zahlen/GUIDs/Hex/Quotes) werden normalisiert, sodass
  „timeout 30s/45s" als eine Signatur zählen.
- **Persistente First-seen (9):** eine Signatur gilt nur beim allerersten Auftreten als „neu".
- **Per-Index-Stille (10)** und **saisonale Baseline (7):** `BASELINE_MODE=previous|yesterday|last_week`.
- **LLM-Budget (11)** `LLM_MAX_CALLS_PER_DAY` + **Verdict-Cache (12)** `LLM_VERDICT_TTL_HOURS` → spart Calls.
- **Sample-Logs (14):** einige *redigierte* Beispielzeilen gehen an den LLM für die Ursachenanalyse.
- **PII-Scrubbing (19):** `SCRUB_PII` entfernt E-Mails/IPs/Tokens vor LLM/Mail/ES.
- **HTTP (15/16):** `HTTP_PORT>0` → `/healthz`, `/status` (JSON), `/metrics` (Prometheus).
- **Multi-Target (17):** `CONFIG_FILE=…yaml` überwacht mehrere Index-Gruppen **und mehrere
  Elasticsearch-Instanzen** aus EINEM Container — jedes Target hat eigenes `es_url` (+ `es_api_key`
  ODER `es_user`/`es_pass`); Reads/Alert-Index/Digest laufen je Target gegen dessen ES. State/
  Alerts/Cooldown sind pro Target getrennt (siehe `config.example.yaml`).
- **Replay (18):** `REPLAY_FROM`/`REPLAY_TO` testet die Regeln über einen vergangenen Zeitraum (nur Log-Ausgabe).
- **Digest (4):** `DIGEST_ENABLED=true` schickt eine periodische Zusammenfassung (`DIGEST_HOUR_UTC`, `DIGEST_PERIOD_DAYS`).

## Erweiterbar
Generisch genug, um **beliebige** Stacks zu überwachen — `ES_INDICES` (und ggf. `ES_LEVEL_FIELD`/
`ES_MESSAGE_FIELD`) anpassen, oder mehrere Targets per `CONFIG_FILE`.
