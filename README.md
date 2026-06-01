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
| `new_errors` | medium | Fehler-Message-Templates, die im Vorfenster nicht vorkamen |
| `ingestion_stopped` | high | vorher Logs, jetzt 0 → Pipeline evtl. tot |

Die Alarm-Mail wird als **HTML** (mit farbigen Severity-Badges + Level-Tabelle Aktuell-vs-Baseline) **plus Plaintext-Fallback** verschickt.

### Alert-Historie in Kibana
Jeder ausgelöste Alarm wird zusätzlich als Dokument nach ES geschrieben (Index
`log-watcher-alerts-YYYY.MM`, via `ES_INDEX_ALERTS`/`ES_ALERT_INDEX_PREFIX`), sodass du in
Kibana eine durchsuchbare Historie + Dashboards bauen kannst. Felder u.a.: `@timestamp`,
`severity`, `summary`, `suspected_cause`, `recommended_action`, `llm_used`, `emailed`,
`signals[]`, `window.levels`, `window.top_error_messages[] {message,count}`, `baseline`.
Beim Start legt der Watcher ein Index-Template mit `number_of_replicas=0` an (Single-Node → green).
Top-Fehler-Messages werden als **Array** indiziert (nicht als Objekt mit Message-Text als Feldname),
um Mapping-Explosionen zu vermeiden.

## Konfiguration (ENV)
Siehe `.env.example`. Wichtigste Werte:

| Variable | Default | Zweck |
|----------|---------|-------|
| `ES_URL` | `http://elasticsearch:9200` | Elasticsearch |
| `ES_INDICES` | `rookhub-logs-*,crawler-logs-*` | überwachte Index-Pattern |
| `WINDOW_HOURS` / `INTERVAL_SECONDS` | `6` / `21600` | Fenstergröße / Prüfintervall |
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

## Deploy (Docker)
1. `cp .env.example .env` und ausfüllen (SMTP, ggf. ANTHROPIC_API_KEY).
2. Netz festlegen, in dem ES erreichbar ist:
   ```bash
   docker network ls | grep rookhub      # Name ermitteln
   echo "MONITORED_NETWORK=<name>" >> .env
   ```
   *Alternativ:* `ES_URL=http://<host>:9200` (gepublishter Port) setzen und den `networks`-Block
   in `compose.yaml` entfernen.
3. Start:
   ```bash
   docker compose up -d --build
   docker compose logs -f
   ```

## Erweiterbar
Generisch genug, um später **beliebige** Stacks zu überwachen — einfach `ES_INDICES`
(und ggf. die Feld-Namen `ES_LEVEL_FIELD`/`ES_MESSAGE_FIELD`) anpassen.
