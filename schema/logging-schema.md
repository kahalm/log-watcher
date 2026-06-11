# Zentrales Logging-Schema (ECS, v1)

Verbindliches Schema für **alle** Anwendungen, die nach dem zentralen Elasticsearch
(`10.24.13.6:9200`) loggen. Ziel: einheitliche Felder über alle Apps hinweg, damit
Discover/Dashboards/log-watcher ohne Doppel-Spalten und Sonderfälle funktionieren.

Es ist ECS-basiert (Elastic Common Schema). Apps **sollen** ECS direkt emittieren;
wer es (noch) nicht tut, wird beim Ingest automatisch normalisiert (siehe unten).

## Kanonische Felder

| Feld | Typ | Pflicht | Bedeutung |
|------|-----|---------|-----------|
| `@timestamp` | date | ✅ | Ereigniszeit (UTC, ISO-8601) |
| `log.level` | keyword | ✅ | Level: `Verbose` `Debug` `Information` `Warning` `Error` `Fatal` (Serilog-Schreibweise, großgeschrieben) |
| `message` | text | ✅ | Gerenderte Log-Nachricht |
| `service.name` | keyword | ✅ | App-Name, z.B. `Lernkompass.Api`, `RookHub.Api`, `schach-bot` |
| `service.environment` | keyword | ⭕ | `prod` / `dev` |
| `user.name` | keyword | ⭕ | Angemeldeter Benutzer |
| `user.id` | keyword | ⭕ | Benutzer-ID |
| `log.logger` | keyword | ⭕ | Logger/SourceContext |
| `host.name` | keyword | ⭕ | Host/Maschine |
| `trace.id`, `span.id` | keyword | ⭕ | Tracing-Korrelation |
| `tags` | keyword[] | ⭕ | Frei belegbare Marker (ECS) — siehe Tag-Katalog unten |
| `labels.*` | keyword | ⭕ | App-spezifische Zusatzfelder (frei) |

## Tag-Katalog

Die Ingest-Pipeline setzt diese `tags` **automatisch** anhand struktureller Signale —
Dienste müssen nichts tun, auch künftige sind abgedeckt. Ein Log kann mehrere Tags tragen
(z.B. ein 401-Request → `request` + `auth`).

| Tag | gesetzt wenn | Zweck |
|-----|--------------|-------|
| `heartbeat` | Message enthält `Heartbeat:` oder `heartbeat_bot` | Keepalive-Rauschen ausblenden |
| `healthcheck` | `url.path` endet auf `/health` `/healthz` `/livez` `/readyz` | Health-Probe-Rauschen ausblenden |
| `request` | `http.response.status_code` vorhanden | HTTP-Zugriffslogs von App-Logs trennen |
| `auth` | Status 401/403 **oder** Message enthält `Anmeldung`/`Unautorisiert`/`Unauthorized` | Anmelde-/Auth-Events (Security) |
| `startup` | `log.logger` = `Microsoft.Hosting.Lifetime` oder `…EntityFrameworkCore.Migrations` | Lifecycle/Boot |
| `db` | `log.logger` beginnt mit `Microsoft.EntityFrameworkCore` (ohne Migrations) | DB-/EF-Logs |

Damit auch **historische** rohe Logs greifen, normalisiert die Pipeline die Request-Synonyme
`fields.RequestPath → url.path`, `fields.RequestMethod → http.request.method`,
`fields.StatusCode → http.response.status_code`.

Neue Dienste mit abweichenden Mustern setzen den Tag selbst (`tags: ["…"]`) oder nehmen ihr
Muster in die Pipeline-Bedingung auf.

**Discover-Default** „Alle Logs (ohne Heartbeat)" filtert `not tags: (heartbeat or healthcheck)`.
Die übrigen Tags sind Filter-Dimensionen (z.B. nur `tags: auth` für Security-Sicht).

> **Level-Werte bleiben großgeschrieben** (`Error`, `Fatal`, …), passend zur
> log-watcher-Konfig (`ES_ERROR_LEVELS=Error,Fatal`). Nicht auf ECS-Kleinschreibung umstellen.

## Synonym-Map (automatische Normalisierung)

Die Ingest-Pipeline `logs-schema-normalize` benennt bekannte Alt-/Synonym-Felder
auf die kanonischen Felder um (idempotent, `ignore_missing`):

| Quelle (Alt/Synonym) | → Kanonisch |
|----------------------|-------------|
| `level` | `log.level` |
| `labels.Username`, `fields.UserName` | `user.name` |
| `fields.UserId` | `user.id` |
| `fields.SourceContext` | `log.logger` |
| `fields.MachineName` | `host.name` |
| `labels.Application` / `fields.Application` (falls `service.name` leer) | `service.name` |
| `labels.Environment` (falls leer) | `service.environment` |

Fehlt `log.level`, wird `Information` gesetzt; fehlt `service.name`, wird `unknown` gesetzt.
Jedes normalisierte Dokument erhält `labels.schema_version: "1"`. Fehler in der Pipeline
landen in `labels.schema_error` und verwerfen das Dokument **nicht**.

## So bindet eine neue App das Schema ein

1. **Bevorzugt:** ECS direkt emittieren.
   - .NET: `Elastic.Serilog.Sinks` (statt `Serilog.Sinks.Elasticsearch`), in einen Data-Stream `<app>-logs`.
   - Python u.a.: ECS-Felder schreiben (`@timestamp`, `log.level`, `message`, `service.name`, …).
2. **Pipeline anhängen:** Das Index-/Data-Stream-Template der App um das Component-Template
   erweitern, damit die Normalisierung greift:
   ```
   PUT _index_template/<app>-logs   { ... "composed_of": ["logs-schema"] ... }
   ```
   (Die `Elastic.Serilog.Sinks`-Apps erzeugen automatisch ein Template `<stream>-generic-*`;
   dort `logs-schema` in `composed_of` ergänzen — siehe `apply.sh`.)
3. **Verifizieren:** `POST _ingest/pipeline/logs-schema-normalize/_simulate` mit einem Beispiel-Doc.

## Dateien in diesem Verzeichnis

- `logging-schema.md` — dieses Dokument (Quelle der Wahrheit für Menschen).
- `logs-schema-normalize.pipeline.json` — die Ingest-Pipeline.
- `logs-schema.component-template.json` — Component-Template (Mappings + `default_pipeline`).
- `apply.sh` — spielt Pipeline + Component-Template ins ES und hängt sie an die App-Templates.

## Übergang / Altdaten

Die Pipeline normalisiert nur **neue** Writes. Historische Indizes behalten ihr altes
Schema, bis sie auslaufen — oder per `_reindex` mit `pipeline=logs-schema-normalize`
nachgezogen werden.
