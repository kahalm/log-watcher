# Kibana-Dashboard für die Alert-Historie

`log-watcher-dashboard.ndjson` enthält fertige **Saved Objects** für die vom log-watcher nach
ES geschriebenen Alerts (Index `log-watcher-alerts-*`):

- **Data View** `log-watcher alerts` (`log-watcher-alerts-*`, Zeitfeld `@timestamp`)
- **Visualisierungen:** „Alerts über Zeit (nach Severity)", „Alerts nach Severity", „Häufigste Signale"
- **Gespeicherte Suche** „log-watcher: Alerts"
- **Dashboard** „log-watcher — Alert-Historie"

## Import (Kibana 8.17)
Stack Management → **Saved Objects** → **Import** → Datei `log-watcher-dashboard.ndjson` wählen
→ „Import". Danach unter **Dashboards** „log-watcher — Alert-Historie" öffnen.

> Getestet/gebaut für **Kibana 8.17**. Selbst wenn eine Visualisierung in einer anderen Version
> zickt, importieren Data View + gespeicherte Suche zuverlässig — damit ist Discover sofort nutzbar.

## Hinweise
- Die Aggregationen nutzen `.keyword`-Unterfelder (`severity.keyword`, `signals.kind.keyword`),
  die das dynamische ES-Mapping automatisch anlegt. Erst nach dem **ersten** geschriebenen Alert
  existiert der Index/das Mapping — vorher zeigt das Dashboard „no data".
- Zum schnellen Befüllen: einmal mit einem echten Alert laufen lassen (oder `DRY_RUN=false` gegen
  Test-Daten). Im `DRY_RUN` werden keine Alerts nach ES geschrieben.

## Ändern
Nicht das NDJSON von Hand editieren — `generate_dashboard.py` anpassen und neu erzeugen:
```bash
python kibana/generate_dashboard.py
```
