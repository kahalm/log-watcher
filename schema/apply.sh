#!/usr/bin/env bash
# Spielt das zentrale Logging-Schema ins Elasticsearch und haengt es an die App-Templates.
# Idempotent. ES-URL via $ES (Default unten).
set -euo pipefail
ES="${ES:-http://10.24.13.6:9200}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== 1) Ingest-Pipeline logs-schema-normalize =="
curl -fsS -X PUT "$ES/_ingest/pipeline/logs-schema-normalize" \
  -H 'Content-Type: application/json' --data-binary "@$DIR/logs-schema-normalize.pipeline.json" >/dev/null
echo "   ok"

echo "== 2) Component-Template logs-schema =="
curl -fsS -X PUT "$ES/_component_template/logs-schema" \
  -H 'Content-Type: application/json' --data-binary "@$DIR/logs-schema.component-template.json" >/dev/null
echo "   ok"

# 3) Component-Template in die App-Index-Templates einhaengen (composed_of).
#    Nur fuer Data-Stream-Templates der Elastic.Serilog.Sinks-/ECS-Apps gedacht.
#    Argumente: Liste von Index-Template-Namen.
#    Python-Teil als QUOTIERTES Heredoc: die ES-Antwort kommt per stdin, nie als Quelltext (ein
#    ''' im Template-Inhalt haette sonst beliebigen Code ausgefuehrt). ES geht als Argument mit,
#    die Shell-Variable ist nicht exportiert.
WIRE_PY=$(cat <<'PY'
import json,sys,subprocess
tpl=sys.argv[1]; es=sys.argv[2]
doc=json.load(sys.stdin)["index_templates"][0]["index_template"]
comp=doc.get("composed_of",[]) or []
if "logs-schema" not in comp:
    comp.append("logs-schema")
doc["composed_of"]=comp
body=json.dumps(doc)
subprocess.run(["curl","-fsS","-X","PUT",f"{es}/_index_template/{tpl}",
    "-H","Content-Type: application/json","--data-binary",body],check=True,stdout=subprocess.DEVNULL)
print(f"   {tpl}: composed_of={comp}")
PY
)
wire () {
  for tpl in "$@"; do
    cur=$(curl -fsS "$ES/_index_template/$tpl" 2>/dev/null) || { echo "   $tpl: nicht vorhanden, skip"; continue; }
    printf '%s' "$cur" | python3 -c "$WIRE_PY" "$tpl" "$ES"
  done
}

if [ "${1:-}" = "--wire" ]; then
  shift
  echo "== 3) An App-Templates haengen =="
  wire "$@"
fi
echo "Fertig."
