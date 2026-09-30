"""schema/apply.sh --wire: ES-Antwort darf nie als Python-Quelltext laufen (Fund S5-018).

Vorher setzte wire() die Antwort von GET _index_template/<tpl> per ungequotetem Heredoc als
r'''$cur''' in ein Python-Skript ein: ein Template-Inhalt mit ''' beendete den String und führte
beliebigen Code als der aufrufende Admin aus (ES läuft ohne Auth im LAN/VPN). Zudem las das Skript
os.environ["ES"], das die Shell nur setzt, nicht exportiert — ohne 'export ES=…' brach --wire mit
KeyError ab. curl ist hier ein Double: kein Netzaufruf.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

APPLY_SH = Path(__file__).resolve().parent.parent / "schema" / "apply.sh"

_FAKE_CURL = r'''#!{python}
import json, os, sys
args = sys.argv[1:]
log = os.environ["FAKE_CURL_LOG"]
url = [a for a in args if a.startswith("http")][-1]
if "-X" in args and args[args.index("-X") + 1] == "PUT":
    body = args[args.index("--data-binary") + 1]
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({{"method": "PUT", "url": url, "body": body}}) + "\n")
    sys.exit(0)
with open(log, "a", encoding="utf-8") as f:
    f.write(json.dumps({{"method": "GET", "url": url}}) + "\n")
if url.endswith("/_index_template/missing"):
    sys.exit(22)
sys.stdout.write(os.environ["FAKE_TEMPLATE_RESPONSE"])
'''


def _evil_response(marker: Path) -> str:
    # JSON escapt einfache Anführungszeichen nicht — genau so käme es aus ES zurück.
    payload = "'''+str(__import__('os').system('touch " + str(marker) + "'))+'''"
    return json.dumps({"index_templates": [{"name": "evil", "index_template": {
        "index_patterns": ["evil-*"], "composed_of": ["ecs"],
        "_meta": {"description": payload}}}]})


def _run(tmp_path: Path, args, response: str, export_es: "str | None"):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    curl = fake_bin / "curl"
    curl.write_text(_FAKE_CURL.format(python=sys.executable), encoding="utf-8")
    curl.chmod(0o755)
    py = fake_bin / "python3"
    if not py.exists():
        py.symlink_to(sys.executable)
    log = tmp_path / "curl.log"
    env = {k: v for k, v in os.environ.items() if k != "ES"}
    env.update(PATH=f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
               FAKE_CURL_LOG=str(log), FAKE_TEMPLATE_RESPONSE=response)
    if export_es is not None:
        env["ES"] = export_es
    proc = subprocess.run(["bash", str(APPLY_SH), *args], env=env, capture_output=True,
                          text=True, timeout=60)
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return proc, calls


def test_template_content_is_never_executed(tmp_path):
    marker = tmp_path / "INJECTED"
    response = _evil_response(marker)
    proc, calls = _run(tmp_path, ["--wire", "evil"], response, export_es="http://es.test:9200")
    assert not marker.exists(), "Template-Inhalt wurde als Code ausgeführt"
    assert proc.returncode == 0, proc.stderr
    put = [c for c in calls if c["method"] == "PUT" and c["url"].endswith("/_index_template/evil")]
    assert len(put) == 1
    assert put[0]["url"] == "http://es.test:9200/_index_template/evil"
    doc = json.loads(put[0]["body"])
    assert doc["composed_of"] == ["ecs", "logs-schema"]
    # Inhalt unverändert durchgereicht (nur als Daten).
    assert doc["_meta"]["description"] == json.loads(response)["index_templates"][0]["index_template"]["_meta"]["description"]


def test_wire_works_without_exported_es(tmp_path):
    """Default-ES aus Z. 5 muss auch im Python-Teil gelten (vorher KeyError 'ES')."""
    response = json.dumps({"index_templates": [{"name": "app", "index_template": {
        "index_patterns": ["app-*"], "composed_of": ["logs-schema"]}}]})
    proc, calls = _run(tmp_path, ["--wire", "app"], response, export_es=None)
    assert proc.returncode == 0, proc.stderr
    put = [c for c in calls if c["method"] == "PUT" and "/_index_template/" in c["url"]]
    assert [c["url"] for c in put] == ["http://10.24.13.6:9200/_index_template/app"]
    assert json.loads(put[0]["body"])["composed_of"] == ["logs-schema"]   # nicht doppelt
    assert "app: composed_of=['logs-schema']" in proc.stdout


def test_missing_template_is_skipped(tmp_path):
    proc, calls = _run(tmp_path, ["--wire", "missing"], "", export_es="http://es.test:9200")
    assert proc.returncode == 0, proc.stderr
    assert "missing: nicht vorhanden, skip" in proc.stdout
    assert not [c for c in calls if c["method"] == "PUT" and "/_index_template/" in c["url"]]


@pytest.mark.parametrize("step", ["_ingest/pipeline/logs-schema-normalize", "_component_template/logs-schema"])
def test_pipeline_and_component_template_are_put_from_the_repo_files(tmp_path, step):
    proc, calls = _run(tmp_path, [], "", export_es="http://es.test:9200")
    assert proc.returncode == 0, proc.stderr
    put = [c for c in calls if c["method"] == "PUT" and c["url"] == f"http://es.test:9200/{step}"]
    assert len(put) == 1 and put[0]["body"].startswith("@")
