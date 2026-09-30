"""config.example.yaml: Beispiel-Heartbeat für piratechess (Begleitteil I2-012).

piratechess hatte als einziger .NET-Dienst keinen Heartbeat; sein Target lief mit
heartbeat_checks: [] und ausgeschalteter Stille-Prüfung — ein hängender Dienst fiel erst beim
nächsten Nutzer-Import auf. piratechess bekommt den HeartbeatService (Template
"Heartbeat: {HeartbeatService} …", HeartbeatService = piratechess-api); die Beispiel-Konfig zeigt
den passenden Check auskommentiert. Der Test hält das Beispiel ladbar und auf der strukturierten
Form "name=index" (kein fälschbarer Freitext).
"""
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from watcher.config import load_targets
from watcher.main import _heartbeat_counts

EXAMPLE = Path(__file__).resolve().parent.parent / "config.example.yaml"
_COMMENTED = re.compile(r"^(\s*)#\s*(heartbeat_checks:\s*\[.*\])\s*$", re.MULTILINE)


class _RecordingES:
    def __init__(self):
        self.queries = []

    def count(self, index, query):
        self.queries.append((index, query))
        return 0


def _piratechess(targets):
    return next(t for t in targets if t.name == "piratechess")


def test_example_loads_and_piratechess_has_no_heartbeat_by_default(monkeypatch):
    monkeypatch.setenv("CONFIG_FILE", str(EXAMPLE))
    targets = load_targets()
    assert _piratechess(targets).heartbeat_checks == []


def test_commented_piratechess_heartbeat_uses_the_structured_field(tmp_path, monkeypatch):
    text = EXAMPLE.read_text(encoding="utf-8")
    examples = _COMMENTED.findall(text)
    assert len(examples) == 1, "genau ein auskommentiertes heartbeat_checks-Beispiel erwartet"
    indent, line = examples[0]
    assert yaml.safe_load(line) == {"heartbeat_checks": ["piratechess-api=piratechess-logs-*"]}

    # Einkommentieren = die leere Liste direkt darunter ersetzen.
    active = text.replace(f"{indent}# {line}\n{indent}heartbeat_checks: []\n", f"{indent}{line}\n", 1)
    assert active != text, "Beispiel steht nicht direkt über heartbeat_checks: []"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(active, encoding="utf-8")
    monkeypatch.setenv("CONFIG_FILE", str(cfg_file))
    monkeypatch.delenv("HEARTBEAT_SERVICE_FIELD", raising=False)
    cfg = _piratechess(load_targets())
    assert cfg.heartbeat_checks == ["piratechess-api=piratechess-logs-*"]

    cfg.heartbeat_max_staleness_minutes = 5
    es = _RecordingES()
    counts = _heartbeat_counts(cfg, es, datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc))
    assert counts == {"piratechess-api": 0}
    index, query = es.queries[0]
    assert index == "piratechess-logs-*"
    assert query["bool"]["must"][0] == {"term": {"labels.HeartbeatService": "piratechess-api"}}


def test_example_heartbeat_checks_never_use_the_free_text_form():
    """Altform name=index=phrase ist fälschbar (S5-008) — die Beispiel-Konfig zeigt sie nicht."""
    text = EXAMPLE.read_text(encoding="utf-8")
    for _, line in _COMMENTED.findall(text):
        for spec in yaml.safe_load(line)["heartbeat_checks"]:
            assert spec.count("=") == 1, spec
