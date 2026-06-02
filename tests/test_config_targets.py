import textwrap

from watcher.config import load_targets


def test_single_target_without_config_file(monkeypatch):
    monkeypatch.delenv("CONFIG_FILE", raising=False)
    targets = load_targets()
    assert len(targets) == 1
    assert targets[0].name == "default"


def test_multi_target_yaml(tmp_path, monkeypatch):
    p = tmp_path / "cfg.yaml"
    p.write_text(textwrap.dedent("""
        defaults:
          window_hours: 3
          cooldown_hours: 6
        targets:
          - name: rookhub
            es_indices: [rookhub-logs-*, crawler-logs-*]
          - name: lern
            es_indices: [lernkompass-logs-*]
            min_errors: 10
    """))
    monkeypatch.setenv("CONFIG_FILE", str(p))
    targets = load_targets()
    assert [c.name for c in targets] == ["rookhub", "lern"]
    # Defaults auf alle angewandt:
    assert targets[0].window_hours == 3 and targets[0].cooldown_hours == 6
    assert targets[0].es_indices == ["rookhub-logs-*", "crawler-logs-*"]
    # Target erbt Default (window_hours=3), eigener Override greift:
    assert targets[1].window_hours == 3 and targets[1].min_errors == 10
    assert targets[1].es_indices == ["lernkompass-logs-*"]


def test_per_target_different_es_instances(tmp_path, monkeypatch):
    p = tmp_path / "cfg.yaml"
    p.write_text(textwrap.dedent("""
        targets:
          - name: a
            es_url: http://es-a:9200
            es_indices: [a-*]
          - name: b
            es_url: http://es-b:9200
            es_api_key: KEY-B
            es_indices: [b-*]
          - name: c
            es_url: https://es-c:9200
            es_user: u
            es_pass: p
            es_indices: [c-*]
    """))
    monkeypatch.setenv("CONFIG_FILE", str(p))
    t = load_targets()
    assert [c.es_url for c in t] == ["http://es-a:9200", "http://es-b:9200", "https://es-c:9200"]
    assert t[0].es_api_key is None
    assert t[1].es_api_key == "KEY-B"
    assert t[2].es_user == "u" and t[2].es_pass == "p"


def test_unknown_key_ignored(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text("targets:\n  - name: x\n    bogus_key: 1\n")
    monkeypatch.setenv("CONFIG_FILE", str(p))
    targets = load_targets()
    assert targets[0].name == "x"  # unbekannter Key ignoriert, kein Crash
