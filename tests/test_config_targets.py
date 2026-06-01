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


def test_unknown_key_ignored(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    p.write_text("targets:\n  - name: x\n    bogus_key: 1\n")
    monkeypatch.setenv("CONFIG_FILE", str(p))
    targets = load_targets()
    assert targets[0].name == "x"  # unbekannter Key ignoriert, kein Crash
