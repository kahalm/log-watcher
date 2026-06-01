from watcher import health


def test_write_read_roundtrip(tmp_path):
    p = str(tmp_path / "hb")
    health.write_heartbeat(p, now=1000.0)
    assert health.read_heartbeat(p) == 1000.0


def test_is_fresh(tmp_path):
    p = str(tmp_path / "hb")
    health.write_heartbeat(p, now=1000.0)
    assert health.is_fresh(p, max_stale_seconds=180, now=1100.0)        # 100s alt -> frisch
    assert not health.is_fresh(p, max_stale_seconds=180, now=1300.0)    # 300s alt -> stale


def test_missing_heartbeat_is_not_fresh(tmp_path):
    assert health.read_heartbeat(str(tmp_path / "nope")) is None
    assert not health.is_fresh(str(tmp_path / "nope"), 180, now=1.0)
