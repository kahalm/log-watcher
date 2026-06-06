from datetime import datetime, timezone
from unittest.mock import patch, call

from watcher.config import Config
from watcher.main import _maybe_alliswell, _any_recent_alert


def _now(hour=8):
    return datetime(2026, 6, 6, hour, 0, 0, tzinfo=timezone.utc)


def _cfg(enabled=True, hour=8, webhook="https://discord.example/webhook"):
    cfg = Config()
    cfg.alliswell_enabled = enabled
    cfg.alliswell_hour = hour
    cfg.discord_webhook_url = webhook
    cfg.state_file = "/tmp/test_alliswell_state.json"
    cfg.dry_run = False
    cfg.name = "test"
    return cfg


def test_alliswell_posts_when_all_clear():
    glob = _cfg()
    st = {}
    with patch("watcher.main.discord_notify.post_text") as mock_post, \
         patch("watcher.main.state.save_state"):
        _maybe_alliswell(glob, [], st, _now(8))
    mock_post.assert_called_once()
    assert "all's well" in mock_post.call_args[0][1].lower() or "well" in mock_post.call_args[0][1]
    assert st["last_alliswell"] == "2026-06-06"


def test_alliswell_skips_before_hour():
    glob = _cfg(hour=8)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as mock_post:
        _maybe_alliswell(glob, [], st, _now(7))
    mock_post.assert_not_called()
    assert "last_alliswell" not in st


def test_alliswell_skips_if_already_sent_today():
    glob = _cfg()
    st = {"last_alliswell": "2026-06-06"}
    with patch("watcher.main.discord_notify.post_text") as mock_post:
        _maybe_alliswell(glob, [], st, _now(9))
    mock_post.assert_not_called()


def test_alliswell_skips_if_recent_alert():
    glob = _cfg()
    now = _now(8)
    recent_ts = now.timestamp() - 3600  # 1h ago
    targets = [glob]
    st = {"targets": {"test": {"alerts": {"abc123": recent_ts}}}}
    with patch("watcher.main.discord_notify.post_text") as mock_post:
        _maybe_alliswell(glob, targets, st, now)
    mock_post.assert_not_called()


def test_alliswell_posts_if_alert_older_than_24h():
    glob = _cfg()
    now = _now(8)
    old_ts = now.timestamp() - 86401  # 24h+1s ago
    targets = [glob]
    st = {"targets": {"test": {"alerts": {"abc123": old_ts}}}}
    with patch("watcher.main.discord_notify.post_text") as mock_post, \
         patch("watcher.main.state.save_state"):
        _maybe_alliswell(glob, targets, st, now)
    mock_post.assert_called_once()


def test_alliswell_disabled():
    glob = _cfg(enabled=False)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as mock_post:
        _maybe_alliswell(glob, [], st, _now(8))
    mock_post.assert_not_called()


def test_alliswell_no_webhook():
    glob = _cfg(webhook=None)
    st = {}
    with patch("watcher.main.discord_notify.post_text") as mock_post:
        _maybe_alliswell(glob, [], st, _now(8))
    mock_post.assert_not_called()


def test_any_recent_alert_true():
    cfg = Config()
    cfg.name = "t"
    now_ts = _now(8).timestamp()
    st = {"targets": {"t": {"alerts": {"x": now_ts - 100}}}}
    assert _any_recent_alert(st, [cfg], now_ts - 86400) is True


def test_any_recent_alert_false():
    cfg = Config()
    cfg.name = "t"
    now_ts = _now(8).timestamp()
    st = {"targets": {"t": {"alerts": {"x": now_ts - 90000}}}}
    assert _any_recent_alert(st, [cfg], now_ts - 86400) is False
