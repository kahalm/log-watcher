"""YAML-Skalare in with_overrides je Feldtyp prüfen/koerzieren (S5-020).

Vorher wurden Bool/Zahl aus der YAML roh gesetzt: `dry_run: "false"` (String) ist truthy und
schaltete still den Trockenlauf ein — validate() übersprang dann sogar die Kanalprüfung, und
kein Alarm ging je raus. Jetzt wie bei ENV (_bool/_int/_float) koerziert, Unlesbares wird ein
Typfehler und bricht den Start ab (validate()).
"""
import pytest

from watcher.config import Config


def _cfg(**over):
    return Config().with_overrides(over)


@pytest.mark.parametrize("raw, expected", [
    ("false", False), ("False", False), ("no", False), ("off", False), ("0", False),
    ("true", True), ("YES", True), ("on", True), ("1", True),
    (False, False), (True, True), (0, False), (1, True),
])
def test_bool_fields_are_coerced(raw, expected):
    c = _cfg(dry_run=raw)
    assert c.dry_run is expected
    assert not c._type_errors


@pytest.mark.parametrize("raw", ["vielleicht", 2, 1.5, [True], {"a": 1}])
def test_bool_field_garbage_is_a_type_error(raw):
    c = _cfg(dry_run=raw)
    assert any("dry_run" in e for e in c.validate())


def test_dry_run_string_false_does_not_silence_channel_check():
    c = _cfg(dry_run="false", discord_webhook_url="", smtp_host="")
    assert c.dry_run is False
    assert any("Kein Alert-Kanal" in e for e in c.validate())


@pytest.mark.parametrize("raw, expected", [("8080", 8080), (8080, 8080), (" 7 ", 7), (3.0, 3)])
def test_int_fields_are_coerced(raw, expected):
    c = _cfg(http_port=raw)
    assert c.http_port == expected and type(c.http_port) is int
    assert not c._type_errors


@pytest.mark.parametrize("raw", ["acht", 2.5, True, None, [1]])
def test_int_field_garbage_is_a_type_error(raw):
    assert any("http_port" in e for e in _cfg(http_port=raw).validate())


@pytest.mark.parametrize("raw, expected", [("1.5", 1.5), (2, 2.0), (0.25, 0.25), ("3", 3.0)])
def test_float_fields_are_coerced(raw, expected):
    c = _cfg(window_hours=raw)
    assert c.window_hours == expected and type(c.window_hours) is float
    assert not c._type_errors


@pytest.mark.parametrize("raw", ["eine Stunde", False, None, {"h": 1}])
def test_float_field_garbage_is_a_type_error(raw):
    assert any("window_hours" in e for e in _cfg(window_hours=raw).validate())


def test_str_fields_stay_untouched():
    c = _cfg(name="rookhub", es_url="http://es:9200")
    assert (c.name, c.es_url) == ("rookhub", "http://es:9200")
    assert not c._type_errors
