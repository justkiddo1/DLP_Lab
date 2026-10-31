import json

from dlp.models import FileFinding, Finding
from dlp.report import render_console, render_json, to_dict


def make(value="4111 1111 1111 1111"):
    f = Finding(rule_id="credit_card", value=value, start=5,
                end=5 + len(value), confidence=1.0)
    return FileFinding(path="a.txt", line=3, finding=f)


def test_to_dict_masks_by_default():
    d = to_dict(make())
    assert d["rule_id"] == "credit_card"
    assert d["line"] == 3
    assert d["value"] != "4111 1111 1111 1111"
    assert d["value"].startswith("41")


def test_to_dict_none_keeps_raw():
    assert to_dict(make(), redaction="none")["value"] == "4111 1111 1111 1111"


def test_render_json_summary():
    data = json.loads(render_json([make(), make()]))
    assert data["total"] == 2
    assert len(data["findings"]) == 2
    assert data["by_rule"] == {"credit_card": 2}


def test_render_json_never_leaks_raw_by_default():
    assert "4111 1111 1111 1111" not in render_json([make()])


def test_render_console_empty():
    assert "No findings" in render_console([])


def test_render_console_shows_location():
    out = render_console([make()])
    assert "a.txt:3" in out
    assert "credit_card" in out