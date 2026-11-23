"""Hợp đồng đầu ra JSONL/ECS cho SIEM: schema ổn định, không lộ giá trị thô, fingerprint ổn định."""
import json
from datetime import datetime, timezone

from dlp.cli import main
from dlp.fingerprint import normalize, occurrence_id, value_fingerprint
from dlp.models import FileFinding, Finding
from dlp.report import render_jsonl

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
KEY = b"test-key"
CARD = "4111 1111 1111 1111"


def make(value=CARD, path="logs/app.log", line=3, rule="credit_card", start=5):
    return FileFinding(path, line, Finding(rule, value, start, start + len(value), 1.0))


# Golden: nếu test này đỏ nghĩa là bạn vừa đổi schema -> tăng SCHEMA_VERSION và cập nhật dòng mẫu.
GOLDEN = (
    '{"@timestamp":"2026-11-23T08:00:00Z","ecs":{"version":"8.11.0"},'
    '"event":{"id":"81852eb84874b232a866f32a0f32d4ea","kind":"event","category":["file"],'
    '"type":["info"],"action":"sensitive-data-match","dataset":"dlp.finding","module":"dlp",'
    '"severity":90},"rule":{"id":"credit_card","name":"Credit card"},'
    '"file":{"path":"logs/app.log","name":"app.log","extension":"log"},"host":{"name":"soc-01"},'
    '"dlp":{"schema_version":"1","line":3,"column":6,"match_length":19,"confidence":1.0,'
    '"value":"41***************11","redaction":"partial",'
    '"fingerprint":"b23f39a9aac0afb011cd83bad14d8ae3"}}'
)


def test_golden_line():
    assert render_jsonl([make()], now=NOW, host="soc-01", key=KEY) == GOLDEN


def test_one_valid_json_object_per_line():
    out = render_jsonl([make(), make(line=4)], now=NOW, host="h", key=KEY)
    lines = out.split("\n")
    assert len(lines) == 2
    docs = [json.loads(x) for x in lines]
    assert docs[0]["dlp"]["line"] == 3 and docs[1]["dlp"]["line"] == 4
    assert all(d["dlp"]["schema_version"] == "1" for d in docs)


def test_empty_results_produce_no_output():
    assert render_jsonl([], now=NOW, host="h", key=KEY) == ""


def test_never_leaks_raw_value_by_default():
    assert CARD not in render_jsonl([make()], now=NOW, host="h", key=KEY)
    assert "4111111111111111" not in render_jsonl([make()], now=NOW, host="h", key=KEY)


def test_redact_none_is_explicit_in_the_document():
    doc = json.loads(render_jsonl([make()], "none", now=NOW, host="h", key=KEY))
    assert doc["dlp"]["value"] == CARD and doc["dlp"]["redaction"] == "none"


def test_fingerprint_stable_and_format_insensitive():
    a = value_fingerprint("credit_card", "4111 1111 1111 1111", KEY)
    assert a == value_fingerprint("credit_card", "4111-1111-1111-1111", KEY)
    assert a == value_fingerprint("credit_card", "4111111111111111", KEY)
    assert a != value_fingerprint("credit_card", "5555 5555 5555 4444", KEY)
    assert a != value_fingerprint("credit_card", CARD, b"other-key")


def test_fingerprint_normalizes_vn_phone_and_email():
    assert normalize("vn_phone", "+84 912 345 678") == normalize("vn_phone", "0912.345.678")
    assert normalize("email", "A.B@Example.com") == "a.b@example.com"


def test_occurrence_id_differs_by_location_but_fingerprint_does_not():
    d1 = json.loads(render_jsonl([make(line=3)], now=NOW, host="h", key=KEY))
    d2 = json.loads(render_jsonl([make(line=9)], now=NOW, host="h", key=KEY))
    assert d1["event"]["id"] != d2["event"]["id"]
    assert d1["dlp"]["fingerprint"] == d2["dlp"]["fingerprint"]
    assert occurrence_id("a", 1, 1, "us_ssn", "123-45-6789", KEY) == \
        occurrence_id("a", 1, 1, "us_ssn", "123-45-6789", KEY)


def test_timestamp_is_utc_iso8601_with_z():
    doc = json.loads(render_jsonl([make()], now=NOW, host="h", key=KEY))
    assert doc["@timestamp"] == "2026-11-23T08:00:00Z"


# ------------------------------------------------------------ CLI
def test_cli_jsonl_stdout_is_only_json_lines(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DLP_FINGERPRINT_KEY", "k")
    f = tmp_path / "a.log"
    f.write_text("SSN: 123-45-6789\ncard 4111 1111 1111 1111\n", encoding="utf-8")
    code = main(["file", str(f), "-f", "jsonl"])
    out = capsys.readouterr().out
    assert code == 1
    docs = [json.loads(line) for line in out.splitlines()]
    assert {d["rule"]["id"] for d in docs} == {"us_ssn", "credit_card"}
    assert "123-45-6789" not in out


def test_cli_jsonl_clean_file_prints_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DLP_FINGERPRINT_KEY", "k")
    f = tmp_path / "a.log"
    f.write_text("hello\n", encoding="utf-8")
    assert main(["file", str(f), "-f", "jsonl"]) == 0
    assert capsys.readouterr().out == ""


def test_cli_jsonl_output_file_is_atomic_and_newline_terminated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_FINGERPRINT_KEY", "k")
    f = tmp_path / "a.log"
    f.write_text("SSN: 123-45-6789\n", encoding="utf-8")
    out = tmp_path / "r.jsonl"
    main(["file", str(f), "-f", "jsonl", "-o", str(out)])
    text = out.read_text(encoding="utf-8")
    assert text.endswith("\n") and len(text.splitlines()) == 1
    assert not (tmp_path / "r.jsonl.tmp").exists()


def test_cli_warns_on_stderr_not_stdout_when_key_missing(tmp_path, capsys, monkeypatch):
    import dlp.fingerprint as fp
    monkeypatch.delenv("DLP_FINGERPRINT_KEY", raising=False)
    monkeypatch.setattr(fp, "_warned", False)
    f = tmp_path / "a.log"
    f.write_text("SSN: 123-45-6789\n", encoding="utf-8")
    main(["file", str(f), "-f", "jsonl"])
    cap = capsys.readouterr()
    assert "DLP_FINGERPRINT_KEY" in cap.err
    assert all(line.startswith("{") for line in cap.out.splitlines())