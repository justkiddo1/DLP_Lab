"""Giảm nhiễu: --min-confidence, --min-severity, baseline (chỉ báo finding mới)."""
import json

import pytest

from dlp.cli import main
from dlp.fingerprint import key_check, value_fingerprint

SSN_LINE = "SSN: 123-45-6789\n"           # điểm 0.80, severity 80
CARD_LINE = "card 4111 1111 1111 1111\n"  # điểm 1.0, severity 90


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("DLP_FINGERPRINT_KEY", "test-key")


def run_json(args, capsys):
    code = main(args + ["-f", "json", "-q"])
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip().startswith("{") else None)


# ------------------------------------------------------------ ngưỡng
def test_min_confidence_hides_low_score_findings(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("code 123-45-6789\n" + SSN_LINE, encoding="utf-8")   # 0.40 và 0.80
    _, data = run_json(["file", str(f)], capsys)
    assert data["total"] == 2
    _, data = run_json(["file", str(f), "--min-confidence", "0.5"], capsys)
    assert data["total"] == 1 and data["findings"][0]["line"] == 2


def test_min_severity_hides_low_severity_rules(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("mail a@example.com\n" + SSN_LINE, encoding="utf-8")  # email 30, ssn 80
    _, data = run_json(["file", str(f), "--min-severity", "50"], capsys)
    assert data["by_rule"] == {"us_ssn": 1}


def test_all_hidden_means_exit_0_and_summary_counts_hidden(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("mail a@example.com\n", encoding="utf-8")
    summ = tmp_path / "s.json"
    code = main(["file", str(f), "--min-severity", "50", "--summary-file", str(summ), "-q"])
    data = json.loads(summ.read_text(encoding="utf-8"))
    assert code == 0 and data["hidden"]["below_min_severity"] == 1 and data["findings"] == 0


# ------------------------------------------------------------ baseline
def test_write_baseline_then_only_new_findings_are_reported(tmp_path, capsys):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "a.txt").write_text(SSN_LINE, encoding="utf-8")
    base = tmp_path / "base.json"

    assert main(["file", str(d), "--write-baseline", str(base), "-q"]) == 0
    doc = json.loads(base.read_text(encoding="utf-8"))
    assert doc["key_check"] == key_check(b"test-key")
    assert [(e["rule"], e["path"]) for e in doc["entries"]] == [("us_ssn", "a.txt")]
    assert "123-45-6789" not in base.read_text(encoding="utf-8")     # không lộ giá trị thô

    code, data = run_json(["file", str(d), "--baseline", str(base)], capsys)
    assert code == 0 and data["total"] == 0

    (d / "b.txt").write_text(CARD_LINE, encoding="utf-8")            # finding mới
    code, data = run_json(["file", str(d), "--baseline", str(base)], capsys)
    assert code == 1 and data["by_rule"] == {"credit_card": 1}


def test_baseline_survives_line_shift(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    base = tmp_path / "base.json"
    main(["file", str(f), "--write-baseline", str(base), "-q"])
    f.write_text("\n\nthêm vài dòng\n" + SSN_LINE, encoding="utf-8")
    code, data = run_json(["file", str(f), "--baseline", str(base)], capsys)
    assert code == 0 and data["total"] == 0


def test_baseline_wildcard_path_suppresses_value_everywhere(tmp_path, capsys):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text(CARD_LINE, encoding="utf-8")
    (d / "b.txt").write_text(CARD_LINE, encoding="utf-8")
    base = tmp_path / "base.json"
    base.write_text(json.dumps({
        "schema_version": "1", "key_check": key_check(b"test-key"),
        "entries": [{"rule": "credit_card", "path": "*", "reason": "số thẻ test",
                     "fingerprint": value_fingerprint("credit_card", "4111 1111 1111 1111", b"test-key")}],
    }), encoding="utf-8")
    code, data = run_json(["file", str(d), "--baseline", str(base)], capsys)
    assert code == 0 and data["total"] == 0


def test_baseline_from_other_key_is_rejected(tmp_path, capsys, monkeypatch):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    base = tmp_path / "base.json"
    main(["file", str(f), "--write-baseline", str(base), "-q"])
    monkeypatch.setenv("DLP_FINGERPRINT_KEY", "another-key")
    assert main(["file", str(f), "--baseline", str(base), "-q"]) == 2
    assert "different DLP_FINGERPRINT_KEY" in capsys.readouterr().err


def test_missing_or_malformed_baseline_is_usage_error(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    assert main(["file", str(f), "--baseline", str(tmp_path / "nope.json"), "-q"]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["file", str(f), "--baseline", str(bad), "-q"]) == 2
    assert "baseline" in capsys.readouterr().err


def test_baseline_and_write_baseline_are_mutually_exclusive(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    assert main(["file", str(f), "--baseline", "x.json", "--write-baseline", "y.json", "-q"]) == 2


def test_baseline_file_inside_scanned_dir_is_not_scanned(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text(SSN_LINE, encoding="utf-8")
    base = d / "base.json"
    main(["file", str(d), "--write-baseline", str(base), "-q"])
    summ = tmp_path / "s.json"
    main(["file", str(d), "--baseline", str(base), "--summary-file", str(summ), "-q"])
    data = json.loads(summ.read_text(encoding="utf-8"))
    assert data["files_scanned"] == 1 and data["files_skipped"].get("excluded") == 1