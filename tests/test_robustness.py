"""Độ bền: cô lập lỗi theo file, nhận diện encoding, bản tổng kết, exit code."""
import json

import pytest

from dlp import scanner
from dlp.cli import main
from dlp.scanner import ScanStats, detect_encoding, scan_path

SSN = "SSN: 123-45-6789\n"


def make_flaky(monkeypatch, bad_name="b.txt"):
    real = scanner.iter_file

    def flaky(path, stats=None):
        if path.name == bad_name:
            raise PermissionError("locked by another process")
        yield from real(path, stats)

    monkeypatch.setattr(scanner, "iter_file", flaky)


# ---------------------------------------------------------- cô lập lỗi theo file
def test_one_unreadable_file_does_not_stop_the_scan(tmp_path, monkeypatch):
    for n in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / n).write_text(SSN, encoding="utf-8")
    make_flaky(monkeypatch)
    stats = ScanStats()
    results = scan_path(tmp_path, stats=stats)
    assert [r.path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for r in results] == ["a.txt", "c.txt"]
    assert len(stats.errors) == 1
    assert stats.errors[0][0].endswith("b.txt") and "PermissionError" in stats.errors[0][1]


# ---------------------------------------------------------- encoding
def test_utf8_bom_is_stripped_and_column_is_correct(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"\xef\xbb\xbf" + SSN.encode())
    res = scan_path(f)
    assert len(res) == 1 and res[0].finding.start == 5


def test_utf16_with_bom_is_scanned(tmp_path):
    f = tmp_path / "a.log"
    f.write_bytes(SSN.encode("utf-16"))          # có BOM
    stats = ScanStats()
    assert len(scan_path(f, stats=stats)) == 1
    assert stats.encodings["utf-16"] == 1


def test_non_utf8_falls_back_to_cp1258(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes("caf\xe9 phone 0912345678\n".encode("cp1258"))
    stats = ScanStats()
    res = scan_path(f, stats=stats)
    assert [r.finding.rule_id for r in res] == ["vn_phone"]
    assert stats.encodings["cp1258"] == 1


def test_binary_file_with_text_suffix_is_reported_not_silently_skipped(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"\x00\x01\x02" + SSN.encode())
    stats = ScanStats()
    assert scan_path(tmp_path, stats=stats) == []
    assert stats.skipped["binary"] == 1
    assert stats.skipped_paths == [(str(f), "binary")]


def test_detect_encoding_utf8_default_and_empty_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("xin chào " + SSN, encoding="utf-8")
    assert detect_encoding(f) == "utf-8"
    e = tmp_path / "empty.txt"
    e.write_bytes(b"")
    assert detect_encoding(e) == "utf-8"


# ---------------------------------------------------------- thống kê
def test_stats_count_scanned_skipped_and_large(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "c.txt").write_text(SSN, encoding="utf-8")
    (tmp_path / "b.png").write_bytes(b"\x89PNG")
    (tmp_path / "big.txt").write_text(SSN * 5, encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_BYTES", 40)
    stats = ScanStats()
    scan_path(tmp_path, stats=stats)
    assert stats.files_scanned == 2
    assert stats.bytes_scanned == (tmp_path / "a.txt").stat().st_size + (tmp_path / "c.txt").stat().st_size
    assert stats.skipped["unsupported_extension"] == 1
    assert stats.skipped["too_large"] == 1
    assert stats.skipped_paths == [(str(tmp_path / "big.txt"), "too_large")]


# ---------------------------------------------------------- exit code + tổng kết (CLI)
def test_cli_exit_3_when_read_error_even_with_findings(tmp_path, monkeypatch, capsys):
    for n in ("a.txt", "b.txt"):
        (tmp_path / n).write_text(SSN, encoding="utf-8")
    make_flaky(monkeypatch)
    code = main(["file", str(tmp_path), "-f", "json"])
    cap = capsys.readouterr()
    assert code == 3
    assert json.loads(cap.out)["total"] == 1           # kết quả của file đọc được vẫn được báo
    assert "errors 1" in cap.err and "b.txt" in cap.err


@pytest.mark.parametrize("content,expected", [("hello\n", 0), (SSN, 1)])
def test_cli_exit_0_and_1(tmp_path, content, expected):
    f = tmp_path / "a.txt"
    f.write_text(content, encoding="utf-8")
    assert main(["file", str(f), "-q"]) == expected


def test_cli_summary_goes_to_stderr_and_quiet_suppresses_it(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN, encoding="utf-8")
    main(["file", str(f), "-f", "json"])
    cap = capsys.readouterr()
    assert "scanned 1 file(s)" in cap.err and "findings 1" in cap.err
    assert "scanned" not in cap.out
    main(["file", str(f), "-f", "json", "-q"])
    assert capsys.readouterr().err == ""


def test_cli_summary_file_content(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text(SSN, encoding="utf-8")
    summ = tmp_path / "summary.json"
    code = main(["file", str(f), "--summary-file", str(summ), "-q"])
    data = json.loads(summ.read_text(encoding="utf-8"))
    assert code == 1 and data["exit_code"] == 1
    assert data["schema_version"] == "1"
    assert data["files_scanned"] == 1 and data["findings"] == 1
    assert data["errors"] == [] and data["encodings"] == {"utf-8": 1}
    assert data["started_at"].endswith("Z")
    assert not (tmp_path / "summary.json.tmp").exists()


def test_cli_does_not_scan_its_own_output_files(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "a.txt").write_text(SSN, encoding="utf-8")
    out = d / "out.json"
    args = ["file", str(d), "-f", "json", "--redact", "none", "-o", str(out), "-q"]
    main(args)
    main(args)                                          # lần 2: out.json đã chứa giá trị thô
    assert json.loads(out.read_text(encoding="utf-8"))["total"] == 1