from dlp.scanner import scan_file, scan_path


def test_scan_file_reports_line_numbers(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello\nSSN: 123-45-6789\nbye\n", encoding="utf-8")
    results = scan_file(f)
    assert len(results) == 1
    assert results[0].line == 2
    assert results[0].finding.rule_id == "us_ssn"


def test_scan_path_walks_directory_and_skips_other_types(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.csv").write_text(
        "name,card\nAn,4111 1111 1111 1111\n", encoding="utf-8"
    )
    (tmp_path / "c.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    results = scan_path(tmp_path)
    assert {r.finding.rule_id for r in results} == {"credit_card"}


def test_scan_file_survives_bad_bytes(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_bytes(b"SSN: 123-45-6789 \xff\xfe\n")
    assert len(scan_file(f)) == 1