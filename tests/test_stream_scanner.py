import inspect

from dlp.scanner import iter_file, iter_path, scan_file, scan_path

SSN_LINES = "SSN: 123-12-3456\nSSN: 123-12-3457\nSSN: 123-12-3458\n"


def test_iter_file_is_a_generator(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINES, encoding="utf-8")
    assert inspect.isgenerator(iter_file(f))


def test_iter_file_yields_lazily(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINES, encoding="utf-8")
    it = iter_file(f)
    first = next(it)                      # chỉ lấy MỘT kết quả
    assert first.line == 1
    assert first.finding.rule_id == "us_ssn"
    assert [r.line for r in it] == [2, 3]  # phần còn lại vẫn còn đó


def test_scan_file_is_still_a_list_with_same_content(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINES, encoding="utf-8")
    result = scan_file(f)
    assert isinstance(result, list)
    assert result == list(iter_file(f))


def test_iter_path_walks_directory_in_sorted_order(tmp_path):
    (tmp_path / "b.txt").write_text("SSN: 123-12-3456\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("SSN: 123-12-3457\n", encoding="utf-8")
    names = [r.path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for r in iter_path(tmp_path)]
    assert names == ["a.txt", "b.txt"]


def test_scan_path_is_still_a_list(tmp_path):
    (tmp_path / "a.txt").write_text(SSN_LINES, encoding="utf-8")
    assert isinstance(scan_path(tmp_path), list)
    assert len(scan_path(tmp_path)) == 3


def test_iter_path_skips_excluded_file(tmp_path):
    """File báo cáo nằm trong thư mục đang quét không được tự quét chính nó."""
    (tmp_path / "a.txt").write_text("SSN: 123-12-3456\n", encoding="utf-8")
    report = tmp_path / "out.json"
    report.write_text("SSN: 123-12-3457\n", encoding="utf-8")
    found = list(iter_path(tmp_path, exclude={report.resolve()}))
    assert len(found) == 1
    assert found[0].path.endswith("a.txt")
    assert len(list(iter_path(tmp_path))) == 2   # không loại trừ thì cả hai đều bị quét