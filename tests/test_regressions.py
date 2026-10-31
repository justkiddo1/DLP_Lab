"""Test bổ sung cho các lỗi và chỗ thiếu test phát hiện khi rà soát dlp-lab.

Nhóm A (3 test): ĐỎ trên code hiện tại, xanh sau khi sửa 3 lỗi.
Nhóm B (còn lại): XANH ngay, vì kiểm tra hành vi đúng nhưng trước đây chưa có test.
"""
import json
import logging

import pytest

from dlp.cli import main
from dlp.redact import mask
from dlp.scanner import find_in_text, scan_path


def by_rule(text: str, rule_id: str):
    return [f for f in find_in_text(text) if f.rule_id == rule_id]


SSN_LINE = "SSN: 000-12-3456\n"


# ============================================================ Nhóm A: bắt lỗi đã tìm thấy
def test_vn_phone_keyword_with_colon_raises_score():
    """Lỗi: từ khóa 'điện thoại ' có dấu cách cuối nên 'điện thoại:' không được cộng điểm."""
    plain = by_rule("hotline 0912345678", "vn_phone")[0].confidence
    with_ctx = by_rule("điện thoại: 0912345678", "vn_phone")[0].confidence
    assert with_ctx > plain


def test_cli_missing_path_message_contains_the_path(tmp_path, capsys):
    """Lỗi: thiếu chữ f nên thông báo in nguyên chữ {path} thay vì đường dẫn."""
    missing = tmp_path / "nope"
    assert main(["file", str(missing)]) == 2
    err = capsys.readouterr().err
    assert str(missing) in err
    assert "{path}" not in err


def test_scan_path_warns_when_skipping_large_file(tmp_path, monkeypatch, caplog):
    """Lỗi: file vượt MAX_BYTES bị bỏ qua mà không báo gì."""
    monkeypatch.setattr("dlp.scanner.MAX_BYTES", 50)
    (tmp_path / "big.txt").write_text(SSN_LINE * 10, encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="dlp.scanner"):
        results = scan_path(tmp_path)
    assert results == []
    assert "big.txt" in caplog.text


# ============================================================ Nhóm B: lấp chỗ thiếu test
def test_mask_rejects_unknown_style():
    with pytest.raises(ValueError):
        mask("secret", style="null")


def test_scan_path_no_warning_for_small_file(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr("dlp.scanner.MAX_BYTES", 1000)
    (tmp_path / "small.txt").write_text(SSN_LINE, encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="dlp.scanner"):
        results = scan_path(tmp_path)
    assert len(results) == 1
    assert caplog.text == ""


def test_scan_path_scans_explicit_large_file(tmp_path, monkeypatch):
    """Ghi lại hành vi hiện tại: file được chỉ định thẳng thì quét bất kể kích thước.
    Nếu sau này bạn đổi quyết định thì sửa test này cho khớp."""
    monkeypatch.setattr("dlp.scanner.MAX_BYTES", 50)
    big = tmp_path / "big.txt"
    big.write_text(SSN_LINE * 10, encoding="utf-8")
    assert len(scan_path(big)) == 10


def test_cli_default_does_not_leak_raw_value(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    main(["file", str(f), "-f", "json"])
    assert "000-12-3456" not in capsys.readouterr().out


def test_cli_redact_none_shows_raw_value(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    main(["file", str(f), "-f", "json", "--redact", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["value"] == "000-12-3456"


def test_cli_redact_full_hides_everything(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(SSN_LINE, encoding="utf-8")
    main(["file", str(f), "-f", "json", "--redact", "full"])
    data = json.loads(capsys.readouterr().out)
    assert set(data["findings"][0]["value"]) == {"*"}