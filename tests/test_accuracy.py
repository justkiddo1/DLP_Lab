"""Test độ chính xác: validator, ranh giới từ, chuẩn hóa Unicode, chồng lấn."""
import unicodedata

import pytest

from dlp.scanner import find_in_text
from dlp.validators import luhn_valid


def by_rule(text: str, rule_id: str):
    return [f for f in find_in_text(text) if f.rule_id == rule_id]


def luhn_number(prefix: str, total_len: int) -> str:
    body = prefix + "0" * (total_len - len(prefix) - 1)
    for c in "0123456789":
        if luhn_valid(body + c):
            return body + c
    raise AssertionError


# ------------------------------------------------------------ ngữ cảnh
def test_keyword_needs_word_boundary():
    inside_word = by_rule("discard 123-45-6789", "us_ssn")[0].confidence
    plain = by_rule("code 123-45-6789", "us_ssn")[0].confidence
    assert inside_word == plain


def test_keyword_adjacent_to_digits_still_counts():
    assert by_rule("ssn=123-45-6789", "us_ssn")[0].confidence > \
        by_rule("x=123-45-6789", "us_ssn")[0].confidence


def test_keyword_without_diacritics():
    ctx = by_rule("so dien thoai: 0912345678", "vn_phone")[0].confidence
    plain = by_rule("xyz 0912345678", "vn_phone")[0].confidence
    assert ctx > plain


@pytest.mark.parametrize("form", ["NFC", "NFD"])
def test_keyword_unicode_normalization(form):
    text = unicodedata.normalize(form, "điện thoại: 0912345678")
    plain = by_rule("xyz 0912345678", "vn_phone")[0].confidence
    assert by_rule(text, "vn_phone")[0].confidence > plain


# ------------------------------------------------------------ validator
@pytest.mark.parametrize("bad", ["000-12-3456", "666-12-3456", "123-00-6789", "123-45-0000"])
def test_ssn_never_issued_is_dropped(bad):
    assert by_rule(f"SSN: {bad}", "us_ssn") == []


def test_cccd_province_code_checked():
    assert by_rule("CCCD: 079203012345", "vn_cccd")         # 079 = TP.HCM
    assert by_rule("tracking 999999999999", "vn_cccd") == []


def test_phone_prefix_checked_and_formats():
    assert by_rule("0312345678", "vn_phone") == []           # 031 không phải đầu số di động
    for ok in ["0912 345 678", "091.234.5678", "+84 912 345 678", "0321234567"]:
        assert by_rule(f"gọi {ok}", "vn_phone"), ok


def test_email_filename_not_email():
    assert by_rule("see logo@2x.png", "email") == []
    assert by_rule("a.b+tag@example.com", "email")


def test_card_unknown_prefix_dropped_even_if_luhn_ok():
    n = luhn_number("99", 16)
    assert luhn_valid(n)
    assert by_rule(f"card {n}", "credit_card") == []


def test_card_wrong_length_for_brand_dropped():
    n = luhn_number("37", 16)        # Amex phải 15 số
    assert by_rule(f"card {n}", "credit_card") == []


def test_long_digit_run_is_not_a_card():
    n = luhn_number("4", 16) + "1234"
    assert by_rule(n, "credit_card") == []


# ------------------------------------------------------------ chồng lấn
def test_no_duplicate_findings_on_same_span():
    found = find_in_text("card 4111 1111 1111 1111")
    assert [f.rule_id for f in found] == ["credit_card"]