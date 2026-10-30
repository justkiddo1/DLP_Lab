from dlp.scanner import find_in_text


def by_rule(text: str, rule_id: str):
    return [f for f in find_in_text(text) if f.rule_id == rule_id]


def test_valid_card_scores_high():
    found = by_rule("card 4111 1111 1111 1111", "credit_card")
    assert len(found) == 1
    assert found[0].confidence >= 0.7


def test_invalid_luhn_is_dropped():
    assert by_rule("order 1234567890123456", "credit_card") == []


def test_keyword_raises_score():
    plain = by_rule("code 123-45-6789", "us_ssn")[0].confidence
    with_ctx = by_rule("SSN: 123-45-6789", "us_ssn")[0].confidence
    assert with_ctx > plain


def test_cccd_without_context_is_low():
    found = by_rule("ma don hang 012345678901", "vn_cccd")
    assert len(found) == 1
    assert all(f.confidence < 0.5 for f in found)


def test_cccd_with_context_is_high():
    found = by_rule("CCCD: 012345678901", "vn_cccd")
    assert len(found) == 1
    assert found[0].confidence >= 0.5