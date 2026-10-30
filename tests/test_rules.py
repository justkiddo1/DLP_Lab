from dlp.scanner import find_in_text

def ids(text:str) -> set[str]:
    return {f.rule_id for f in find_in_text(text)}

def test_ssn():
    assert "us_ssn" in ids("SSN: 123-45-6789")

def test_credit_card_with_spaces():
    assert "credit_card" in ids("card 4111 1111 1111 1111")

def test_vn_phone_variants():
    assert "vn_phone" in ids("gọi 0912345678")
    assert "vn_phone" in ids("gọi +84912345678")

def test_no_false_positive_on_plain_text():
    assert ids("Hôm nay trời đẹp, không có gì nhạy cảm.") == set()