from dlp.redact import mask


def test_mask_partial_keeps_ends():
    m = mask("4111 1111 1111 1111")
    assert len(m) == len("4111 1111 1111 1111")
    assert m.startswith("41") and m.endswith("11")
    assert set(m[2:-2]) == {"*"}


def test_mask_short_value_fully_hidden():
    assert mask("123") == "***"


def test_mask_full_style():
    assert mask("secret", style="full") == "******"