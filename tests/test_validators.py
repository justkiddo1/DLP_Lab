from dlp.validators import luhn_valid

def test_valid_numbers():
    assert luhn_valid("79927398713")
    assert luhn_valid("4111111111111111")
    assert luhn_valid("5555555555554444")
    assert luhn_valid("378282246310005")

def test_ignores_spaces_and_dashes():
    assert luhn_valid("4111 1111 1111 1111")
    assert luhn_valid("4111-1111-1111-1111")

def test_invalid_numbers():
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("79927398710")

def test_garbage_input():
    assert not luhn_valid("")
    assert not luhn_valid("abcd")
    assert not luhn_valid("4111 1111 xxxx 1111")