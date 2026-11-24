import hashlib
import hmac
import os
import re
import sys

ENV_KEY = "DLP_FINGERPRINT_KEY"
_DEFAULT_KEY = b"dlp-lab-default-key-not-secret"
_warned = False

def get_key() -> bytes:
    global _warned
    raw = os.environ.get(ENV_KEY)
    if raw:
        return raw.encode("utf-8")
    if not _warned:
        print(
            f"warning: {ENV_KEY} is not set; fingerprints use a public default key "
            "and can be brute-forced for low-entropy values",
            file=sys.stderr,
        )
        _warned = True
    return _DEFAULT_KEY

def normalize(rule_id: str, value : str) -> str:
    """Cùng một giá trị viết khác định dạng thì phải ra cùng fingerprint."""
    if rule_id == "email":
        return value.strip().lower()
    digits_or_alnum = re.sub(r"[^0-9A-Za-z]", "", value)
    if rule_id == "vn_phone" and digits_or_alnum.startswith("84"):
        return "0" + digits_or_alnum[2:]
    return digits_or_alnum

def _mac(key:bytes, *parts: str) -> str:
    msg = "\0".join(parts).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]

def value_fingerprint(rule_id: str, value: str, key: bytes | None = None) -> str:
    """Cùng giá trị ở bất kỳ file nào -> cùng fingerprint (dùng để đối chiếu chéo file)."""
    return _mac(key or get_key(), rule_id, normalize(rule_id, value))

def occurrence_id(path: str, line: int, column: int, rule_id : str, value: str, key: bytes | None = None) -> str:
    """Định danh một lần xuất hiện cụ thể; ổn định nếu file không đổi."""
    return _mac(key or get_key(), path, str(line), str(column), rule_id, normalize(rule_id, value))

def key_check(key: bytes | None = None) -> str:
    """Dấu nhận biết khóa (không lộ khóa): baseline tạo bằng khóa khác sẽ bị từ chối thay vì lặng lẽ không khớp."""
    return _mac(key or get_key(), "baseline-key-check")[:16]