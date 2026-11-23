import re

def luhn_valid(number: str) -> bool:
    """Trả về True nếu chuỗi số vượt qua kiểm tra Luhn."""
    cleaned = number.replace(" ", "").replace("-", "")
    if not cleaned.isdigit():
        return False

    total = 0
    for i,ch in enumerate(reversed(cleaned), start=1):
        d = int(ch)
        if i % 2 ==0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def card_valid(number: str) -> bool:
    """Luhn + đầu số/độ dài khớp một hãng thẻ phổ biến.
    Đánh đổi: thẻ có đầu số lạ (Maestro, thẻ nội địa...) sẽ bị loại. Muốn ưu
    tiên recall thì đổi `return False` cuối hàm thành `return True`.
    """
    if not luhn_valid(number):
        return False
    d = re.sub(r"\D","",number)
    n = len(d)
    p2,p3,p4 = int(d[:2]), int(d[:3]), int(d[:4])
    if d[0] == "4":  # Visa
        return n in (13,16)
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720: # Mastercard
        return n == 16
    if p2 in (34,37):
        return n == 15  # American Express
    if p2 in (36,38) or 300 <= p3 <= 305: # Diners Club
        return n == 14
    if d.startswith("6011") or p2 == 65 or 644 <= p3 <= 649: # Discover
        return n == 16
    if 3528 <= p4  <= 3589: # JCB
        return n == 16
    if p2 == 62: # UnionPay
        return n == 16

    return False

def ssn_valid(value: str) -> bool:
    """Loại các SSN không bao giờ được cấp: area 000/666, group 00, serial 0000.
    Area 9xx (ITIN) vẫn được giữ lại vì cũng là định danh thuế nhạy cảm."""
    m = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", value)
    if not m :
        return False
    area, group, serial = m.groups()
    return area not in ("000","666") and group != "00" and serial != "0000"

CCCD_PROVINCES = frozenset("""
001 002 004 006 008 010 011 012 014 015 017 019 020 022 024 025 026 027
030 031 033 034 035 036 037 038 040 042 044 045 046 048 049 051 052 054
056 058 060 062 064 066 067 068 070 072 074 075 077 079 080 082 083 084
086 087 089 091 092 093 094 095 096
""".split())

def cccd_valid(value: str) -> bool:
    return len(value) == 12 and value.isdigit() and value[:3] in CCCD_PROVINCES

_VN_MOBILE = re.compile(r"0(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9\d)\d{7}")

def vn_phone_valid(value:str) -> bool:
    """Chuẩn hóa +84 -> 0 rồi kiểm tra đầu số di động. Nên đối chiếu bảng đầu số hiện hành."""
    digits = re.sub(r"\D", "", value)
    if digits.startswith("84"):
        digits = "0" + digits[2:]
    return bool(_VN_MOBILE.fullmatch(digits))

_FILE_EXIST = frozenset({"png","jpg","jpeg", "gif", "svg", "webp", "css", "js", "ico"})

def email_valid(value:str) -> bool:
    """Loại tên file kiểu logo@2x.png bị regex nhận nhầm là email."""
    return value.rsplit(".", 1)[-1].lower() not in _FILE_EXIST