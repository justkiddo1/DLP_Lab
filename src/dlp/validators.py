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
