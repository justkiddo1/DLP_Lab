def mask(value: str, style: str = "partial") -> str:
    "Che giá trị nhạy cảm"
    if style not in ("partial","full"):
        raise ValueError(f"style không hợp lệ: {style!r}")
    if style == "full" or len(value) <= 4:
        return "*" * len(value)
    hidden = "*" * (len(value) - 4)
    return value[:2] + hidden + value[-2:]
