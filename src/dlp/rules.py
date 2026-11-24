import re
from dataclasses import dataclass
from collections.abc import Callable
from dlp.validators import (card_valid, cccd_valid, email_valid, ssn_valid, vn_phone_valid,)

@dataclass(frozen=True)
class Rule:
    id : str
    description: str
    pattern: re.Pattern[str]
    base_score: float = 0.30
    validator: Callable[[str], bool] | None = None
    keywords: tuple[str, ...] = ()
    validator_boost: float = 0.40
    # mức nghiêm trọng 0-100 (ECS event.severity); dùng cho --min-severity và SIEM
    severity: int = 50

RULES: list[Rule] = [
    Rule(
        id ="us_ssn",
        severity=80,
        description="US Social Security Number",
        pattern=re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        base_score=0.40,
        validator = ssn_valid,
        validator_boost = 0.0, #  chỉ là cổng loại bỏ, không cộng điểm
        keywords=("ssn","social security"),
    ),

    Rule(
        id ="email",
        severity = 30,
        description="Email",
        pattern=re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        base_score=0.50,
        validator = email_valid,
        validator_boost = 0.0,
    ),

    Rule(
        id="credit_card",
        severity=90,
        description="Credit card",
        pattern=re.compile(r"(?<!\d)(?:\d[ -]?){12,15}\d(?!\d)"),
        base_score=0.20,
        validator=card_valid,
        keywords=("card","visa","mastercard","thẻ","credit","amex","debit","cvv","the tin dung"),
    ),

    Rule(
        id="vn_phone",
        severity = 40,
        description="Vietnamese phone number",
        pattern=re.compile(r"(?<!\d)(?:\+84|0)[ .-]?[35789](?:[ .-]?\d){8}(?!\d)"),
        base_score=0.50,
        validator = vn_phone_valid,
        validator_boost = 0.20,
        keywords=("sđt","sdt","phone","điện thoại","liên hệ","tel","mobile","zalo","dien thoai","lien he"),
    ),

    Rule(
        id="vn_cccd",
        severity = 80,
        description="Vietnamese citizen identification card",
        pattern=re.compile(r"(?<!\d)\d{12}(?!\d)"),
        base_score=0.20,
        validator = cccd_valid,
        validator_boost = 0.10,
        keywords=("cccd", "cmnd", "căn cước", "cmt","can cuoc","số định danh","so dinh danh"),
    ),
]