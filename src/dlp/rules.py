import re
from dataclasses import dataclass
from collections.abc import Callable
from dlp.validators import luhn_valid

@dataclass(frozen=True)
class Rule:
    id : str
    description: str
    pattern: re.Pattern[str]
    base_score: float = 0.30
    validator: Callable[[str], bool] | None = None
    keywords: tuple[str, ...] = ()

RULES: list[Rule] = [
    Rule(
        id ="us_ssn",
        description="US Social Security Number",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        base_score=0.40,
        keywords=("ssn","social security"),
    ),

    Rule(
        id ="email",
        description="Email",
        pattern=re.compile(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        base_score=0.50,
    ),

    Rule(
        id="credit_card",
        description="Credit card",
        pattern=re.compile(r"\b(?:\d[ -]?){12,15}\d\b"),
        base_score=0.20,
        validator=luhn_valid,
        keywords=("card","visa","mastercard","thẻ","credit"),
    ),

    Rule(
        id="vn_phone",
        description="Vietnamese phone number",
        pattern=re.compile(r"(?<!\d)(?:\+84|0)[35789]\d{8}(?!\d)"),
        base_score=0.50,
        keywords=("sđt","phone","điện thoại ","liên hệ")
    ),

    Rule(
        id="vn_cccd",
        description="Vietnamese citizen identification card",
        pattern=re.compile(r"\b[0-9]{12}\b"),
        base_score=0.20,
        keywords=("cccd", "cmnd", "căn cước"),
    )
]