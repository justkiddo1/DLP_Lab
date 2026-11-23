import re
from functools import lru_cache

from dlp.rules import Rule

WINDOW = 40
CONTEXT_BOOST = 0.40

_L = r"(?<![^\W\d_])"
_R = r"(?<![^\W\d_])"

@lru_cache(maxsize=None)
def _keyword_re(keywords: tuple[str, ...]) -> re.Pattern[str] | None:
    if not keywords:
        return None
    alts = "|".join(re.escape(k.lower()) for k in sorted(keywords, key=len, reverse=True))
    return re.compile(f"{_L}(?:{alts}){_R}")


def has_context(text:str, start:int, end:int, keywords: tuple[str, ...]) -> bool:
    rx = _keyword_re(keywords)
    if rx is None:
        return False
    left = text[max(0, start - WINDOW): start]
    right = text[end:end + WINDOW]
    return rx.search((left + "\n" + right).lower()) is not None


def score(rule: Rule, text: str, start: int, end: int) -> float:
    s = rule.base_score
    if rule.validator:
        if not rule.validator(text[start:end]):
            return 0.0
        s += rule.validator_boost

    if has_context(text,start,end,rule.keywords): 
        s += CONTEXT_BOOST
    return min(round(s,2),1.0)