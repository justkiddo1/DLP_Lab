from dlp.rules import Rule

WINDOW = 40
VALIDATOR_BOOST = 0.40
CONTEXT_BOOST = 0.40

def has_context(text:str, start:int, end:int, keywords: tuple[str, ...]) -> bool:
    left = text[max(0, start - WINDOW): start]
    right = text[end:end + WINDOW]
    region = (left + right).lower()
    return any(k in region for k in keywords)


def score(rule: Rule, text: str, start: int, end: int) -> float:
    value = text[start:end]
    s = rule.base_score
    if rule.validator:
        if not rule.validator(value):
            return 0.0
        s += VALIDATOR_BOOST

    if has_context(text,start,end,rule.keywords): 
        s += CONTEXT_BOOST
    return min(s,1.0)