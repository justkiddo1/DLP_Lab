from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    rule_id : str
    value : str
    start: int
    end: int
    confidence: float = 0.0

@dataclass(frozen=True)
class FileFinding:
    path: str
    line: int
    finding: Finding
