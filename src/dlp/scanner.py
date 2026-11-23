from dlp.models import Finding
from dlp.rules import RULES
from dlp.scoring import score
from pathlib import Path
from dlp.models import FileFinding
import unicodedata
from collections.abc import Collection, Iterator
import logging


MIN_CONFIDENCE = 0.20

TEXT_SUFFIXES = {".txt",".csv",".json",".log",".md"}
MAX_BYTES = 10 * 1024 * 1024 # bỏ qua file lớn hơn 10MB

logger = logging.getLogger(__name__)

def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Hai finding chồng lên nhau thì giữ cái điểm cao hơn (hòa thì cái dài hơn)."""
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda f: (-f.confidence, -(f.end - f.start))):
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)

def find_in_text(text:str) -> list[Finding]:
    """Trả về mọi chỗ trong text khớp với một rule nào đó"""
    text = unicodedata.normalize("NFC",text)
    findings = []
    for rule in RULES :
        for m in rule.pattern.finditer(text):
            conf = score(rule, text, m.start(), m.end())
            if conf < MIN_CONFIDENCE:
                continue
            findings.append(
                Finding(
                    rule_id= rule.id,
                    value= m.group(),
                    start=m.start(),
                    end=m.end(),
                    confidence= conf
                )
            )
    return _resolve_overlaps(findings)

def iter_file(path: Path) -> Iterator[FileFinding]:
    """Quét từng dòng và trả về kết quả ngay khi tìm thấy"""
    with path.open("r", encoding="utf8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            for finding in find_in_text(line):
                yield(FileFinding(str(path),line_no,finding))

def scan_file(path: Path) -> list[FileFinding]:
    return list(iter_file(path))

def iter_path(path: Path, exclude: Collection[Path] = ()) -> Iterator[FileFinding]:
    if path.is_file():
        yield from iter_file(path)
        return
    for p in sorted(path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if exclude and p.resolve() in exclude:
            continue
        if p.stat().st_size > MAX_BYTES:
            logger.warning("Skipped %s: larger than %d bytes", p, MAX_BYTES)
            continue
    yield from iter_file(p)

def scan_path(path: Path) -> list[FileFinding]:
    return list(iter_path(path))





