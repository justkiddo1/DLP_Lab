from dlp.models import Finding
from dlp.rules import RULES
from dlp.scoring import score
from pathlib import Path
from dlp.models import FileFinding
import logging

logger = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.20

TEXT_SUFFIXES = {".txt",".csv",".json",".log",".md"}
MAX_BYTES = 10 * 1024 * 1024 # bỏ qua file lớn hơn 10MB

def find_in_text(text:str) -> list[Finding]:
    """Trả về mọi chỗ trong text khớp với một rule nào đó"""
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
    return findings

def scan_file(path: Path) -> list[FileFinding]:
    results = []
    with path.open("r",encoding="utf-8",errors="replace") as fh:
        for line_no,line in enumerate(fh, start=1):
            for f in find_in_text(line):
                results.append(
                    FileFinding(str(path),line_no,f)
                )
    return results

def scan_path(path: Path) -> list[FileFinding]:
    if path.is_file():
        return scan_file(path)

    results = []
    for p in sorted(path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if p.stat().st_size > MAX_BYTES:
            logger.warning("Skipped %s: larger than %d bytes", p, MAX_BYTES)
            continue
        results.extend(scan_file(p))
    return results





