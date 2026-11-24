import codecs
from collections import Counter
from dataclasses import dataclass,field
from dlp.models import Finding
from dlp.rules import RULES
from dlp.scoring import score
from pathlib import Path
from dlp.models import FileFinding, Finding
import unicodedata
from collections.abc import Collection, Iterator
import logging


MIN_CONFIDENCE = 0.20

TEXT_SUFFIXES = {".txt",".csv",".json",".log",".md"}
MAX_BYTES = 10 * 1024 * 1024 # bỏ qua file lớn hơn 10MB
SAMPLE_BYTES = 64 * 1024

logger = logging.getLogger(__name__)

# UTF-32 phải kiểm tra trước UTF-16 vì BOM của UTF-32 LE bắt đầu bằng BOM của UTF-16 LE.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

@dataclass
class ScanStats:
    """Những gì lần quét thực sự đã làm, để biết "0 finding" có đáng tin hay không."""
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped: Counter = field(default_factory=Counter) # lý do -> số file
    skipped_paths: list = field(default_factory=list) # (path, lý do), trừ unsupported_extension
    errors: list = field(default_factory=list) #(path,mô tả lỗi)
    encodings: Counter = field(default_factory=Counter) # encoding -> số file

    def skip(self, path: Path, reason: str) -> None:
        self.skipped[reason] += 1
        self.skipped_paths.append((str(path), reason))

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "files_skipped": dict(self.skipped),
            "skipped_paths": [{"path": p, "reason": r} for p,r in self.skipped_paths],
            "errors": [{"path": p, "error": e} for p,e in self.errors],
            "encodings": dict(self.encodings),
        }

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

def detect_encoding(path: Path) -> str | None:
    """Đoán encoding từ BOM và đoạn đầu file. Trả về None nếu có vẻ là file nhị phân.

    Giới hạn: UTF-16 không có BOM có byte NUL nên bị coi là nhị phân (và được ghi vào
    bản tổng kết, không bỏ qua trong im lặng). File không phải UTF-8 hợp lệ được đọc
    như cp1258 (tiếng Việt trên Windows cũ); ký tự không giải mã được thành U+FFFD.
    """
    with path.open("rb") as fh:
        sample = fh.read(SAMPLE_BYTES)
    for bom, enc in _BOMS:
        if sample.startswith(bom):
            return enc
    if b"\x00" in sample:
        return None
    try:
        codecs.getincrementaldecoder("utf-8")().decode(sample, final=False)
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1258"

def iter_file(path: Path, stats: ScanStats | None = None) -> Iterator[FileFinding]:
    """Quét từng dòng và trả về kết quả ngay khi tìm thấy"""
    encoding = detect_encoding(path)
    if encoding is None:
        logger.warning("Skipped %s: looks like a binary file", path)
        if stats is not None:
            stats.skip(path, "binary")
        return
    with path.open("r", encoding=encoding, errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            for finding in find_in_text(line):
                yield(FileFinding(str(path),line_no,finding))
    if stats is not None:
        stats.files_scanned += 1
        stats.bytes_scanned += path.stat().st_size
        stats.encodings[encoding] += 1

def scan_file(path: Path, stats: ScanStats | None = None) -> list[FileFinding]:
    return list(iter_file(path, stats))

def _record_error(path: Path, exc: OSError, stats: ScanStats | None) -> None:
    logger.warning("Error reading %s: %s", path, exc)
    if stats is not None:
        stats.errors.append((str(path), f"{type(exc).__name__}: {exc}"))

def _guarded(path: Path, stats: ScanStats | None) -> Iterator[FileFinding]:
    """Một file lỗi (quyền truy cập, bị khóa...) chỉ được ghi nhận, lần quét vẫn tiếp tục."""
    try:
        yield from iter_file(path, stats)
    except OSError as exc:
        _record_error(path, exc, stats)

def iter_path(path: Path, exclude: Collection[Path] = (), stats: ScanStats | None = None) -> Iterator[FileFinding]:
    if path.is_file():
        yield from iter_file(path,stats)
        return
    for p in sorted(path.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            if stats is not None:
                stats.skipped["unsupported_extension"] += 1
            continue
        if exclude and p.resolve() in exclude:
            if stats is not None:
                stats.skip(p, "excluded")
            continue
        try:
            too_big = p.stat().st_size > MAX_BYTES
        except OSError as exc:
            _record_error(p, exc, stats)
            continue
        if too_big:
            logger.warning("Skipped %s: larger than %d bytes", p, MAX_BYTES)
            if stats is not None:
                stats.skip(p, "too_large")
            continue
        yield from _guarded(p, stats)

def scan_path(path: Path, exclude: Collection[Path] = (), stats: ScanStats | None = None) -> list[FileFinding]:
    return list(iter_path(path, exclude, stats))





