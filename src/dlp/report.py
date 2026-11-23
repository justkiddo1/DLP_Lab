import json
import socket
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from dlp.fingerprint import get_key, occurrence_id, value_fingerprint
from dlp.models import FileFinding
from dlp.redact import mask
from dlp.rules import RULES

SCHEMA_VERSION = "1" # đổi/xóa tên trường -> tăng số này
ECS_VERSION = "8.11.0"
# severity số theo kiểu ECS (0-100); rule lạ nhận mặc định.
SEVERITY = {"credit_card": 90, "us_ssn": 80, "vn_cccd": 80, "vn_phone": 40, "email": 30}
DEFAULT_SEVERITY = 50
_RULE_NAMES = {r.id: r.description for r in RULES}

def to_dict(ff: FileFinding, redaction: str = "partial") -> dict:
    f = ff.finding
    if redaction == "none":
        value = f.value
    else:
        value = mask(f.value, style=redaction)

    return {
        "path":ff.path,
        "line":ff.line,
        "rule_id": f.rule_id,
        "value": value,
        "confidence": f.confidence,
    }

def render_json(results: list[FileFinding], redaction: str = "partial") -> str:
    findings = [to_dict(r, redaction) for r in results]
    by_rule = dict(Counter(r.finding.rule_id for r in results))
    report = {"total": len(findings), "by_rule": by_rule, "findings": findings}
    return json.dumps(report, ensure_ascii=False, indent=2)

def render_console(results: list[FileFinding], redaction: str = "partial") -> str:
    if not results:
        return "No findings."
    lines = []
    for r in results:
        d = to_dict(r, redaction)
        lines.append(f"{d['path']}:{d['line']}  {d['rule_id']}  {d['value']}  {d['confidence']:.2f}")
    lines.append(f"{len(results)} finding(s)")
    return "\n".join(lines)

def _utc_iso(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def to_ecs(ff: FileFinding, redaction:str = "partial", *, ts: str, host: str, key: bytes| None = None) -> dict:
    """Một finding -> một document theo ECS (trường tùy biến nằm trong namespace `dlp`)."""
    f = ff.finding
    key = key or get_key()
    p = Path(ff.path)
    value = f.value if redaction == "none" else mask(f.value, style=redaction)
    column = f.start + 1
    return {
        "@timestamp": ts,
        "ecs" : {"version": ECS_VERSION},
        "event": {
            "id": occurrence_id(ff.path, ff.line, column, f.rule_id, f.value, key),
            "kind": "event",
            "category": ["file"],
            "type": ["info"],
            "action": "sensitive-data-match",
            "dataset": "dlp.finding",
            "module": "dlp",
            "severity": SEVERITY.get(f.rule_id, DEFAULT_SEVERITY),
        },
        "rule": {"id": f.rule_id, "name": _RULE_NAMES.get(f.rule_id, f.rule_id)},
        "file": {"path": ff.path, "name": p.name, "extension": p.suffix.lstrip(".")},
        "host": {"name": host},
        "dlp": {
            "schema_version": SCHEMA_VERSION,
            "line": ff.line,
            "column": column,
            "match_length": len(f.value),
            "confidence": f.confidence,
            "value": value,
            "redaction": redaction,
            "fingerprint": value_fingerprint(f.rule_id, f.value, key)
        },
    }

def render_jsonl(results: list[FileFinding], redaction: str = "partial", *, now: datetime | None = None, host: str | None = None, key: bytes | None = None) -> str:
    """Mỗi finding một dòng JSON (NDJSON), không có dòng tổng kết/dòng trống."""
    if not results:
        return ""
    ts = _utc_iso(now)
    host = host or socket.gethostname()
    key = key or get_key()
    return "\n".join(
        json.dumps(to_ecs(r, redaction, ts=ts, host=host, key=key),ensure_ascii=False, separators=(",",":"))
        for r in results
    )

