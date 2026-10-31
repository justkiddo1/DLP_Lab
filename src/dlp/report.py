import json
from collections import Counter
from dlp.models import FileFinding
from dlp.redact import mask

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
