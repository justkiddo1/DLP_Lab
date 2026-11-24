"""Baseline: danh sách finding đã triage (false positive / rủi ro chấp nhận) để lần sau chỉ báo cái MỚI.

Baseline chỉ chứa fingerprint HMAC, không chứa giá trị thô, nên commit/chia sẻ được.
Khóa mục: (rule, fingerprint của giá trị, đường dẫn tương đối so với thư mục quét).
Đường dẫn "*" nghĩa là giá trị đó được bỏ qua ở mọi file (vd. số thẻ test 4111...).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from dlp.fingerprint import key_check, value_fingerprint
from dlp.models import FileFinding

SCHEMA_VERSION = "1"
WILDCARD = "*"


class BaselineError(Exception):
    pass


def relative_path(ff_path: str, root: Path) -> str:
    """Đường dẫn ổn định giữa các máy/thư mục làm việc: tương đối so với nơi quét, dùng dấu /."""
    base = root if root.is_dir() else root.parent
    p = Path(ff_path)
    try:
        return p.relative_to(base).as_posix()
    except ValueError:
        return p.as_posix()


def _entry(ff: FileFinding, root: Path, key: bytes) -> tuple[str, str, str]:
    f = ff.finding
    return (f.rule_id, value_fingerprint(f.rule_id, f.value, key), relative_path(ff.path, root))


def load(path: Path, key: bytes) -> set[tuple[str, str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != SCHEMA_VERSION:
            raise BaselineError(f"unsupported baseline schema_version in {path}")
        if data.get("key_check") != key_check(key):
            raise BaselineError(
                f"{path} was created with a different DLP_FINGERPRINT_KEY; "
                "regenerate it with --write-baseline or set the original key")
        return {(e["rule"], e["fingerprint"], e["path"]) for e in data.get("entries", [])}
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
        raise BaselineError(f"malformed baseline {path}: {exc!r}") from exc


def is_suppressed(ff: FileFinding, root: Path, entries: set, key: bytes) -> bool:
    rule, fp, rel = _entry(ff, root, key)
    return (rule, fp, rel) in entries or (rule, fp, WILDCARD) in entries


def render(results: list[FileFinding], root: Path, key: bytes,now: datetime | None = None) -> tuple[str, int]:
    """Trả về (nội dung JSON, số mục). Mục sắp xếp ổn định để diff trong git gọn."""
    entries = sorted({_entry(r, root, key) for r in results})
    now = now or datetime.now(timezone.utc)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "key_check": key_check(key),
        "created_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "entries": [{"rule": r, "fingerprint": fp, "path": p, "reason": ""} for r, fp, p in entries],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2), len(entries)