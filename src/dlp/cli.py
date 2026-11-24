import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dlp import baseline as bl
from dlp.fingerprint import get_key
from dlp.report import render_console, render_json, render_jsonl, severity_of
from dlp.scanner import ScanStats, scan_path

# Exit code: 0 sạch | 1 có phát hiện | 2 dùng sai/đường dẫn không tồn tại
#            3 có lỗi khi quét (kết quả không đầy đủ), ưu tiên hơn 1
EXIT_CLEAN, EXIT_FINDINGS, EXIT_USAGE, EXIT_SCAN_ERROR = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlp-scan", description="Data Loss Prevention scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_file = sub.add_parser("file", help="quét một file hoặc cả thư mục")
    p_file.add_argument("path")
    p_file.add_argument("-f", "--format", choices=["console", "json", "jsonl"], default="console")
    p_file.add_argument("-o", "--output", help="ghi báo cáo ra file thay vì in ra màn hình")
    p_file.add_argument("--redact", choices=["partial", "full", "none"], default="partial")
    p_file.add_argument("--summary-file", help="ghi bản tổng kết lần quét (JSON) ra file")
    p_file.add_argument("--min-confidence", type=float, default=0.0, metavar="0-1",
                        help="chỉ báo finding có điểm tin cậy >= ngưỡng này")
    p_file.add_argument("--min-severity", type=int, default=0, metavar="0-100",
                        help="chỉ báo finding có severity >= ngưỡng này")
    p_file.add_argument("--baseline", help="bỏ qua các finding đã có trong file baseline (chỉ báo cái mới)")
    p_file.add_argument("--write-baseline", metavar="FILE",
                        help="ghi các finding hiện tại thành baseline rồi thoát (không in báo cáo)")
    p_file.add_argument("-q", "--quiet", action="store_true", help="không in tổng kết ra stderr")
    return parser


def _write_atomic(path: Path, text: str) -> None:
    """Ghi file tạm rồi đổi tên, để agent (Filebeat...) không đọc phải file ghi dở."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _own_outputs(args) -> set[Path]:
    """File do chính lần chạy này ghi ra (kể cả file .tmp) không được tự quét chính nó."""
    out: set[Path] = set()
    for name in (args.output, args.summary_file, args.baseline, args.write_baseline):
        if name:
            out.add(Path(name).resolve())
            out.add(Path(name + ".tmp").resolve())
    return out


def _human_summary(stats: ScanStats, findings: int, duration: float, code: int,
                   filtered: dict | None = None) -> str:
    skipped = ", ".join(f"{k}={v}" for k, v in sorted(stats.skipped.items())) or "0"
    mb = stats.bytes_scanned / (1024 * 1024)
    return (f"dlp-scan: scanned {stats.files_scanned} file(s), {mb:.2f} MB in {duration:.2f}s | "
            f"skipped {skipped} | errors {len(stats.errors)} | findings {findings}"
            f"{_filtered_text(filtered)} | exit {code}")


def _filtered_text(filtered: dict | None) -> str:
    parts = [f"{k}={v}" for k, v in (filtered or {}).items() if v]
    return f" (hidden: {', '.join(parts)})" if parts else ""


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)

    if not path.exists():
        print(f"Error: path does not exist : {path}", file=sys.stderr)
        return EXIT_USAGE

    if args.baseline and args.write_baseline:
        print("Error: --baseline and --write-baseline cannot be used together", file=sys.stderr)
        return EXIT_USAGE
    key = get_key() if (args.baseline or args.write_baseline) else None
    entries = set()
    if args.baseline:
        try:
            entries = bl.load(Path(args.baseline), key)
        except bl.BaselineError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_USAGE

    stats = ScanStats()
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    results = scan_path(path, exclude=_own_outputs(args), stats=stats)
    duration = time.perf_counter() - t0

    # Giảm nhiễu: ngưỡng điểm/severity, rồi baseline (chỉ báo finding mới).
    filtered = {"below_min_confidence": 0, "below_min_severity": 0, "baseline": 0}
    kept = []
    for r in results:
        if r.finding.confidence < args.min_confidence:
            filtered["below_min_confidence"] += 1
        elif severity_of(r.finding.rule_id) < args.min_severity:
            filtered["below_min_severity"] += 1
        elif entries and bl.is_suppressed(r, path, entries, key):
            filtered["baseline"] += 1
        else:
            kept.append(r)
    results = kept

    if args.write_baseline:
        text, n = bl.render(results, path, key)
        _write_atomic(Path(args.write_baseline), text)
        print(f"dlp-scan: baseline written: {n} entr{'y' if n == 1 else 'ies'} -> {args.write_baseline}",
              file=sys.stderr)
        return EXIT_SCAN_ERROR if stats.errors else EXIT_CLEAN

    if args.format == "json":
        text = render_json(results, args.redact)
    elif args.format == "jsonl":
        text = render_jsonl(results, args.redact)
    else:
        text = render_console(results, args.redact)

    if args.format == "jsonl":
        # NDJSON: mỗi dòng kết thúc bằng \n; không có finding thì không in gì cả.
        if args.output:
            _write_atomic(Path(args.output), text + "\n" if text else "")
        elif text:
            print(text)
    elif args.output:
        _write_atomic(Path(args.output), text)
    else:
        print(text)

    if stats.errors:
        code = EXIT_SCAN_ERROR
    elif results:
        code = EXIT_FINDINGS
    else:
        code = EXIT_CLEAN

    if args.summary_file:
        summary = {
            "schema_version": "1",
            "path": str(path),
            "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "duration_seconds": round(duration, 3),
            "findings": len(results),
            "hidden": filtered,
            "exit_code": code,
            **stats.to_dict(),
        }
        _write_atomic(Path(args.summary_file), json.dumps(summary, ensure_ascii=False, indent=2))

    if not args.quiet:
        print(_human_summary(stats, len(results), duration, code, filtered), file=sys.stderr)
        for p, err in stats.errors[:10]:
            print(f"dlp-scan: error: {p}: {err}", file=sys.stderr)
        if len(stats.errors) > 10:
            print(f"dlp-scan: ... and {len(stats.errors) - 10} more error(s)", file=sys.stderr)

    return code