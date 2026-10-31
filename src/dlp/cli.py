import argparse
import sys
from pathlib import Path

from dlp.report import render_console, render_json
from dlp.scanner import scan_path

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlp-scan", description="Data Loss Prevention scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_file = sub.add_parser("file", help="quét một file hoặc cả thư mục")
    p_file.add_argument("path")
    p_file.add_argument("-f", "--format", choices=["console","json"], default="console")
    p_file.add_argument("-o", "--output", help="ghi báo cáo ra file thay vì in ra màn hình")
    p_file.add_argument("--redact", choices=["partial", "full", "none"], default="partial")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.path)

    if not path.exists():
        print("Error: path does not exist : {path}", file=sys.stderr)
        return 2
    results = scan_path(path)
    if args.format == "json":
        text = render_json(results, args.redact)
    else:
        text = render_console(results, args.redact)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)

    return 1 if results else 0