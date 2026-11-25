#!/usr/bin/env python3
"""So kết quả quét với "đáp án" trong manifest.meta do gen_data.py sinh ra, và đo tốc độ.

Ví dụ:
  python tools/eval_bench.py data/bench_small
  python tools/eval_bench.py data/bench_small --min-confidence 0.5

Cách tính: so SỐ LƯỢNG finding mỗi rule với số lượng đã "gài". Delta = 0 nghĩa là khớp;
delta > 0 là báo thừa (false positive), < 0 là bỏ sót (false negative). Vì chỉ so số lượng
nên một báo thừa và một bỏ sót cùng rule có thể triệt tiêu nhau; dùng như bài kiểm tra
nhanh, không phải bằng chứng chính xác tuyệt đối. Thoát với mã 1 nếu có rule lệch.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from dlp.scanner import ScanStats, scan_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Đánh giá dlp-scan trên dữ liệu từ gen_data.py")
    ap.add_argument("bench_dir", help="thư mục chứa manifest.meta và các file dữ liệu")
    ap.add_argument("--min-confidence", type=float, default=0.0,
                    help="chỉ tính finding có điểm >= ngưỡng này")
    args = ap.parse_args()

    root = Path(args.bench_dir)
    manifest = json.loads((root / "manifest.meta").read_text(encoding="utf-8"))
    expected: dict[str, int] = manifest["expected_findings_with_current_rules"]

    stats = ScanStats()
    t0 = time.perf_counter()
    results = scan_path(root, stats=stats)
    elapsed = time.perf_counter() - t0
    found = Counter(r.finding.rule_id for r in results if r.finding.confidence >= args.min_confidence)

    rules = sorted(set(expected) | set(found))
    print(f"{'rule':<14}{'expected':>10}{'found':>10}{'delta':>8}")
    bad = False
    for rule in rules:
        exp, got = expected.get(rule, 0), found.get(rule, 0)
        delta = got - exp
        bad |= delta != 0
        print(f"{rule:<14}{exp:>10}{got:>10}{delta:>+8}")

    mb = stats.bytes_scanned / (1024 * 1024)
    print(f"\nfiles={stats.files_scanned} size={mb:.1f} MB time={elapsed:.2f}s "
          f"speed={mb / elapsed if elapsed else 0:.1f} MB/s errors={len(stats.errors)}")
    print("RESULT:", "MISMATCH (xem delta)" if bad else "OK (khớp đáp án)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())