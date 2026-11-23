"""Đo thời gian và RAM đỉnh khi quét một thư mục bằng chính CLI của dự án.

Cách dùng (từ thư mục gốc dlp_lab):
    python tools/bench.py data/bench_mid
    python tools/bench.py data/bench_mid --format console --output ketqua.txt
Kết quả (báo cáo) được ghi ra file --output, KHÔNG nên đặt trong thư mục đang quét.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dlp.cli import main  # noqa: E402


def peak_memory_mb() -> float:
    try:  # Linux / macOS
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except ImportError:
        pass
    try:  # Windows: cần  pip install psutil
        import psutil
        info = psutil.Process().memory_info()
        return getattr(info, "peak_wset", info.rss) / (1024 * 1024)
    except ImportError:
        return float("nan")


def dir_size_mb(root: Path) -> float:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file()) / (1024 * 1024)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--format", default="json", choices=["json", "console"])
    ap.add_argument("--output", default="bench_report.out")
    a = ap.parse_args()

    root = Path(a.path)
    t0 = time.perf_counter()
    code = main(["file", a.path, "-f", a.format, "-o", a.output])
    dt = time.perf_counter() - t0
    mb = dir_size_mb(root) if root.is_dir() else root.stat().st_size / (1024 * 1024)
    rep = Path(a.output).stat().st_size / (1024 * 1024)
    print(f"exit={code}  dữ liệu={mb:.1f} MB  thời gian={dt:.2f}s  ({mb / dt:.2f} MB/s)")
    print(f"RAM đỉnh={peak_memory_mb():.0f} MB   báo cáo={rep:.1f} MB")