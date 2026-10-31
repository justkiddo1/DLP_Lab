#!/usr/bin/env python3
"""Sinh dữ liệu GIẢ để thử tốc độ và độ chính xác của dlp-scan.

Chỉ dùng thư viện chuẩn của Python (không cần cài thêm gì).

Tạo ra trong thư mục --out:
  employees_0001.csv, employees_0002.csv, ...   (bảng có cột PII)
  app_0001.log,       app_0002.log, ...         (log tự do, PII nằm lẫn trong câu)
  manifest.meta                                 (đáp án: đã "gài" bao nhiêu mục mỗi loại)

Mỗi file được cắt nhỏ dưới --max-mb (mặc định 8 MB) vì scanner của bạn
bỏ qua file lớn hơn MAX_BYTES (10 MB).

Ví dụ:
  python gen_data.py --rows 10000  --log-lines 20000  --out data\\bench_small
  python gen_data.py --rows 200000 --log-lines 400000 --out data\\bench_big
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

DIGITS = "0123456789"

HO = ["Nguyen", "Tran", "Le", "Pham", "Hoang", "Vu", "Dang", "Bui", "Do", "Ngo"]
DEM = ["Van", "Thi", "Minh", "Quoc", "Ngoc", "Thanh", "Hong", "Gia"]
TEN = ["An", "Binh", "Chi", "Dung", "Hanh", "Huy", "Khanh", "Lan", "Linh",
       "Nam", "Phuc", "Quang", "Trang", "Tuan", "Vy", "Yen"]
DEPTS = ["Sales", "HR", "IT", "Finance", "Support", "Legal", "Ops"]
DOMAINS = ["example.com", "example.org", "example.net"]  # tên miền dành riêng, không phải của ai

COUNT_KEYS = [
    "email", "us_ssn", "credit_card", "vn_phone", "vn_cccd",
    "trap_card_bad_luhn", "trap_digits12", "trap_short",
]


# ---------------------------------------------------------------- bộ sinh giá trị
def luhn_check_digit(partial: str) -> str:
    """Chữ số kiểm tra Luhn cho dãy số `partial` (chưa gồm chữ số cuối)."""
    total = 0
    for i, ch in enumerate(reversed(partial), start=1):
        d = int(ch)
        if i % 2 == 1:  # chữ số cuối của `partial` sẽ nằm ở vị trí 2 -> bị nhân đôi
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def gen_card(rng: random.Random, valid: bool = True) -> tuple[str, str]:
    brand = rng.choices(["visa", "mc", "amex"], weights=[6, 3, 1])[0]
    if brand == "visa":
        body = "4" + "".join(rng.choices(DIGITS, k=14))
    elif brand == "mc":
        body = "5" + str(rng.randint(1, 5)) + "".join(rng.choices(DIGITS, k=13))
    else:
        body = "3" + rng.choice("47") + "".join(rng.choices(DIGITS, k=12))
    number = body + luhn_check_digit(body)
    if not valid:  # đổi chữ số cuối -> chắc chắn sai Luhn
        number = number[:-1] + str((int(number[-1]) + 1) % 10)
    return number, brand


def format_card(rng: random.Random, number: str, brand: str) -> str:
    style = rng.choice(["plain", "space", "dash"])
    if style == "plain":
        return number
    sep = " " if style == "space" else "-"
    if brand == "amex":
        groups = [number[:4], number[4:10], number[10:]]
    else:
        groups = [number[i:i + 4] for i in range(0, len(number), 4)]
    return sep.join(groups)


def gen_phone(rng: random.Random) -> str:
    prefix = rng.choice(["0", "0", "+84"])
    return prefix + rng.choice("35789") + "".join(rng.choices(DIGITS, k=8))


def gen_cccd(rng: random.Random) -> str:
    # 3 số tỉnh + 1 số giới tính/thế kỷ + 2 số năm sinh + 6 số ngẫu nhiên = 12 số
    return f"{rng.randint(1, 96):03d}{rng.randint(0, 3)}{rng.randint(0, 99):02d}{rng.randint(0, 999999):06d}"


def gen_ssn(rng: random.Random) -> str:
    # vùng 000 không bao giờ được cấp phát cho người thật
    return f"000-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def gen_email(rng: random.Random, ho: str, ten: str) -> str:
    local = f"{ten}.{ho}".lower()
    if rng.random() < 0.5:
        local += str(rng.randint(1, 999))
    return f"{local}@{rng.choice(DOMAINS)}"


def gen_digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choices(DIGITS, k=n))


# ---------------------------------------------------------------- ghi file chia mảnh
class ShardWriter:
    """Ghi dòng vào file; vượt max_bytes thì mở file kế tiếp."""

    def __init__(self, outdir: Path, prefix: str, suffix: str,
                 max_bytes: int, header: str | None = None) -> None:
        self.outdir, self.prefix, self.suffix = outdir, prefix, suffix
        self.max_bytes, self.header = max_bytes, header
        self.index = 0
        self.size = 0
        self.fh = None
        self.files: list[str] = []
        self.total_bytes = 0

    def _raw(self, line: str) -> None:
        self.fh.write(line + "\n")
        self.size += len(line) + 1      # toàn ký tự ASCII nên 1 ký tự = 1 byte
        self.total_bytes += len(line) + 1

    def _open_next(self) -> None:
        if self.fh:
            self.fh.close()
        self.index += 1
        path = self.outdir / f"{self.prefix}_{self.index:04d}{self.suffix}"
        self.fh = path.open("w", encoding="utf-8", newline="\n")
        self.files.append(path.name)
        self.size = 0
        if self.header:
            self._raw(self.header)

    def write(self, line: str) -> None:
        if self.fh is None or self.size + len(line) + 1 > self.max_bytes:
            self._open_next()
        self._raw(line)

    def close(self) -> None:
        if self.fh:
            self.fh.close()
            self.fh = None


# ---------------------------------------------------------------- sinh từng dòng
def csv_row(rng: random.Random, i: int, counts: dict[str, int]) -> str:
    ho, dem, ten = rng.choice(HO), rng.choice(DEM), rng.choice(TEN)
    name = f"{ho} {dem} {ten}"

    phone = email = ssn = card = cccd = note = ""
    if rng.random() < 0.80:
        phone = gen_phone(rng)
        counts["vn_phone"] += 1
    if rng.random() < 0.80:
        email = gen_email(rng, ho, ten)
        counts["email"] += 1
    if rng.random() < 0.15:
        ssn = gen_ssn(rng)
        counts["us_ssn"] += 1
    if rng.random() < 0.40:
        number, brand = gen_card(rng, valid=True)
        card = format_card(rng, number, brand)
        counts["credit_card"] += 1
    if rng.random() < 0.60:
        cccd = gen_cccd(rng)
        counts["vn_cccd"] += 1

    r = rng.random()
    if r < 0.05:      # mã đơn hàng 16 số SAI Luhn: không được báo là thẻ
        number, _ = gen_card(rng, valid=False)
        note = f"order {number}"
        counts["trap_card_bad_luhn"] += 1
    elif r < 0.08:    # mã vận đơn 12 số: scanner hiện tại sẽ báo nhầm là CCCD (điểm thấp)
        note = f"tracking {gen_digits(rng, 12)}"
        counts["trap_digits12"] += 1
    elif r < 0.10:    # số quá ngắn/quá dài: không được báo
        note = f"ref {gen_digits(rng, rng.choice([9, 11]))}"
        counts["trap_short"] += 1

    return f"{i},{name},{phone},{email},{ssn},{card},{cccd},{rng.choice(DEPTS)},{note}"


CLEAN_TEMPLATES = [
    "INFO user=u{n} action=login ip=10.{a}.{b}.{c} latency={ms}ms",
    "INFO GET /api/items/{n} status=200 latency={ms}ms",
    "WARN cache miss key=item:{n}",
    "DEBUG worker-{k} heartbeat ok",
    "INFO session u{n} closed after {ms}s",
]


def log_line(rng: random.Random, stamp: str, counts: dict[str, int], pii_ratio: float) -> str:
    if rng.random() >= pii_ratio:
        t = rng.choice(CLEAN_TEMPLATES)
        body = t.format(n=rng.randint(1, 99999), a=rng.randint(0, 255), b=rng.randint(0, 255),
                        c=rng.randint(0, 255), ms=rng.randint(1, 999), k=rng.randint(1, 8))
        return f"{stamp} {body}"

    ho, ten = rng.choice(HO), rng.choice(TEN)
    kind = rng.choice(["card", "card_bare", "phone", "cccd", "email", "ssn",
                       "trap_luhn", "trap12"])
    if kind == "card":
        number, brand = gen_card(rng)
        counts["credit_card"] += 1
        return f"{stamp} INFO payment ok card {format_card(rng, number, brand)} amount={rng.randint(1, 999) * 1000}"
    if kind == "card_bare":
        number, brand = gen_card(rng)
        counts["credit_card"] += 1
        return f"{stamp} DEBUG payload value={format_card(rng, number, brand)} end"
    if kind == "phone":
        counts["vn_phone"] += 1
        return f"{stamp} WARN contact customer phone {gen_phone(rng)} retry={rng.randint(1, 5)}"
    if kind == "cccd":
        counts["vn_cccd"] += 1
        return f"{stamp} INFO verify CCCD: {gen_cccd(rng)} result=ok"
    if kind == "email":
        counts["email"] += 1
        return f"{stamp} DEBUG send mail to {gen_email(rng, ho, ten)} template=welcome"
    if kind == "ssn":
        counts["us_ssn"] += 1
        return f"{stamp} ERROR ssn lookup failed {gen_ssn(rng)} code=404"
    if kind == "trap_luhn":
        number, _ = gen_card(rng, valid=False)
        counts["trap_card_bad_luhn"] += 1
        return f"{stamp} INFO order {number} shipped"
    counts["trap_digits12"] += 1
    return f"{stamp} INFO tracking {gen_digits(rng, 12)} in transit"


# ---------------------------------------------------------------- chương trình chính
def main() -> None:
    ap = argparse.ArgumentParser(description="Sinh dữ liệu giả để thử dlp-scan")
    ap.add_argument("--rows", type=int, default=10_000, help="số dòng CSV (mặc định 10000)")
    ap.add_argument("--log-lines", type=int, default=20_000, help="số dòng log (mặc định 20000)")
    ap.add_argument("--out", default="data/bench", help="thư mục đầu ra")
    ap.add_argument("--seed", type=int, default=42, help="seed ngẫu nhiên, cùng seed ra cùng dữ liệu")
    ap.add_argument("--max-mb", type=float, default=8.0, help="kích thước tối đa mỗi file (MB)")
    ap.add_argument("--pii-ratio", type=float, default=0.10, help="tỉ lệ dòng log có PII (0-1)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    max_bytes = int(args.max_mb * 1024 * 1024)

    counts = {k: 0 for k in COUNT_KEYS}
    t0 = time.perf_counter()

    csv_w = ShardWriter(outdir, "employees", ".csv", max_bytes,
                        header="id,full_name,phone,email,ssn,card_number,cccd,department,note")
    for i in range(1, args.rows + 1):
        csv_w.write(csv_row(rng, i, counts))
    csv_w.close()

    log_w = ShardWriter(outdir, "app", ".log", max_bytes)
    for i in range(args.log_lines):
        s = i % 86400
        stamp = f"2026-10-31 {s // 3600:02d}:{s // 60 % 60:02d}:{s % 60:02d}"
        log_w.write(log_line(rng, stamp, counts, args.pii_ratio))
    log_w.close()

    expected = {
        "email": counts["email"],
        "us_ssn": counts["us_ssn"],
        "credit_card": counts["credit_card"],
        "vn_phone": counts["vn_phone"],
        # mã vận đơn 12 số cũng khớp CCCD (điểm 0.20 = đúng ngưỡng) nên scanner hiện tại sẽ báo
        "vn_cccd": counts["vn_cccd"] + counts["trap_digits12"],
    }
    manifest = {
        "params": {"rows": args.rows, "log_lines": args.log_lines, "seed": args.seed,
                   "pii_ratio": args.pii_ratio, "max_mb": args.max_mb},
        "files": {"csv": csv_w.files, "log": log_w.files},
        "total_bytes": csv_w.total_bytes + log_w.total_bytes,
        "planted": counts,
        "expected_findings_with_current_rules": expected,
        "note": ("vn_cccd bao gồm cả mã vận đơn 12 số (trap_digits12). "
                 "Nếu bạn đổi base_score/ngưỡng của CCCD thì con số này sẽ lệch, đó là bình thường. "
                 "trap_card_bad_luhn và trap_short KHÔNG được xuất hiện trong kết quả."),
    }
    (outdir / "manifest.meta").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    elapsed = time.perf_counter() - t0
    mb = manifest["total_bytes"] / (1024 * 1024)
    n_files = len(csv_w.files) + len(log_w.files)
    print(f"Đã tạo {n_files} file, {mb:.1f} MB trong {elapsed:.1f}s -> {outdir}")
    print("Đáp án (số phát hiện kỳ vọng với luật hiện tại):")
    for k, v in expected.items():
        print(f"  {k:12s} {v}")
    print(f"Bẫy không được báo: trap_card_bad_luhn={counts['trap_card_bad_luhn']}, "
          f"trap_short={counts['trap_short']}")


if __name__ == "__main__":
    main()