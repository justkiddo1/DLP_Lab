# Dòng lệnh `dlp-scan file`

```
python -m dlp file <path> [-f console|json|jsonl] [-o FILE] [--redact partial|full|none]
                          [--summary-file FILE] [-q]
                          [--min-confidence 0-1] [--min-severity 0-100]
                          [--baseline FILE | --write-baseline FILE]
```

## Exit code
| Mã | Ý nghĩa |
|---|---|
| 0 | Quét xong, không có phát hiện |
| 1 | Quét xong, có phát hiện |
| 2 | Dùng sai tham số hoặc đường dẫn không tồn tại |
| 3 | Có lỗi khi quét (vd. file bị khóa, không đủ quyền). Kết quả **không đầy đủ**; ưu tiên hơn mã 1 dù vẫn có phát hiện |

Pipeline/SIEM nên coi `3` là "cần xem lại lần quét", không phải "sạch".

## Bản tổng kết
- In ra **stderr** một dòng tổng kết (tắt bằng `-q`), cộng tối đa 10 dòng lỗi. Dữ liệu (`stdout` hoặc `-o`) không bao giờ lẫn với tổng kết.
- `--summary-file` ghi JSON (nguyên tử) gồm: `schema_version`, `path`, `started_at` (UTC), `duration_seconds`, `findings`, `exit_code`, `files_scanned`, `bytes_scanned`, `files_skipped` (lý do -> số file), `skipped_paths`, `errors`, `encodings`.
- Lý do bỏ qua: `unsupported_extension` (chỉ đếm), `too_large`, `binary`, `excluded`.

## Encoding
BOM UTF-8/UTF-16/UTF-32 được nhận diện. Không có BOM thì thử UTF-8, không hợp lệ thì đọc như cp1258.
File chứa byte NUL mà không có BOM (vd. UTF-16 không BOM) bị coi là nhị phân: được **ghi vào tổng kết**, không quét.

## File do chính lệnh ghi ra
`-o` và `--summary-file` (kể cả file `.tmp` tạm) tự động bị loại khỏi lần quét, nên ghi báo cáo vào chính thư mục đang quét là an toàn.

## Giảm nhiễu
- `--min-confidence 0.5`: chỉ báo finding có điểm tin cậy >= 0.5.
- `--min-severity 50`: chỉ báo finding thuộc rule có severity >= 50 (credit_card 90, us_ssn 80, vn_cccd 80, vn_phone 40, email 30; đặt trong `rules.py`).
- Số finding bị ẩn được ghi trong tổng kết (`hidden` trong `--summary-file`, và `(hidden: ...)` ở dòng stderr), nên ẩn bao nhiêu luôn kiểm tra được.
- Exit code tính trên kết quả **sau khi lọc**.

## Baseline (chỉ báo finding mới)
```
dlp-scan file logs/ --write-baseline baseline.json     # ghi mọi finding hiện tại, exit 0, không in báo cáo
dlp-scan file logs/ --baseline baseline.json -f jsonl  # lần sau chỉ báo cái mới
```
- Baseline chỉ chứa fingerprint HMAC, **không có giá trị thô**, nên commit/chia sẻ được.
- Mỗi mục: `rule`, `fingerprint`, `path` (tương đối so với thư mục quét, dấu `/`) và `reason` (để bạn ghi lý do triage). Dòng bị dịch chuyển trong file không làm mất khớp.
- `"path": "*"` bỏ qua giá trị đó ở **mọi file** (vd. số thẻ test `4111 1111 1111 1111`). Tự sửa tay file baseline để thêm.
- Baseline gắn với `DLP_FINGERPRINT_KEY`: đổi khóa thì baseline bị **từ chối** (exit 2) thay vì lặng lẽ không khớp.
- `--baseline` và `--write-baseline` không dùng chung. `--write-baseline` ghi đè file và xóa các `reason` đã ghi tay, nên chỉ dùng để tạo mới.
- File baseline nằm trong thư mục đang quét tự động bị loại khỏi lần quét.