# Đầu ra JSONL (`--format jsonl`)

Mỗi finding là **một dòng JSON** (NDJSON), theo ECS 8.11 cộng namespace tùy biến `dlp`.
Dữ liệu ra stdout (hoặc `-o file`, ghi nguyên tử); cảnh báo/log ra stderr. Không có finding thì không in gì.

| Trường | Ý nghĩa |
|---|---|
| `@timestamp` | Thời điểm quét, UTC ISO 8601 (`...Z`), cùng giá trị cho cả lần chạy |
| `event.id` | Định danh một lần xuất hiện (HMAC của path+line+column+rule+value) |
| `event.kind/category/type/action` | `event` / `["file"]` / `["info"]` / `sensitive-data-match` |
| `event.severity` | 0-100 theo rule (card 90, ssn/cccd 80, phone 40, email 30) |
| `rule.id`, `rule.name` | Rule đã khớp |
| `file.path/name/extension` | File chứa finding |
| `host.name` | Máy chạy tool |
| `dlp.schema_version` | Hiện là `"1"`; đổi/xóa trường thì tăng số này |
| `dlp.line`, `dlp.column` | Vị trí (tính từ 1; cột tính trên text đã chuẩn hóa NFC) |
| `dlp.match_length`, `dlp.confidence` | Độ dài chuỗi khớp, điểm tin cậy 0-1 |
| `dlp.value`, `dlp.redaction` | Giá trị đã che (mặc định `partial`) và mức che |
| `dlp.fingerprint` | HMAC của giá trị đã chuẩn hóa: cùng giá trị ở file khác -> cùng fingerprint |

## Fingerprint
HMAC-SHA256 với khóa bí mật `DLP_FINGERPRINT_KEY` (không dùng hash trần vì SSN/CCCD/SĐT có
không gian giá trị nhỏ, dò ngược được bằng vét cạn). Thiếu khóa, tool dùng khóa mặc định công khai
và in cảnh báo ra stderr: chỉ nên làm vậy khi demo.