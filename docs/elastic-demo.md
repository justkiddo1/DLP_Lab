# Demo end-to-end với Elastic

```
dlp-scan (JSONL/ECS) -> deploy/data/out.jsonl -> Filebeat -> Elasticsearch -> Kibana (Discover, dashboard, cảnh báo)
```

Chỉ dùng để demo trên máy cá nhân: xác thực Elasticsearch bị tắt, các cổng chỉ mở trên 127.0.0.1. Cần Docker Desktop và ~3 GB RAM trống.

## 1. Sinh dữ liệu và quét
```powershell
$env:DLP_FINGERPRINT_KEY = "doi-thanh-chuoi-bi-mat-cua-ban"
$env:PYTHONPATH = "src"
python tools\gen_data.py --rows 5000 --log-lines 10000 --out data\bench_small
python tools\eval_bench.py data\bench_small                      # so với đáp án, phải ra OK
python -m dlp file data\bench_small -f jsonl -o deploy\data\out.jsonl --redact partial
```

## 2. Khởi động stack
```powershell
cd deploy
docker compose up -d
docker compose ps            # setup phải ở trạng thái "Exited (0)"
docker compose logs setup    # thấy "[setup] xong"
```
Lần đầu mất vài phút (tải image, Kibana khởi động chậm).

## 3. Kiểm tra dữ liệu đã vào
```powershell
curl.exe http://localhost:9200/dlp-findings/_count
curl.exe "http://localhost:9200/dlp-findings/_search?size=1&pretty"
```
`count` phải bằng số dòng trong `out.jsonl`. Nạp lại cùng một file **không** làm count tăng (`event.id` được dùng làm `_id`).

## 4. Kibana (http://localhost:5601)
Data view "DLP findings" đã được tạo sẵn. Vào **Discover** và thử các truy vấn KQL:
- `event.severity >= 80`: finding mức cao (thẻ, SSN, CCCD)
- `rule.id : "credit_card" and dlp.confidence >= 0.9`
- `dlp.fingerprint : "<giá trị>"`: tìm cùng một giá trị xuất hiện ở nhiều file

Dashboard (**Analytics > Dashboard > Create**, dùng Lens), gợi ý 4 panel:
1. Số finding theo thời gian (`@timestamp`, đếm bản ghi)
2. Cột theo `rule.id`
3. Top 10 `file.path` có nhiều finding nhất
4. Bảng `rule.id` x `event.severity`

## 5. Cảnh báo "có finding mức cao"
**Stack Management > Rules > Create rule > Elasticsearch query**
- Data view: `DLP findings`, KQL: `event.severity >= 80`
- Điều kiện: số document `is above 0`, trong `5 minutes`, kiểm tra mỗi `1 minute`
- Action: connector **Server log**

Kết hợp với `--baseline`: lần quét định kỳ chỉ ghi finding **mới** vào `out.jsonl`, nên cảnh báo chỉ nổ khi có phát hiện mới thật sự.

## 6. Quét định kỳ (Windows Task Scheduler)
```powershell
python -m dlp file D:\logs -f jsonl -o deploy\data\out.jsonl --baseline baseline.json --summary-file deploy\data\summary.json -q
```
Exit code `3` nghĩa là lần quét không trọn vẹn: nên cảnh báo riêng.

## Xử lý sự cố
- `docker compose logs elasticsearch` / `kibana` / `filebeat` để xem lỗi từng dịch vụ.
- Filebeat không đọc file: file `.jsonl` phải nằm trong `deploy/data/` và dài hơn 64 byte.
- Elasticsearch thoát ngay: tăng RAM cho Docker Desktop (Settings > Resources).
- Dọn sạch: `docker compose down -v` (xóa cả dữ liệu đã nạp).