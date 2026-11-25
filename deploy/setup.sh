#!/bin/sh
# Chạy trong container curlimages/curl (xem docker-compose.yaml).
set -eu

for f in /template.json /dlp-kibana.ndjson; do
  if [ ! -f "$f" ]; then
    echo "[setup] LOI: $f khong phai file. Kiem tra lai duong dan trong deploy/ (neu Docker da tu tao mot THU MUC trung ten, hay xoa no va chep file that vao)"
    exit 1
  fi
done

ES=http://elasticsearch:9200
KB=http://kibana:5601
RULE_ID=51c9164b-da2d-4c4c-8db5-9401a07c79e3

echo "[setup] cai index template dlp-findings"
curl -sSf -X PUT "$ES/_index_template/dlp-findings" \
  -H 'Content-Type: application/json' --data-binary @/template.json
echo

echo "[setup] nap dashboard, rule, connector va data view vao Kibana"
curl -sSf -X POST "$KB/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' --form file=@/dlp-kibana.ndjson -o /tmp/import.json
cat /tmp/import.json
echo
if ! grep -q '"success":true' /tmp/import.json; then
  echo "[setup] LOI: nap saved objects that bai (xem noi dung o tren)"
  exit 1
fi

echo "[setup] bat rule canh bao (rule nhap vao luon o trang thai tat)"
curl -sSf -X POST "$KB/api/alerting/rule/$RULE_ID/_enable" -H 'kbn-xsrf: true' \
  || echo "[setup] canh bao: khong bat duoc rule, hay bat tay trong Stack Management > Rules"
echo
echo "[setup] xong"