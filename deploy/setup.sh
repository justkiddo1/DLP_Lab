#!/bin/sh
# Chạy trong container curlimages/curl (xem docker-compose.yml).
set -eu
if [ ! -f /template.json ]; then
  echo "[setup] LOI: /template.json khong phai file. Kiem tra deploy/elasticsearch/dlp-findings-template.json"
  echo "        (neu Docker da tu tao mot THU MUC trung ten, hay xoa thu muc do va chep file that vao)"
  exit 1
fi
ES=http://elasticsearch:9200
KB=http://kibana:5601

echo "[setup] cai index template dlp-findings"
curl -sSf -X PUT "$ES/_index_template/dlp-findings" \
  -H 'Content-Type: application/json' --data-binary @/template.json
echo

echo "[setup] tao data view trong Kibana"
curl -sSf -X POST "$KB/api/data_views/data_view" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"data_view":{"title":"dlp-findings*","name":"DLP findings","timeFieldName":"@timestamp"},"override":true}'
echo
echo "[setup] xong"