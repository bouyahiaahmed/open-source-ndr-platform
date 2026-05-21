#!/usr/bin/env bash
# =============================================================
# NDR Central — Production Bootstrap
# =============================================================

set -euo pipefail

CA_CERT="certs/ca/ca.crt"

OS_URL="https://localhost:9200"
DASH_URL="https://localhost:5601"

OS_USER="admin"
OS_PASS="admin"

TODAY=$(date +%Y.%m.%d)
INDEX_NAME="zeek-conn-$TODAY"

CURL="curl --silent --show-error --fail --cacert $CA_CERT"

echo ""
echo "============================================="
echo "  NDR Central — Production Bootstrap"
echo "============================================="
echo ""

# -------------------------------------------------------------
# Wait for OpenSearch
# -------------------------------------------------------------
echo "Waiting for OpenSearch..."
for i in {1..30}; do
  STATUS=$($CURL -u "$OS_USER:$OS_PASS" \
    "$OS_URL/_cluster/health" | jq -r '.status' || echo "")
  if [[ "$STATUS" == "green" || "$STATUS" == "yellow" ]]; then
    echo "[✓] OpenSearch ready ($STATUS)"
    break
  fi
  sleep 3
done

# -------------------------------------------------------------
# Ensure index template
# -------------------------------------------------------------
echo "Ensuring zeek-* index template..."

$CURL -u "$OS_USER:$OS_PASS" \
  -X PUT "$OS_URL/_index_template/zeek-template" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "index_patterns": ["zeek-*"],
  "priority": 100,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "log_type":   { "type": "keyword" },
        "proto":      { "type": "keyword" },
        "id.orig_h":  { "type": "ip" },
        "id.resp_h":  { "type": "ip" },
        "id.orig_p":  { "type": "integer" },
        "id.resp_p":  { "type": "integer" }
      }
    }
  }
}
EOF

echo "[✓] Template ensured"


# -------------------------------------------------------------
# Clean up any stale indices from today (wrong mapping)
# -------------------------------------------------------------
echo "Cleaning up stale indices from today..."
for LOG_TYPE in conn dns http ssl files weird notice other; do
  MAPPING=$(curl --silent --cacert "$CA_CERT" \
    -u "$OS_USER:$OS_PASS" \
    "$OS_URL/zeek-${LOG_TYPE}-${TODAY}/_mapping" 2>/dev/null)
  TS_TYPE=$(echo "$MAPPING" | jq -r '.. | objects | .["@timestamp"].type? // empty' 2>/dev/null | head -1)
  if [[ "$TS_TYPE" != "date" && -n "$(echo $MAPPING | grep -v 'index_not_found')" ]]; then
    curl --silent --cacert "$CA_CERT" \
      -u "$OS_USER:$OS_PASS" \
      -X DELETE "$OS_URL/zeek-${LOG_TYPE}-${TODAY}" \
      >/dev/null 2>&1 || true
    echo "  [!] Deleted bad index: zeek-${LOG_TYPE}-${TODAY}"
  fi
done
echo "[✓] Stale indices checked"

# -------------------------------------------------------------
# Inject sample logs only if empty
# -------------------------------------------------------------
COUNT=$($CURL -u "$OS_USER:$OS_PASS" \
  "$OS_URL/$INDEX_NAME/_count" | jq -r '.count' 2>/dev/null || echo "0")

if [[ "$COUNT" == "0" ]]; then
  echo "Injecting sample logs..."

  NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  $CURL -u "$OS_USER:$OS_PASS" \
    -X POST "$OS_URL/$INDEX_NAME/_doc" \
    -H "Content-Type: application/json" \
    -d "{
      \"@timestamp\": \"$NOW\",
      \"log_type\": \"conn\",
      \"proto\": \"tcp\",
      \"id.orig_h\": \"192.168.1.10\",
      \"id.resp_h\": \"8.8.8.8\",
      \"id.orig_p\": 51514,
      \"id.resp_p\": 53
    }" >/dev/null

  $CURL -u "$OS_USER:$OS_PASS" \
    -X POST "$OS_URL/$INDEX_NAME/_doc" \
    -H "Content-Type: application/json" \
    -d "{
      \"@timestamp\": \"$NOW\",
      \"log_type\": \"conn\",
      \"proto\": \"udp\",
      \"id.orig_h\": \"192.168.1.20\",
      \"id.resp_h\": \"1.1.1.1\",
      \"id.orig_p\": 53000,
      \"id.resp_p\": 443
    }" >/dev/null

  echo "[✓] Sample logs injected"
else
  echo "[✓] Logs already exist ($COUNT docs)"
fi

# -------------------------------------------------------------
# Wait for Dashboards
# -------------------------------------------------------------
echo "Waiting for Dashboards..."
for i in {1..30}; do
  HTTP=$(curl --silent --output /dev/null \
    --cacert "$CA_CERT" \
    -u "$OS_USER:$OS_PASS" \
    -w "%{http_code}" \
    "$DASH_URL/api/status" || echo "000")
  if [[ "$HTTP" == "200" ]]; then
    echo "[✓] Dashboards ready"
    break
  fi
  sleep 3
done

# -------------------------------------------------------------
# Reset index pattern (idempotent)
# -------------------------------------------------------------
echo "Resetting index pattern..."

curl --silent --cacert "$CA_CERT" \
  -u "$OS_USER:$OS_PASS" \
  -H "osd-xsrf: true" \
  -X DELETE \
  "$DASH_URL/api/saved_objects/index-pattern/zeek-star" \
  >/dev/null 2>&1 || true

echo "[✓] Old index pattern removed (if existed)"

# -------------------------------------------------------------
# Create index pattern
# -------------------------------------------------------------
echo "Creating index pattern..."

$CURL -u "$OS_USER:$OS_PASS" \
  -H "osd-xsrf: true" \
  -H "Content-Type: application/json" \
  -X POST \
  "$DASH_URL/api/saved_objects/index-pattern/zeek-star" \
  -d '{
    "attributes": {
      "title": "zeek-*",
      "timeFieldName": "@timestamp"
    }
  }' >/dev/null

echo "[✓] Index pattern created"

# -------------------------------------------------------------
# Set default index pattern
# -------------------------------------------------------------
echo "Setting default index pattern..."

$CURL -u "$OS_USER:$OS_PASS" \
  -H "osd-xsrf: true" \
  -H "Content-Type: application/json" \
  -X POST \
  "$DASH_URL/api/opensearch-dashboards/settings" \
  -d '{"changes":{"defaultIndex":"zeek-star"}}' >/dev/null

echo "[✓] Default index pattern set"

echo ""
echo "============================================="
echo " Bootstrap completed successfully."
echo "============================================="
echo ""
