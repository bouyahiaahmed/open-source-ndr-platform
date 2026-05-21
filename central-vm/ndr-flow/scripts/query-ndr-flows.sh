#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OS_URL:-https://127.0.0.1:9200}"
OS_USER="${OS_USER:-admin}"
OS_PASS="${OS_PASS:-admin}"

CURL_TLS_ARGS=(-k)
if [[ "${OS_VERIFY_SSL:-false}" == "true" && -n "${OS_CA_CERT:-}" ]]; then
  CURL_TLS_ARGS=(--cacert "${OS_CA_CERT}")
fi

echo "[count]"
curl "${CURL_TLS_ARGS[@]}" -u "${OS_USER}:${OS_PASS}" \
  "${OS_URL%/}/ndr-flows-*/_count?pretty"

echo
echo "[latest flows]"
curl "${CURL_TLS_ARGS[@]}" -u "${OS_USER}:${OS_PASS}" \
  -H 'Content-Type: application/json' \
  -X GET "${OS_URL%/}/ndr-flows-*/_search?pretty" \
  -d '{
    "size": 10,
    "sort": [{ "@timestamp": "desc" }],
    "_source": [
      "@timestamp",
      "observer.vendor",
      "observer.ip",
      "source.ip",
      "source.port",
      "destination.ip",
      "destination.port",
      "network.transport",
      "network.direction",
      "network.bytes",
      "network.packets",
      "netflow.version",
      "ndr.source_type",
      "ndr.collector"
    ]
  }'

echo
