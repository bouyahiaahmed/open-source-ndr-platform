#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OS_URL:-https://127.0.0.1:9200}"
OS_USER="${OS_USER:-admin}"
OS_PASS="${OS_PASS:-admin}"
TEMPLATE_PATH="${TEMPLATE_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/mappings/ndr-flows-template.json}"

CURL_TLS_ARGS=(-k)
if [[ "${OS_VERIFY_SSL:-false}" == "true" && -n "${OS_CA_CERT:-}" ]]; then
  CURL_TLS_ARGS=(--cacert "${OS_CA_CERT}")
fi

curl "${CURL_TLS_ARGS[@]}" -u "${OS_USER}:${OS_PASS}" \
  -H 'Content-Type: application/json' \
  -X PUT "${OS_URL%/}/_index_template/ndr-flows-template" \
  --data-binary "@${TEMPLATE_PATH}"

echo
