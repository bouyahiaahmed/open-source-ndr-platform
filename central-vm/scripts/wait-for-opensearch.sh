#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if [ ! -f "${ENV_FILE}" ]; then
  echo "❌ Missing .env at ${ENV_FILE}"
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?Missing OPENSEARCH_INITIAL_ADMIN_PASSWORD in .env}"

OS_URL="${OS_URL:-https://localhost:9200}"

echo "⏳ Waiting for OpenSearch at ${OS_URL} ..."

for i in $(seq 1 120); do
  if curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "${OS_URL}" >/dev/null 2>&1; then
    echo "✅ OpenSearch is responding with auth."
    exit 0
  fi
  sleep 2
done

echo "❌ Timeout waiting for OpenSearch."
exit 1
