#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?Missing OPENSEARCH_INITIAL_ADMIN_PASSWORD}"

OS_URL="${OS_URL:-https://localhost:9200}"

NEW_PASS="$(openssl rand -base64 24 | tr -d '\n')"

echo "🔄 Rotating bootstrap 'admin' password to a random value..."
echo "NEW admin password: ${NEW_PASS}"
echo

curl -sk -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
  -H "Content-Type: application/json" \
  -X PUT "${OS_URL}/_plugins/_security/api/internalusers/admin" \
  -d "{
    \"password\": \"${NEW_PASS}\",
    \"attributes\": {\"rotated_by\": \"rotate-initial-admin.sh\"}
  }" | sed 's/\\n/\n/g'

echo
echo "✅ Bootstrap admin password rotated."
