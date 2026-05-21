#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
USERS_FILE="${ROOT_DIR}/users/users.json"
CERTS_DIR="${ROOT_DIR}/certs"

# Load environment variables
# shellcheck disable=SC1090
source "${ENV_FILE}"

OS_URL="${OS_URL:-https://localhost:9200}"

ADMIN_CERT="${CERTS_DIR}/admin/admin.crt"
ADMIN_KEY="${CERTS_DIR}/admin/admin.key"
CA_CERT="${CERTS_DIR}/ca/ca.crt"

for f in "$ADMIN_CERT" "$ADMIN_KEY" "$CA_CERT" "$USERS_FILE"; do
  [ -f "$f" ] || { echo "❌ Missing required file: $f"; exit 1; }
done

command -v jq >/dev/null 2>&1 || {
  echo "❌ jq is required but not installed."
  exit 1
}

echo "🔐 Creating users defined in users/users.json via Security REST API (mTLS)..."

USER_COUNT=$(jq '.users | length' "$USERS_FILE")

for ((i=0; i<USER_COUNT; i++)); do

  USERNAME_ENV=$(jq -r ".users[$i].username_env" "$USERS_FILE")
  PASSWORD_ENV=$(jq -r ".users[$i].password_env" "$USERS_FILE")

  USERNAME="${!USERNAME_ENV:-}"
  PASSWORD="${!PASSWORD_ENV:-}"

  if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "❌ Environment variables for user index $i not properly set."
    echo "   username_env=$USERNAME_ENV password_env=$PASSWORD_ENV"
    exit 1
  fi

  echo "👤 Processing user: ${USERNAME}"

  # Create / update user
  CREATE_STATUS=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    --cacert "$CA_CERT" \
    -H "Content-Type: application/json" \
    -o /tmp/create_user_response.json \
    -w "%{http_code}" \
    -X PUT "${OS_URL}/_plugins/_security/api/internalusers/${USERNAME}" \
    -d "{
          \"password\": \"${PASSWORD}\",
          \"attributes\": {
            \"managed_by\": \"bootstrap-script\"
          }
        }")

  if [[ "$CREATE_STATUS" != "200" && "$CREATE_STATUS" != "201" ]]; then
    echo "❌ Failed to create user '${USERNAME}' (HTTP ${CREATE_STATUS})"
    cat /tmp/create_user_response.json
    exit 1
  fi

  # Map roles
  ROLE_COUNT=$(jq ".users[$i].roles | length" "$USERS_FILE")

  for ((r=0; r<ROLE_COUNT; r++)); do
    ROLE=$(jq -r ".users[$i].roles[$r]" "$USERS_FILE")

    ROLE_CHECK=$(curl -sk -o /dev/null -w "%{http_code}" \
      --cert "$ADMIN_CERT" \
      --key "$ADMIN_KEY" \
      --cacert "$CA_CERT" \
      "${OS_URL}/_plugins/_security/api/rolesmapping/${ROLE}")

    if [[ "$ROLE_CHECK" != "200" ]]; then
      echo "⚠️  Role '${ROLE}' does not exist — skipping"
      continue
    fi

    PATCH_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
      --cert "$ADMIN_CERT" \
      --key "$ADMIN_KEY" \
      --cacert "$CA_CERT" \
      -X PATCH "${OS_URL}/_plugins/_security/api/rolesmapping/${ROLE}" \
      -H "Content-Type: application/json" \
      -d "[
            {\"op\": \"add\", \"path\": \"/users\", \"value\": [\"${USERNAME}\"]}
          ]")

    if [[ "$PATCH_STATUS" != "200" ]]; then
      echo "❌ Failed to map role '${ROLE}' to '${USERNAME}'"
      exit 1
    fi

    echo "   🔗 Mapped role '${ROLE}'"
  done

  echo "✅ User '${USERNAME}' processed successfully"
done

echo "🎉 All users from users/users.json processed successfully."
