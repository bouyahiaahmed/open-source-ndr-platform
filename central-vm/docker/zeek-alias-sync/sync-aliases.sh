#!/usr/bin/env bash
# sync-aliases.sh
#
# Manages OpenSearch aliases for Zeek indices.
#
# DESIGN:
#   • For every rolled index type (zeek-conn-2026.04.08 → type 'conn'):
#     Issues idempotent PUT /zeek-conn-*/_alias/zeek-conn every cycle.
#     This automatically covers new day-shards as they appear.
#   • Static indices (zeek-logs — no date suffix) need no alias.
#   • Reconciles deletions: if all indices for a type vanish (deleted),
#     there's nothing to alias — on next poll the PUT will just succeed with 0 targets.
#     When the indices come back, the alias is re-attached automatically.
#   • POLL_INTERVAL_SECONDS defaults to 10 for near-instant response.
#
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:?missing OPENSEARCH_URL}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:?missing OPENSEARCH_USERNAME}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:?missing OPENSEARCH_PASSWORD}"

INDEX_PREFIX="${INDEX_PREFIX:-zeek-}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-10}"
INSECURE_TLS="${INSECURE_TLS:-true}"
INITIAL_WAIT_SECONDS="${INITIAL_WAIT_SECONDS:-120}"
MIN_EXPECTED_INDICES="${MIN_EXPECTED_INDICES:-3}"

[[ "${INSECURE_TLS}" == "true" ]] && TLS="-k" || TLS=""

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

os_curl() {
  curl -sS ${TLS} -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" "$@"
}

# ── wait helpers ──────────────────────────────────────────────────────────────

wait_for_opensearch() {
  log "Waiting for OpenSearch..."
  until os_curl "${OPENSEARCH_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" \
      | jq -e '.status != null' >/dev/null 2>&1; do
    sleep 3
  done
  log "OpenSearch is ready."
}

get_index_names() {
  os_curl "${OPENSEARCH_URL}/_cat/indices/${INDEX_PREFIX}*?h=index&format=json" \
    2>/dev/null | jq -r '.[].index' 2>/dev/null || true
}

wait_for_indices() {
  log "Waiting for at least ${MIN_EXPECTED_INDICES} indices with prefix '${INDEX_PREFIX}'..."
  local start=$( date +%s )
  while true; do
    local n
    n=$( get_index_names | grep -c . 2>/dev/null || echo 0 )
    if [[ "${n}" -ge "${MIN_EXPECTED_INDICES}" ]]; then
      log "Found ${n} indices — proceeding."
      return
    fi
    local elapsed=$(( $(date +%s) - start ))
    if [[ "${elapsed}" -ge "${INITIAL_WAIT_SECONDS}" ]]; then
      log "Timeout reached with ${n} indices — proceeding anyway."
      return
    fi
    log "Still waiting... (${n}/${MIN_EXPECTED_INDICES} found)"
    sleep 3
  done
}

# ── type helpers ──────────────────────────────────────────────────────────────

# zeek-conn-2026.04.08 → conn
index_to_type() {
  local name="${1#${INDEX_PREFIX}}"
  echo "${name}" | sed -E 's/-[0-9]{4}\.[0-9]{2}\.[0-9]{2}.*$//'
}

is_rolled() {
  echo "$1" | grep -qE -- '-[0-9]{4}\.[0-9]{2}\.[0-9]{2}'
}

# ── alias management ──────────────────────────────────────────────────────────

# Idempotent: PUT /zeek-TYPE-*/_alias/zeek-TYPE
# Safe to call every cycle — covers all present day-shards.
apply_alias() {
  local type="$1"
  local alias="${INDEX_PREFIX}${type}"
  local target="${INDEX_PREFIX}${type}-*"

  local resp code
  resp=$( os_curl -w "\n%{http_code}" -X PUT \
    "${OPENSEARCH_URL}/${target}/_alias/${alias}" )
  code=$( echo "${resp}" | tail -1 )
  resp=$( echo "${resp}" | head -n -1 )

  if [[ "${code}" =~ ^2 ]]; then
    log "Alias OK: ${alias} → ${target}"
  else
    log "Alias FAILED (HTTP ${code}) for ${alias}: ${resp}"
  fi
}

# ── sync loop ─────────────────────────────────────────────────────────────────

sync_once() {
  # Collect all unique ROLLED types
  declare -A rolled_types=()
  while IFS= read -r idx; do
    [[ -z "${idx}" ]] && continue
    if is_rolled "${idx}"; then
      local t
      t="$( index_to_type "${idx}" )"
      [[ -n "${t}" ]] && rolled_types["${t}"]=1
    fi
  done < <( get_index_names )

  if [[ ${#rolled_types[@]} -eq 0 ]]; then
    log "No rolled indices found — nothing to alias."
    return
  fi

  for type in "${!rolled_types[@]}"; do
    apply_alias "${type}"
  done
}

main() {
  wait_for_opensearch
  wait_for_indices
  log "Starting alias sync loop (poll every ${POLL_INTERVAL_SECONDS}s)..."
  while true; do
    sync_once
    sleep "${POLL_INTERVAL_SECONDS}"
  done
}

main
