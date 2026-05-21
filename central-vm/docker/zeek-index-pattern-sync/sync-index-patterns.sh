#!/usr/bin/env bash
# sync-index-patterns.sh
#
# Manages OpenSearch Dashboards index patterns for Zeek indices.
#
# DESIGN:
#   • Uses the data_views API (OSD 3.x) for both CREATION and REFRESH.
#     This is the ONLY API that correctly registers patterns with OSD's
#     internal IndexPatternsService — which is why the old saved_objects
#     approach caused persistent 404s on refresh.
#   • Falls back to the index_patterns API (OSD 2.x compat path).
#   • No in-memory state: every cycle checks OSD directly, so manually
#     deleted patterns are detected and recreated within POLL_INTERVAL.
#   • Reconciles deletions: if a pattern's underlying index has no data,
#     the pattern is removed from OSD automatically.
#   • Deduplicates: cleans up any stale per-day patterns (zeek-conn-2026.04.08)
#     on startup and replaces with correct wildcard versions (zeek-conn-*).
#   • POLL_INTERVAL_SECONDS defaults to 10 for near-instant response.
#
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:?missing OPENSEARCH_URL}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:?missing OPENSEARCH_USERNAME}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:?missing OPENSEARCH_PASSWORD}"

OPENSEARCH_DASHBOARDS_URL="${OPENSEARCH_DASHBOARDS_URL:?missing OPENSEARCH_DASHBOARDS_URL}"
OPENSEARCH_DASHBOARDS_USERNAME="${OPENSEARCH_DASHBOARDS_USERNAME:?missing OPENSEARCH_DASHBOARDS_USERNAME}"
OPENSEARCH_DASHBOARDS_PASSWORD="${OPENSEARCH_DASHBOARDS_PASSWORD:?missing OPENSEARCH_DASHBOARDS_PASSWORD}"

INDEX_PREFIX="${INDEX_PREFIX:-zeek-}"
DEFAULT_PATTERN="${DEFAULT_PATTERN:-zeek-log*}"
DASHBOARDS_TENANT="${DASHBOARDS_TENANT:-global}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-10}"
INSECURE_TLS="${INSECURE_TLS:-true}"

[[ "${INSECURE_TLS}" == "true" ]] && TLS="-k" || TLS=""

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

os_curl() {
  curl -sS ${TLS} -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" "$@"
}

osd_curl() {
  curl -sS ${TLS} \
    -u "${OPENSEARCH_DASHBOARDS_USERNAME}:${OPENSEARCH_DASHBOARDS_PASSWORD}" \
    -H "osd-xsrf: true" \
    -H "securitytenant: ${DASHBOARDS_TENANT}" \
    -H "Content-Type: application/json" \
    "$@"
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

wait_for_dashboards() {
  log "Waiting for Dashboards..."
  until [[ "$( curl -s -o /dev/null -w '%{http_code}' ${TLS} \
      -u "${OPENSEARCH_DASHBOARDS_USERNAME}:${OPENSEARCH_DASHBOARDS_PASSWORD}" \
      "${OPENSEARCH_DASHBOARDS_URL}/api/status" )" == "200" ]]; do
    sleep 3
  done
  log "Dashboards is ready."
}

# ── OpenSearch helpers ────────────────────────────────────────────────────────

get_index_names() {
  os_curl "${OPENSEARCH_URL}/_cat/indices/${INDEX_PREFIX}*?h=index&format=json" \
    2>/dev/null | jq -r '.[].index' 2>/dev/null || true
}

refresh_os_indices() {
  os_curl -X POST "${OPENSEARCH_URL}/${INDEX_PREFIX}*/_refresh" >/dev/null 2>&1 || true
}

# Count of indices (not docs) matching a pattern. Used to detect if underlying data vanished.
index_count() {
  local pattern="$1"
  os_curl "${OPENSEARCH_URL}/_cat/indices/${pattern}?h=index&format=json" 2>/dev/null \
    | jq 'length' 2>/dev/null || echo 0
}

# ── pattern title / id helpers ────────────────────────────────────────────────

# zeek-conn-2026.04.08        →  zeek-conn-*
# zeek-dns-2026.04.09.000001  →  zeek-dns-*
# zeek-logs                   →  zeek-logs
index_to_pattern_title() {
  local name="$1"
  if echo "${name}" | grep -qE -- '-[0-9]{4}\.[0-9]{2}\.[0-9]{2}'; then
    echo "${name}" | sed -E 's/-[0-9]{4}\.[0-9]{2}\.[0-9]{2}.*$/-*/'
  else
    echo "${name}"
  fi
}

# zeek-conn-*  →  zeek-conn
# zeek-log*    →  zeek-log
# zeek-logs    →  zeek-logs
pattern_to_id() {
  echo "$1" | sed -E 's/\*+$//' | sed -E 's/-+$//'
}

# Returns 0 if a title looks like a per-day mistake: zeek-conn-2026.04.08
is_perday_title() {
  echo "$1" | grep -qE -- "^${INDEX_PREFIX}.+-[0-9]{4}\.[0-9]{2}\.[0-9]{2}$"
}

# ── OSD data_views / index_patterns API ──────────────────────────────────────
# OSD 3.x primary API: /api/data_views/data_view
# OSD 2.x compat API: /api/index_patterns/index_pattern
# We try data_views first; fall back to index_patterns.

# Determine which API base path to use. Cached after first successful probe.
_API_BASE=""
get_api_base() {
  if [[ -n "${_API_BASE}" ]]; then echo "${_API_BASE}"; return; fi
  # Probe data_views endpoint (OSD 3.x)
  local code
  code=$(osd_curl -o /dev/null -w '%{http_code}' \
    "${OPENSEARCH_DASHBOARDS_URL}/api/data_views")
  if [[ "${code}" == "200" ]]; then
    _API_BASE="data_views/data_view"
  else
    _API_BASE="index_patterns/index_pattern"
  fi
  log "Using OSD API: /api/${_API_BASE}"
  echo "${_API_BASE}"
}

# The JSON wrapper key differs between the two APIs.
api_body_key() {
  local base="$1"
  if [[ "${base}" == "data_views/data_view" ]]; then echo "data_view"
  else echo "index_pattern"; fi
}

# Create a pattern. Returns the ID assigned by OSD.
# Uses the data_views or index_patterns API so OSD registers it properly.
create_pattern() {
  local title="$1"
  local preferred_id
  preferred_id="$(pattern_to_id "${title}")"

  local base
  base="$(get_api_base)"
  local key
  key="$(api_body_key "${base}")"

  log "Creating pattern: '${title}' (preferred id=${preferred_id})"

  local body
  body=$(jq -nc \
    --arg title "${title}" \
    --arg id    "${preferred_id}" \
    --arg key   "${key}" \
    '{($key): {title: $title, timeFieldName: "@timestamp", id: $id}}')

  local resp code
  resp=$(osd_curl -w "\n%{http_code}" -X POST \
    "${OPENSEARCH_DASHBOARDS_URL}/api/${base}" \
    -d "${body}")
  code=$(echo "${resp}" | tail -1)
  resp=$(echo "${resp}" | head -n -1)

  if [[ "${code}" =~ ^2 ]]; then
    local assigned_id
    assigned_id=$(echo "${resp}" | jq -r ".${key}.id // \"${preferred_id}\"")
    log "  Pattern created OK: '${title}' (id=${assigned_id})"
    echo "${assigned_id}"
    return 0
  else
    log "  Pattern creation FAILED (HTTP ${code}): ${resp}"
    echo ""
    return 1
  fi
}

# Refresh field list for a pattern using the correct OSD API.
refresh_fields() {
  local id="$1" title="${2:-}"
  local base
  base="$(get_api_base)"

  local code
  code=$(osd_curl -o /dev/null -w '%{http_code}' -X POST \
    "${OPENSEARCH_DASHBOARDS_URL}/api/${base}/${id}/fields/refresh")

  if [[ "${code}" =~ ^2 ]]; then
    log "  Fields refreshed: '${title:-${id}}'"
    return 0
  fi
  # Non-fatal: OSD will serve whatever fields are cached; refresh again next cycle.
  log "  WARN: fields/refresh returned HTTP ${code} for '${title:-${id}}' (will retry next cycle)"
  return 0
}

# ── OSD saved-objects helpers (for reading/deleting) ─────────────────────────

# Returns all index-pattern saved objects from OSD as lines: {id}\t{title}
get_all_osd_patterns() {
  local resp
  resp=$(osd_curl \
    "${OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/_find?type=index-pattern&per_page=500")
  echo "${resp}" | jq -r '.saved_objects[] | "\(.id)\t\(.attributes.title)"' 2>/dev/null || true
}

# Returns 0 if a saved object with this ID already exists.
pattern_exists() {
  local id="$1"
  local code
  code=$(osd_curl -o /dev/null -w '%{http_code}' \
    "${OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/index-pattern/${id}")
  [[ "${code}" == "200" ]]
}

delete_pattern_by_id() {
  local id="$1" title="${2:-}"
  local code
  code=$(osd_curl -o /dev/null -w '%{http_code}' -X DELETE \
    "${OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/index-pattern/${id}")
  if [[ "${code}" =~ ^2 ]]; then
    log "  Deleted pattern: '${title}' (id=${id})"
  else
    log "  WARN: could not delete '${title}' (id=${id}, HTTP ${code})"
  fi
}

# ── default pattern ───────────────────────────────────────────────────────────

set_default_pattern() {
  local id
  id="$(pattern_to_id "${DEFAULT_PATTERN}")"
  local config_id
  config_id=$(osd_curl \
    "${OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/_find?type=config&per_page=1" \
    | jq -r '.saved_objects[0].id // empty')
  [[ -z "${config_id}" ]] && return 0
  local body
  body=$(jq -nc --arg id "${id}" '{attributes:{defaultIndex:$id}}')
  osd_curl -X PUT \
    "${OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/config/${config_id}" \
    -d "${body}" >/dev/null
  log "Default pattern → '${DEFAULT_PATTERN}'"
}

# ── startup cleanup ───────────────────────────────────────────────────────────

# Delete per-day patterns (zeek-conn-2026.04.08) left by previous bad runs.
cleanup_perday_patterns() {
  local found=0
  while IFS=$'\t' read -r id title; do
    [[ -z "${title}" ]] && continue
    if is_perday_title "${title}"; then
      (( found++ )) || true
      delete_pattern_by_id "${id}" "${title}"
    fi
  done < <(get_all_osd_patterns)
  [[ "${found}" -gt 0 ]] \
    && log "Cleaned up ${found} stale per-day pattern(s)." \
    || log "No stale per-day patterns found."
}

# Delete duplicate patterns: if multiple saved objects share the same title,
# keep the one with the shortest ID (our preferred custom ID) and remove the rest.
cleanup_duplicate_patterns() {
  declare -A seen_titles=()
  declare -A title_to_best_id=()
  local found=0

  while IFS=$'\t' read -r id title; do
    [[ -z "${title}" ]] && continue
    if [[ -n "${seen_titles[${title}]+x}" ]]; then
      # Duplicate: keep the one whose id == pattern_to_id(title) — our canonical ID
      local canonical
      canonical="$(pattern_to_id "${title}")"
      if [[ "${id}" == "${canonical}" ]]; then
        # This one is the canonical — delete the one we stored before
        delete_pattern_by_id "${title_to_best_id[${title}]}" "${title} (dup)"
        title_to_best_id["${title}"]="${id}"
      else
        delete_pattern_by_id "${id}" "${title} (dup)"
      fi
      (( found++ )) || true
    else
      seen_titles["${title}"]=1
      title_to_best_id["${title}"]="${id}"
    fi
  done < <(get_all_osd_patterns | sort)   # sort so canonical IDs come first alphabetically

  [[ "${found}" -gt 0 ]] \
    && log "Cleaned up ${found} duplicate pattern(s)." \
    || log "No duplicate patterns found."
}

# ── main sync loop ────────────────────────────────────────────────────────────

sync_once() {
  refresh_os_indices

  # ── Build wanted pattern set from current indices ──────────────────────────
  declare -A wanted=()   # title → 1
  while IFS= read -r idx; do
    [[ -z "${idx}" ]] && continue
    local pt
    pt="$(index_to_pattern_title "${idx}")"
    [[ -n "${pt}" ]] && wanted["${pt}"]=1
  done < <(get_index_names)

  # ── Reconcile: delete OSD patterns whose data is gone ────────────────────
  while IFS=$'\t' read -r id title; do
    [[ -z "${title}" ]] && continue
    # Only consider zeek-* patterns; skip the catch-all
    [[ "${title}" == "${DEFAULT_PATTERN}" ]] && continue
    [[ "${title}" =~ ^${INDEX_PREFIX} ]] || continue
    # If this pattern is in wanted set, keep it
    [[ -n "${wanted[${title}]+x}" ]] && continue
    # Pattern not in wanted set: check if indices still exist
    local n
    n="$(index_count "${title}")"
    if [[ "${n}" -eq 0 ]]; then
      log "No indices left for '${title}' — removing pattern from OSD."
      delete_pattern_by_id "${id}" "${title}"
    fi
  done < <(get_all_osd_patterns)

  # ── Create missing patterns ───────────────────────────────────────────────
  local new_count=0
  for title in "${!wanted[@]}"; do
    local id
    id="$(pattern_to_id "${title}")"
    if ! pattern_exists "${id}"; then
      local assigned
      assigned="$(create_pattern "${title}")" && {
        [[ -n "${assigned}" ]] && refresh_fields "${assigned}" "${title}"
        (( new_count++ )) || true
      } || true
    else
      # Pattern exists — still refresh fields every cycle to pick up new mappings
      refresh_fields "${id}" "${title}"
    fi
  done

  # ── Ensure catch-all default ──────────────────────────────────────────────
  local default_id
  default_id="$(pattern_to_id "${DEFAULT_PATTERN}")"
  if ! pattern_exists "${default_id}"; then
    # Only create if there's at least one zeek index
    if [[ ${#wanted[@]} -gt 0 ]]; then
      local assigned
      assigned="$(create_pattern "${DEFAULT_PATTERN}")" && {
        [[ -n "${assigned}" ]] && refresh_fields "${assigned}" "${DEFAULT_PATTERN}"
      } || true
    fi
  else
    refresh_fields "${default_id}" "${DEFAULT_PATTERN}"
  fi

  if pattern_exists "${default_id}"; then
    set_default_pattern
  fi

  [[ "${new_count}" -gt 0 ]] && log "Created ${new_count} new pattern(s)."
}

main() {
  wait_for_opensearch
  wait_for_dashboards

  # Probe API once so it's cached
  get_api_base >/dev/null

  log "Running startup cleanup..."
  cleanup_perday_patterns
  cleanup_duplicate_patterns

  log "Starting sync loop (poll every ${POLL_INTERVAL_SECONDS}s)..."
  while true; do
    sync_once
    sleep "${POLL_INTERVAL_SECONDS}"
  done
}

main
