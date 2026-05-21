#!/usr/bin/env bash
set -euo pipefail

FLOW_COLLECTOR_PORT="${FLOW_COLLECTOR_PORT:-2055}"
FLOW_LISTEN="${FLOW_LISTEN:-netflow://:${FLOW_COLLECTOR_PORT}}"
GOFLOW_FORMAT="${GOFLOW_FORMAT:-json}"

cat <<MSG
[ndr-flow-collector] Starting
[ndr-flow-collector] Listen: ${FLOW_LISTEN}
[ndr-flow-collector] Format: ${GOFLOW_FORMAT}
[ndr-flow-collector] OpenSearch: ${OS_URL:-https://127.0.0.1:9200}
[ndr-flow-collector] Index prefix: ${OS_INDEX_PREFIX:-ndr-flows}
MSG

# GoFlow2 logs may include non-JSON lines. The Python normalizer safely ignores them.
exec /usr/local/bin/goflow2 \
  -listen="${FLOW_LISTEN}" \
  -format="${GOFLOW_FORMAT}" \
  | python3 -u /app/flow_to_opensearch.py
