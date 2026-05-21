# ndr-sessionizer

`ndr-sessionizer` is a central, deterministic Zeek sessionization service.

It reads corrected raw Zeek documents from `zeek-logs*`, groups events by Zeek `uid` first, `community_id` second, and a synthetic fallback key when neither exists, then writes normalized session documents to `ndr-sessions-*`.

This service intentionally does **not** redesign or fix the raw `zeek-logs*` template. It assumes the raw Zeek layer is already clean and correctly typed.

## Pipeline position

```text
zeek-logs*
  -> ndr-sessionizer
  -> ndr-sessions-*
  -> future ndr-behaviors-* / ML / ElastAlert2 / dashboards
```

## What this service does

- Connects securely to OpenSearch over HTTPS.
- Reads incrementally from `zeek-logs*`.
- Uses a checkpoint index named `ndr-sessionizer-state`.
- Applies an overlap window to handle late-arriving Zeek events.
- Groups raw documents into session documents.
- Treats `conn.log` as the backbone when present.
- Preserves raw evidence references.
- Preserves raw Zeek event content under `zeek.<log_type>.events[]`.
- Writes idempotent session documents using deterministic OpenSearch document IDs.
- Updates existing sessions when late `ssl`, `notice`, `files`, `weird`, or other logs arrive later.

## What this service does not do

- It does not generate final behavioral detections.
- It does not do ML.
- It does not replace ElastAlert2.
- It does not perform DNS-to-web cross-flow behavior correlation. That belongs in a later `ndr-behaviors-*` layer.
- It does not require any sensor architecture change.

## Raw Zeek preservation strategy

The template uses this mapping:

```json
"zeek": {
  "type": "object",
  "enabled": false
}
```

This is the safest v1 option because stable dashboard/search fields are already normalized at the top level, while raw dynamic Zeek events remain safely stored in `_source`. OpenSearch does not index the dynamic `zeek.*` object, so new Zeek log types and future fields do not create mapping explosion or field conflicts.

If you later need to search individual raw dynamic fields, create a controlled `zeek_summary` layer or promote selected fields into stable normalized mappings.

## Repository structure

```text
ndr-sessionizer/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── opensearch_client.py
│   ├── checkpoint.py
│   ├── reader.py
│   ├── session_builder.py
│   ├── normalizer.py
│   ├── writer.py
│   ├── metrics.py
│   └── utils.py
├── mappings/
│   ├── ndr-sessions-template.json
│   └── ndr-sessionizer-state-template.json
├── tests/
│   ├── test_normalizer.py
│   ├── test_session_builder.py
│   └── fixtures/
├── Dockerfile
├── docker-compose.example.yml
├── requirements.txt
├── config.example.yaml
└── README.md
```

## Configuration

Environment variables:

| Variable | Default |
|---|---|
| `OPENSEARCH_URL` | `https://opensearch:9200` |
| `OPENSEARCH_USERNAME` | `admin` |
| `OPENSEARCH_PASSWORD` | `admin` |
| `OPENSEARCH_CA_CERT` | unset |
| `OPENSEARCH_VERIFY_CERTS` | `true` |
| `SOURCE_INDEX_PATTERN` | `zeek-logs*` |
| `TARGET_INDEX_PREFIX` | `ndr-sessions` |
| `STATE_INDEX` | `ndr-sessionizer-state` |
| `POLL_INTERVAL_SECONDS` | `30` |
| `LOOKBACK_OVERLAP_SECONDS` | `120` |
| `BULK_SIZE` | `500` |
| `MAX_EVENTS_PER_LOG_TYPE_PER_SESSION` | `20` |
| `MAX_EVIDENCE_ITEMS` | `100` |
| `PRESERVE_RAW_EVENT_FIELDS` | `true` |
| `RUN_ONCE` | `false` |
| `DRY_RUN` | `false` |

TLS verification is enabled by default. Do not disable verification in production.

## Apply OpenSearch index templates

From a machine that can reach OpenSearch:

```bash
curl --cacert ./certs/ca/ca.crt \
  -u "$NDR_ADMIN_USERNAME:$NDR_ADMIN_PASSWORD" \
  -X PUT "https://localhost:9200/_index_template/ndr-sessions-template" \
  -H 'Content-Type: application/json' \
  --data-binary @mappings/ndr-sessions-template.json

curl --cacert ./certs/ca/ca.crt \
  -u "$NDR_ADMIN_USERNAME:$NDR_ADMIN_PASSWORD" \
  -X PUT "https://localhost:9200/_index_template/ndr-sessionizer-state-template" \
  -H 'Content-Type: application/json' \
  --data-binary @mappings/ndr-sessionizer-state-template.json
```

For OpenSearch Dashboards Dev Tools:

```http
PUT _index_template/ndr-sessions-template
<copy mappings/ndr-sessions-template.json here>

PUT _index_template/ndr-sessionizer-state-template
<copy mappings/ndr-sessionizer-state-template.json here>
```

## Build Docker image

```bash
docker build -t ndr-sessionizer:0.1.0 .
```

## Run locally with Docker

```bash
docker run --rm \
  --name ndr-sessionizer \
  -p 8080:8080 \
  -e OPENSEARCH_URL="https://opensearch:9200" \
  -e OPENSEARCH_USERNAME="$NDR_ADMIN_USERNAME" \
  -e OPENSEARCH_PASSWORD="$NDR_ADMIN_PASSWORD" \
  -e OPENSEARCH_CA_CERT="/certs/ca/ca.crt" \
  -e OPENSEARCH_VERIFY_CERTS="true" \
  -e SOURCE_INDEX_PATTERN="zeek-logs*" \
  -e TARGET_INDEX_PREFIX="ndr-sessions" \
  -e STATE_INDEX="ndr-sessionizer-state" \
  -v "$PWD/certs:/certs:ro" \
  ndr-sessionizer:0.1.0
```

## Run once in dry-run mode

This validates reading, grouping, and building session documents without writing to `ndr-sessions-*`.

```bash
docker run --rm \
  --name ndr-sessionizer-dry-run \
  -e OPENSEARCH_URL="https://opensearch:9200" \
  -e OPENSEARCH_USERNAME="$NDR_ADMIN_USERNAME" \
  -e OPENSEARCH_PASSWORD="$NDR_ADMIN_PASSWORD" \
  -e OPENSEARCH_CA_CERT="/certs/ca/ca.crt" \
  -e OPENSEARCH_VERIFY_CERTS="true" \
  -e RUN_ONCE="true" \
  -e DRY_RUN="true" \
  -v "$PWD/certs:/certs:ro" \
  ndr-sessionizer:0.1.0
```

## Run continuously with Docker Compose

Copy `docker-compose.example.yml` into your central stack or merge the `ndr-sessionizer` service into your existing Compose file.

```bash
docker compose --env-file .env -f docker-compose.example.yml up -d --build ndr-sessionizer
```

Health endpoints:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
curl http://localhost:8080/metrics
```

## Query `ndr-sessions-*`

### 1. Count sessions

```http
GET ndr-sessions*/_count
```

### 2. Search by UID

```http
GET ndr-sessions*/_search
{
  "query": {
    "term": {
      "session.uid": "SOME_UID"
    }
  }
}
```

### 3. Search by community_id

```http
GET ndr-sessions*/_search
{
  "query": {
    "term": {
      "network.community_id": "SOME_COMMUNITY_ID"
    }
  }
}
```

### 4. Sessions with notices

```http
GET ndr-sessions*/_search
{
  "query": {
    "term": {
      "session.has_notice": true
    }
  }
}
```

### 5. TLS sessions with invalid cert evidence

```http
GET ndr-sessions*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "session.has_tls": true } },
        { "exists": { "field": "tls.validation_status" } }
      ]
    }
  }
}
```

### 6. DNS sessions with long queries

```http
GET ndr-sessions*/_search
{
  "query": {
    "range": {
      "dns.query_length": {
        "gte": 80
      }
    }
  }
}
```

### 7. Check session log type distribution

```http
GET ndr-sessions*/_search
{
  "size": 0,
  "aggs": {
    "log_types": {
      "terms": {
        "field": "session.log_types",
        "size": 50
      }
    }
  }
}
```

### 8. Verify mapped field types

```http
GET ndr-sessions*/_field_caps?fields=source.ip,destination.ip,session.uid,network.community_id,dns.query_length,conn.duration
```

## Sessionization rules

### Key selection

1. If `uid` exists, use it as `session.id`.
2. Else if `community_id` exists, use it as `session.id`.
3. Else generate a deterministic synthetic ID from sensor, log type, rounded timestamp, and source/destination fields.

### Backbone selection

1. Prefer `conn`.
2. Otherwise use the earliest event in the group.

### Direction

- `local_orig=true`, `local_resp=false` -> `outbound`
- `local_orig=false`, `local_resp=true` -> `inbound`
- `local_orig=true`, `local_resp=true` -> `internal`
- otherwise -> `external_or_unknown`

### Late events

The worker rereads a configurable overlap window. It also looks up existing session documents by deterministic `_id`, merges arrays and evidence, deduplicates by raw `_id`, and reindexes the merged session document.

## Testing

Install dependencies locally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

The tests cover:

1. conn-only session
2. conn + ssl
3. conn + ssl + notice
4. conn + dns
5. conn + http + files
6. notice without conn
7. unknown log_type with dynamic fields
8. duplicate raw event does not duplicate evidence
9. late-arriving ssl updates existing conn session
10. malformed document is skipped safely
11. IP fields are indexed as IPs in the target mapping
12. keyword fields are searchable/aggregatable
13. disabled dynamic raw Zeek object does not cause mapping explosion

## Troubleshooting

### TLS failures

Check that the CA file is mounted inside the container:

```bash
docker exec -it ndr-sessionizer ls -l /certs/ca/ca.crt
```

Test OpenSearch from inside the container:

```bash
docker exec -it ndr-sessionizer python - <<'PY'
from app.config import load_settings
from app.opensearch_client import create_client
s = load_settings()
c = create_client(s)
print(c.info())
PY
```

### No sessions created

Check source data exists:

```http
GET zeek-logs*/_count
```

Check checkpoint:

```http
GET ndr-sessionizer-state/_search
{
  "query": { "match_all": {} }
}
```

Run a dry-run with a larger initial lookback:

```bash
docker run --rm \
  -e RUN_ONCE=true \
  -e DRY_RUN=true \
  -e INITIAL_LOOKBACK_SECONDS=3600 \
  ndr-sessionizer:0.1.0
```

### Mapping conflicts

The template sets `dynamic: false` and disables indexing for the raw `zeek` object. If you still see mapping conflicts, check whether a stable normalized field received incompatible source values.

```http
GET ndr-sessions*/_field_caps?fields=*
```

### Duplicate sessions

Session documents use deterministic IDs. If duplicate-looking sessions appear, compare:

- `session.uid`
- `session.community_id`
- `evidence.id`
- target index date

A session without `uid` may be grouped by `community_id` or synthetic fallback. That is expected for logs that do not carry Zeek `uid`.

## Production notes

- Keep `OPENSEARCH_VERIFY_CERTS=true` in production.
- Keep `zeek` disabled in the index mapping to prevent dynamic field explosion.
- Promote only selected raw fields into stable normalized mappings.
- Use `MAX_EVENTS_PER_LOG_TYPE_PER_SESSION` and `MAX_EVIDENCE_ITEMS` to avoid unbounded document growth.
- This is a v1 session layer. Build behavior models or advanced correlation into a separate `ndr-behaviors-*` service.
