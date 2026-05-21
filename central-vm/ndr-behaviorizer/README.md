# ndr-behaviorizer

`ndr-behaviorizer` converts enriched session documents into host-level behavior windows that are useful for dashboards, SOC triage, and ML anomaly detection.

Flow:

```text
zeek-logs* -> ndr-sessionizer -> ndr-sessions-* -> ndr-behaviorizer -> ndr-behaviors-* -> optional ndr-findings-*
```

## What it does

`ndr-sessions-*` is the correct source for behavior analytics because the sessionizer has already joined Zeek evidence by UID/community ID and enriched TLS/x509/files/notice context. The behaviorizer does **not** rebuild behavior directly from `zeek-logs*`.

For each entity/window, it writes one deterministic document to `ndr-behaviors-YYYY.MM.DD` with:

- human-readable summaries and top values,
- stable numeric features,
- ordered `ml.feature_names`,
- ordered `ml.feature_vector`,
- `ml.vector_version` / feature set version,
- data quality counters and warnings,
- optional IsolationForest scoring metadata,
- optional anomaly findings in `ndr-findings-*`.

Default behavior window: `1h`.

Default entity strategy: `source.ip + sensor.name` when `sensor.name` exists, otherwise `source.ip`.

## Folder contents

```text
ndr-behaviorizer/
  Dockerfile
  README.md
  requirements.txt
  config.example.yaml
  docker-compose.example.yml
  pytest.ini
  app/
  features/host_hourly_v1.yaml
  mappings/
  tests/
```

## Install into your current repo without touching the original ZIP

From your extracted `central-vm` repo:

```bash
cd /home/vagrant/central-vm
unzip /path/to/ndr-behavoirzer.zip
```

This creates:

```text
/home/vagrant/central-vm/ndr-behaviorizer
```

Then copy the two services from:

```text
ndr-behaviorizer/docker-compose.example.yml
```

into `docker/docker-compose.yml` under `services:`.

The file intentionally contains only the behaviorizer services so you do not need a full modified project ZIP.

## Compose validation

```bash
docker compose -f docker/docker-compose.yml --env-file .env config >/tmp/compose-check.yml && echo "Compose OK"
```

Apply templates once:

```bash
docker compose -f docker/docker-compose.yml --env-file .env up ndr-behaviorizer-template-init
```

Build and run:

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d --build ndr-behaviorizer
```

Or rebuild the whole stack after adding the services:

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d --build
```

Validate behavior output:

```bash
docker exec ndr-behaviorizer python -m app.validate_behaviors
```

Run tests locally from the component folder:

```bash
cd ndr-behaviorizer
python -m pytest -q
```

## Runtime configuration

Main environment variables:

```bash
OPENSEARCH_URL=https://opensearch-node1:9200
OPENSEARCH_USERNAME=${NDR_ADMIN_USERNAME:-admin}
OPENSEARCH_PASSWORD=${NDR_ADMIN_PASSWORD:-admin}
OPENSEARCH_CA_CERT=/certs/ca/ca.crt
OPENSEARCH_VERIFY_CERTS=true

SOURCE_INDEX_PATTERN=ndr-sessions*
TARGET_INDEX_PREFIX=ndr-behaviors
STATE_INDEX=ndr-behaviorizer-state
PROCESS_TIME_FIELD=sessionizer.updated_at
EVENT_TIME_FIELD=@timestamp

BEHAVIOR_WINDOW_SECONDS=3600
LOOKBACK_OVERLAP_SECONDS=7200
INITIAL_LOOKBACK_SECONDS=86400
POLL_INTERVAL_SECONDS=60

FEATURE_SET=host_hourly_v1
FEATURE_CONFIG_PATH=/app/features/host_hourly_v1.yaml
BEHAVIOR_ENTITY_MODE=host_sensor

ML_ENABLED=true
ML_MIN_TRAINING_ROWS=20
ML_CONTAMINATION=0.05
FINDINGS_ENABLED=true
FINDINGS_INDEX_PREFIX=ndr-findings
```

## Behavior eligibility

Included in ML features:

- `session.flow_based = true`
- `session.excluded_from_behavior != true`

Excluded from ML features but counted in quality:

- `session.category = control_plane`
- `session.category = malformed_raw`
- DHCP/NTP/control-plane noise reasons
- `session.flow_based = false`
- `session.excluded_from_behavior = true`

## ML readiness

The feature list is versioned in:

```text
features/host_hourly_v1.yaml
```

The exact `vector_order` in this YAML controls:

- `ml.feature_names`
- `ml.feature_vector`
- `ml.vector_length`
- model input order

A model can immediately read:

```json
{
  "ml": {
    "ready": true,
    "feature_set": "host_hourly_v1",
    "feature_names": ["session_count", "unique_destination_ip_count"],
    "feature_vector": [88.0, 22.0],
    "vector_version": "host_hourly_v1"
  }
}
```

If there are fewer than `ML_MIN_TRAINING_ROWS`, the service does not crash. It marks `ml.scoring_status` as:

```text
not_enough_training_data
```

## Dev Tools queries

Count behavior docs:

```json
GET ndr-behaviors*/_count
```

Show latest behavior docs:

```json
GET ndr-behaviors*/_search
{
  "size": 10,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

Feature set / ML readiness / quality:

```json
GET ndr-behaviors*/_search
{
  "size": 0,
  "aggs": {
    "feature_set": {"terms": {"field": "behavior.feature_set"}},
    "ml_ready": {"terms": {"field": "ml.ready"}},
    "feature_complete": {"terms": {"field": "quality.feature_complete"}},
    "scoring_status": {"terms": {"field": "ml.scoring_status"}}
  }
}
```

Check vector length consistency:

```json
GET ndr-behaviors*/_search
{
  "size": 5,
  "_source": [
    "behavior.id",
    "behavior.entity",
    "behavior.sensor",
    "quality",
    "features",
    "ml.feature_names",
    "ml.feature_vector",
    "ml.vector_length",
    "ml.scoring_status",
    "score"
  ]
}
```

Find anomalies:

```json
GET ndr-findings*/_search
{
  "size": 20,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

## Safe lab reset

To delete behavior outputs only:

```json
DELETE ndr-behaviors-*
DELETE ndr-behaviorizer-state
DELETE ndr-findings-*
DELETE ndr-ml-models
```

Then restart:

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d --build ndr-behaviorizer
```

## Notes

- This component is idempotent: behavior document IDs are deterministic by `feature_set + sensor + entity + window_start`.
- It overwrites the same behavior document when a window is recomputed.
- It uses overlap lookback for late session updates.
- It handles missing `ndr-sessions*` gracefully.
- It does not include secrets or certificate private keys.

## Production-hardening added in v0.2.0

This package includes the first production-hardening pass over the initial behaviorizer:

1. **Exact rollback evidence**: each behavior now stores bounded `evidence.session_refs[]` pointing back to the source `ndr-sessions-*` documents used for the feature vector. Each ref includes session document index/id, session_id, uid when available, community_id when available, timestamp, log types, source/destination, and destination port.
2. **Cleaner ML eligibility**: non-host/control-plane addresses such as `0.0.0.0`, `::`, multicast, loopback, link-local, broadcast, and unknown protocol/port-zero traffic are excluded from ML features and counted in `quality.excluded_reasons`.
3. **Minimum behavior size for ML**: `BEHAVIOR_MIN_SESSIONS_FOR_ML=2` by default. A behavior document can still be written with 0/1 eligible sessions, but it is not used for ML training/scoring.
4. **Deterministic findings**: `ndr-findings-*` uses `finding.dedup_id = behavior.id + finding.type`, so the same anomaly for the same host/window is overwritten instead of creating a duplicate alert every minute.
5. **More stable model pipeline**: Isolation Forest is wrapped with `RobustScaler` and model metadata records training quality controls.
6. **Training data quality filter**: historical training docs must have `quality.data_quality_score >= ML_TRAINING_MIN_QUALITY_SCORE`.
7. **Cleaner quality warnings**: global missing-session counters are no longer copied into every behavior document.

## Rollback from anomaly to sessions to raw logs

When a finding appears in `ndr-findings-*`, use its `behavior.id`, `behavior.entity`, `behavior.sensor`, `behavior.window_start`, and `behavior.window_end`.

First, open the behavior document:

```json
GET ndr-behaviors*/_search
{
  "size": 1,
  "query": {
    "term": {
      "behavior.id": "PUT_BEHAVIOR_ID_HERE"
    }
  },
  "_source": [
    "behavior",
    "features",
    "human",
    "ml.top_features",
    "score",
    "evidence.session_refs"
  ]
}
```

Then inspect the exact session documents from `evidence.session_refs[]`:

```json
GET ndr-sessions*/_search
{
  "size": 100,
  "query": {
    "ids": {
      "values": ["PUT_SESSION_DOC_ID_1", "PUT_SESSION_DOC_ID_2"]
    }
  },
  "_source": [
    "@timestamp",
    "session",
    "source",
    "destination",
    "network",
    "dns",
    "http",
    "files",
    "tls",
    "x509",
    "ssh",
    "notice",
    "weird",
    "evidence",
    "zeek"
  ]
}
```

If a session contains `session.uid` or a raw Zeek `uid`, pivot to raw logs:

```json
GET zeek-logs*/_search
{
  "size": 100,
  "query": {
    "term": {
      "uid": "PUT_ZEEK_UID_HERE"
    }
  },
  "sort": [
    {"@timestamp": "asc"}
  ]
}
```

If `uid` is unavailable but `community_id` exists, pivot with:

```json
GET zeek-logs*/_search
{
  "size": 100,
  "query": {
    "term": {
      "network.community_id": "PUT_COMMUNITY_ID_HERE"
    }
  },
  "sort": [
    {"@timestamp": "asc"}
  ]
}
```

## Additional validation checks

The validator now also reports:

```text
MISSING_EVIDENCE_REFS
NOISY_ENTITY_ML_READY
FINDING_COUNT
FINDINGS_MISSING_DEDUP_ID
```

`NOISY_ENTITY_ML_READY` should stay `0` after deleting old behavior indices and rerunning the v0.2.0 behaviorizer.
