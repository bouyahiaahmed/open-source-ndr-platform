# NDR Validator 2.0

A standalone validation container and UI for the open-source NDR platform:

```text
Zeek sensors → Vector → Data Prepper → OpenSearch → ndr-sessionizer → ndr-behaviorizer → ML/findings → ElastAlert2/Dashboards
```

This version is a clean rebuild of the validator. It focuses on catching silent failures across the moving parts instead of only checking whether containers are alive.

## What it checks

### OpenSearch
- API reachability and authentication.
- Cluster health.
- Required index families: `zeek-*`, `ndr-sessions-*`, `ndr-behaviors-*`.
- Required index templates: Zeek, sessions, behaviors, findings.
- Latest timestamps and document counts.
- Required field presence / schema quality.

### Data Prepper
- Prometheus management metrics endpoint.
- New deltas in error/drop/failure/DLQ-like counters.
- It stores previous metric values in SQLite, so the first run creates a baseline and later runs detect new silent failures.

### Vector sensors
- Scrapes Vector Prometheus metrics from `VECTOR_TARGETS`.
- Detects new error/drop/discard/failure counter deltas.
- Tracks basic sent/received event counters when available.

### Raw Zeek ingestion
- Latest raw event freshness in `zeek-logs*`.
- Required log type coverage in the last hour.
- Sensor coverage using candidate fields such as `sensor.name`, `sensor`, `host.name`.
- Required field missing percentage.

### Sessionizer
- `/readyz` endpoint.
- Raw-to-session correlation health.
- Session freshness and recent session counts.
- Required session fields.
- Excessive `session.excluded_from_behavior` percentage.

### Behaviorizer
- `/readyz` endpoint.
- Session-to-behavior aggregation health.
- Behavior freshness and recent behavior counts.
- `ml.ready` behavior counts.
- Required behavior fields.

### ML service
- `/readyz` endpoint.
- ML-ready behavior count.
- Scored behavior count.
- Unscored ML-ready backlog.
- Findings and model document counts.

### ElastAlert2
- Writeback index state.
- Indexed alert counts in `ndr-alerts*`.
- No alerts is not treated as a failure; missing ElastAlert state is a warning.

### NetFlow
- Optional `ndr-flows-*` checks.
- Missing NetFlow is warning-level because the collector may not be part of every deployment.

### Docker runtime
- Optional Docker socket check for expected containers.
- Detects missing/stopped central containers.

## UI

The UI is available at:

```bash
http://localhost:8000
```

It includes:

- Global health score.
- Critical/warning highlights.
- Component health cards.
- Pipeline timeline.
- Filterable checks with evidence and remediation.
- Sensor/Vector view.
- Scan history.
- Safe configuration view.

## Quick start

1. Copy the environment file:

```bash
cp .env.example .env
```

2. Find your central Docker network:

```bash
docker network ls | grep backend
```

Common names are:

```text
central-vm_backend
docker_backend
backend
```

3. Edit `.env`:

```bash
NDR_DOCKER_NETWORK=central-vm_backend
OPENSEARCH_PASSWORD=your_admin_password
DASHBOARDS_PASSWORD=your_dashboard_password
DATAPREPPER_INGEST_PASSWORD=your_vector_to_dataprepper_password
VECTOR_TARGETS=sensor01=http://10.51.1.12:9598/metrics,sensor02=http://10.51.1.13:9598/metrics
EXPECTED_SENSORS=sensor01,sensor02
```

4. Start the validator:

```bash
docker compose -f docker-compose.standalone.yml up -d --build
```

5. Open:

```text
http://localhost:8000
```

## If the central compose network name is unknown

Run:

```bash
docker inspect ndr-sessionizer --format '{{json .NetworkSettings.Networks}}' | jq
```

Use the network name as `NDR_DOCKER_NETWORK`.

## Running from the host instead of the Docker network

Set service URLs to host-reachable ports:

```env
OPENSEARCH_URL=https://host.docker.internal:9200
DASHBOARDS_URL=https://host.docker.internal:5601
DATAPREPPER_METRICS_URL=https://host.docker.internal:4900/metrics/sys
SESSIONIZER_URL=http://host.docker.internal:8088
BEHAVIORIZER_URL=http://host.docker.internal:8091
ML_SERVICE_URL=http://host.docker.internal:8092
```

On Linux, add this to the compose service if needed:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

## TLS modes

Lab mode, easiest:

```env
INSECURE_SKIP_VERIFY=true
```

Stricter mode:

```env
INSECURE_SKIP_VERIFY=false
CA_CERT_LOCAL_DIR=../central-vm/certs/ca
CA_CERT_PATH=/certs/ca/ca.crt
OPENSEARCH_VERIFY_SSL=true
DASHBOARDS_VERIFY_SSL=true
DATAPREPPER_VERIFY_SSL=true
```

## API endpoints

```text
GET  /                  UI
GET  /healthz           process health
GET  /readyz            first scan completed or not
GET  /api/summary       latest scan
POST /api/run           run validation immediately
GET  /api/checks        latest checks only
GET  /api/history       scan history
GET  /api/config        safe effective config
GET  /metrics           Prometheus metrics for the validator itself
```

## Important notes

- The first scan after startup establishes metric counter baselines. Data Prepper/Vector silent drop detection becomes more meaningful from the second scan onward.
- If you do not configure `VECTOR_TARGETS`, Vector checks will be `unknown`, not `critical`.
- If you do not use NetFlow, keep `ENABLE_NETFLOW_CHECKS=false` to remove NetFlow warnings.
- If your Zeek documents do not use `sensor.name`, set `SENSOR_FIELD_CANDIDATES` or `EXPECTED_SENSORS` to match your actual documents.

## Local smoke test

```bash
python -m compileall app
DATA_DIR=./data SQLITE_DB_PATH=./data/ndr-validator.db uvicorn app.main:app --reload
```

