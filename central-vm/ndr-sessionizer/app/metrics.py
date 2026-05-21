from __future__ import annotations

from prometheus_client import Counter, Gauge

DOCUMENTS_READ = Counter("documents_read_total", "Raw Zeek documents read from OpenSearch")
SESSIONS_UPSERTED = Counter("sessions_upserted_total", "Session documents bulk-upserted")
SESSIONS_CREATED = Counter("sessions_created_total", "Session documents created")
SESSIONS_UPDATED = Counter("sessions_updated_total", "Session documents updated")
RAW_EVENTS_SKIPPED = Counter("raw_events_skipped_total", "Malformed or unsupported raw events skipped")
OPENSEARCH_ERRORS = Counter("opensearch_errors_total", "OpenSearch operation errors")
LAST_CHECKPOINT_TS = Gauge("last_checkpoint_timestamp", "Last successful checkpoint timestamp as Unix epoch")
PROCESSING_LAG_SECONDS = Gauge("processing_lag_seconds", "Lag between now and checkpoint timestamp")
READY = Gauge("ready", "Service readiness, 1 ready, 0 not ready")
