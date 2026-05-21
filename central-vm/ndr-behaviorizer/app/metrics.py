from __future__ import annotations

from prometheus_client import Counter, Gauge

READY = Gauge("ndr_behaviorizer_ready", "1 when the behaviorizer is ready")
DOCUMENTS_READ = Counter("ndr_behaviorizer_documents_read_total", "Session documents read")
BEHAVIORS_WRITTEN = Counter("ndr_behaviorizer_behaviors_written_total", "Behavior documents written")
FINDINGS_WRITTEN = Counter("ndr_behaviorizer_findings_written_total", "Finding documents written")
OPENSEARCH_ERRORS = Counter("ndr_behaviorizer_opensearch_errors_total", "OpenSearch errors")
PROCESSING_FAILURES = Counter("ndr_behaviorizer_processing_failures_total", "Processing failures")
LAST_CHECKPOINT_TS = Gauge("ndr_behaviorizer_last_checkpoint_timestamp_seconds", "Last checkpoint timestamp")
PROCESSING_LAG_SECONDS = Gauge("ndr_behaviorizer_processing_lag_seconds", "Processing lag in seconds")
