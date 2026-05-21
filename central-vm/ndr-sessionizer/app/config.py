from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _bool(value: str | bool | None, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int(value: str | int | None, default: int) -> int:
    if value is None or value == "":
        return default
    return int(value)


@dataclass(frozen=True)
class Settings:
    opensearch_url: str = "https://opensearch:9200"
    opensearch_username: str = "admin"
    opensearch_password: str = "admin"
    opensearch_ca_cert: str | None = None
    opensearch_verify_certs: bool = True

    source_index_pattern: str = "zeek-logs*"

    process_time_field: str = "ingest_time_vt"

    event_time_field: str = "@timestamp"
    target_index_prefix: str = "ndr-sessions"
    state_index: str = "ndr-sessionizer-state"

    poll_interval_seconds: int = 30
    lookback_overlap_seconds: int = 120
    initial_lookback_seconds: int = 300
    bulk_size: int = 500
    read_page_size: int = 500
    max_events_per_log_type_per_session: int = 20
    max_evidence_items: int = 100
    preserve_raw_event_fields: bool = True

    run_once: bool = False
    dry_run: bool = False
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    service_version: str = "0.1.0"
    checkpoint_id: str = "default"
    local_networks: list[str] = field(default_factory=list)


def _load_yaml(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return {}
    return data


def _get(data: dict[str, Any], name: str, default: Any = None) -> Any:
    return data.get(name, default)


def load_settings(config_path: str | None = None) -> Settings:
    cfg = _load_yaml(config_path or os.getenv("CONFIG_FILE"))
    return Settings(
        opensearch_url=os.getenv("OPENSEARCH_URL", _get(cfg, "opensearch_url", Settings.opensearch_url)),
        opensearch_username=os.getenv("OPENSEARCH_USERNAME", _get(cfg, "opensearch_username", Settings.opensearch_username)),
        opensearch_password=os.getenv("OPENSEARCH_PASSWORD", _get(cfg, "opensearch_password", Settings.opensearch_password)),
        opensearch_ca_cert=os.getenv("OPENSEARCH_CA_CERT", _get(cfg, "opensearch_ca_cert", None)),
        opensearch_verify_certs=_bool(os.getenv("OPENSEARCH_VERIFY_CERTS", str(_get(cfg, "opensearch_verify_certs", True))), True),
        source_index_pattern=os.getenv("SOURCE_INDEX_PATTERN", _get(cfg, "source_index_pattern", Settings.source_index_pattern)),
        process_time_field=os.getenv("PROCESS_TIME_FIELD", _get(cfg, "process_time_field", Settings.process_time_field)),
        event_time_field=os.getenv("EVENT_TIME_FIELD", _get(cfg, "event_time_field", Settings.event_time_field)),
        target_index_prefix=os.getenv("TARGET_INDEX_PREFIX", _get(cfg, "target_index_prefix", Settings.target_index_prefix)),
        state_index=os.getenv("STATE_INDEX", _get(cfg, "state_index", Settings.state_index)),
        poll_interval_seconds=_int(os.getenv("POLL_INTERVAL_SECONDS"), int(_get(cfg, "poll_interval_seconds", 30))),
        lookback_overlap_seconds=_int(os.getenv("LOOKBACK_OVERLAP_SECONDS"), int(_get(cfg, "lookback_overlap_seconds", 120))),
        initial_lookback_seconds=_int(os.getenv("INITIAL_LOOKBACK_SECONDS"), int(_get(cfg, "initial_lookback_seconds", 300))),
        bulk_size=_int(os.getenv("BULK_SIZE"), int(_get(cfg, "bulk_size", 500))),
        read_page_size=_int(os.getenv("READ_PAGE_SIZE"), int(_get(cfg, "read_page_size", 500))),
        max_events_per_log_type_per_session=_int(os.getenv("MAX_EVENTS_PER_LOG_TYPE_PER_SESSION"), int(_get(cfg, "max_events_per_log_type_per_session", 20))),
        max_evidence_items=_int(os.getenv("MAX_EVIDENCE_ITEMS"), int(_get(cfg, "max_evidence_items", 100))),
        preserve_raw_event_fields=_bool(os.getenv("PRESERVE_RAW_EVENT_FIELDS", str(_get(cfg, "preserve_raw_event_fields", True))), True),
        run_once=_bool(os.getenv("RUN_ONCE", str(_get(cfg, "run_once", False))), False),
        dry_run=_bool(os.getenv("DRY_RUN", str(_get(cfg, "dry_run", False))), False),
        http_host=os.getenv("HTTP_HOST", _get(cfg, "http_host", "0.0.0.0")),
        http_port=_int(os.getenv("HTTP_PORT"), int(_get(cfg, "http_port", 8080))),
        service_version=os.getenv("SERVICE_VERSION", _get(cfg, "service_version", "0.1.0")),
        checkpoint_id=os.getenv("CHECKPOINT_ID", _get(cfg, "checkpoint_id", "default")),
        local_networks=list(_get(cfg, "local_networks", [])),
    )
