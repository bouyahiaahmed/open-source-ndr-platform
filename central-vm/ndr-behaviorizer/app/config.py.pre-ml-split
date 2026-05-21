from __future__ import annotations

import os
from dataclasses import dataclass
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


def _float(value: str | float | None, default: float) -> float:
    if value is None or value == "":
        return default
    return float(value)


@dataclass(frozen=True)
class Settings:
    opensearch_url: str = "https://opensearch:9200"
    opensearch_username: str = "admin"
    opensearch_password: str = "admin"
    opensearch_ca_cert: str | None = None
    opensearch_verify_certs: bool = True

    source_index_pattern: str = "ndr-sessions*"
    target_index_prefix: str = "ndr-behaviors"
    state_index: str = "ndr-behaviorizer-state"

    process_time_field: str = "sessionizer.updated_at"
    event_time_field: str = "@timestamp"
    behavior_window_seconds: int = 3600
    lookback_overlap_seconds: int = 7200
    initial_lookback_seconds: int = 86400
    poll_interval_seconds: int = 60
    read_page_size: int = 500
    bulk_size: int = 500

    feature_set: str = "host_hourly_v1"
    feature_config_path: str = "/app/features/host_hourly_v1.yaml"
    behavior_entity_mode: str = "host_sensor"

    run_once: bool = False
    dry_run: bool = False
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    checkpoint_id: str = "default"
    service_version: str = "0.2.0"

    ml_enabled: bool = True
    ml_min_training_rows: int = 20
    ml_contamination: float = 0.05
    ml_training_max_docs: int = 2000
    ml_training_min_quality_score: int = 80
    ml_score_current_only: bool = True
    behavior_max_session_refs: int = 200
    behavior_min_sessions_for_ml: int = 2
    ml_model_artifact_path: str = "/tmp/ndr_behaviorizer_model.pkl"
    findings_enabled: bool = True
    findings_index_prefix: str = "ndr-findings"


def _load_yaml(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


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
        target_index_prefix=os.getenv("TARGET_INDEX_PREFIX", _get(cfg, "target_index_prefix", Settings.target_index_prefix)),
        state_index=os.getenv("STATE_INDEX", _get(cfg, "state_index", Settings.state_index)),
        process_time_field=os.getenv("PROCESS_TIME_FIELD", _get(cfg, "process_time_field", Settings.process_time_field)),
        event_time_field=os.getenv("EVENT_TIME_FIELD", _get(cfg, "event_time_field", Settings.event_time_field)),
        behavior_window_seconds=_int(os.getenv("BEHAVIOR_WINDOW_SECONDS"), int(_get(cfg, "behavior_window_seconds", Settings.behavior_window_seconds))),
        lookback_overlap_seconds=_int(os.getenv("LOOKBACK_OVERLAP_SECONDS"), int(_get(cfg, "lookback_overlap_seconds", Settings.lookback_overlap_seconds))),
        initial_lookback_seconds=_int(os.getenv("INITIAL_LOOKBACK_SECONDS"), int(_get(cfg, "initial_lookback_seconds", Settings.initial_lookback_seconds))),
        poll_interval_seconds=_int(os.getenv("POLL_INTERVAL_SECONDS"), int(_get(cfg, "poll_interval_seconds", Settings.poll_interval_seconds))),
        read_page_size=_int(os.getenv("READ_PAGE_SIZE"), int(_get(cfg, "read_page_size", Settings.read_page_size))),
        bulk_size=_int(os.getenv("BULK_SIZE"), int(_get(cfg, "bulk_size", Settings.bulk_size))),
        feature_set=os.getenv("FEATURE_SET", _get(cfg, "feature_set", Settings.feature_set)),
        feature_config_path=os.getenv("FEATURE_CONFIG_PATH", _get(cfg, "feature_config_path", Settings.feature_config_path)),
        behavior_entity_mode=os.getenv("BEHAVIOR_ENTITY_MODE", _get(cfg, "behavior_entity_mode", Settings.behavior_entity_mode)),
        run_once=_bool(os.getenv("RUN_ONCE", str(_get(cfg, "run_once", False))), False),
        dry_run=_bool(os.getenv("DRY_RUN", str(_get(cfg, "dry_run", False))), False),
        http_host=os.getenv("HTTP_HOST", _get(cfg, "http_host", Settings.http_host)),
        http_port=_int(os.getenv("HTTP_PORT"), int(_get(cfg, "http_port", Settings.http_port))),
        checkpoint_id=os.getenv("CHECKPOINT_ID", _get(cfg, "checkpoint_id", Settings.checkpoint_id)),
        service_version=os.getenv("SERVICE_VERSION", _get(cfg, "service_version", Settings.service_version)),
        ml_enabled=_bool(os.getenv("ML_ENABLED", str(_get(cfg, "ml_enabled", True))), True),
        ml_min_training_rows=_int(os.getenv("ML_MIN_TRAINING_ROWS"), int(_get(cfg, "ml_min_training_rows", Settings.ml_min_training_rows))),
        ml_contamination=_float(os.getenv("ML_CONTAMINATION"), float(_get(cfg, "ml_contamination", Settings.ml_contamination))),
        ml_training_max_docs=_int(os.getenv("ML_TRAINING_MAX_DOCS"), int(_get(cfg, "ml_training_max_docs", Settings.ml_training_max_docs))),
        ml_training_min_quality_score=_int(os.getenv("ML_TRAINING_MIN_QUALITY_SCORE"), int(_get(cfg, "ml_training_min_quality_score", Settings.ml_training_min_quality_score))),
        ml_score_current_only=_bool(os.getenv("ML_SCORE_CURRENT_ONLY", str(_get(cfg, "ml_score_current_only", Settings.ml_score_current_only))), Settings.ml_score_current_only),
        behavior_max_session_refs=_int(os.getenv("BEHAVIOR_MAX_SESSION_REFS"), int(_get(cfg, "behavior_max_session_refs", Settings.behavior_max_session_refs))),
        behavior_min_sessions_for_ml=_int(os.getenv("BEHAVIOR_MIN_SESSIONS_FOR_ML"), int(_get(cfg, "behavior_min_sessions_for_ml", Settings.behavior_min_sessions_for_ml))),
        ml_model_artifact_path=os.getenv("ML_MODEL_ARTIFACT_PATH", _get(cfg, "ml_model_artifact_path", Settings.ml_model_artifact_path)),
        findings_enabled=_bool(os.getenv("FINDINGS_ENABLED", str(_get(cfg, "findings_enabled", True))), True),
        findings_index_prefix=os.getenv("FINDINGS_INDEX_PREFIX", _get(cfg, "findings_index_prefix", Settings.findings_index_prefix)),
    )
