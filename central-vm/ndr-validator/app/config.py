from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _int(name: str, default: int) -> int:
    value = _get(name, str(default))
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    value = _get(name, str(default))
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool = False) -> bool:
    value = _get(name, "true" if default else "false").lower()
    return value in {"1", "true", "yes", "y", "on"}


def _list(name: str, default: str = "") -> list[str]:
    value = _get(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _target_map(name: str, default: str = "") -> dict[str, str]:
    """
    Parse TARGETS env values like:
      sensor-a=http://10.0.0.4:9598/metrics,sensor-b=http://10.0.0.5:9598/metrics
    or:
      http://10.0.0.4:9598/metrics,http://10.0.0.5:9598/metrics
    """
    result: dict[str, str] = {}
    for raw in _list(name, default):
        if "=" in raw:
            label, url = raw.split("=", 1)
            result[label.strip()] = url.strip()
        else:
            label = raw.replace("https://", "").replace("http://", "").split("/", 1)[0]
            result[label] = raw
    return result


@dataclass(frozen=True)
class Settings:
    app_name: str = field(default_factory=lambda: _get("APP_NAME", "NDR Validator"))
    app_env: str = field(default_factory=lambda: _get("APP_ENV", "prod"))
    log_level: str = field(default_factory=lambda: _get("LOG_LEVEL", "INFO"))
    data_dir: Path = field(default_factory=lambda: Path(_get("DATA_DIR", "/data")))
    sqlite_path: Path = field(default_factory=lambda: Path(_get("SQLITE_DB_PATH", "/data/ndr-validator.db")))
    scrape_interval_seconds: int = field(default_factory=lambda: _int("SCRAPE_INTERVAL_SECONDS", 30))
    request_timeout_seconds: float = field(default_factory=lambda: _float("REQUEST_TIMEOUT_SECONDS", 5.0))
    max_concurrency: int = field(default_factory=lambda: _int("MAX_CONCURRENCY", 8))

    # TLS/auth defaults are intentionally lab-friendly. Use CA_CERT_PATH + *_VERIFY_SSL=true for production.
    ca_cert_path: str = field(default_factory=lambda: _get("CA_CERT_PATH", ""))
    insecure_skip_verify: bool = field(default_factory=lambda: _bool("INSECURE_SKIP_VERIFY", True))

    opensearch_url: str = field(default_factory=lambda: _get("OPENSEARCH_URL", "https://opensearch-node1:9200"))
    opensearch_user: str = field(default_factory=lambda: _get("OPENSEARCH_USER", _get("OPENSEARCH_USERNAME", "admin")))
    opensearch_password: str = field(default_factory=lambda: _get("OPENSEARCH_PASSWORD", _get("OPENSEARCH_PASS", "admin")))
    opensearch_verify_ssl: bool = field(default_factory=lambda: _bool("OPENSEARCH_VERIFY_SSL", False))

    dashboards_url: str = field(default_factory=lambda: _get("DASHBOARDS_URL", "https://dashboards:5601"))
    dashboards_user: str = field(default_factory=lambda: _get("DASHBOARDS_USER", _get("DASHBOARDS_USERNAME", "admin")))
    dashboards_password: str = field(default_factory=lambda: _get("DASHBOARDS_PASSWORD", _get("DASHBOARDS_PASS", "admin")))
    dashboards_verify_ssl: bool = field(default_factory=lambda: _bool("DASHBOARDS_VERIFY_SSL", False))
    dashboards_check_saved_objects: bool = field(default_factory=lambda: _bool("DASHBOARDS_CHECK_SAVED_OBJECTS", True))

    dataprepper_metrics_url: str = field(default_factory=lambda: _get("DATAPREPPER_METRICS_URL", "https://dataprepper:4900/metrics/sys"))
    dataprepper_health_url: str = field(default_factory=lambda: _get("DATAPREPPER_HEALTH_URL", ""))
    dataprepper_ingest_url: str = field(default_factory=lambda: _get("DATAPREPPER_INGEST_URL", "https://dataprepper:2021/log/ingest"))
    dataprepper_user: str = field(default_factory=lambda: _get("DATAPREPPER_USER", _get("DATAPREPPER_USERNAME", "admin")))
    dataprepper_password: str = field(default_factory=lambda: _get("DATAPREPPER_PASSWORD", ""))
    dataprepper_ingest_user: str = field(default_factory=lambda: _get("DATAPREPPER_INGEST_USER", "vector"))
    dataprepper_ingest_password: str = field(default_factory=lambda: _get("DATAPREPPER_INGEST_PASSWORD", _get("DP_HTTP_PASSWORD", "")))
    dataprepper_verify_ssl: bool = field(default_factory=lambda: _bool("DATAPREPPER_VERIFY_SSL", False))

    sessionizer_url: str = field(default_factory=lambda: _get("SESSIONIZER_URL", "http://ndr-sessionizer:8080"))
    behaviorizer_url: str = field(default_factory=lambda: _get("BEHAVIORIZER_URL", "http://ndr-behaviorizer:8080"))
    ml_service_url: str = field(default_factory=lambda: _get("ML_SERVICE_URL", "http://ndr-behavior-ml:8080"))

    vector_targets: dict[str, str] = field(default_factory=lambda: _target_map("VECTOR_TARGETS", ""))
    expected_sensors: list[str] = field(default_factory=lambda: _list("EXPECTED_SENSORS", ""))
    sensor_field_candidates: list[str] = field(default_factory=lambda: _list("SENSOR_FIELD_CANDIDATES", "sensor.name,sensor,host.name,agent.name"))

    zeek_index_pattern: str = field(default_factory=lambda: _get("ZEEK_INDEX_PATTERN", "zeek-*"))
    raw_index_pattern: str = field(default_factory=lambda: _get("RAW_INDEX_PATTERN", "zeek-logs*"))
    sessions_index_pattern: str = field(default_factory=lambda: _get("SESSIONS_INDEX_PATTERN", "ndr-sessions-*"))
    behaviors_index_pattern: str = field(default_factory=lambda: _get("BEHAVIORS_INDEX_PATTERN", "ndr-behaviors-*"))
    findings_index_pattern: str = field(default_factory=lambda: _get("FINDINGS_INDEX_PATTERN", "ndr-findings-*"))
    alerts_index_pattern: str = field(default_factory=lambda: _get("ALERTS_INDEX_PATTERN", "ndr-alerts*"))
    flows_index_pattern: str = field(default_factory=lambda: _get("FLOWS_INDEX_PATTERN", "ndr-flows-*"))
    elastalert_status_index_pattern: str = field(default_factory=lambda: _get("ELASTALERT_STATUS_INDEX_PATTERN", "elastalert_status*"))
    ml_models_index_pattern: str = field(default_factory=lambda: _get("ML_MODELS_INDEX_PATTERN", "ndr-ml-models*"))

    required_log_types: list[str] = field(default_factory=lambda: _list("REQUIRED_LOG_TYPES", "conn,dns,http,ssl,files,notice,weird,ssh"))
    required_raw_fields: list[str] = field(default_factory=lambda: _list("REQUIRED_RAW_FIELDS", "@timestamp,log_type,source.ip,destination.ip"))
    required_session_fields: list[str] = field(default_factory=lambda: _list("REQUIRED_SESSION_FIELDS", "@timestamp,source.ip,destination.ip,network.protocol,network.direction,network.scope,session.log_types"))
    required_behavior_fields: list[str] = field(default_factory=lambda: _list("REQUIRED_BEHAVIOR_FIELDS", "@timestamp,entity.id,features,quality.data_quality_score,ml.ready"))

    raw_fresh_warn_seconds: int = field(default_factory=lambda: _int("RAW_FRESH_WARN_SECONDS", 300))
    raw_fresh_crit_seconds: int = field(default_factory=lambda: _int("RAW_FRESH_CRIT_SECONDS", 900))
    session_fresh_warn_seconds: int = field(default_factory=lambda: _int("SESSION_FRESH_WARN_SECONDS", 900))
    session_fresh_crit_seconds: int = field(default_factory=lambda: _int("SESSION_FRESH_CRIT_SECONDS", 1800))
    behavior_fresh_warn_seconds: int = field(default_factory=lambda: _int("BEHAVIOR_FRESH_WARN_SECONDS", 1800))
    behavior_fresh_crit_seconds: int = field(default_factory=lambda: _int("BEHAVIOR_FRESH_CRIT_SECONDS", 3600))
    max_missing_required_field_percent: float = field(default_factory=lambda: _float("MAX_MISSING_REQUIRED_FIELD_PERCENT", 5.0))
    max_excluded_session_percent_warn: float = field(default_factory=lambda: _float("MAX_EXCLUDED_SESSION_PERCENT_WARN", 80.0))
    ml_min_ready_behaviors: int = field(default_factory=lambda: _int("ML_MIN_READY_BEHAVIORS", 20))
    ml_max_unscored_ready_behaviors: int = field(default_factory=lambda: _int("ML_MAX_UNSCORED_READY_BEHAVIORS", 200))

    enable_docker_checks: bool = field(default_factory=lambda: _bool("ENABLE_DOCKER_CHECKS", True))
    docker_socket: str = field(default_factory=lambda: _get("DOCKER_SOCKET", "/var/run/docker.sock"))
    expected_containers: list[str] = field(default_factory=lambda: _list("EXPECTED_CONTAINERS", "os-node-1,ndr-dataprepper,ndr-dashboards,ndr-sessionizer,ndr-behaviorizer,ndr-behavior-ml,elastalert2"))

    # Optional features
    enable_netflow_checks: bool = field(default_factory=lambda: _bool("ENABLE_NETFLOW_CHECKS", True))
    enable_elastalert_checks: bool = field(default_factory=lambda: _bool("ENABLE_ELASTALERT_CHECKS", True))

    def verify_for(self, component: str) -> bool | str:
        if self.insecure_skip_verify:
            return False
        verify = {
            "opensearch": self.opensearch_verify_ssl,
            "dashboards": self.dashboards_verify_ssl,
            "dataprepper": self.dataprepper_verify_ssl,
        }.get(component, True)
        if verify and self.ca_cert_path and Path(self.ca_cert_path).exists():
            return self.ca_cert_path
        return verify

    def safe_dict(self) -> dict[str, Any]:
        redacted = {
            "app_name": self.app_name,
            "app_env": self.app_env,
            "scrape_interval_seconds": self.scrape_interval_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
            "opensearch_url": self.opensearch_url,
            "dashboards_url": self.dashboards_url,
            "dataprepper_metrics_url": self.dataprepper_metrics_url,
            "dataprepper_ingest_url": self.dataprepper_ingest_url,
            "sessionizer_url": self.sessionizer_url,
            "behaviorizer_url": self.behaviorizer_url,
            "ml_service_url": self.ml_service_url,
            "vector_targets": self.vector_targets,
            "expected_sensors": self.expected_sensors,
            "index_patterns": {
                "zeek": self.zeek_index_pattern,
                "raw": self.raw_index_pattern,
                "sessions": self.sessions_index_pattern,
                "behaviors": self.behaviors_index_pattern,
                "findings": self.findings_index_pattern,
                "alerts": self.alerts_index_pattern,
                "flows": self.flows_index_pattern,
            },
            "required_log_types": self.required_log_types,
            "enable_docker_checks": self.enable_docker_checks,
            "expected_containers": self.expected_containers,
            "tls": {
                "insecure_skip_verify": self.insecure_skip_verify,
                "ca_cert_path_configured": bool(self.ca_cert_path),
            },
        }
        return redacted


settings = Settings()
