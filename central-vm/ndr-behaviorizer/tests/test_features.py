from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from app.aggregator import BehaviorAggregator
from app.config import Settings
from app.feature_registry import load_feature_spec

ROOT = Path(__file__).parent
FEATURE_CONFIG = ROOT.parent / "features" / "host_hourly_v1.yaml"


def load_fixture(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))


def aggregate(*names: str):
    settings = replace(Settings(), feature_config_path=str(FEATURE_CONFIG), ml_enabled=False)
    spec = load_feature_spec(str(FEATURE_CONFIG))
    docs = [{"_source": load_fixture(name)} for name in names]
    return BehaviorAggregator(settings, spec).aggregate_hits(docs)


def test_dns_behavior_features():
    docs = aggregate("session_dns.json")
    assert len(docs) == 1
    features = docs[0]["features"]
    assert features["session_count"] == 1
    assert features["dns_session_count"] == 1
    assert features["dns_unique_query_count"] == 1
    assert features["dns_nxdomain_count"] == 0
    assert docs[0]["human"]["top_dns_queries"][0]["value"] == "example.com"


def test_http_files_behavior_features():
    docs = aggregate("session_http_files.json")
    features = docs[0]["features"]
    assert features["http_session_count"] == 1
    assert features["http_unique_host_count"] == 1
    assert features["http_download_count"] == 1
    assert features["files_count"] == 1
    assert features["files_hash_count"] == 3
    assert features["files_unique_mime_type_count"] == 1


def test_tls_x509_behavior_features():
    docs = aggregate("session_tls_x509.json")
    features = docs[0]["features"]
    assert features["tls_session_count"] == 1
    assert features["tls_invalid_cert_count"] == 1
    assert features["tls_sni_mismatch_count"] == 1
    assert features["tls_self_signed_count"] == 1
    assert features["tls_expired_cert_count"] == 1
    assert features["notice_count"] == 1


def test_ssh_behavior_features():
    docs = aggregate("session_ssh.json")
    features = docs[0]["features"]
    assert features["ssh_session_count"] == 1
    assert features["ssh_external_session_count"] == 1
    assert features["ssh_nonstandard_port_count"] == 1
    assert features["ssh_auth_success_count"] == 1
    assert features["ssh_auth_attempt_sum"] == 2


def test_control_plane_excluded_from_behavior_features_but_counted_in_quality():
    docs = aggregate("session_dns.json", "session_control_plane.json")
    features = docs[0]["features"]
    quality = docs[0]["quality"]
    assert quality["session_count_total"] == 2
    assert quality["session_count_used"] == 1
    assert quality["excluded_session_count"] == 1
    assert features["session_count"] == 1
    assert "excluded_sessions_present" in quality["warnings"]


def test_feature_vector_order_and_length():
    settings = replace(Settings(), feature_config_path=str(FEATURE_CONFIG), ml_enabled=False)
    spec = load_feature_spec(str(FEATURE_CONFIG))
    docs = BehaviorAggregator(settings, spec).aggregate_hits([{"_source": load_fixture("session_dns.json")}])
    doc = docs[0]
    assert doc["ml"]["feature_names"] == spec.vector_order
    assert len(doc["ml"]["feature_vector"]) == len(spec.vector_order)
    assert doc["ml"]["vector_length"] == len(spec.vector_order)
    assert doc["ml"]["feature_vector"][0] == doc["features"][spec.vector_order[0]]


def test_deterministic_behavior_id():
    first = aggregate("session_dns.json")[0]["behavior"]["id"]
    second = aggregate("session_dns.json")[0]["behavior"]["id"]
    assert first == second
    assert first == "host_hourly_v1|sensor1|192.168.25.129|2026-05-06T16:00:00.000Z"


def test_quality_warning_when_only_excluded():
    docs = aggregate("session_control_plane.json")
    doc = docs[0]
    assert doc["ml"]["ready"] is False
    assert doc["quality"]["feature_complete"] is False
    assert "no_behavior_eligible_sessions" in doc["quality"]["warnings"]
