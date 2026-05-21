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


def test_entity_strategy_host_sensor_separates_duplicate_sensor_views():
    spec = load_feature_spec(str(FEATURE_CONFIG))
    settings = replace(Settings(), behavior_entity_mode="host_sensor", feature_config_path=str(FEATURE_CONFIG))
    one = load_fixture("session_dns.json")
    two = load_fixture("session_dns.json")
    two["session"]["id"] = "dns-2"
    two["sensor"]["name"] = "sensor2"
    docs = BehaviorAggregator(settings, spec).aggregate_hits([{"_source": one}, {"_source": two}])
    assert len(docs) == 2
    assert {doc["behavior"]["sensor"] for doc in docs} == {"sensor1", "sensor2"}


def test_entity_strategy_host_merges_sensors_when_configured():
    spec = load_feature_spec(str(FEATURE_CONFIG))
    settings = replace(Settings(), behavior_entity_mode="host", feature_config_path=str(FEATURE_CONFIG))
    one = load_fixture("session_dns.json")
    two = load_fixture("session_dns.json")
    two["session"]["id"] = "dns-2"
    two["sensor"]["name"] = "sensor2"
    docs = BehaviorAggregator(settings, spec).aggregate_hits([{"_source": one}, {"_source": two}])
    assert len(docs) == 1
    assert docs[0]["behavior"]["sensor"] is None
    assert docs[0]["features"]["session_count"] == 2


def test_behavior_contains_exact_session_refs_for_rollback():
    spec = load_feature_spec(str(FEATURE_CONFIG))
    settings = replace(Settings(), behavior_entity_mode="host_sensor", feature_config_path=str(FEATURE_CONFIG))
    doc = load_fixture("session_dns.json")
    hit = {"_index": "ndr-sessions-2026.05.06", "_id": "session-doc-1", "_source": doc}
    behavior = BehaviorAggregator(settings, spec).aggregate_hits([hit])[0]
    assert behavior["evidence"]["session_ref_count"] == 1
    assert behavior["evidence"]["session_refs"][0]["index"] == "ndr-sessions-2026.05.06"
    assert behavior["evidence"]["session_refs"][0]["id"] == "session-doc-1"
    assert behavior["evidence"]["session_refs"][0]["session_id"] == doc["session"]["id"]
