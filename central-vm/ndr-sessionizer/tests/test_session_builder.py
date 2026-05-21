from __future__ import annotations

import json
from pathlib import Path

from app.config import Settings
from app.session_builder import SessionBuilder

FIXTURES = Path(__file__).parent / "fixtures"


def raw(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def hit(name: str, raw_id: str | None = None) -> dict:
    source = raw(name)
    return {
        "_index": "zeek-logs-2026.05.05",
        "_id": raw_id or name.replace(".json", "-id"),
        "_source": source,
    }


def builder() -> SessionBuilder:
    return SessionBuilder(Settings())


def test_conn_only_session():
    doc = builder().build_from_group([hit("conn.json")])
    assert doc is not None
    assert doc["session"]["id"] == "CjCShr3NQntSvbTNr3"
    assert doc["source"]["ip"] == "192.168.25.129"
    assert doc["destination"]["port"] == 443
    assert doc["conn"]["state"] == "SF"
    assert doc["session"]["event_count"] == 1


def test_conn_plus_ssl():
    doc = builder().build_from_group([hit("conn.json"), hit("ssl.json")])
    assert doc is not None
    assert doc["session"]["has_tls"] is True
    assert "ssl" in doc["session"]["log_types"]
    assert doc["tls"]["server_name"] == "self-signed.badssl.com"
    assert len(doc["zeek"]["ssl"]["events"]) == 1


def test_conn_ssl_notice():
    doc = builder().build_from_group([hit("conn.json"), hit("ssl.json"), hit("notice.json")])
    assert doc is not None
    assert doc["session"]["has_notice"] is True
    assert doc["notice"]["notes"] == ["SSL::Invalid_Server_Cert"]
    assert doc["session"]["event_count"] == 3


def test_conn_dns():
    doc = builder().build_from_group([hit("conn.json"), hit("dns.json")])
    assert doc is not None
    assert doc["session"]["has_dns"] is True
    assert doc["dns"]["query"] == "example.com"
    assert doc["dns"]["query_length"] == 11


def test_conn_http_files():
    doc = builder().build_from_group([hit("conn.json"), hit("http.json"), hit("files.json")])
    assert doc is not None
    assert doc["session"]["has_http"] is True
    assert doc["session"]["has_files"] is True
    assert doc["http"]["host"] == "example.com"
    assert doc["files"]["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]


def test_notice_without_conn_uses_uid_and_notice_source():
    doc = builder().build_from_group([hit("notice.json")])
    assert doc is not None
    assert doc["session"]["id"] == "CjCShr3NQntSvbTNr3"
    assert doc["session"]["has_notice"] is True
    assert doc["notice"]["messages"] == ["SSL certificate validation failed with self signed certificate"]


def test_unknown_log_type_is_preserved_under_disabled_zeek_object():
    doc = builder().build_from_group([hit("unknown_log_type.json")])
    assert doc is not None
    assert "new_future_protocol" in doc["zeek"]
    event = doc["zeek"]["new_future_protocol"]["events"][0]
    assert event["future_dynamic_field"] == "kept in disabled zeek object"


def test_duplicate_raw_event_does_not_duplicate_evidence():
    duplicate = hit("conn.json", raw_id="same-raw-id")
    doc = builder().build_from_group([duplicate, duplicate])
    assert doc is not None
    assert len(doc["evidence"]) == 1
    assert len(doc["zeek"]["conn"]["events"]) == 1


def test_late_arriving_ssl_updates_existing_conn_session():
    b = builder()
    existing = b.build_from_group([hit("conn.json")])
    late = b.build_from_group([hit("ssl.json")])
    assert existing is not None and late is not None
    merged = b.merge_existing(existing, late)
    assert merged["session"]["has_tls"] is True
    assert merged["session"]["event_count"] == 2
    assert len(merged["evidence"]) == 2
    assert merged["tls"]["server_name"] == "self-signed.badssl.com"


def test_malformed_document_is_skipped_safely():
    groups = builder().group_hits([{"_index": "x", "_id": "bad", "_source": "not-a-dict"}])
    assert groups == {}


def test_mapping_ip_fields_are_ips_and_keywords_are_aggregatable():
    mapping = json.loads((Path(__file__).parents[1] / "mappings" / "ndr-sessions-template.json").read_text())
    props = mapping["template"]["mappings"]["properties"]
    assert props["source"]["properties"]["ip"]["type"] == "ip"
    assert props["destination"]["properties"]["ip"]["type"] == "ip"
    assert props["session"]["properties"]["uid"]["type"] == "keyword"
    assert props["network"]["properties"]["community_id"]["type"] == "keyword"


def test_zeek_object_disabled_to_avoid_mapping_explosion():
    mapping = json.loads((Path(__file__).parents[1] / "mappings" / "ndr-sessions-template.json").read_text())
    zeek = mapping["template"]["mappings"]["properties"]["zeek"]
    assert zeek["type"] == "object"
    assert zeek["enabled"] is False
