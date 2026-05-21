from __future__ import annotations

import json
from pathlib import Path

from app.normalizer import normalize_dns, normalize_http, normalize_tls

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


def test_dns_features_are_computed():
    dns = normalize_dns([load("dns.json")])
    assert dns["query"] == "example.com"
    assert dns["query_length"] == len("example.com")
    assert dns["label_count"] == 2
    assert dns["longest_label_length"] == 7
    assert dns["is_txt"] is False
    assert dns["is_nxdomain"] is False
    assert dns["answers"] == ["93.184.216.34"]


def test_http_fields_are_normalized():
    http = normalize_http([load("http.json")])
    assert http["host"] == "example.com"
    assert http["method"] == "GET"
    assert http["uri"] == "/index.html"
    assert http["status_code"] == 200
    assert http["response_body_bytes"] == 1256


def test_tls_fields_are_normalized():
    tls = normalize_tls([load("ssl.json")])
    assert tls["server_name"] == "self-signed.badssl.com"
    assert tls["established"] is True
    assert tls["validation_status"] == "self signed certificate"
