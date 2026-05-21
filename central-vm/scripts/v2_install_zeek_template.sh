#!/bin/bash
# Installs ECS-typed index template for all zeek-* indices
# Run from central-vm: bash scripts/install_zeek_template.sh

set -euo pipefail
OS_URL="https://localhost:9200"
OS_USER="admin"
OS_PASS="${OPENSEARCH_INITIAL_ADMIN_PASSWORD}"
CA="certs/ca/ca.crt"

curl -s -u "$OS_USER:$OS_PASS" --cacert "$CA" \
  -X PUT "$OS_URL/_index_template/zeek-ecs" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["zeek-*"],
  "template": {
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp":                          { "type": "date" },
        "event.created":                       { "type": "date" },
        "event.duration":                      { "type": "float" },
        "event.kind":                          { "type": "keyword" },
        "event.category":                      { "type": "keyword" },
        "event.outcome":                       { "type": "keyword" },
        "source.ip":                           { "type": "ip" },
        "source.port":                         { "type": "integer" },
        "source.bytes":                        { "type": "long" },
        "source.packets":                      { "type": "long" },
        "source.domain":                       { "type": "keyword" },
        "source.geo.location":                 { "type": "geo_point" },
        "source.geo.country_iso_code":         { "type": "keyword" },
        "source.geo.city_name":                { "type": "keyword" },
        "destination.ip":                      { "type": "ip" },
        "destination.port":                    { "type": "integer" },
        "destination.bytes":                   { "type": "long" },
        "destination.packets":                 { "type": "long" },
        "destination.domain":                  { "type": "keyword" },
        "destination.geo.location":            { "type": "geo_point" },
        "destination.geo.country_iso_code":    { "type": "keyword" },
        "destination.geo.city_name":           { "type": "keyword" },
        "network.transport":                   { "type": "keyword" },
        "network.protocol":                    { "type": "keyword" },
        "network.community_id":                { "type": "keyword" },
        "network.bytes":                       { "type": "long" },
        "dns.question.name":                   { "type": "keyword" },
        "dns.question.type":                   { "type": "keyword" },
        "dns.question.class":                  { "type": "keyword" },
        "dns.response_code":                   { "type": "keyword" },
        "dns.id":                              { "type": "integer" },
        "http.request.method":                 { "type": "keyword" },
        "http.request.body.bytes":             { "type": "long" },
        "http.response.status_code":           { "type": "integer" },
        "http.response.body.bytes":            { "type": "long" },
        "http.version":                        { "type": "keyword" },
        "url.original":                        { "type": "wildcard" },
        "url.domain":                          { "type": "keyword" },
        "user_agent.original":                 { "type": "keyword" },
        "tls.cipher":                          { "type": "keyword" },
        "tls.version":                         { "type": "keyword" },
        "tls.server.x509.subject.common_name": { "type": "keyword" },
        "file.mime_type":                      { "type": "keyword" },
        "file.hash.md5":                       { "type": "keyword" },
        "file.hash.sha1":                      { "type": "keyword" },
        "file.hash.sha256":                    { "type": "keyword" },
        "file.size":                           { "type": "long" },
        "file.name":                           { "type": "keyword" },
        "user.name":                           { "type": "keyword" },
        "log_type":                            { "type": "keyword" },
        "sensor":                              { "type": "keyword" },
        "zeek.session_id":                     { "type": "keyword" }
      }
    }
  }
}'

echo "Template installed."
