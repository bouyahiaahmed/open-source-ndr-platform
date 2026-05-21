#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
OS_URL="${OS_URL:-https://localhost:9200}"
OS_USERNAME="${OS_USERNAME:-admin}"
OS_PASSWORD="${OS_PASSWORD:-admin}"
auth=(-k -u "${OS_USERNAME}:${OS_PASSWORD}")
json=(-H "Content-Type: application/json")

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
check_response() {
  local label="$1"
  local response="$2"
  if echo "$response" | grep -q '"error"'; then
    echo "  [FAIL] $label"
    echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
    exit 1
  else
    echo "  [OK]   $label"
  fi
}

# ─────────────────────────────────────────────
# STEP 1 — Install ingest pipeline
# Key fixes vs original:
#   - ctx['id.orig_h'] bracket notation for flat dot-key fields
#     (Vector ships id.orig_h as a literal string key, not a nested object)
#   - Ports set as strings first, then converted to integer
#   - related.ip appended properly (override:true so it accumulates)
#   - Added http.*, url.*, tls.*, file.* ECS processors
# ─────────────────────────────────────────────
echo ""
echo "==> [1/4] Installing ingest pipeline: zeek_ecs_pipeline"

PIPELINE_RESPONSE=$(curl -s "${auth[@]}" -X PUT \
  "${OS_URL}/_ingest/pipeline/zeek_ecs_pipeline" \
  "${json[@]}" -d '
{
  "description": "Normalize Zeek logs to ECS-compatible fields (flat dot-key aware)",
  "processors": [

    {
      "set": {
        "tag": "set_event_module",
        "field": "event.module",
        "value": "zeek",
        "override": false
      }
    },
    {
      "set": {
        "tag": "set_event_kind",
        "field": "event.kind",
        "value": "event",
        "override": false
      }
    },
    {
      "set": {
        "tag": "set_event_category",
        "field": "event.category",
        "value": ["network"],
        "override": false
      }
    },
    {
      "set": {
        "tag": "set_event_type",
        "field": "event.type",
        "value": ["info"],
        "override": false
      }
    },
    {
      "set": {
        "tag": "set_event_dataset",
        "if": "ctx.containsKey(\"log_type\") && ctx.log_type != null",
        "field": "event.dataset",
        "value": "zeek.{{{log_type}}}",
        "ignore_empty_value": true,
        "override": false
      }
    },

    {
      "set": {
        "tag": "set_network_transport",
        "if": "ctx.containsKey(\"proto\") && ctx.proto != null",
        "field": "network.transport",
        "value": "{{{proto}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_network_protocol",
        "if": "ctx.containsKey(\"service\") && ctx.service != null",
        "field": "network.protocol",
        "value": "{{{service}}}",
        "ignore_empty_value": true
      }
    },

    {
      "set": {
        "tag": "set_source_ip",
        "if": "ctx.containsKey(\"id.orig_h\") && ctx[\"id.orig_h\"] != null",
        "field": "source.ip",
        "value": "{{id.orig_h}}",
        "ignore_empty_value": true
      }
    },
    {
      "convert": {
        "tag": "convert_source_ip",
        "if": "ctx.containsKey(\"source\") && ctx.source != null && ctx.source.containsKey(\"ip\") && ctx.source.ip != null",
        "field": "source.ip",
        "type": "ip",
        "ignore_failure": true
      }
    },

    {
      "set": {
        "tag": "set_source_port",
        "if": "ctx.containsKey(\"id.orig_p\") && ctx[\"id.orig_p\"] != null",
        "field": "source.port",
        "value": "{{id.orig_p}}",
        "ignore_empty_value": true
      }
    },
    {
      "convert": {
        "tag": "convert_source_port",
        "if": "ctx.containsKey(\"source\") && ctx.source != null && ctx.source.containsKey(\"port\") && ctx.source.port != null",
        "field": "source.port",
        "type": "integer",
        "ignore_failure": true
      }
    },

    {
      "set": {
        "tag": "set_destination_ip",
        "if": "ctx.containsKey(\"id.resp_h\") && ctx[\"id.resp_h\"] != null",
        "field": "destination.ip",
        "value": "{{id.resp_h}}",
        "ignore_empty_value": true
      }
    },
    {
      "convert": {
        "tag": "convert_destination_ip",
        "if": "ctx.containsKey(\"destination\") && ctx.destination != null && ctx.destination.containsKey(\"ip\") && ctx.destination.ip != null",
        "field": "destination.ip",
        "type": "ip",
        "ignore_failure": true
      }
    },

    {
      "set": {
        "tag": "set_destination_port",
        "if": "ctx.containsKey(\"id.resp_p\") && ctx[\"id.resp_p\"] != null",
        "field": "destination.port",
        "value": "{{id.resp_p}}",
        "ignore_empty_value": true
      }
    },
    {
      "convert": {
        "tag": "convert_destination_port",
        "if": "ctx.containsKey(\"destination\") && ctx.destination != null && ctx.destination.containsKey(\"port\") && ctx.destination.port != null",
        "field": "destination.port",
        "type": "integer",
        "ignore_failure": true
      }
    },

    {
      "set": {
        "tag": "set_dns_question_name",
        "if": "ctx.containsKey(\"query\") && ctx.query != null",
        "field": "dns.question.name",
        "value": "{{{query}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_dns_rcode",
        "if": "ctx.containsKey(\"rcode_name\") && ctx.rcode_name != null",
        "field": "dns.response_code",
        "value": "{{{rcode_name}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_dns_answers",
        "if": "ctx.containsKey(\"answers\") && ctx.answers != null",
        "field": "dns.answers.data",
        "value": "{{{answers}}}",
        "ignore_empty_value": true
      }
    },

    {
      "set": {
        "tag": "set_http_method",
        "if": "ctx.containsKey(\"method\") && ctx.method != null",
        "field": "http.request.method",
        "value": "{{{method}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_http_status_code",
        "if": "ctx.containsKey(\"status_code\") && ctx.status_code != null",
        "field": "http.response.status_code",
        "value": "{{{status_code}}}",
        "ignore_empty_value": true
      }
    },
    {
      "convert": {
        "tag": "convert_http_status_code",
        "if": "ctx.containsKey(\"http\") && ctx.http != null && ctx.http.containsKey(\"response\") && ctx.http.response.containsKey(\"status_code\")",
        "field": "http.response.status_code",
        "type": "integer",
        "ignore_failure": true
      }
    },
    {
      "set": {
        "tag": "set_url_path",
        "if": "ctx.containsKey(\"uri\") && ctx.uri != null",
        "field": "url.path",
        "value": "{{{uri}}}",
        "ignore_empty_value": true
      }
    },
    {
      "script": {
        "tag": "remap_user_agent",
        "if": "ctx.containsKey(\"user_agent\") && ctx.user_agent instanceof String && ctx.user_agent != null",
        "lang": "painless",
        "source": "String ua = ctx.user_agent; ctx.remove(\"user_agent\"); if (ctx.user_agent == null) { ctx.user_agent = new HashMap(); } ctx.user_agent.original = ua;"
      }
    },

    {
      "set": {
        "tag": "set_tls_version",
        "if": "ctx.containsKey(\"version\") && ctx.version != null",
        "field": "tls.version",
        "value": "{{{version}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_tls_sni",
        "if": "ctx.containsKey(\"server_name\") && ctx.server_name != null",
        "field": "tls.client.server_name",
        "value": "{{{server_name}}}",
        "ignore_empty_value": true
      }
    },

    {
      "set": {
        "tag": "set_file_name",
        "if": "ctx.containsKey(\"filename\") && ctx.filename != null",
        "field": "file.name",
        "value": "{{{filename}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_file_mime_type",
        "if": "ctx.containsKey(\"mime_type\") && ctx.mime_type != null",
        "field": "file.mime_type",
        "value": "{{{mime_type}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_file_hash_md5",
        "if": "ctx.containsKey(\"md5\") && ctx.md5 != null",
        "field": "file.hash.md5",
        "value": "{{{md5}}}",
        "ignore_empty_value": true
      }
    },
    {
      "set": {
        "tag": "set_file_hash_sha1",
        "if": "ctx.containsKey(\"sha1\") && ctx.sha1 != null",
        "field": "file.hash.sha1",
        "value": "{{{sha1}}}",
        "ignore_empty_value": true
      }
    },

    {
      "set": {
        "tag": "set_related_ip_source",
        "if": "ctx.containsKey(\"source\") && ctx.source != null && ctx.source.containsKey(\"ip\") && ctx.source.ip != null",
        "field": "related.ip",
        "value": ["{{{source.ip}}}"],
        "override": false
      }
    },
    {
      "set": {
        "tag": "set_related_ip_destination",
        "if": "ctx.containsKey(\"destination\") && ctx.destination != null && ctx.destination.containsKey(\"ip\") && ctx.destination.ip != null",
        "field": "related.ip",
        "value": ["{{{destination.ip}}}"],
        "override": false
      }
    },

    {
      "convert": {
        "tag": "force_version_string",
        "if": "ctx.containsKey(\"version\") && ctx.version != null",
        "field": "version",
        "type": "string",
        "ignore_failure": true
      }
    },
    {
      "convert": {
        "tag": "force_opcode_string",
        "if": "ctx.containsKey(\"opcode\") && ctx.opcode != null",
        "field": "opcode",
        "type": "string",
        "ignore_failure": true
      }
    },
    {
      "convert": {
        "tag": "force_name_string",
        "if": "ctx.containsKey(\"name\") && ctx.name != null && !(ctx.name instanceof List) && !(ctx.name instanceof Map)",
        "field": "name",
        "type": "string",
        "ignore_failure": true
      }
    }

  ],
  "on_failure": [
    {
      "set": {
        "field": "ingest.error",
        "value": "{{{_ingest.on_failure_message}}}"
      }
    }
  ]
}')
check_response "zeek_ecs_pipeline installed" "$PIPELINE_RESPONSE"


# ─────────────────────────────────────────────
# STEP 2 — Install index template
# ─────────────────────────────────────────────
echo ""
echo "==> [2/4] Installing index template: zeek_template"

TEMPLATE_RESPONSE=$(curl -s "${auth[@]}" -X PUT \
  "${OS_URL}/_index_template/zeek_template" \
  "${json[@]}" -d '
{
  "index_patterns": ["zeek-*"],
  "priority": 500,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.default_pipeline": "zeek_ecs_pipeline",
      "index.mapping.ignore_malformed": false
    },
    "mappings": {
      "dynamic": true,
      "date_detection": false,
      "numeric_detection": false,
      "dynamic_templates": [
        {
          "strings_as_keywords": {
            "match_mapping_type": "string",
            "mapping": {
              "type": "keyword",
              "ignore_above": 1024
            }
          }
        }
      ],
      "properties": {

        "@timestamp": { "type": "date" },

        "uid":          { "type": "keyword" },
        "log_type":     { "type": "keyword" },
        "log_file":     { "type": "keyword" },
        "sensor":       { "type": "keyword" },
        "peer":         { "type": "keyword" },
        "notice":       { "type": "keyword" },
        "community_id": { "type": "keyword" },

        "proto":      { "type": "keyword" },
        "service":    { "type": "keyword" },
        "conn_state": { "type": "keyword" },
        "history":    { "type": "keyword" },

        "duration":      { "type": "float"   },
        "orig_bytes":    { "type": "long"     },
        "resp_bytes":    { "type": "long"     },
        "orig_ip_bytes": { "type": "long"     },
        "resp_ip_bytes": { "type": "long"     },
        "orig_pkts":     { "type": "integer"  },
        "resp_pkts":     { "type": "integer"  },
        "missed_bytes":  { "type": "long"     },
        "ip_proto":      { "type": "integer"  },

        "local_orig": { "type": "boolean" },
        "local_resp": { "type": "boolean" },
        "rejected":   { "type": "boolean" },

        "query":       { "type": "keyword" },
        "qclass_name": { "type": "keyword" },
        "qtype_name":  { "type": "keyword" },
        "rcode_name":  { "type": "keyword" },
        "answers":     { "type": "keyword" },
        "TTLs":        { "type": "float"   },
        "trans_id":    { "type": "integer" },

        "method":      { "type": "keyword" },
        "uri":         { "type": "keyword" },
        "status_code": { "type": "integer" },
        "host":        { "type": "keyword" },

        "server_name": { "type": "keyword" },
        "subject":     { "type": "keyword" },
        "issuer":      { "type": "keyword" },

        "filename":  { "type": "keyword" },
        "mime_type": { "type": "keyword" },
        "md5":       { "type": "keyword" },
        "sha1":      { "type": "keyword" },
        "sha256":    { "type": "keyword" },

        "version": { "type": "keyword" },
        "opcode":  { "type": "keyword" },
        "name":    { "type": "keyword" },

        "id": {
          "properties": {
            "orig_h": { "type": "ip"      },
            "resp_h": { "type": "ip"      },
            "orig_p": { "type": "integer" },
            "resp_p": { "type": "integer" }
          }
        },

        "source": {
          "properties": {
            "ip":   { "type": "ip"      },
            "port": { "type": "integer" }
          }
        },
        "destination": {
          "properties": {
            "ip":   { "type": "ip"      },
            "port": { "type": "integer" }
          }
        },
        "network": {
          "properties": {
            "transport": { "type": "keyword" },
            "protocol":  { "type": "keyword" }
          }
        },
        "dns": {
          "properties": {
            "question": {
              "properties": {
                "name": { "type": "keyword" }
              }
            },
            "answers": {
              "properties": {
                "data": { "type": "keyword" }
              }
            },
            "response_code": { "type": "keyword" }
          }
        },
        "http": {
          "properties": {
            "request": {
              "properties": {
                "method": { "type": "keyword" },
                "body": {
                  "properties": {
                    "bytes": { "type": "long" }
                  }
                }
              }
            },
            "response": {
              "properties": {
                "status_code": { "type": "integer" }
              }
            }
          }
        },
        "url": {
          "properties": {
            "path":     { "type": "keyword" },
            "original": { "type": "keyword" },
            "domain":   { "type": "keyword" }
          }
        },
        "user_agent": {
          "properties": {
            "original": { "type": "keyword" },
            "name":     { "type": "keyword" }
          }
        },
        "tls": {
          "properties": {
            "version": { "type": "keyword" },
            "client": {
              "properties": {
                "server_name": { "type": "keyword" }
              }
            },
            "server": {
              "properties": {
                "subject": { "type": "keyword" },
                "issuer":  { "type": "keyword" }
              }
            }
          }
        },
        "file": {
          "properties": {
            "name":      { "type": "keyword" },
            "mime_type": { "type": "keyword" },
            "hash": {
              "properties": {
                "md5":    { "type": "keyword" },
                "sha1":   { "type": "keyword" },
                "sha256": { "type": "keyword" }
              }
            }
          }
        },
        "event": {
          "properties": {
            "module":   { "type": "keyword" },
            "dataset":  { "type": "keyword" },
            "kind":     { "type": "keyword" },
            "category": { "type": "keyword" },
            "type":     { "type": "keyword" }
          }
        },
        "related": {
          "properties": {
            "ip": { "type": "ip" }
          }
        },
        "ingest": {
          "properties": {
            "error": { "type": "keyword" }
          }
        }
      }
    }
  }
}')
check_response "zeek_template installed" "$TEMPLATE_RESPONSE"


# ─────────────────────────────────────────────
# STEP 3 — Validate pipeline with simulate
# Tests both flat dot-key (Vector style) and
# nested object style inputs
# ─────────────────────────────────────────────
echo ""
echo "==> [3/4] Simulating pipeline (flat dot-key input — Vector style)"

SIM_RESPONSE=$(curl -s "${auth[@]}" -X POST \
  "${OS_URL}/_ingest/pipeline/zeek_ecs_pipeline/_simulate" \
  "${json[@]}" -d '
{
  "docs": [
    {
      "_index": "zeek-conn-test",
      "_id": "test-conn-1",
      "_source": {
        "@timestamp": "2026-03-25T10:00:00.000Z",
        "log_type": "conn",
        "id.orig_h": "10.51.1.12",
        "id.resp_h": "8.8.8.8",
        "id.orig_p": 54321,
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "conn_state": "SF",
        "duration": 1.234,
        "orig_bytes": 1024,
        "resp_bytes": 4096
      }
    },
    {
      "_index": "zeek-dns-test",
      "_id": "test-dns-1",
      "_source": {
        "@timestamp": "2026-03-25T10:00:01.000Z",
        "log_type": "dns",
        "id.orig_h": "192.168.1.50",
        "id.resp_h": "8.8.8.8",
        "id.orig_p": 33445,
        "id.resp_p": 53,
        "proto": "udp",
        "query": "malicious-domain.com",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": "1.2.3.4"
      }
    },
    {
      "_index": "zeek-http-test",
      "_id": "test-http-1",
      "_source": {
        "@timestamp": "2026-03-25T10:00:02.000Z",
        "log_type": "http",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "93.184.216.34",
        "id.orig_p": 55000,
        "id.resp_p": 80,
        "proto": "tcp",
        "method": "GET",
        "uri": "/malware.exe",
        "status_code": 200,
        "user_agent": "Mozilla/5.0"
      }
    }
  ]
}')

echo "$SIM_RESPONSE" | python3 -c "
import json, sys

data = json.load(sys.stdin)
docs = data.get('docs', [])
all_ok = True

checks = {
    'test-conn-1': ['source.ip', 'destination.ip', 'source.port', 'destination.port', 'network.transport', 'event.module', 'event.dataset'],
    'test-dns-1':  ['source.ip', 'destination.ip', 'dns.question.name', 'network.transport', 'event.dataset'],
    'test-http-1': ['source.ip', 'destination.ip', 'http.request.method', 'url.path', 'event.dataset'],
}

for doc in docs:
    doc_id = doc.get('doc', {}).get('_id', 'unknown')
    src = doc.get('doc', {}).get('_source', {})

    def get_nested(d, path):
        parts = path.split('.')
        for p in parts:
            if not isinstance(d, dict) or p not in d:
                return None
            d = d[p]
        return d

    expected = checks.get(doc_id, [])
    print(f'  Doc: {doc_id}')
    for field in expected:
        val = get_nested(src, field)
        status = '[OK]  ' if val is not None else '[MISS]'
        if val is None:
            all_ok = False
        print(f'    {status} {field} = {val}')

    if 'ingest' in src and 'error' in src.get('ingest', {}):
        print(f'    [ERR]  ingest.error = {src[\"ingest\"][\"error\"]}')
        all_ok = False

print()
if all_ok:
    print('  All ECS fields populated correctly.')
else:
    print('  WARNING: Some fields are missing. Check pipeline conditions.')
    sys.exit(1)
"


# ─────────────────────────────────────────────
# STEP 4 — Delete old zeek-* indices and verify
# template applies cleanly to new ones
# ─────────────────────────────────────────────
echo ""
echo "==> [4/4] Reindex existing data through updated pipeline"
echo ""
echo "  Discovering existing zeek-* indices..."

INDICES=$(curl -s "${auth[@]}" "${OS_URL}/zeek-*?pretty" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(sorted(d.keys())))" 2>/dev/null || true)

if [ -z "$INDICES" ]; then
  echo "  No existing indices found. Nothing to reindex."
else
  echo "  Found indices:"
  echo "$INDICES" | sed 's/^/    /'
  echo ""
  echo "  Choose an option:"
  echo "    a) Delete and let Vector re-populate (lose historical data)"
  echo "    b) Reindex through pipeline (preserve historical data)"
  echo ""
  read -rp "  Enter choice [a/b]: " CHOICE

  case "$CHOICE" in
    a)
      echo ""
      echo "  Deleting old indices..."
      while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        DEL_RESP=$(curl -s "${auth[@]}" -X DELETE "${OS_URL}/${idx}")
        if echo "$DEL_RESP" | grep -q '"acknowledged":true'; then
          echo "  [OK]  Deleted: $idx"
        else
          echo "  [WARN] Could not delete: $idx — $DEL_RESP"
        fi
      done <<< "$INDICES"
      echo ""
      echo "  Done. New indices will be created by Vector with the updated pipeline."
      ;;

    b)
      echo ""
      echo "  Reindexing through pipeline..."
      while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        new_idx="${idx}-v2"
        echo "  Reindexing $idx → $new_idx ..."
        RI_RESP=$(curl -s "${auth[@]}" -X POST "${OS_URL}/_reindex?wait_for_completion=true" \
          "${json[@]}" -d "{
            \"source\": { \"index\": \"${idx}\" },
            \"dest\":   { \"index\": \"${new_idx}\", \"pipeline\": \"zeek_ecs_pipeline\" }
          }")
        TOTAL=$(echo "$RI_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null || echo "?")
        echo "  [OK]  $idx → $new_idx ($TOTAL docs)"
      done <<< "$INDICES"
      echo ""
      echo "  Reindex complete. Update Vector to write to the new -v2 indices,"
      echo "  or re-run this script after deleting the old indices."
      ;;

    *)
      echo "  Skipping reindex step."
      ;;
  esac
fi


# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo "  Setup complete. Quick verification queries:"
echo "══════════════════════════════════════════════"
echo ""
echo "  # Confirm ECS fields in a real document:"
echo "  GET /zeek-conn-*/_search"
echo "  { \"size\": 1, \"_source\": [\"source.ip\",\"destination.ip\",\"source.port\",\"destination.port\",\"network.transport\",\"event.module\",\"id.orig_h\"] }"
echo ""
echo "  # Field types (no conflicts expected):"
echo "  GET /zeek-*/_field_caps?fields=source.ip,destination.ip,source.port,destination.port,network.transport,network.protocol"
echo ""
echo "  # Any pipeline errors?"
echo "  GET /zeek-*/_search"
echo "  { \"query\": { \"exists\": { \"field\": \"ingest.error\" } }, \"size\": 5 }"
echo ""
echo "  # Security Analytics mapping:"
echo "  GET /_plugins/_security_analytics/mappings/view"
echo "  { \"index_name\": \"zeek-conn-*\" }"
echo ""
