import os
import json
from datetime import datetime, timedelta, timezone

import requests
import yaml

from elastalert.enhancements import BaseEnhancement


class NdrPortScanEnricher(BaseEnhancement):
    """
    Enriches Nmap/port-scan alerts by querying ndr-sessions-* around the matched event.

    Adds fields:
      - ndr_scan_unique_destination_ports
      - ndr_scan_interesting_ports
      - ndr_scan_conn_state_summary
      - ndr_scan_protocol_summary
      - ndr_scan_ports_sample
      - ndr_scan_message
    """

    def process(self, match):
        source_ip = self._get(match, "source.ip")
        destination_ip = self._get(match, "destination.ip")
        event_time = self._get(match, "@timestamp")

        if not source_ip or not destination_ip or not event_time:
            match["ndr_scan_enrichment_error"] = "missing source.ip, destination.ip, or @timestamp"
            return

        try:
            start, end = self._window(event_time)
            result = self._query_sessions(source_ip, destination_ip, start, end)
            aggs = result.get("aggregations", {})

            unique_ports = aggs.get("unique_destination_ports", {}).get("value", 0)

            conn_states = self._buckets_to_dict(
                aggs.get("by_conn_state", {}).get("buckets", [])
            )

            protocols = self._buckets_to_dict(
                aggs.get("interesting_ports_not_rej", {})
                    .get("by_protocol", {})
                    .get("buckets", [])
            )

            interesting_ports = [
                b.get("key")
                for b in aggs.get("interesting_ports_not_rej", {})
                             .get("ports", {})
                             .get("buckets", [])
            ]

            scanned_ports_sample = [
                b.get("key")
                for b in aggs.get("all_scanned_ports_sample", {})
                             .get("buckets", [])
            ]

            rej_count = conn_states.get("REJ", 0)

            match["ndr_scan_unique_destination_ports"] = unique_ports
            match["ndr_scan_interesting_ports"] = interesting_ports
            match["ndr_scan_conn_state_summary"] = conn_states
            match["ndr_scan_protocol_summary"] = protocols
            match["ndr_scan_ports_sample"] = scanned_ports_sample
            match["ndr_scan_window_start"] = start
            match["ndr_scan_window_end"] = end

            if interesting_ports:
                interesting = ", ".join(str(p) for p in interesting_ports)
            else:
                interesting = "none observed"

            match["ndr_scan_message"] = (
                f"Possible Nmap port scan detected: {source_ip} scanned "
                f"{unique_ports} unique TCP destination ports on {destination_ip} "
                f"within the detection window. Most ports were rejected/closed "
                f"(REJ={rej_count}). Interesting/open ports observed: {interesting}."
            )

        except Exception as e:
            match["ndr_scan_enrichment_error"] = f"{type(e).__name__}: {e}"

    def _window(self, event_time):
        dt = self._parse_time(event_time)

        before_minutes = int(self.rule.get("ndr_enrich_before_minutes", 5))
        after_seconds = int(self.rule.get("ndr_enrich_after_seconds", 60))

        start = dt - timedelta(minutes=before_minutes)
        end = dt + timedelta(seconds=after_seconds)

        return (
            start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        )

    def _parse_time(self, value):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        value = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(value).astimezone(timezone.utc)

    def _query_sessions(self, source_ip, destination_ip, start, end):
        cfg = self._load_config()

        scheme = "https" if cfg.get("use_ssl", True) else "http"
        host = os.getenv("ES_HOST") or cfg.get("es_host", "opensearch-node1")
        port = os.getenv("ES_PORT") or cfg.get("es_port", 9200)

        index = self.rule.get("ndr_enrich_index", "ndr-sessions-*")
        url = f"{scheme}://{host}:{port}/{index}/_search"

        username = os.getenv("ES_USERNAME") or cfg.get("es_username")
        password = os.getenv("ES_PASSWORD") or cfg.get("es_password")
        auth = (username, password) if username and password else None

        verify_certs = cfg.get("verify_certs", True)
        ca_certs = cfg.get("ca_certs")
        verify = ca_certs if verify_certs and ca_certs else verify_certs

        max_ports = int(self.rule.get("ndr_enrich_max_ports", 1000))

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start, "lte": end}}},
                        {"term": {"source.ip": source_ip}},
                        {"term": {"destination.ip": destination_ip}},
                        {"term": {"network.transport": "tcp"}},
                    ]
                }
            },
            "aggs": {
                "unique_destination_ports": {
                    "cardinality": {"field": "destination.port"}
                },
                "by_conn_state": {
                    "terms": {"field": "conn.state", "size": 20}
                },
                "interesting_ports_not_rej": {
                    "filter": {
                        "bool": {
                            "must_not": [
                                {"term": {"conn.state": "REJ"}}
                            ]
                        }
                    },
                    "aggs": {
                        "ports": {
                            "terms": {
                                "field": "destination.port",
                                "size": 100,
                                "order": {"_key": "asc"}
                            }
                        },
                        "by_protocol": {
                            "terms": {
                                "field": "network.protocol",
                                "size": 20
                            }
                        },
                        "by_state": {
                            "terms": {
                                "field": "conn.state",
                                "size": 20
                            }
                        }
                    }
                },
                "all_scanned_ports_sample": {
                    "terms": {
                        "field": "destination.port",
                        "size": max_ports,
                        "order": {"_key": "asc"}
                    }
                }
            }
        }

        response = requests.post(
            url,
            auth=auth,
            json=body,
            verify=verify,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()

    def _load_config(self):
        config_path = os.getenv("ELASTALERT_CONFIG", "/opt/elastalert/config.yaml")
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _get(self, data, path, default=None):
        if path in data:
            return data[path]

        cur = data
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    def _buckets_to_dict(self, buckets):
        return {b.get("key"): b.get("doc_count", 0) for b in buckets}
