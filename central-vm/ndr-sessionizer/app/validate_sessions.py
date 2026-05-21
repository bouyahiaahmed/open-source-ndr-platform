from __future__ import annotations

import os
from collections import Counter
from typing import Any

from opensearchpy import OpenSearch


OS_URL = os.getenv("OPENSEARCH_URL", "https://opensearch-node1:9200")
OS_USER = os.getenv("OPENSEARCH_USERNAME", os.getenv("OS_USER", "admin"))
OS_PASS = os.getenv("OPENSEARCH_PASSWORD", os.getenv("OS_PASS", "admin"))
CA_CERT = os.getenv("OPENSEARCH_CA_CERT")
VERIFY = os.getenv("OPENSEARCH_VERIFY_CERTS", "true").lower() == "true"


client = OpenSearch(
    OS_URL,
    http_auth=(OS_USER, OS_PASS),
    verify_certs=VERIFY,
    ca_certs=CA_CERT if CA_CERT else None,
    ssl_show_warn=False,
)


def getn(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def search_all(index: str, query: dict[str, Any], size: int = 1000):
    pit_resp = client.create_pit(index=index, keep_alive="2m")
    pit_id = pit_resp.get("pit_id") or pit_resp.get("id")
    search_after = None

    try:
        while True:
            body: dict[str, Any] = {
                "size": size,
                "pit": {"id": pit_id, "keep_alive": "2m"},
                "query": query,
                "sort": [{"_shard_doc": "asc"}],
            }
            if search_after:
                body["search_after"] = search_after

            resp = client.search(body=body)
            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                yield hit

            search_after = hits[-1].get("sort")
    finally:
        if pit_id:
            try:
                client.delete_pit(body={"pit_id": pit_id})
            except Exception:
                pass


def main() -> None:
    sessions = list(search_all("ndr-sessions*", {"match_all": {}}))

    ids = [str(h.get("_id")) for h in sessions]
    duplicate_ids = [k for k, v in Counter(ids).items() if v > 1]

    missing_protocol = 0
    missing_evidence = 0
    missing_source_ip = 0
    missing_destination_ip = 0
    control_plane = 0
    non_flow = 0
    malformed = 0
    truncated = 0
    flag_mismatches = 0

    protocols = Counter()
    combos = Counter()
    noise_reasons = Counter()

    for hit in sessions:
        src = hit.get("_source") or {}
        session = src.get("session") or {}
        network = src.get("network") or {}

        log_types = as_list(session.get("log_types"))
        combo = ",".join(sorted(str(x) for x in log_types))
        combos[combo or "MISSING"] += 1

        protocol = network.get("protocol") or "MISSING"
        protocols[protocol] += 1

        evidence = as_list(src.get("evidence"))

        if not network.get("protocol"):
            missing_protocol += 1
        if not evidence:
            missing_evidence += 1
        if session.get("flow_based") is False:
            non_flow += 1

        if session.get("category") == "malformed_raw":
            malformed += 1

        # Missing IPs are expected for non-flow synthetic sessions such as DHCP.
        if session.get("flow_based") is not False:
            if not getn(src, "source.ip"):
                missing_source_ip += 1
            if not getn(src, "destination.ip"):
                missing_destination_ip += 1
        if session.get("excluded_from_behavior") is True:
            control_plane += 1
            for reason in as_list(session.get("noise_reasons")):
                noise_reasons[str(reason)] += 1
        if session.get("events_truncated") is True:
            truncated += 1

        expected_flags = {
            "has_dns": "dns",
            "has_http": "http",
            "has_tls": "ssl",
            "has_ssh": "ssh",
            "has_notice": "notice",
            "has_files": "files",
            "has_weird": "weird",
        }

        for flag, log_type in expected_flags.items():
            expected = log_type in log_types
            actual = bool(session.get(flag))
            if actual != expected:
                flag_mismatches += 1

    print(f"SESSION_COUNT={len(sessions)}")
    print(f"DUPLICATE_SESSION_IDS={len(duplicate_ids)}")
    print(f"MISSING_NETWORK_PROTOCOL={missing_protocol}")
    print(f"MISSING_EVIDENCE={missing_evidence}")
    print(f"MISSING_SOURCE_IP={missing_source_ip}")
    print(f"MISSING_DESTINATION_IP={missing_destination_ip}")
    print(f"CONTROL_PLANE_TAGGED={control_plane}")
    print(f"NON_FLOW_SESSIONS={non_flow}")
    print(f"MALFORMED_RAW_SESSIONS={malformed}")
    print(f"EVENTS_TRUNCATED={truncated}")
    print(f"FLAG_MISMATCHES={flag_mismatches}")

    print("\nTOP_PROTOCOLS")
    for key, value in protocols.most_common(30):
        print(f"{key}: {value}")

    print("\nTOP_LOG_TYPE_COMBOS")
    for key, value in combos.most_common(30):
        print(f"{key}: {value}")

    print("\nTOP_NOISE_REASONS")
    for key, value in noise_reasons.most_common(30):
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
