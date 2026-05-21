#!/usr/bin/env python3
"""
Read GoFlow2 JSON lines from stdin, normalize them to an ECS-like NDR flow schema,
and bulk index them into OpenSearch.

Input:
  GoFlow2 JSON, for example:
  {"type":"NETFLOW_V9","sampler_address":"192.168.25.135", ...}

Output index:
  ndr-flows-YYYY.MM.dd by default.
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

OS_URL = os.getenv("OS_URL", "https://127.0.0.1:9200").rstrip("/")
OS_USER = os.getenv("OS_USER", "admin")
OS_PASS = os.getenv("OS_PASS", "admin")
OS_INDEX_PREFIX = os.getenv("OS_INDEX_PREFIX", "ndr-flows")
OS_VERIFY_SSL = os.getenv("OS_VERIFY_SSL", "false").lower() in ("1", "true", "yes", "y")
OS_CA_CERT = os.getenv("OS_CA_CERT", "")

APPLY_TEMPLATE_ON_START = os.getenv("APPLY_TEMPLATE_ON_START", "true").lower() in ("1", "true", "yes", "y")
TEMPLATE_PATH = os.getenv("TEMPLATE_PATH", "/app/mappings/ndr-flows-template.json")

BULK_SIZE = int(os.getenv("BULK_SIZE", "100"))
BULK_FLUSH_SECONDS = int(os.getenv("BULK_FLUSH_SECONDS", "5"))

FLOW_OBSERVER_VENDOR = os.getenv("FLOW_OBSERVER_VENDOR", "pfsense")
FLOW_OBSERVER_TYPE = os.getenv("FLOW_OBSERVER_TYPE", "firewall")
NDR_ENV = os.getenv("NDR_ENV", "lab")
NDR_COLLECTOR_NAME = os.getenv("NDR_COLLECTOR_NAME", "goflow2")
KEEP_RAW_GOFLOW = os.getenv("KEEP_RAW_GOFLOW", "true").lower() in ("1", "true", "yes", "y")

NDR_TAG_NOISE = os.getenv("NDR_TAG_NOISE", "true").lower() in ("1", "true", "yes", "y")
NDR_DROP_NOISE = os.getenv("NDR_DROP_NOISE", "false").lower() in ("1", "true", "yes", "y")

def csv_set(name: str, default: str = "") -> set[str]:
    return {x.strip() for x in os.getenv(name, default).split(",") if x.strip()}

NDR_NOISE_IPS = csv_set("NDR_NOISE_IPS", "168.63.129.16,169.254.169.254")
NDR_FIREWALL_IPS = csv_set("NDR_FIREWALL_IPS", "10.51.1.15")
NDR_COLLECTOR_IPS = csv_set("NDR_COLLECTOR_IPS", "10.51.1.11")
NDR_NETFLOW_PORTS = {int(x) for x in csv_set("NDR_NETFLOW_PORTS", "2055")}

AUTH = base64.b64encode(f"{OS_USER}:{OS_PASS}".encode("utf-8")).decode("ascii")

PROTO_MAP = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    89: "ospf",
    132: "sctp",
}



def normalize_proto(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Return ECS-like network.transport and IANA protocol number.

    GoFlow2 may output proto as numeric values like 6/17 or strings like TCP/UDP.
    """
    if value is None or value == "":
        return None, None

    raw = str(value).strip()
    lowered = raw.lower()

    numeric_to_name = {
        "1": "icmp",
        "2": "igmp",
        "6": "tcp",
        "17": "udp",
        "41": "ipv6",
        "47": "gre",
        "50": "esp",
        "51": "ah",
        "58": "ipv6-icmp",
        "89": "ospf",
        "132": "sctp",
    }

    name_to_numeric = {
        "icmp": "1",
        "igmp": "2",
        "tcp": "6",
        "udp": "17",
        "ipv6": "41",
        "gre": "47",
        "esp": "50",
        "ah": "51",
        "ipv6-icmp": "58",
        "ospf": "89",
        "sctp": "132",
    }

    if lowered in numeric_to_name:
        return numeric_to_name[lowered], lowered

    if lowered in name_to_numeric:
        return lowered, name_to_numeric[lowered]

    number = to_int(value)
    if number is not None:
        return PROTO_MAP.get(number, str(number)), str(number)

    return lowered, None


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def build_ssl_context() -> ssl.SSLContext:
    if not OS_VERIFY_SSL:
        return ssl._create_unverified_context()  # nosec - lab-friendly by default
    if OS_CA_CERT:
        return ssl.create_default_context(cafile=OS_CA_CERT)
    return ssl.create_default_context()


SSL_CONTEXT = build_ssl_context()


def request(method: str, path: str, body: Optional[bytes] = None, timeout: int = 20) -> Tuple[int, bytes]:
    url = f"{OS_URL}{path}"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Basic {AUTH}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=timeout) as resp:
        return resp.status, resp.read()


def apply_template() -> None:
    if not APPLY_TEMPLATE_ON_START:
        return
    try:
        with open(TEMPLATE_PATH, "rb") as f:
            template = f.read()
        status, body = request("PUT", "/_index_template/ndr-flows-template", template)
        log(f"[template] applied ndr-flows-template status={status}")
    except FileNotFoundError:
        log(f"[template] skipped: template file not found: {TEMPLATE_PATH}")
    except Exception as exc:
        log(f"[template] warning: could not apply template: {exc}")


def to_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def ns_to_iso(value: Any) -> Optional[str]:
    ns = to_int(value)
    if ns is None or ns <= 0:
        return None
    return dt.datetime.fromtimestamp(ns / 1_000_000_000, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def get_first(raw: Dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return None


def is_private_ip(ip_value: Any) -> Optional[bool]:
    if not ip_value:
        return None
    try:
        ip = ipaddress.ip_address(str(ip_value))
        return ip.is_private
    except Exception:
        return None


def infer_direction(src_ip: Any, dst_ip: Any) -> Optional[str]:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private is None or dst_private is None:
        return None
    if src_private and not dst_private:
        return "outbound"
    if not src_private and dst_private:
        return "inbound"
    if src_private and dst_private:
        return "internal"
    return "external"


def remove_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            cleaned = remove_nulls(item)
            if cleaned is not None and cleaned != {} and cleaned != []:
                result[key] = cleaned
        return result
    if isinstance(value, list):
        return [remove_nulls(item) for item in value if item is not None]
    return value



def classify_noise(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    src_ip = doc.get("source", {}).get("ip")
    dst_ip = doc.get("destination", {}).get("ip")
    dst_port = doc.get("destination", {}).get("port")

    bytes_value = doc.get("network", {}).get("bytes", 0) or 0
    packets_value = doc.get("network", {}).get("packets", 0) or 0

    reasons: List[str] = []

    if src_ip in NDR_NOISE_IPS or dst_ip in NDR_NOISE_IPS:
        reasons.append("azure_platform_or_metadata")

    if (
        src_ip in NDR_FIREWALL_IPS
        and dst_ip in NDR_COLLECTOR_IPS
        and dst_port in NDR_NETFLOW_PORTS
    ):
        reasons.append("netflow_export_self_traffic")

    if bytes_value == 0 and packets_value == 0:
        reasons.append("zero_counters")

    return bool(reasons), reasons

def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    proto_raw = get_first(raw, ["proto", "protocol", "ip_proto"])
    proto_transport, proto_iana = normalize_proto(proto_raw)
    src_ip = get_first(raw, ["src_addr", "srcaddr", "ipv4_src_addr", "ipv6_src_addr"])
    dst_ip = get_first(raw, ["dst_addr", "dstaddr", "ipv4_dst_addr", "ipv6_dst_addr"])
    src_port = to_int(get_first(raw, ["src_port", "l4_src_port", "srcport"]))
    dst_port = to_int(get_first(raw, ["dst_port", "l4_dst_port", "dstport"]))

    start = ns_to_iso(get_first(raw, ["time_flow_start_ns", "flow_start_ns"]))
    end = ns_to_iso(get_first(raw, ["time_flow_end_ns", "flow_end_ns"]))
    received = ns_to_iso(get_first(raw, ["time_received_ns", "received_ns"]))
    timestamp = end or received or now_iso()

    duration_ms: Optional[int] = None
    start_dt = parse_iso(start)
    end_dt = parse_iso(end)
    if start_dt and end_dt:
        duration_ms = int((end_dt - start_dt).total_seconds() * 1000)

    bytes_value = to_int(get_first(raw, ["bytes", "in_bytes", "octets", "flow_bytes"]))
    packets_value = to_int(get_first(raw, ["packets", "in_pkts", "pkts", "flow_packets"]))

    doc: Dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "dataset": "firewall.netflow",
            "module": "ndr-flow-collector",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
        },
        "observer": {
            "type": FLOW_OBSERVER_TYPE,
            "vendor": FLOW_OBSERVER_VENDOR,
            "ip": get_first(raw, ["sampler_address", "agent_ip", "exporter_ip"]),
        },
        "source": {
            "ip": src_ip,
            "port": src_port,
            "mac": get_first(raw, ["src_mac", "source_mac"]),
            "vlan": {"id": to_int(get_first(raw, ["src_vlan", "vlan_id"]))},
        },
        "destination": {
            "ip": dst_ip,
            "port": dst_port,
            "mac": get_first(raw, ["dst_mac", "destination_mac"]),
            "vlan": {"id": to_int(get_first(raw, ["dst_vlan", "vlan_id"]))},
        },
        "network": {
            "transport": proto_transport,
            "iana_number": proto_iana,
            "bytes": bytes_value,
            "packets": packets_value,
            "direction": infer_direction(src_ip, dst_ip),
        },
        "flow": {
            "id": get_first(raw, ["flow_id", "id"]),
            "start": start,
            "end": end,
            "duration": {"ms": duration_ms},
        },
        "netflow": {
            "version": get_first(raw, ["type", "version"]),
            "sequence_num": to_int(raw.get("sequence_num")),
            "sampling_rate": to_int(raw.get("sampling_rate")),
            "in_interface": to_int(get_first(raw, ["in_if", "input_snmp"])),
            "out_interface": to_int(get_first(raw, ["out_if", "output_snmp"])),
            "tcp_flags": to_int(raw.get("tcp_flags")),
            "ip_tos": to_int(raw.get("ip_tos")),
            "forwarding_status": to_int(raw.get("forwarding_status")),
        },
        "ndr": {
            "source_type": "firewall_netflow",
            "collector": NDR_COLLECTOR_NAME,
            "env": NDR_ENV,
            "pipeline": "goflow2_to_opensearch",
        },
    }

    if NDR_TAG_NOISE:
        is_noise, noise_reasons = classify_noise(doc)
        doc.setdefault("ndr", {})
        doc["ndr"]["noise"] = is_noise
        doc["ndr"]["noise_reason"] = noise_reasons
        doc["ndr"]["flow_quality"] = "zero_counters" if "zero_counters" in noise_reasons else "normal"

    if KEEP_RAW_GOFLOW:
        doc["goflow2"] = raw

    return remove_nulls(doc)


def index_name_for_doc(doc: Dict[str, Any]) -> str:
    timestamp = doc.get("@timestamp")
    parsed = parse_iso(timestamp if isinstance(timestamp, str) else None)
    if parsed is None:
        parsed = dt.datetime.now(dt.timezone.utc)
    return f"{OS_INDEX_PREFIX}-{parsed.strftime('%Y.%m.%d')}"


def bulk_flush(docs: List[Dict[str, Any]]) -> None:
    if not docs:
        return

    lines: List[str] = []
    for doc in docs:
        index = index_name_for_doc(doc)
        lines.append(json.dumps({"index": {"_index": index}}, separators=(",", ":")))
        lines.append(json.dumps(doc, separators=(",", ":")))

    payload = ("\n".join(lines) + "\n").encode("utf-8")

    try:
        status, body = request("POST", "/_bulk", payload, timeout=30)
        response = json.loads(body.decode("utf-8"))
        if response.get("errors"):
            first_error = None
            for item in response.get("items", []):
                action = item.get("index", {})
                if "error" in action:
                    first_error = action["error"]
                    break
            log(f"[bulk] indexed_with_errors docs={len(docs)} status={status} first_error={first_error}")
        else:
            log(f"[bulk] indexed docs={len(docs)} status={status}")
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="ignore")
        log(f"[bulk] HTTP error status={exc.code} body={body_text}")
    except Exception as exc:
        log(f"[bulk] error: {exc}")


def main() -> int:
    log("[collector] starting GoFlow2 -> OpenSearch normalizer")
    log(f"[collector] OS_URL={OS_URL} index_prefix={OS_INDEX_PREFIX} verify_ssl={OS_VERIFY_SSL}")
    apply_template()

    buffer: List[Dict[str, Any]] = []
    last_flush = time.time()
    seen = 0
    skipped = 0

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                skipped += 1
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            try:
                doc = normalize(raw)

                if NDR_DROP_NOISE and doc.get("ndr", {}).get("noise") is True:
                    skipped += 1
                    src = doc.get("source", {}).get("ip")
                    dst = doc.get("destination", {}).get("ip")
                    reasons = doc.get("ndr", {}).get("noise_reason")
                    log(f"[flow] dropped_noise src={src} dst={dst} reasons={reasons}")
                    continue

                buffer.append(doc)
                seen += 1
                src = doc.get("source", {}).get("ip")
                dst = doc.get("destination", {}).get("ip")
                log(f"[flow] queued #{seen} src={src} dst={dst} bytes={doc.get('network', {}).get('bytes')} noise={doc.get('ndr', {}).get('noise')}")
            except Exception as exc:
                log(f"[flow] normalize error: {exc}")
                continue

            now = time.time()
            if len(buffer) >= BULK_SIZE or (now - last_flush) >= BULK_FLUSH_SECONDS:
                bulk_flush(buffer)
                buffer.clear()
                last_flush = now

    except KeyboardInterrupt:
        log("[collector] interrupted")
    finally:
        if buffer:
            bulk_flush(buffer)
        log(f"[collector] stopped seen={seen} skipped_non_json={skipped}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
