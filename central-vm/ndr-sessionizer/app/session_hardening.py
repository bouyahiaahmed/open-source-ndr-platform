from __future__ import annotations

import ipaddress
import os
from typing import Any

from app.azure_topology import enrich_azure_topology


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def split_int_csv(value: str | None) -> set[int]:
    out: set[int] = set()
    for item in split_csv(value):
        try:
            out.add(int(item))
        except ValueError:
            pass
    return out


INTERNAL_NETWORKS = [
    ipaddress.ip_network(x, strict=False)
    for x in split_csv(os.getenv("INTERNAL_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
]

CONTROL_PLANE_PORTS = split_int_csv(os.getenv("CONTROL_PLANE_PORTS", "2021,4900,5601,9200,9300,9598"))
CONTROL_PLANE_PROTOCOLS = set(split_csv(os.getenv("CONTROL_PLANE_PROTOCOLS", "ntp,dhcp")))
DEFAULT_UNKNOWN_PROTOCOL = os.getenv("DEFAULT_UNKNOWN_PROTOCOL", "unknown")
TAG_CONTROL_PLANE = os.getenv("TAG_CONTROL_PLANE", "true").lower() == "true"


def getn(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def setn(obj: dict[str, Any], path: str, value: Any) -> None:
    cur = obj
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unique(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    seen: set[str] = set()
    for value in values:
        if value is None or value == "":
            continue
        key = str(value)
        if key not in seen:
            seen.add(key)
            out.append(value)
    return out


def ip_is_local(value: Any) -> bool | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True

    for net in INTERNAL_NETWORKS:
        if ip in net:
            return True

    return False


def first_conn_event(doc: dict[str, Any]) -> dict[str, Any] | None:
    events = getn(doc, "zeek.conn.events")
    if isinstance(events, list) and events and isinstance(events[0], dict):
        return events[0]
    return None


def harden_protocol(doc: dict[str, Any]) -> None:
    if getn(doc, "network.protocol"):
        return

    log_types = as_list(getn(doc, "session.log_types"))
    dest_port = getn(doc, "destination.port")

    protocol = None

    if "dns" in log_types:
        protocol = "dns"
    elif "http" in log_types:
        protocol = "http"
    elif "ssl" in log_types or "tls" in log_types:
        protocol = "tls"
    elif "ssh" in log_types:
        protocol = "ssh"
    elif "ldap" in log_types:
        protocol = "ldap"
    elif "ftp" in log_types:
        protocol = "ftp"
    elif "smtp" in log_types:
        protocol = "smtp"
    elif "dhcp" in log_types:
        protocol = "dhcp"
    elif "ntp" in log_types:
        protocol = "ntp"

    if not protocol:
        try:
            port = int(dest_port)
        except (TypeError, ValueError):
            port = None

        protocol = {
            22: "ssh",
            25: "smtp",
            53: "dns",
            67: "dhcp",
            68: "dhcp",
            80: "http",
            123: "ntp",
            389: "ldap",
            443: "tls",
            636: "ldaps",
            5353: "mdns",
            5355: "llmnr",
            1900: "ssdp",
        }.get(port)

    setn(doc, "network.protocol", protocol or DEFAULT_UNKNOWN_PROTOCOL)


def harden_direction(doc: dict[str, Any]) -> None:
    src_ip = getn(doc, "source.ip")
    dst_ip = getn(doc, "destination.ip")

    conn = first_conn_event(doc)
    local_orig = conn.get("local_orig") if conn else None
    local_resp = conn.get("local_resp") if conn else None

    src_local = local_orig if isinstance(local_orig, bool) else ip_is_local(src_ip)
    dst_local = local_resp if isinstance(local_resp, bool) else ip_is_local(dst_ip)

    if src_local is not None:
        setn(doc, "source.local", src_local)
    if dst_local is not None:
        setn(doc, "destination.local", dst_local)

    if src_local is True and dst_local is True:
        direction = "internal"
    elif src_local is True and dst_local is False:
        direction = "outbound"
    elif src_local is False and dst_local is True:
        direction = "inbound"
    else:
        direction = "external_or_unknown"

    setn(doc, "network.direction", direction)


def harden_counts(doc: dict[str, Any]) -> None:
    evidence = [x for x in as_list(doc.get("evidence")) if isinstance(x, dict)]
    evidence_count = len(evidence)

    normalized_count = 0
    zeek = doc.get("zeek")
    if isinstance(zeek, dict):
        for section in zeek.values():
            if isinstance(section, dict):
                events = section.get("events")
                if isinstance(events, list):
                    normalized_count += len(events)

    setn(doc, "session.evidence_count", evidence_count)
    setn(doc, "session.raw_event_count", evidence_count)
    setn(doc, "session.normalized_event_count", normalized_count)
    setn(doc, "session.events_truncated", evidence_count > normalized_count)


def harden_x509(doc: dict[str, Any]) -> None:
    events = getn(doc, "zeek.x509.events")
    if not isinstance(events, list) or not events:
        return

    fingerprints = []
    subjects = []
    issuers = []
    san_dns = []
    not_valid_before = []
    not_valid_after = []
    key_types = []
    key_lengths = []
    sig_algs = []
    is_ca = False

    for event in events:
        if not isinstance(event, dict):
            continue

        fingerprints.append(event.get("fingerprint"))
        subjects.append(event.get("certificate.subject"))
        issuers.append(event.get("certificate.issuer"))
        san_dns.extend(as_list(event.get("san.dns")))
        not_valid_before.append(event.get("certificate.not_valid_before"))
        not_valid_after.append(event.get("certificate.not_valid_after"))
        key_types.append(event.get("certificate.key_type"))
        key_lengths.append(event.get("certificate.key_length"))
        sig_algs.append(event.get("certificate.sig_alg"))
        is_ca = is_ca or bool(event.get("basic_constraints.ca"))

    setn(doc, "x509.fingerprints", unique(fingerprints))
    setn(doc, "x509.subjects", unique(subjects))
    setn(doc, "x509.issuers", unique(issuers))
    setn(doc, "x509.san_dns", unique(san_dns))
    setn(doc, "x509.not_valid_before", unique(not_valid_before))
    setn(doc, "x509.not_valid_after", unique(not_valid_after))
    setn(doc, "x509.key_types", unique(key_types))
    setn(doc, "x509.key_lengths", unique(key_lengths))
    setn(doc, "x509.signature_algorithms", unique(sig_algs))
    setn(doc, "x509.is_ca", is_ca)


def harden_files(doc: dict[str, Any]) -> None:
    files = doc.get("files")
    if not isinstance(files, dict):
        return

    fuids = unique(as_list(files.get("fuids")))
    mime_types = unique(as_list(files.get("mime_types")))
    hashes = unique(
        as_list(files.get("md5")) +
        as_list(files.get("sha1")) +
        as_list(files.get("sha256"))
    )

    files["count"] = len(fuids)
    files["mime_type_count"] = len(mime_types)
    files["hash_count"] = len(hashes)

    if files.get("total_bytes") in (None, "", 0) and files.get("seen_bytes") not in (None, ""):
        files["total_bytes"] = files.get("seen_bytes")


def tag_control_plane(doc: dict[str, Any]) -> None:
    if not TAG_CONTROL_PLANE:
        return

    protocol = getn(doc, "network.protocol")

    try:
        dst_port = int(getn(doc, "destination.port"))
    except (TypeError, ValueError):
        dst_port = None

    try:
        src_port = int(getn(doc, "source.port"))
    except (TypeError, ValueError):
        src_port = None

    reasons = []

    if protocol in CONTROL_PLANE_PROTOCOLS:
        reasons.append(f"protocol:{protocol}")

    if dst_port in CONTROL_PLANE_PORTS:
        reasons.append(f"destination_port:{dst_port}")

    if src_port in CONTROL_PLANE_PORTS:
        reasons.append(f"source_port:{src_port}")

    semantic_ports = {
        2021: "data_prepper_ingest",
        4900: "data_prepper_metrics",
        5601: "opensearch_dashboards",
        9200: "opensearch_api",
        9300: "opensearch_transport",
        9598: "vector_metrics",
    }

    if dst_port in semantic_ports:
        reasons.append(semantic_ports[dst_port])
    if src_port in semantic_ports:
        reasons.append(semantic_ports[src_port])

    if reasons:
        setn(doc, "session.category", "control_plane")
        setn(doc, "session.excluded_from_behavior", True)
        setn(doc, "session.noise_reasons", unique(reasons))
    else:
        setn(doc, "session.excluded_from_behavior", False)



def has_flow_tuple(doc: dict[str, Any]) -> bool:
    return bool(
        getn(doc, "source.ip")
        and getn(doc, "destination.ip")
        and getn(doc, "source.port") is not None
        and getn(doc, "destination.port") is not None
    )


def has_uid(doc: dict[str, Any]) -> bool:
    return bool(getn(doc, "session.uid"))


def has_raw_parse_fragment(doc: dict[str, Any]) -> bool:
    zeek = doc.get("zeek")
    if not isinstance(zeek, dict):
        return False

    for section in zeek.values():
        if not isinstance(section, dict):
            continue
        events = section.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("message") and not event.get("uid") and not event.get("id.orig_h") and not event.get("id.resp_h"):
                return True
    return False



def harden_vector_noise(doc: dict[str, Any]) -> None:
    zeek = doc.get("zeek")
    if not isinstance(zeek, dict):
        return

    reasons = as_list(getn(doc, "session.noise_reasons"))
    found_noise = False

    for section in zeek.values():
        if not isinstance(section, dict):
            continue

        events = section.get("events")
        if not isinstance(events, list):
            continue

        for event in events:
            if not isinstance(event, dict):
                continue

            if event.get("ndr_noise") is True:
                found_noise = True
                noise_type = event.get("ndr_noise_type") or "vector_noise"
                noise_reason = event.get("ndr_noise_reason") or noise_type
                reasons.append(str(noise_type))
                reasons.append(str(noise_reason))

    if found_noise:
        setn(doc, "session.category", "noise")
        setn(doc, "session.excluded_from_behavior", True)
        setn(doc, "session.noise_reasons", unique(reasons))

def harden_key_type_and_flow(doc: dict[str, Any]) -> None:
    session_id = str(getn(doc, "session.id") or "")
    log_types = as_list(getn(doc, "session.log_types"))

    if session_id.startswith("synthetic:"):
        setn(doc, "session.key_type", "synthetic")
    elif has_uid(doc):
        setn(doc, "session.key_type", "uid")
    elif getn(doc, "session.community_id"):
        setn(doc, "session.key_type", "community_id")
    else:
        setn(doc, "session.key_type", "unknown")

    flow_based = has_flow_tuple(doc) and has_uid(doc)
    setn(doc, "session.flow_based", flow_based)

    # DHCP, files-only, x509-only and malformed records are useful evidence,
    # but they are not normal flow sessions for behavior baselines.
    if not flow_based:
        reasons = as_list(getn(doc, "session.noise_reasons"))

        if "dhcp" in log_types:
            reasons.append("non_flow:dhcp")
            setn(doc, "session.category", "control_plane")
        elif has_raw_parse_fragment(doc):
            reasons.append("malformed_raw_event")
            setn(doc, "session.category", "malformed_raw")
        else:
            reasons.append("non_flow:synthetic")
            if not getn(doc, "session.category"):
                setn(doc, "session.category", "non_flow")

        setn(doc, "session.excluded_from_behavior", True)
        setn(doc, "session.noise_reasons", unique(reasons))

def harden_session_document(doc: dict[str, Any]) -> dict[str, Any]:
    harden_protocol(doc)
    harden_direction(doc)
    enrich_azure_topology(doc)
    harden_counts(doc)
    harden_x509(doc)
    harden_files(doc)
    harden_vector_noise(doc)
    harden_key_type_and_flow(doc)
    tag_control_plane(doc)
    return doc
