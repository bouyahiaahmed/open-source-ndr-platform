from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from app.config import Settings
from app.normalizer import NORMALIZERS
from app.utils import (
    as_list,
    deep_merge_keep_existing,
    direction_from_local,
    first_present,
    floor_time,
    get_field,
    is_private_ip,
    isoformat,
    parse_ts,
    safe_int,
    safe_log_type,
    strip_empty,
    synthetic_session_id,
    unique_extend,
    unique_values,
    utc_now,
)

logger = logging.getLogger(__name__)




def split_service_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(split_service_names(item))
        return out
    return [part.strip().lower() for part in str(value).split(",") if part.strip()]


def normalize_service_token(value: str) -> str:
    mapping = {
        "ssl": "tls",
        "ldap_tcp": "ldap",
        "ldap_udp": "ldap",
        "dce-rpc": "dce_rpc",
    }
    return mapping.get(value, value)


def normalize_network_protocols(value: Any) -> list[str]:
    return unique_values(normalize_service_token(token) for token in split_service_names(value))


def canonical_network_protocol(value: Any) -> str | None:
    protocols = normalize_network_protocols(value)
    if not protocols:
        return None

    priority = [
        "http",
        "dns",
        "tls",
        "ssh",
        "ftp",
        "ftp-data",
        "smb",
        "ldap",
        "smtp",
        "irc",
        "postgresql",
        "ntp",
        "dhcp",
        "dce_rpc",
        "ntlm",
        "gssapi",
    ]

    for candidate in priority:
        if candidate in protocols:
            return candidate

    return protocols[0]

class SessionBuilder:
    def __init__(self, settings: Settings):
        self.settings = settings

    def group_hits(self, hits: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        x509_by_fingerprint: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for hit in hits:
            source = hit.get("_source") or {}
            if not isinstance(source, dict):
                continue

            log_type = safe_log_type(get_field(source, "log_type"))

            # x509.log usually does not share the same Zeek UID as ssl.log.
            # Keep it aside and attach it later using ssl.cert_chain_fps[] -> x509.fingerprint.
            if log_type == "x509":
                fingerprint = get_field(source, "fingerprint")
                if fingerprint:
                    x509_by_fingerprint[str(fingerprint)].append(hit)
                continue

            key = self.session_key(source)
            groups[key].append(hit)

        # Enrich TLS/SSL sessions with matching x509 certificate documents.
        for key, group in list(groups.items()):
            cert_fps: list[str] = []
            for hit in group:
                source = hit.get("_source") or {}
                if not isinstance(source, dict):
                    continue
                if safe_log_type(get_field(source, "log_type")) not in {"ssl", "tls"}:
                    continue
                for fp in as_list(get_field(source, "cert_chain_fps")):
                    if fp:
                        cert_fps.append(str(fp))

            seen_x509_ids = {str(hit.get("_id") or "") for hit in group}
            for fp in unique_values(cert_fps):
                for x509_hit in x509_by_fingerprint.get(fp, []):
                    x509_id = str(x509_hit.get("_id") or "")
                    if x509_id and x509_id in seen_x509_ids:
                        continue
                    group.append(x509_hit)
                    if x509_id:
                        seen_x509_ids.add(x509_id)

        return groups

    def session_key(self, event: dict[str, Any]) -> str:
        uid = get_field(event, "uid")
        if uid:
            return str(uid)
        community_id = get_field(event, "community_id")
        if community_id:
            return str(community_id)
        timestamp = parse_ts(first_present(get_field(event, "@timestamp"), get_field(event, "timestamp"), get_field(event, "ts"))) or utc_now()
        return synthetic_session_id(
            [
                get_field(event, "sensor"),
                get_field(event, "log_type"),
                isoformat(floor_time(timestamp, 60)),
                first_present(get_field(event, "id.orig_h"), get_field(event, "src")),
                first_present(get_field(event, "id.orig_p"), get_field(event, "p")),
                first_present(get_field(event, "id.resp_h"), get_field(event, "dst")),
                get_field(event, "id.resp_p"),
            ]
        )

    def build_from_group(self, hits: list[dict[str, Any]]) -> dict[str, Any] | None:
        prepared = [self._prepare_hit(hit) for hit in hits]
        prepared = [item for item in prepared if item is not None]
        if not prepared:
            return None
        prepared.sort(key=lambda item: (item["timestamp"] or datetime.max, item["raw_id"]))
        raw_events = [item["event"] for item in prepared]
        backbone_item = next((item for item in prepared if item["log_type"] == "conn"), prepared[0])
        backbone = backbone_item["event"]
        timestamps = [item["timestamp"] for item in prepared if item["timestamp"] is not None]
        first_seen = min(timestamps) if timestamps else utc_now()
        last_seen = max(timestamps) if timestamps else first_seen

        uid = first_present(*(get_field(e, "uid") for e in raw_events))
        community_id = first_present(
            get_field(backbone, "community_id"),
            *(get_field(e, "community_id") for e in raw_events),
        )
        session_id = str(first_present(uid, community_id, self.session_key(backbone)))
        log_types = sorted(unique_values(item["log_type"] for item in prepared))
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in prepared:
            by_type[item["log_type"]].append(item["event"])

        src_ip = first_present(get_field(backbone, "id.orig_h"), get_field(backbone, "src"), *(get_field(e, "id.orig_h") for e in raw_events), *(get_field(e, "src") for e in raw_events))
        src_port = safe_int(first_present(get_field(backbone, "id.orig_p"), get_field(backbone, "p"), *(get_field(e, "id.orig_p") for e in raw_events), *(get_field(e, "p") for e in raw_events)))
        dst_ip = first_present(get_field(backbone, "id.resp_h"), get_field(backbone, "dst"), *(get_field(e, "id.resp_h") for e in raw_events), *(get_field(e, "dst") for e in raw_events))
        dst_port = safe_int(first_present(get_field(backbone, "id.resp_p"), *(get_field(e, "id.resp_p") for e in raw_events)))
        local_orig = first_present(get_field(backbone, "local_orig"), *(get_field(e, "local_orig") for e in raw_events))
        local_resp = first_present(get_field(backbone, "local_resp"), *(get_field(e, "local_resp") for e in raw_events))
        source_local = first_present(local_orig, is_private_ip(src_ip))
        destination_local = first_present(local_resp, is_private_ip(dst_ip))
        proto = first_present(get_field(backbone, "proto"), *(get_field(e, "proto") for e in raw_events))
        raw_service = first_present(get_field(backbone, "service"), self._infer_service(log_types, dst_port))
        service = canonical_network_protocol(raw_service)
        total_bytes = sum(v for v in [safe_int(get_field(backbone, "orig_bytes")), safe_int(get_field(backbone, "resp_bytes"))] if v is not None)
        total_packets = sum(v for v in [safe_int(get_field(backbone, "orig_pkts")), safe_int(get_field(backbone, "resp_pkts"))] if v is not None)

        doc: dict[str, Any] = {
            "@timestamp": isoformat(parse_ts(get_field(backbone, "@timestamp")) or first_seen),
            "doc": {"type": "ndr_session"},
            "session": {
                "id": session_id,
                "uid": uid,
                "community_id": community_id,
                "first_seen": isoformat(first_seen),
                "last_seen": isoformat(last_seen),
                "log_types": log_types,
                "event_count": len(prepared),
                "has_notice": "notice" in log_types,
                "has_weird": "weird" in log_types,
                "has_files": "files" in log_types,
                "has_tls": "ssl" in log_types or "tls" in log_types,
                "has_http": "http" in log_types,
                "has_dns": "dns" in log_types,
                "has_ssh": "ssh" in log_types,
            },
            "sensor": {"name": first_present(get_field(backbone, "sensor"), *(get_field(e, "sensor") for e in raw_events))},
            "source": {"ip": src_ip, "port": src_port, "local": source_local},
            "destination": {"ip": dst_ip, "port": dst_port, "local": destination_local},
            "network": {
                "transport": proto,
                "protocol": service,
                "protocols": normalize_network_protocols(raw_service),
                "community_id": community_id,
                "bytes": total_bytes or None,
                "packets": total_packets or None,
                "direction": direction_from_local(source_local, destination_local),
            },
            "evidence": self._build_evidence(prepared),
            "zeek": self._build_zeek(prepared),
            "sessionizer": {"version": self.settings.service_version, "updated_at": isoformat(utc_now())},
        }

        for log_type, events in by_type.items():
            normalizer = NORMALIZERS.get(log_type)
            if not normalizer:
                continue
            section_name = self._section_name_for_log_type(log_type)
            section = normalizer(events)
            if section:
                if section_name not in doc:
                    doc[section_name] = {}
                doc[section_name] = deep_merge_keep_existing(doc[section_name], section)

        return strip_empty(doc)

    def merge_existing(self, existing: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
        if not existing:
            return new
        merged = deep_merge_keep_existing(existing, new)
        # Recompute session-level fields from merged arrays and timestamps.
        session = merged.setdefault("session", {})
        old_log_types = as_list(get_field(existing, "session.log_types"))
        new_log_types = as_list(get_field(new, "session.log_types"))
        log_types = sorted(unique_values([*old_log_types, *new_log_types]))
        session["log_types"] = log_types
        session["has_notice"] = "notice" in log_types
        session["has_weird"] = "weird" in log_types
        session["has_files"] = "files" in log_types
        session["has_tls"] = "ssl" in log_types or "tls" in log_types
        session["has_http"] = "http" in log_types
        session["has_dns"] = "dns" in log_types
        session["has_ssh"] = "ssh" in log_types
        first_seen = min(
            [ts for ts in [parse_ts(get_field(existing, "session.first_seen")), parse_ts(get_field(new, "session.first_seen"))] if ts],
            default=None,
        )
        last_seen = max(
            [ts for ts in [parse_ts(get_field(existing, "session.last_seen")), parse_ts(get_field(new, "session.last_seen"))] if ts],
            default=None,
        )
        if first_seen:
            session["first_seen"] = isoformat(first_seen)
        if last_seen:
            session["last_seen"] = isoformat(last_seen)
        merged["@timestamp"] = get_field(existing, "@timestamp", get_field(new, "@timestamp"))
        merged["sessionizer"] = {"version": self.settings.service_version, "updated_at": isoformat(utc_now())}
        merged["evidence"] = self._dedupe_limited_evidence(as_list(merged.get("evidence")))
        merged["zeek"] = self._dedupe_limited_zeek(merged.get("zeek", {}))
        session["event_count"] = self._count_zeek_events(merged.get("zeek", {})) or len(merged.get("evidence", []))
        return strip_empty(merged)

    def _prepare_hit(self, hit: dict[str, Any]) -> dict[str, Any] | None:
        source = hit.get("_source") or {}
        if not isinstance(source, dict):
            return None
        raw_id = str(hit.get("_id") or "")
        log_type = safe_log_type(get_field(source, "log_type"))
        if log_type.startswith("conn-summary"):
            return None
        timestamp = parse_ts(first_present(get_field(source, "@timestamp"), get_field(source, "timestamp"), get_field(source, "ts")))
        event = dict(source)
        event["_raw_id"] = raw_id
        event["_raw_index"] = hit.get("_index")
        return {"raw_id": raw_id, "raw_index": hit.get("_index"), "log_type": log_type, "timestamp": timestamp, "event": event}

    def _build_evidence(self, prepared: list[dict[str, Any]]) -> list[dict[str, Any]]:
        evidence = []
        seen: set[str] = set()
        for item in prepared:
            raw_id = item["raw_id"]
            if raw_id in seen:
                continue
            event = item["event"]
            evidence.append(
                {
                    "index": item["raw_index"],
                    "id": raw_id,
                    "log_type": item["log_type"],
                    "timestamp": isoformat(item["timestamp"]),
                    "uid": get_field(event, "uid"),
                    "community_id": get_field(event, "community_id"),
                }
            )
            seen.add(raw_id)
            if len(evidence) >= self.settings.max_evidence_items:
                break
        return strip_empty(evidence)

    def _build_zeek(self, prepared: list[dict[str, Any]]) -> dict[str, Any]:
        zeek: dict[str, Any] = {}
        counts: dict[str, int] = defaultdict(int)
        seen_by_type: dict[str, set[str]] = defaultdict(set)
        for item in prepared:
            log_type = item["log_type"]
            if log_type.startswith("conn-summary"):
                continue
            raw_id = item["raw_id"]
            if raw_id in seen_by_type[log_type]:
                continue
            if counts[log_type] >= self.settings.max_events_per_log_type_per_session:
                continue
            event = dict(item["event"])
            if not self.settings.preserve_raw_event_fields:
                event = {
                    "_raw_id": raw_id,
                    "_raw_index": item["raw_index"],
                    "@timestamp": get_field(event, "@timestamp"),
                    "uid": get_field(event, "uid"),
                    "community_id": get_field(event, "community_id"),
                    "log_type": get_field(event, "log_type"),
                }
            section = zeek.setdefault(log_type, {"present": True, "events": []})
            section["events"].append(strip_empty(event))
            counts[log_type] += 1
            seen_by_type[log_type].add(raw_id)
        return zeek

    def _dedupe_limited_evidence(self, evidence: list[Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in evidence:
            if not isinstance(item, dict):
                continue
            raw_id = str(item.get("id") or "")
            if raw_id and raw_id in seen:
                continue
            out.append(item)
            if raw_id:
                seen.add(raw_id)
            if len(out) >= self.settings.max_evidence_items:
                break
        return out

    def _dedupe_limited_zeek(self, zeek: Any) -> dict[str, Any]:
        if not isinstance(zeek, dict):
            return {}
        out: dict[str, Any] = {}
        for log_type, section in zeek.items():
            if not isinstance(section, dict):
                continue
            events = section.get("events", [])
            clean_events: list[dict[str, Any]] = []
            seen: set[str] = set()
            for event in events:
                if not isinstance(event, dict):
                    continue
                raw_id = str(event.get("_raw_id") or "")
                if raw_id and raw_id in seen:
                    continue
                clean_events.append(event)
                if raw_id:
                    seen.add(raw_id)
                if len(clean_events) >= self.settings.max_events_per_log_type_per_session:
                    break
            out[log_type] = {"present": bool(clean_events), "events": clean_events}
        return out

    def _count_zeek_events(self, zeek: Any) -> int:
        if not isinstance(zeek, dict):
            return 0
        total = 0
        for section in zeek.values():
            if isinstance(section, dict):
                total += len(section.get("events") or [])
        return total

    def _section_name_for_log_type(self, log_type: str) -> str:
        if log_type in {"ssl", "tls"}:
            return "tls"
        if log_type in {"smb_files", "smb_mapping", "ntlm", "dce_rpc"}:
            return "smb"
        if log_type in {"ldap_search"}:
            return "ldap"
        return log_type

    def _infer_service(self, log_types: list[str], dst_port: int | None) -> str | None:
        for candidate in ["http", "dns", "ssl", "ssh", "ftp", "smtp", "ldap", "irc"]:
            if candidate in log_types:
                return "tls" if candidate == "ssl" else candidate
        port_map = {53: "dns", 80: "http", 443: "tls", 22: "ssh", 21: "ftp", 25: "smtp", 389: "ldap", 636: "ldaps"}
        return port_map.get(dst_port or -1)
