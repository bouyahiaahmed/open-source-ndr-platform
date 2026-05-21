from __future__ import annotations

from collections import Counter
from datetime import datetime
import ipaddress
from typing import Any

from app.feature_registry import FeatureSpec
from app.utils import as_list, get_field, parse_ts, safe_bool, safe_float, safe_int, top_counter


def has_log_type(doc: dict[str, Any], log_type: str) -> bool:
    flag = get_field(doc, f"session.has_{log_type}")
    if flag is not None:
        return safe_bool(flag)
    return log_type in {str(x).lower() for x in as_list(get_field(doc, "session.log_types"))}


def _ip_reason(value: Any, role: str) -> str | None:
    """Return a non-ML reason for addresses that should not train host behavior.

    We keep RFC1918/private hosts, but exclude addresses that represent
    multicast/broadcast/link-local/unspecified infrastructure chatter.
    """
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return "invalid_ip"
    if ip.is_unspecified:
        return f"{role}_unspecified"
    if ip.is_multicast:
        return f"{role}_multicast"
    if ip.is_loopback:
        return f"{role}_loopback"
    if ip.is_link_local:
        return f"{role}_link_local"
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return f"{role}_broadcast"
    return None


def is_behavior_eligible(doc: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    flow_based = get_field(doc, "session.flow_based")
    if flow_based is not True:
        reasons.append("not_flow_based")
    if get_field(doc, "session.excluded_from_behavior") is True:
        reasons.append("session_excluded_from_behavior")
    category = str(get_field(doc, "session.category", "") or "").lower().replace("-", "_")
    if category in {"control_plane", "malformed_raw"}:
        reasons.append(category)
    noise = {str(x).strip().lower().replace("-", "_") for x in as_list(get_field(doc, "session.noise_reasons"))}
    noisy_reasons = noise.intersection({"control_plane", "dhcp", "ntp", "malformed_raw", "broadcast", "multicast", "link_local"})
    if noisy_reasons:
        reasons.extend(sorted(noisy_reasons))
    for role, path in (("source", "source.ip"), ("destination", "destination.ip")):
        reason = _ip_reason(get_field(doc, path), role)
        if reason:
            reasons.append(reason)
    # Zeek control chatter often appears as unknown protocol to port 0.
    if str(get_field(doc, "network.protocol", "") or "").lower() in {"", "unknown"} and int(get_field(doc, "destination.port", 0) or 0) == 0:
        reasons.append("unknown_port_zero")
    return (len(reasons) == 0), sorted(set(reasons))


class FeatureAccumulator:
    def __init__(self, spec: FeatureSpec):
        self.spec = spec
        self.total_sessions = 0
        self.used_sessions = 0
        self.excluded_sessions = 0
        self.excluded_reasons: Counter[str] = Counter()
        self.missing_required_fields = 0
        self.warnings: set[str] = set()

        self.destination_ips: set[str] = set()
        self.destination_ports: set[int] = set()
        self.protocols: set[str] = set()
        self.network_bytes_sum = 0
        self.network_packets_sum = 0
        self.durations: list[float] = []
        self.external_destination_count = 0
        self.internal_destination_count = 0
        self.inbound_count = 0
        self.outbound_count = 0
        self.internal_count = 0

        self.same_subnet_count = 0
        self.same_spoke_count = 0
        self.same_spoke_cross_subnet_count = 0
        self.same_vnet_cross_subnet_count = 0
        self.cross_spoke_count = 0
        self.internal_unknown_count = 0
        self.inbound_external_count = 0
        self.outbound_external_count = 0
        self.external_external_count = 0
        self.rejected_inbound_count = 0

        self.unique_external_source_ips: set[str] = set()
        self.unique_external_destination_ips: set[str] = set()
        self.counterpart_ips: set[str] = set()
        self.inbound_destination_ports: set[int] = set()
        self.outbound_destination_ports: set[int] = set()

        self.dns_session_count = 0
        self.dns_queries: set[str] = set()
        self.dns_nxdomain_count = 0
        self.dns_txt_count = 0
        self.dns_long_query_count = 0
        self.dns_query_lengths: list[int] = []
        self.dns_label_counts: list[int] = []
        self.dns_label_lengths: list[int] = []

        self.http_session_count = 0
        self.http_hosts: set[str] = set()
        self.http_user_agents: set[str] = set()
        self.http_error_4xx_count = 0
        self.http_error_5xx_count = 0
        self.http_response_body_bytes_sum = 0
        self.http_download_count = 0

        self.files_count = 0
        self.files_total_bytes_sum = 0
        self.files_mime_types: set[str] = set()
        self.files_hash_count = 0

        self.tls_session_count = 0
        self.tls_snis: set[str] = set()
        self.tls_invalid_cert_count = 0
        self.tls_sni_mismatch_count = 0
        self.tls_self_signed_count = 0
        self.tls_expired_cert_count = 0
        self.tls_issuers: set[str] = set()
        self.tls_subjects: set[str] = set()
        self.tls_resumed_count = 0

        self.ssh_session_count = 0
        self.ssh_external_session_count = 0
        self.ssh_nonstandard_port_count = 0
        self.ssh_auth_success_count = 0
        self.ssh_auth_attempt_sum = 0

        self.notice_count = 0
        self.weird_count = 0

        self.top_protocols: Counter[str] = Counter()
        self.top_destination_ips: Counter[str] = Counter()
        self.top_destination_ports: Counter[int] = Counter()
        self.top_counterpart_ips: Counter[str] = Counter()
        self.top_external_source_ips: Counter[str] = Counter()
        self.top_inbound_destination_ports: Counter[int] = Counter()
        self.top_outbound_destination_ports: Counter[int] = Counter()
        self.top_dns_queries: Counter[str] = Counter()
        self.top_http_hosts: Counter[str] = Counter()
        self.top_tls_sni: Counter[str] = Counter()
        self.top_file_mime_types: Counter[str] = Counter()
        self.top_tls_issuers: Counter[str] = Counter()

        self.session_refs: list[dict[str, Any]] = []
        self.session_ref_count = 0

    def add(self, doc: dict[str, Any], hit_meta: dict[str, Any] | None = None, max_session_refs: int = 200) -> None:
        self.total_sessions += 1
        eligible, reasons = is_behavior_eligible(doc)
        if not eligible:
            self.excluded_sessions += 1
            self.excluded_reasons.update(reasons or ["excluded"])
            return
        self.used_sessions += 1
        self._capture_session_ref(doc, hit_meta, max_session_refs)
        self._session_network(doc)
        self._dns(doc)
        self._http(doc)
        self._files(doc)
        self._tls(doc)
        self._ssh(doc)
        self._notice_weird(doc)

    def _capture_session_ref(self, doc: dict[str, Any], hit_meta: dict[str, Any] | None, max_session_refs: int) -> None:
        self.session_ref_count += 1
        if len(self.session_refs) >= max(0, max_session_refs):
            return
        hit_meta = hit_meta or {}
        ref = {
            "index": hit_meta.get("_index"),
            "id": hit_meta.get("_id") or get_field(doc, "session.id"),
            "session_id": get_field(doc, "session.id"),
            "uid": get_field(doc, "session.uid") or get_field(doc, "uid"),
            "community_id": get_field(doc, "session.community_id") or get_field(doc, "network.community_id"),
            "timestamp": get_field(doc, "@timestamp") or get_field(doc, "session.first_seen"),
            "log_types": [str(x) for x in as_list(get_field(doc, "session.log_types")) if x],
            "source_ip": get_field(doc, "source.ip"),
            "destination_ip": get_field(doc, "destination.ip"),
            "destination_port": get_field(doc, "destination.port"),
        }
        self.session_refs.append({k: v for k, v in ref.items() if v not in (None, "", [])})

    def _session_network(self, doc: dict[str, Any]) -> None:
        dst_ip = get_field(doc, "destination.ip")
        dst_port = safe_int(get_field(doc, "destination.port"), -1)
        if dst_ip:
            self.destination_ips.add(str(dst_ip))
            self.top_destination_ips[str(dst_ip)] += 1
        if dst_port >= 0:
            self.destination_ports.add(dst_port)
            self.top_destination_ports[dst_port] += 1

        protocols = [str(x).lower() for x in as_list(get_field(doc, "network.protocols")) if x]
        if not protocols:
            protocol = get_field(doc, "network.protocol")
            if protocol:
                protocols = [str(protocol).lower()]
        if not protocols:
            protocols = [str(x).lower() for x in as_list(get_field(doc, "session.log_types")) if x]
        for proto in protocols:
            self.protocols.add(proto)
            self.top_protocols[proto] += 1

        bytes_value = safe_int(get_field(doc, "network.bytes"), -1)
        if bytes_value < 0:
            bytes_value = safe_int(get_field(doc, "conn.orig_bytes")) + safe_int(get_field(doc, "conn.resp_bytes"))
        packets_value = safe_int(get_field(doc, "network.packets"), -1)
        if packets_value < 0:
            packets_value = safe_int(get_field(doc, "conn.orig_pkts")) + safe_int(get_field(doc, "conn.resp_pkts"))
        self.network_bytes_sum += max(0, bytes_value)
        self.network_packets_sum += max(0, packets_value)

        duration = safe_float(get_field(doc, "conn.duration"), 0.0)
        if duration >= 0:
            self.durations.append(duration)

        src_ip = get_field(doc, "source.ip")
        dst_local = get_field(doc, "destination.local")
        src_local = get_field(doc, "source.local")
        direction = str(get_field(doc, "network.direction", "") or "").lower()
        scope = str(get_field(doc, "network.scope", "") or "").lower()
        asset_side = str(get_field(doc, "network.asset.side", "") or "").lower()

        if dst_local is True:
            self.internal_destination_count += 1
        elif dst_local is False:
            self.external_destination_count += 1
            if dst_ip:
                self.unique_external_destination_ips.add(str(dst_ip))

        if src_local is False and src_ip:
            self.unique_external_source_ips.add(str(src_ip))
            self.top_external_source_ips[str(src_ip)] += 1

        if asset_side == "destination" and src_ip:
            self.counterpart_ips.add(str(src_ip))
            self.top_counterpart_ips[str(src_ip)] += 1
        elif dst_ip:
            self.counterpart_ips.add(str(dst_ip))
            self.top_counterpart_ips[str(dst_ip)] += 1

        if direction == "inbound":
            self.inbound_count += 1
            if dst_port >= 0:
                self.inbound_destination_ports.add(dst_port)
                self.top_inbound_destination_ports[dst_port] += 1
        elif direction == "outbound":
            self.outbound_count += 1
            if dst_port >= 0:
                self.outbound_destination_ports.add(dst_port)
                self.top_outbound_destination_ports[dst_port] += 1
        elif direction == "internal":
            self.internal_count += 1

        if scope == "same_subnet":
            self.same_subnet_count += 1
            self.same_spoke_count += 1
        elif scope == "same_spoke_cross_subnet":
            self.same_spoke_cross_subnet_count += 1
            self.same_spoke_count += 1
        elif scope == "same_vnet_cross_subnet":
            self.same_vnet_cross_subnet_count += 1
        elif scope == "cross_spoke":
            self.cross_spoke_count += 1
        elif scope == "internal_unknown":
            self.internal_unknown_count += 1
        elif scope == "inbound_external":
            self.inbound_external_count += 1
        elif scope == "outbound_external":
            self.outbound_external_count += 1
        elif scope == "external_external":
            self.external_external_count += 1

        conn_state = str(get_field(doc, "conn.state", "") or "").upper()
        history = str(get_field(doc, "conn.history", "") or "")
        if direction == "inbound" and (conn_state == "REJ" or history == "Hr"):
            self.rejected_inbound_count += 1

    def _dns(self, doc: dict[str, Any]) -> None:
        if not has_log_type(doc, "dns"):
            return
        self.dns_session_count += 1
        query = get_field(doc, "dns.query")
        if query:
            q = str(query).lower()
            self.dns_queries.add(q)
            self.top_dns_queries[q] += 1
        is_nxdomain = safe_bool(get_field(doc, "dns.is_nxdomain")) or str(get_field(doc, "dns.rcode_name", "")).upper() == "NXDOMAIN"
        if is_nxdomain:
            self.dns_nxdomain_count += 1
        is_txt = safe_bool(get_field(doc, "dns.is_txt")) or str(get_field(doc, "dns.qtype_name", "")).upper() == "TXT"
        if is_txt:
            self.dns_txt_count += 1
        query_length = safe_int(get_field(doc, "dns.query_length"), -1)
        if query_length < 0 and query:
            query_length = len(str(query))
        if query_length >= 0:
            self.dns_query_lengths.append(query_length)
            threshold = int(self.spec.thresholds.get("dns_long_query_length", 80))
            if query_length >= threshold:
                self.dns_long_query_count += 1
        label_count = safe_int(get_field(doc, "dns.label_count"), -1)
        if label_count < 0 and query:
            label_count = len([x for x in str(query).split(".") if x])
        if label_count >= 0:
            self.dns_label_counts.append(label_count)
        longest_label = safe_int(get_field(doc, "dns.longest_label_length"), -1)
        if longest_label < 0 and query:
            longest_label = max((len(x) for x in str(query).split(".") if x), default=0)
        if longest_label >= 0:
            self.dns_label_lengths.append(longest_label)

    def _http(self, doc: dict[str, Any]) -> None:
        if not has_log_type(doc, "http"):
            return
        self.http_session_count += 1
        host = get_field(doc, "http.host")
        if host:
            h = str(host).lower()
            self.http_hosts.add(h)
            self.top_http_hosts[h] += 1
        ua = get_field(doc, "http.user_agent")
        if ua:
            self.http_user_agents.add(str(ua))
        status = safe_int(get_field(doc, "http.status_code"), -1)
        if 400 <= status <= 499:
            self.http_error_4xx_count += 1
        elif 500 <= status <= 599:
            self.http_error_5xx_count += 1
        response_bytes = safe_int(get_field(doc, "http.response_body_bytes"))
        self.http_response_body_bytes_sum += response_bytes
        if safe_int(get_field(doc, "files.count")) > 0 or response_bytes > 0:
            self.http_download_count += 1

    def _files(self, doc: dict[str, Any]) -> None:
        if not has_log_type(doc, "files") and safe_int(get_field(doc, "files.count")) == 0:
            return
        count = safe_int(get_field(doc, "files.count"), 0)
        if count == 0:
            count = len(as_list(get_field(doc, "files.fuids")))
        self.files_count += count
        self.files_total_bytes_sum += safe_int(get_field(doc, "files.total_bytes"), 0)
        for mt in as_list(get_field(doc, "files.mime_types")):
            if mt:
                value = str(mt).lower()
                self.files_mime_types.add(value)
                self.top_file_mime_types[value] += 1
        hash_count = safe_int(get_field(doc, "files.hash_count"), -1)
        if hash_count < 0:
            hash_count = len([x for field in ["files.md5", "files.sha1", "files.sha256"] for x in as_list(get_field(doc, field)) if x])
        self.files_hash_count += max(0, hash_count)

    def _tls(self, doc: dict[str, Any]) -> None:
        if not has_log_type(doc, "tls") and not has_log_type(doc, "ssl"):
            return
        self.tls_session_count += 1
        sni = get_field(doc, "tls.server_name")
        if sni:
            value = str(sni).lower()
            self.tls_snis.add(value)
            self.top_tls_sni[value] += 1
        validation = str(get_field(doc, "tls.validation_status", "") or "").lower()
        if validation and validation not in {"ok", "valid", "success", "trusted"}:
            self.tls_invalid_cert_count += 1
        if get_field(doc, "tls.sni_matches_cert") is False:
            self.tls_sni_mismatch_count += 1
        issuers = [str(x) for x in as_list(get_field(doc, "x509.issuers")) if x]
        subjects = [str(x) for x in as_list(get_field(doc, "x509.subjects")) if x]
        for issuer in issuers:
            self.tls_issuers.add(issuer)
            self.top_tls_issuers[issuer] += 1
        for subject in subjects:
            self.tls_subjects.add(subject)
        if validation.find("self") >= 0 or any(s and s in issuers for s in subjects):
            self.tls_self_signed_count += 1
        if validation.find("expired") >= 0:
            self.tls_expired_cert_count += 1
        else:
            not_after_values = [parse_ts(x) for x in as_list(get_field(doc, "x509.not_valid_after"))]
            nowish = parse_ts(get_field(doc, "session.first_seen")) or parse_ts(doc.get("@timestamp"))
            if nowish and any(dt and dt < nowish for dt in not_after_values):
                self.tls_expired_cert_count += 1
        if safe_bool(get_field(doc, "tls.resumed")):
            self.tls_resumed_count += 1

    def _ssh(self, doc: dict[str, Any]) -> None:
        if not has_log_type(doc, "ssh"):
            return
        self.ssh_session_count += 1
        if get_field(doc, "destination.local") is False or str(get_field(doc, "network.direction", "")).lower() == "outbound":
            self.ssh_external_session_count += 1
        port = safe_int(get_field(doc, "destination.port"), 22)
        if port != 22:
            self.ssh_nonstandard_port_count += 1
        if safe_bool(get_field(doc, "ssh.auth_success")):
            self.ssh_auth_success_count += 1
        self.ssh_auth_attempt_sum += safe_int(get_field(doc, "ssh.auth_attempts"), 0)

    def _notice_weird(self, doc: dict[str, Any]) -> None:
        if has_log_type(doc, "notice"):
            notes = as_list(get_field(doc, "notice.notes")) or as_list(get_field(doc, "notice.messages"))
            self.notice_count += max(1, len(notes))
        if has_log_type(doc, "weird"):
            names = as_list(get_field(doc, "weird.names")) or as_list(get_field(doc, "weird.messages"))
            self.weird_count += max(1, len(names))

    def features(self) -> dict[str, float | int]:
        avg_duration = sum(self.durations) / len(self.durations) if self.durations else 0.0
        dns_avg_query = sum(self.dns_query_lengths) / len(self.dns_query_lengths) if self.dns_query_lengths else 0.0
        dns_avg_label = sum(self.dns_label_counts) / len(self.dns_label_counts) if self.dns_label_counts else 0.0
        dns_ratio = self.dns_nxdomain_count / self.dns_session_count if self.dns_session_count else 0.0
        return {
            "session_count": self.used_sessions,
            "unique_destination_ip_count": len(self.destination_ips),
            "unique_destination_port_count": len(self.destination_ports),
            "unique_protocol_count": len(self.protocols),
            "network_bytes_sum": self.network_bytes_sum,
            "network_packets_sum": self.network_packets_sum,
            "avg_session_duration": round(avg_duration, 6),
            "max_session_duration": round(max(self.durations) if self.durations else 0.0, 6),
            "external_destination_count": self.external_destination_count,
            "internal_destination_count": self.internal_destination_count,
            "inbound_count": self.inbound_count,
            "outbound_count": self.outbound_count,
            "internal_count": self.internal_count,

            "same_subnet_count": self.same_subnet_count,
            "same_spoke_count": self.same_spoke_count,
            "same_spoke_cross_subnet_count": self.same_spoke_cross_subnet_count,
            "same_vnet_cross_subnet_count": self.same_vnet_cross_subnet_count,
            "cross_spoke_count": self.cross_spoke_count,
            "internal_unknown_count": self.internal_unknown_count,
            "inbound_external_count": self.inbound_external_count,
            "outbound_external_count": self.outbound_external_count,
            "external_external_count": self.external_external_count,
            "unique_external_source_ip_count": len(self.unique_external_source_ips),
            "unique_external_destination_ip_count": len(self.unique_external_destination_ips),
            "unique_counterpart_ip_count": len(self.counterpart_ips),
            "unique_inbound_destination_port_count": len(self.inbound_destination_ports),
            "unique_outbound_destination_port_count": len(self.outbound_destination_ports),
            "rejected_inbound_count": self.rejected_inbound_count,

            "dns_session_count": self.dns_session_count,
            "dns_unique_query_count": len(self.dns_queries),
            "dns_nxdomain_count": self.dns_nxdomain_count,
            "dns_nxdomain_ratio": round(dns_ratio, 6),
            "dns_txt_count": self.dns_txt_count,
            "dns_long_query_count": self.dns_long_query_count,
            "dns_max_query_length": max(self.dns_query_lengths) if self.dns_query_lengths else 0,
            "dns_avg_query_length": round(dns_avg_query, 6),
            "dns_max_label_length": max(self.dns_label_lengths) if self.dns_label_lengths else 0,
            "dns_avg_label_count": round(dns_avg_label, 6),
            "http_session_count": self.http_session_count,
            "http_unique_host_count": len(self.http_hosts),
            "http_unique_user_agent_count": len(self.http_user_agents),
            "http_error_4xx_count": self.http_error_4xx_count,
            "http_error_5xx_count": self.http_error_5xx_count,
            "http_response_body_bytes_sum": self.http_response_body_bytes_sum,
            "http_download_count": self.http_download_count,
            "files_count": self.files_count,
            "files_total_bytes_sum": self.files_total_bytes_sum,
            "files_unique_mime_type_count": len(self.files_mime_types),
            "files_hash_count": self.files_hash_count,
            "tls_session_count": self.tls_session_count,
            "tls_unique_sni_count": len(self.tls_snis),
            "tls_invalid_cert_count": self.tls_invalid_cert_count,
            "tls_sni_mismatch_count": self.tls_sni_mismatch_count,
            "tls_self_signed_count": self.tls_self_signed_count,
            "tls_expired_cert_count": self.tls_expired_cert_count,
            "tls_unique_issuer_count": len(self.tls_issuers),
            "tls_unique_subject_count": len(self.tls_subjects),
            "tls_resumed_count": self.tls_resumed_count,
            "ssh_session_count": self.ssh_session_count,
            "ssh_external_session_count": self.ssh_external_session_count,
            "ssh_nonstandard_port_count": self.ssh_nonstandard_port_count,
            "ssh_auth_success_count": self.ssh_auth_success_count,
            "ssh_auth_attempt_sum": self.ssh_auth_attempt_sum,
            "notice_count": self.notice_count,
            "weird_count": self.weird_count,
        }

    def human(self, entity: str) -> dict[str, Any]:
        return {
            "summary": f"Host {entity} generated {self.used_sessions} behavior-eligible sessions in this {self.spec.window} window.",
            "top_protocols": top_counter(self.top_protocols),
            "top_destination_ips": top_counter(self.top_destination_ips),
            "top_destination_ports": top_counter(self.top_destination_ports, numeric_value=True),
            "top_counterpart_ips": top_counter(self.top_counterpart_ips),
            "top_external_source_ips": top_counter(self.top_external_source_ips),
            "top_inbound_destination_ports": top_counter(self.top_inbound_destination_ports, numeric_value=True),
            "top_outbound_destination_ports": top_counter(self.top_outbound_destination_ports, numeric_value=True),
            "top_dns_queries": top_counter(self.top_dns_queries),
            "top_http_hosts": top_counter(self.top_http_hosts),
            "top_tls_sni": top_counter(self.top_tls_sni),
            "top_file_mime_types": top_counter(self.top_file_mime_types),
            "top_tls_issuers": top_counter(self.top_tls_issuers),
        }


    def evidence(self, source_index_pattern: str, max_session_refs: int) -> dict[str, Any]:
        return {
            "source_index_pattern": source_index_pattern,
            "session_ref_count": self.session_ref_count,
            "session_refs_truncated": self.session_ref_count > max(0, max_session_refs),
            "session_refs": self.session_refs,
        }

    def quality(self, feature_complete: bool) -> dict[str, Any]:
        warnings = sorted(self.warnings)
        if self.used_sessions == 0:
            warnings.append("no_behavior_eligible_sessions")
        if self.excluded_sessions > 0:
            warnings.append("excluded_sessions_present")
        score = 100 - (self.missing_required_fields * 5) - (len(set(warnings)) * 5)
        return {
            "feature_complete": feature_complete,
            "session_count_total": self.total_sessions,
            "session_count_used": self.used_sessions,
            "excluded_session_count": self.excluded_sessions,
            "missing_required_fields": self.missing_required_fields,
            "warnings": sorted(set(warnings)),
            "excluded_reasons": [{"value": key, "count": value} for key, value in sorted(self.excluded_reasons.items())],
            "data_quality_score": max(0, min(100, score)),
        }
