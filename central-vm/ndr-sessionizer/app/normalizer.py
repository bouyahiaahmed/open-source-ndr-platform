from __future__ import annotations

from typing import Any

from app.utils import (
    as_list,
    first_present,
    get_field,
    safe_float,
    safe_int,
    set_if_present,
    unique_values,
)


def normalize_conn(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    set_if_present(out, "state", get_field(event, "conn_state"))
    set_if_present(out, "duration", safe_float(get_field(event, "duration")))
    set_if_present(out, "orig_bytes", safe_int(get_field(event, "orig_bytes")))
    set_if_present(out, "resp_bytes", safe_int(get_field(event, "resp_bytes")))
    set_if_present(out, "orig_pkts", safe_int(get_field(event, "orig_pkts")))
    set_if_present(out, "resp_pkts", safe_int(get_field(event, "resp_pkts")))
    set_if_present(out, "history", get_field(event, "history"))
    set_if_present(out, "missed_bytes", safe_int(get_field(event, "missed_bytes")))
    return out


def normalize_dns(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    query = get_field(event, "query")
    labels = [label for label in str(query or "").strip(".").split(".") if label]
    answers = unique_values(v for e in events for v in as_list(get_field(e, "answers")))
    ttls = unique_values(safe_float(v) for e in events for v in as_list(get_field(e, "TTLs", get_field(e, "ttls"))))
    out: dict[str, Any] = {}
    set_if_present(out, "query", query)
    set_if_present(out, "qtype", safe_int(get_field(event, "qtype")))
    set_if_present(out, "qtype_name", get_field(event, "qtype_name"))
    set_if_present(out, "rcode", first_present(get_field(event, "rcode"), get_field(event, "rcode_name")))
    set_if_present(out, "rcode_name", get_field(event, "rcode_name"))
    set_if_present(out, "answers", answers)
    set_if_present(out, "ttls", [v for v in ttls if v is not None])
    if query:
        out["query_length"] = len(str(query))
        out["label_count"] = len(labels)
        out["longest_label_length"] = max((len(label) for label in labels), default=0)
    qtype_name = str(get_field(event, "qtype_name", "")).upper()
    rcode_name = str(get_field(event, "rcode_name", "")).upper()
    out["is_txt"] = qtype_name == "TXT"
    out["is_nxdomain"] = rcode_name == "NXDOMAIN"
    return out


def normalize_http(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    set_if_present(out, "host", get_field(event, "host"))
    set_if_present(out, "method", first_present(get_field(event, "method"), get_field(event, "http.request.method")))
    set_if_present(out, "uri", first_present(get_field(event, "uri"), get_field(event, "path"), get_field(event, "url.path")))
    set_if_present(out, "status_code", safe_int(first_present(get_field(event, "status_code"), get_field(event, "http.response.status_code"))))
    set_if_present(out, "user_agent", first_present(get_field(event, "user_agent"), get_field(event, "user_agent.name")))
    set_if_present(out, "request_body_bytes", safe_int(first_present(
        get_field(event, "request_body_len"),
        get_field(event, "request_body_bytes"),
        get_field(event, "http.request.body.bytes"),
    )))
    set_if_present(out, "response_body_bytes", safe_int(first_present(
        get_field(event, "response_body_len"),
        get_field(event, "response_body_bytes"),
        get_field(event, "http.response.body.bytes"),
    )))
    set_if_present(out, "referrer", first_present(
        get_field(event, "referrer"),
        get_field(event, "referer"),
        get_field(event, "http.request.referrer"),
    ))
    return out


def normalize_tls(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    set_if_present(out, "server_name", get_field(event, "server_name"))
    set_if_present(out, "version", get_field(event, "version"))
    set_if_present(out, "cipher", get_field(event, "cipher"))
    set_if_present(out, "curve", get_field(event, "curve"))
    set_if_present(out, "validation_status", get_field(event, "validation_status"))
    set_if_present(out, "established", get_field(event, "established"))
    set_if_present(out, "resumed", get_field(event, "resumed"))
    set_if_present(out, "sni_matches_cert", get_field(event, "sni_matches_cert"))
    set_if_present(out, "next_protocol", get_field(event, "next_protocol"))
    return out


def normalize_x509(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    cert = get_field(event, "certificate", {}) if isinstance(get_field(event, "certificate", {}), dict) else {}
    out: dict[str, Any] = {}
    set_if_present(out, "subject", first_present(get_field(event, "subject"), cert.get("subject")))
    set_if_present(out, "issuer", first_present(get_field(event, "issuer"), cert.get("issuer")))
    set_if_present(out, "serial", first_present(get_field(event, "serial"), cert.get("serial")))
    set_if_present(out, "not_valid_before", safe_float(first_present(get_field(event, "not_valid_before"), cert.get("not_valid_before"))))
    set_if_present(out, "not_valid_after", safe_float(first_present(get_field(event, "not_valid_after"), cert.get("not_valid_after"))))
    set_if_present(out, "key_type", first_present(get_field(event, "key_type"), cert.get("key_type")))
    set_if_present(out, "key_alg", first_present(get_field(event, "key_alg"), cert.get("key_alg")))
    set_if_present(out, "key_length", safe_int(first_present(get_field(event, "key_length"), cert.get("key_length"))))
    set_if_present(out, "sig_alg", first_present(get_field(event, "sig_alg"), cert.get("sig_alg")))
    set_if_present(out, "san_dns", unique_values(v for e in events for v in as_list(first_present(get_field(e, "san.dns"), get_field(e, "san_dns")))))
    set_if_present(out, "basic_constraints_ca", first_present(get_field(event, "basic_constraints.ca"), get_field(event, "basic_constraints_ca")))
    return out


def normalize_notice(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "notes": unique_values(get_field(e, "note") for e in events),
        "messages": unique_values(get_field(e, "msg") for e in events),
        "actions": unique_values(v for e in events for v in as_list(get_field(e, "actions"))),
        "subs": unique_values(get_field(e, "sub") for e in events),
        "suppress_for": unique_values(safe_float(get_field(e, "suppress_for")) for e in events),
    }


def normalize_weird(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "names": unique_values(get_field(e, "name") for e in events),
        "messages": unique_values(first_present(get_field(e, "msg"), get_field(e, "message")) for e in events),
    }


def normalize_analyzer(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "names": unique_values(first_present(get_field(e, "analyzer"), get_field(e, "name")) for e in events),
        "kinds": unique_values(get_field(e, "kind") for e in events),
        "failure_reasons": unique_values(first_present(get_field(e, "failure_reason"), get_field(e, "reason")) for e in events),
    }


def normalize_files(events: list[dict[str, Any]]) -> dict[str, Any]:
    fuids = []
    mime_types = []
    for event in events:
        fuids.extend(as_list(get_field(event, "fuid")))
        fuids.extend(as_list(get_field(event, "fuids")))
        mime_types.extend(as_list(get_field(event, "mime_type")))
        mime_types.extend(as_list(get_field(event, "mime_types")))

    out: dict[str, Any] = {
        "fuids": unique_values(fuids),
        "mime_types": unique_values(mime_types),
        "md5": unique_values(get_field(e, "md5") for e in events),
        "sha1": unique_values(get_field(e, "sha1") for e in events),
        "sha256": unique_values(get_field(e, "sha256") for e in events),
        "filenames": unique_values(first_present(get_field(e, "filename"), get_field(e, "name")) for e in events),
    }

    for target, source in {
        "seen_bytes": "seen_bytes",
        "total_bytes": "total_bytes",
        "missing_bytes": "missing_bytes",
        "overflow_bytes": "overflow_bytes",
    }.items():
        values = [safe_int(get_field(e, source)) for e in events]
        values = [v for v in values if v is not None]
        if values:
            out[target] = sum(values)

    return out


def normalize_ssh(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    for target, source in {
        "auth_success": "auth_success",
        "auth_attempts": "auth_attempts",
        "client": "client",
        "server": "server",
        "cipher_alg": "cipher_alg",
        "mac_alg": "mac_alg",
        "kex_alg": "kex_alg",
        "host_key_alg": "host_key_alg",
        "host_key_fingerprint": "host_key_fingerprint",
    }.items():
        value = get_field(event, source)
        if target == "auth_attempts":
            value = safe_int(value)
        set_if_present(out, target, value)
    return out


def normalize_ftp(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    fields = {
        "user": "user",
        "command": "command",
        "reply_code": "reply_code",
        "reply_msg": "reply_msg",
        "data_channel_orig_h": "data_channel.orig_h",
        "data_channel_resp_h": "data_channel.resp_h",
        "data_channel_resp_p": "data_channel.resp_p",
        "data_channel_passive": "data_channel.passive",
    }
    for target, source in fields.items():
        value = get_field(event, source)
        if target.endswith("_p") or target == "reply_code":
            value = safe_int(value)
        set_if_present(out, target, value)
    return out


def normalize_smtp(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    for target, source in {
        "helo": "helo",
        "mailfrom": "mailfrom",
        "rcptto": "rcptto",
        "from": "from",
        "to": "to",
        "subject": "subject",
        "date": "date",
        "msg_id": "msg_id",
        "last_reply": "last_reply",
        "is_webmail": "is_webmail",
        "tls": "tls",
    }.items():
        value = get_field(event, source)
        if target in {"rcptto", "to"}:
            value = as_list(value)
        set_if_present(out, target, value)
    return out


def normalize_smb(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "operations": unique_values(get_field(e, "operation") for e in events),
        "paths": unique_values(first_present(get_field(e, "path"), get_field(e, "name")) for e in events),
        "names": unique_values(get_field(e, "name") for e in events),
        "named_pipes": unique_values(get_field(e, "named_pipe") for e in events),
        "share_types": unique_values(get_field(e, "share_type") for e in events),
        "usernames": unique_values(first_present(get_field(e, "username"), get_field(e, "user")) for e in events),
        "hostnames": unique_values(first_present(get_field(e, "hostname"), get_field(e, "host")) for e in events),
        "server_dns_computer_names": unique_values(get_field(e, "server_dns_computer_name") for e in events),
        "server_nb_computer_names": unique_values(get_field(e, "server_nb_computer_name") for e in events),
        "success_values": unique_values(get_field(e, "success") for e in events),
    }


def normalize_ldap(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "operations": unique_values(first_present(get_field(e, "operation"), get_field(e, "message_type")) for e in events),
        "arguments": unique_values(first_present(get_field(e, "argument"), get_field(e, "attributes"), get_field(e, "base_object")) for e in events),
        "results": unique_values(first_present(get_field(e, "result"), get_field(e, "result_code")) for e in events),
    }


def normalize_dhcp(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    for target, source in {
        "assigned_addr": "assigned_addr",
        "client_addr": "client_addr",
        "server_addr": "server_addr",
        "host_name": "host_name",
        "domain": "domain",
        "lease_time": "lease_time",
        "mac": "mac",
    }.items():
        value = get_field(event, source)
        if target == "lease_time":
            value = safe_float(value)
        set_if_present(out, target, value)
    msg_types = []
    for e in events:
        msg_types.extend(as_list(get_field(e, "msg_type")))
        msg_types.extend(as_list(get_field(e, "msg_types")))
    set_if_present(out, "msg_types", unique_values(msg_types))
    return out


def normalize_irc(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {}
    event = events[0]
    out: dict[str, Any] = {}
    for target in ["nick", "command", "value", "addl"]:
        set_if_present(out, target, get_field(event, target))
    return out


NORMALIZERS = {
    "conn": normalize_conn,
    "dns": normalize_dns,
    "http": normalize_http,
    "ssl": normalize_tls,
    "tls": normalize_tls,
    "x509": normalize_x509,
    "notice": normalize_notice,
    "weird": normalize_weird,
    "analyzer": normalize_analyzer,
    "files": normalize_files,
    "ftp": normalize_ftp,
    "ssh": normalize_ssh,
    "smtp": normalize_smtp,
    "smb_files": normalize_smb,
    "smb_mapping": normalize_smb,
    "ntlm": normalize_smb,
    "dce_rpc": normalize_smb,
    "ldap": normalize_ldap,
    "ldap_search": normalize_ldap,
    "dhcp": normalize_dhcp,
    "irc": normalize_irc,
}
