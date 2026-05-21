from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

_SAFE_KEY_RE = re.compile(r"[^A-Za-z0-9_\-]")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            try:
                return datetime.fromtimestamp(float(text), tz=timezone.utc)
            except ValueError:
                return None
    return None


def isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def floor_time(dt: datetime, seconds: int = 60) -> datetime:
    epoch = int(dt.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=timezone.utc)


def get_field(doc: dict[str, Any], path: str, default: Any = None) -> Any:
    """Read fields safely from either flat Zeek keys or nested objects.

    Zeek JSON often contains flat keys such as `id.orig_h`; some pipelines may
    convert those into nested objects. This helper supports both forms.
    """
    if path in doc:
        return doc[path]
    current: Any = doc
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "" and value != []:
            return value
    return None


def as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def unique_extend(target: list[Any], values: Iterable[Any]) -> None:
    seen = {json.dumps(v, sort_keys=True, default=str) for v in target}
    for value in values:
        if value is None or value == "":
            continue
        key = json.dumps(value, sort_keys=True, default=str)
        if key not in seen:
            target.append(value)
            seen.add(key)


def unique_values(values: Iterable[Any]) -> list[Any]:
    out: list[Any] = []
    unique_extend(out, values)
    return out


def safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def set_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None and value != "" and value != []:
        target[key] = value


def is_private_ip(value: Any) -> bool | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return None


def direction_from_local(local_orig: Any, local_resp: Any) -> str:
    if local_orig is True and local_resp is False:
        return "outbound"
    if local_orig is False and local_resp is True:
        return "inbound"
    if local_orig is True and local_resp is True:
        return "internal"
    return "external_or_unknown"


def safe_log_type(value: Any) -> str:
    text = str(value or "unknown").strip().lower() or "unknown"
    return _SAFE_KEY_RE.sub("_", text)


def synthetic_session_id(parts: Iterable[Any]) -> str:
    normalized = "|".join(str(p) for p in parts if p is not None and p != "")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
    return f"synthetic:{digest}"


def deep_merge_keep_existing(existing: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge dictionaries recursively, preserving existing scalar values when new is empty.

    Arrays are unioned using JSON-stable identity. This is intentionally small and
    deterministic for session document merges before bulk indexing.
    """
    merged = dict(existing)
    for key, value in new.items():
        if value is None or value == "" or value == []:
            continue
        if key not in merged or merged[key] in (None, "", []):
            merged[key] = value
            continue
        old_value = merged[key]
        if isinstance(old_value, dict) and isinstance(value, dict):
            merged[key] = deep_merge_keep_existing(old_value, value)
        elif isinstance(old_value, list) and isinstance(value, list):
            combined = list(old_value)
            unique_extend(combined, value)
            merged[key] = combined
        else:
            # Prefer the new value for timestamps/counters that are recomputed by the builder.
            merged[key] = value
    return merged


def strip_empty(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_empty(v) for k, v in value.items() if strip_empty(v) not in (None, "", [], {})}
    if isinstance(value, list):
        return [strip_empty(v) for v in value if strip_empty(v) not in (None, "", [], {})]
    return value
