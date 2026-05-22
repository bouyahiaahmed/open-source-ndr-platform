from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Zeek ts is often epoch seconds.
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except Exception:
        return None


def age_seconds(value: Any) -> float | None:
    ts = parse_ts(value)
    if not ts:
        return None
    return max(0.0, (utc_now() - ts).total_seconds())


def seconds_to_human(seconds: float | int | None) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m {seconds % 60}s"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h {minutes % 60}m"
    days = hours // 24
    return f"{days}d {hours % 24}h"
