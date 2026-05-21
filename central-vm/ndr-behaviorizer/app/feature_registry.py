from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class FeatureSpec:
    feature_set: str
    behavior_type: str
    entity: str
    window: str
    window_seconds: int
    vector_order: list[str]
    thresholds: dict[str, Any]
    raw: dict[str, Any]


def load_feature_spec(path: str) -> FeatureSpec:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"feature config not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    vector_order = data.get("vector_order") or []
    if not isinstance(vector_order, list) or not vector_order:
        raise ValueError("feature config must define a non-empty vector_order list")
    return FeatureSpec(
        feature_set=str(data.get("feature_set") or p.stem),
        behavior_type=str(data.get("behavior_type") or "host_hourly"),
        entity=str(data.get("entity") or "source.ip"),
        window=str(data.get("window") or "1h"),
        window_seconds=int(data.get("window_seconds") or 3600),
        vector_order=[str(x) for x in vector_order],
        thresholds=dict(data.get("thresholds") or {}),
        raw=data,
    )
