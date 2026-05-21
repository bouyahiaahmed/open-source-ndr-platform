from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.config import Settings
from app.feature_registry import FeatureSpec
from app.features import FeatureAccumulator
from app.utils import deterministic_id, floor_time, get_field, isoformat, parse_ts, stable_hash, utc_now

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BehaviorGroupKey:
    entity: str
    sensor: str | None
    window_start: str


def get_event_time(doc: dict[str, Any], settings: Settings) -> Any:
    return get_field(doc, settings.event_time_field) or get_field(doc, "session.first_seen") or doc.get("@timestamp")


def entity_for_doc(doc: dict[str, Any], settings: Settings) -> tuple[str | None, str | None, str]:
    source_ip = get_field(doc, "source.ip")
    destination_ip = get_field(doc, "destination.ip")
    source_local = get_field(doc, "source.local")
    destination_local = get_field(doc, "destination.local")
    asset_ip = get_field(doc, "network.asset.ip")
    asset_side = get_field(doc, "network.asset.side")

    sensor = get_field(doc, "sensor.name") or get_field(doc, "sensor") or get_field(doc, "host.name")
    sensor_text = str(sensor) if sensor else None

    mode = (settings.behavior_entity_mode or "asset_sensor").strip().lower()

    # Correct NDR mode:
    # behavior entity = monitored/local asset involved in the session.
    # outbound/internal: entity=source.ip
    # inbound: entity=destination.ip
    if mode in {"asset_sensor", "local_asset_sensor", "monitored_asset_sensor"}:
        if asset_ip:
            entity_type = (
                f"local_asset.ip+sensor.name:{asset_side or 'unknown'}"
                if sensor_text
                else f"local_asset.ip:{asset_side or 'unknown'}"
            )
            return str(asset_ip), sensor_text, entity_type

        if source_local is True and source_ip:
            return str(source_ip), sensor_text, "local_asset.source.ip+sensor.name" if sensor_text else "local_asset.source.ip"

        if destination_local is True and destination_ip:
            return str(destination_ip), sensor_text, "local_asset.destination.ip+sensor.name" if sensor_text else "local_asset.destination.ip"

        return None, sensor_text, "local_asset.ip"

    # Legacy source-IP mode.
    if not source_ip:
        return None, sensor_text, "source.ip"

    entity = str(source_ip)

    if mode in {"host_sensor", "source_sensor", "source.ip+sensor.name"}:
        entity_type = "source.ip+sensor.name" if sensor_text else "source.ip"
        return entity, sensor_text, entity_type

    if mode in {"sensor_host", "sensor_source"}:
        entity_type = "sensor.name+source.ip" if sensor_text else "source.ip"
        return entity, sensor_text, entity_type

    return entity, None, "source.ip"



class BehaviorAggregator:
    def __init__(self, settings: Settings, spec: FeatureSpec):
        self.settings = settings
        self.spec = spec
        if self.spec.feature_set != settings.feature_set:
            logger.warning("feature_set_mismatch", extra={"settings_feature_set": settings.feature_set, "spec_feature_set": self.spec.feature_set})

    def aggregate_hits(self, hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[BehaviorGroupKey, FeatureAccumulator] = {}
        group_meta: dict[BehaviorGroupKey, dict[str, Any]] = {}
        missing_entity = 0
        missing_time = 0

        for hit in hits:
            doc = hit.get("_source", hit)
            entity, sensor, entity_type = entity_for_doc(doc, self.settings)
            if not entity:
                missing_entity += 1
                continue
            event_time = parse_ts(get_event_time(doc, self.settings))
            if not event_time:
                missing_time += 1
                continue
            window_start_dt = floor_time(event_time, self.settings.behavior_window_seconds)
            window_end_dt = window_start_dt + timedelta(seconds=self.settings.behavior_window_seconds)
            key = BehaviorGroupKey(entity=entity, sensor=sensor, window_start=isoformat(window_start_dt) or "")
            if key not in groups:
                groups[key] = FeatureAccumulator(self.spec)
                group_meta[key] = {
                    "entity_type": entity_type,
                    "window_start_dt": window_start_dt,
                    "window_end_dt": window_end_dt,
                    "source_local": get_field(doc, "source.local"),
                    "asset_side": get_field(doc, "network.asset.side"),
                    "asset_spoke": get_field(doc, "network.asset.spoke"),
                    "asset_vnet": get_field(doc, "network.asset.vnet"),
                    "asset_subnet": get_field(doc, "network.asset.subnet"),
                    "asset_subnet_cidr": get_field(doc, "network.asset.subnet_cidr"),
                }
            groups[key].add(doc, hit_meta=hit, max_session_refs=self.settings.behavior_max_session_refs)

        docs: list[dict[str, Any]] = []
        now = utc_now()
        for key, acc in sorted(groups.items(), key=lambda item: (item[0].window_start, item[0].sensor or "", item[0].entity)):
            meta = group_meta[key]
            features = acc.features()
            vector = [float(features.get(name, 0) or 0) for name in self.spec.vector_order]
            feature_complete = len(vector) == len(self.spec.vector_order) and acc.used_sessions >= self.settings.behavior_min_sessions_for_ml
            behavior_id_parts = [self.spec.feature_set]
            if key.sensor:
                behavior_id_parts.append(key.sensor)
            behavior_id_parts.extend([key.entity, key.window_start])
            behavior_id = deterministic_id(behavior_id_parts)
            if len(behavior_id) > 512:
                behavior_id = f"{self.spec.feature_set}|{stable_hash(behavior_id_parts)}|{key.window_start}"

            doc = {
                "@timestamp": key.window_start,
                "doc": {"type": "ndr_behavior"},
                "behavior": {
                    "id": behavior_id,
                    "type": self.spec.behavior_type,
                    "feature_set": self.spec.feature_set,
                    "entity_type": ("local_asset.ip+sensor.name:asset" if key.sensor else "local_asset.ip:asset"),
                    "entity": key.entity,
                    "sensor": key.sensor,
                    "window": self.spec.window,
                    "window_start": key.window_start,
                    "window_end": isoformat(meta["window_end_dt"]),
                    "session_index_pattern": self.settings.source_index_pattern,
                },
                "source": {"ip": key.entity, "local": True},
                "asset": {
                    "ip": key.entity,
                    "side": "combined",
                    "spoke": meta.get("asset_spoke"),
                    "vnet": meta.get("asset_vnet"),
                    "subnet": meta.get("asset_subnet"),
                    "subnet_cidr": meta.get("asset_subnet_cidr"),
                },
                "quality": acc.quality(feature_complete=feature_complete),
                "features": features,
                "human": acc.human(key.entity),
                "evidence": acc.evidence(self.settings.source_index_pattern, self.settings.behavior_max_session_refs),
                "ml": {
                    "ready": feature_complete,
                    "feature_set": self.spec.feature_set,
                    "feature_names": list(self.spec.vector_order),
                    "feature_vector": vector,
                    "vector_length": len(vector),
                    "vector_version": self.spec.feature_set,
                    "preprocessing": {
                        "missing_numeric_default": 0,
                        "categorical_strategy": "counts_and_cardinality_only",
                        "scaling_required": True,
                    },
                    "model_name": None,
                    "model_version": None,
                    "anomaly_score": None,
                    "is_anomaly": None,
                    "scored_at": None,
                    "scoring_status": "not_scored",
                    "top_features": [],
                },
                "score": {"statistical": None, "ml": None, "final": None, "severity": "none", "reasons": []},
                "behaviorizer": {"version": self.settings.service_version, "updated_at": isoformat(now)},
            }
            docs.append(doc)
        return docs
