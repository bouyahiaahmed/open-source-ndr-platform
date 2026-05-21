from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from opensearchpy import OpenSearch

from app.config import Settings
from app.metrics import LAST_CHECKPOINT_TS, PROCESSING_LAG_SECONDS
from app.utils import isoformat, parse_ts, utc_now

logger = logging.getLogger(__name__)


@dataclass
class Checkpoint:
    last_successful_timestamp: datetime | None
    last_run_time: datetime | None = None
    documents_read: int = 0
    sessions_updated: int = 0
    failures: int = 0
    service_version: str = "0.1.0"

    @classmethod
    def from_doc(cls, source: dict[str, Any] | None) -> "Checkpoint":
        if not source:
            return cls(last_successful_timestamp=None)
        return cls(
            last_successful_timestamp=parse_ts(source.get("last_successful_timestamp")),
            last_run_time=parse_ts(source.get("last_run_time")),
            documents_read=int(source.get("documents_read", 0) or 0),
            sessions_updated=int(source.get("sessions_updated", 0) or 0),
            failures=int(source.get("failures", 0) or 0),
            service_version=str(source.get("service_version", "0.1.0")),
        )

    def to_doc(self) -> dict[str, Any]:
        return {
            "last_successful_timestamp": isoformat(self.last_successful_timestamp),
            "last_run_time": isoformat(self.last_run_time),
            "documents_read": self.documents_read,
            "sessions_updated": self.sessions_updated,
            "failures": self.failures,
            "service_version": self.service_version,
        }


class CheckpointStore:
    def __init__(self, client: OpenSearch, settings: Settings):
        self.client = client
        self.settings = settings

    def ensure_state_index(self) -> None:
        if self.client.indices.exists(index=self.settings.state_index):
            return
        self.client.indices.create(
            index=self.settings.state_index,
            body={
                "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
                "mappings": {
                    "dynamic": "strict",
                    "properties": {
                        "last_successful_timestamp": {"type": "date"},
                        "last_run_time": {"type": "date"},
                        "documents_read": {"type": "long"},
                        "sessions_updated": {"type": "long"},
                        "failures": {"type": "long"},
                        "service_version": {"type": "keyword"},
                    },
                },
            },
        )

    def load(self) -> Checkpoint:
        try:
            result = self.client.get(index=self.settings.state_index, id=self.settings.checkpoint_id, ignore=[404])
            if not result or result.get("found") is False:
                return Checkpoint(last_successful_timestamp=None, service_version=self.settings.service_version)
            cp = Checkpoint.from_doc(result.get("_source"))
            if cp.last_successful_timestamp:
                LAST_CHECKPOINT_TS.set(cp.last_successful_timestamp.timestamp())
                PROCESSING_LAG_SECONDS.set(max(0, (utc_now() - cp.last_successful_timestamp).total_seconds()))
            return cp
        except Exception:
            logger.exception("checkpoint_load_failed")
            raise

    def save(self, checkpoint: Checkpoint) -> None:
        checkpoint.last_run_time = utc_now()
        checkpoint.service_version = self.settings.service_version
        self.client.index(
            index=self.settings.state_index,
            id=self.settings.checkpoint_id,
            body=checkpoint.to_doc(),
            refresh=False,
        )
        if checkpoint.last_successful_timestamp:
            LAST_CHECKPOINT_TS.set(checkpoint.last_successful_timestamp.timestamp())
            PROCESSING_LAG_SECONDS.set(max(0, (utc_now() - checkpoint.last_successful_timestamp).total_seconds()))

    def compute_window_start(self, checkpoint: Checkpoint) -> datetime:
        if checkpoint.last_successful_timestamp is None:
            return utc_now() - timedelta(seconds=self.settings.initial_lookback_seconds)
        return checkpoint.last_successful_timestamp - timedelta(seconds=self.settings.lookback_overlap_seconds)
