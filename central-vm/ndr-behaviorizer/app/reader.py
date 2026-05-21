from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterator

from opensearchpy import OpenSearch

from app.config import Settings
from app.metrics import DOCUMENTS_READ, OPENSEARCH_ERRORS
from app.utils import isoformat

logger = logging.getLogger(__name__)


class SessionReader:
    def __init__(self, client: OpenSearch, settings: Settings):
        self.client = client
        self.settings = settings

    def read_window(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        """Yield ndr-sessions hits using PIT + search_after.

        The checkpoint is driven by sessionizer.updated_at when present. If older
        session documents do not contain that field, the reader falls back to the
        event timestamp so the first run still works safely.
        """
        pit_id: str | None = None
        search_after: list[Any] | None = None
        process_field = self.settings.process_time_field
        event_field = self.settings.event_time_field
        try:
            count_response = self.client.count(
                index=self.settings.source_index_pattern,
                body={"query": {"match_all": {}}},
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )
            if int(count_response.get("count", 0) or 0) == 0:
                logger.info("source_index_empty_or_not_ready", extra={"source_index_pattern": self.settings.source_index_pattern})
                return

            pit_response = self.client.create_pit(index=self.settings.source_index_pattern, keep_alive="2m")
            pit_id = pit_response.get("pit_id") or pit_response.get("id")
            if not pit_id:
                raise RuntimeError("OpenSearch did not return a PIT id")

            while True:
                body: dict[str, Any] = {
                    "size": self.settings.read_page_size,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "bool": {
                                        "should": [
                                            {"range": {process_field: {"gte": isoformat(start), "lte": isoformat(end)}}},
                                            {
                                                "bool": {
                                                    "must_not": [{"exists": {"field": process_field}}],
                                                    "filter": [{"range": {event_field: {"gte": isoformat(start), "lte": isoformat(end)}}}],
                                                }
                                            },
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                }
                            ]
                        }
                    },
                    "sort": [{"_shard_doc": "asc"}],
                    "pit": {"id": pit_id, "keep_alive": "2m"},
                    "track_total_hits": False,
                }
                if search_after is not None:
                    body["search_after"] = search_after
                response = self.client.search(body=body)
                hits = response.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for hit in hits:
                    DOCUMENTS_READ.inc()
                    yield hit
                search_after = hits[-1].get("sort")
        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("read_window_failed", extra={"start": isoformat(start), "end": isoformat(end)})
            raise
        finally:
            if pit_id:
                try:
                    self.client.delete_pit(body={"pit_id": pit_id})
                except Exception:
                    logger.warning("delete_pit_failed", exc_info=True)

    def read_entity_event_window(
        self,
        entity: str,
        sensor: str | None,
        window_start_iso: str,
        window_end_iso: str,
    ) -> Iterator[dict[str, Any]]:
        """Yield all sessions for one entity/sensor inside the full event-time behavior window.

        This is used after the incremental checkpoint read. The incremental read only tells us
        which behavior windows changed. This method rebuilds the complete 15-minute window so
        we never overwrite a behavior doc with a partial batch.
        """
        pit_id: str | None = None
        search_after: list[Any] | None = None
        event_field = self.settings.event_time_field

        entity_should = [
            {"term": {"network.asset.ip": entity}},
            {"term": {"source.ip": entity}},
            {"term": {"destination.ip": entity}},
        ]

        filters: list[dict[str, Any]] = [
            {"range": {event_field: {"gte": window_start_iso, "lt": window_end_iso}}},
            {
                "bool": {
                    "should": entity_should,
                    "minimum_should_match": 1,
                }
            },
        ]

        if sensor:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"sensor.name": sensor}},
                            {"term": {"sensor": sensor}},
                            {"term": {"host.name": sensor}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        try:
            pit_response = self.client.create_pit(index=self.settings.source_index_pattern, keep_alive="2m")
            pit_id = pit_response.get("pit_id") or pit_response.get("id")
            if not pit_id:
                raise RuntimeError("OpenSearch did not return a PIT id")

            while True:
                body: dict[str, Any] = {
                    "size": self.settings.read_page_size,
                    "query": {
                        "bool": {
                            "filter": filters
                        }
                    },
                    "sort": [{"_shard_doc": "asc"}],
                    "pit": {"id": pit_id, "keep_alive": "2m"},
                    "track_total_hits": False,
                }

                if search_after is not None:
                    body["search_after"] = search_after

                response = self.client.search(body=body)
                hits = response.get("hits", {}).get("hits", [])

                if not hits:
                    break

                for hit in hits:
                    DOCUMENTS_READ.inc()
                    yield hit

                search_after = hits[-1].get("sort")

        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception(
                "read_entity_event_window_failed",
                extra={
                    "entity": entity,
                    "sensor": sensor,
                    "window_start": window_start_iso,
                    "window_end": window_end_iso,
                },
            )
            raise

        finally:
            if pit_id:
                try:
                    self.client.delete_pit(body={"pit_id": pit_id})
                except Exception:
                    logger.warning("delete_pit_failed", exc_info=True)
