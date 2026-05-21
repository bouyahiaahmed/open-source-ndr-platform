from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterator

from opensearchpy import OpenSearch

from app.config import Settings
from app.metrics import DOCUMENTS_READ, OPENSEARCH_ERRORS
from app.utils import isoformat

logger = logging.getLogger(__name__)


class ZeekReader:
    def __init__(self, client: OpenSearch, settings: Settings):
        self.client = client
        self.settings = settings

    def read_window(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        process_time_field = self.settings.process_time_field
        """Yield raw OpenSearch hits using PIT + search_after.

        Sorting by process_time_field then _shard_doc is stable inside a PIT and avoids
        missing documents when many events share the same timestamp.
        """
        pit_id: str | None = None
        search_after: list[Any] | None = None
        try:
            if not self.client.indices.exists(index=self.settings.source_index_pattern):
                logger.info(
                    "source_index_not_ready",
                    extra={"source_index_pattern": self.settings.source_index_pattern},
                )
                return

            count_response = self.client.count(

                index=self.settings.source_index_pattern,

                params={"ignore_unavailable": "true", "allow_no_indices": "true"},

            )

            if int(count_response.get("count", 0)) == 0:

                logger.info(

                    "source_index_empty_or_not_ready",

                    extra={"source_index_pattern": self.settings.source_index_pattern},

                )

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
                                            {
                                                "range": {
                                                    process_time_field: {
                                                        "gte": isoformat(start),
                                                        "lte": isoformat(end),
                                                    }
                                                }
                                            },
                                            {
                                                "bool": {
                                                    "must_not": [
                                                        {"exists": {"field": process_time_field}}
                                                    ],
                                                    "filter": [
                                                        {
                                                            "range": {
                                                                self.settings.event_time_field: {
                                                                    "gte": isoformat(start),
                                                                    "lte": isoformat(end),
                                                                }
                                                            }
                                                        }
                                                    ],
                                                }
                                            },
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                }
                            ]
                        }
                    },
                    "sort": [
                        {"_shard_doc": "asc"},
                    ],
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
