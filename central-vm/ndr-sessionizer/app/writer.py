from __future__ import annotations

import logging
from datetime import datetime
from itertools import islice
from typing import Any, Iterable

from opensearchpy import OpenSearch, helpers

from app.config import Settings
from app.metrics import OPENSEARCH_ERRORS, SESSIONS_CREATED, SESSIONS_UPDATED, SESSIONS_UPSERTED
from app.session_builder import SessionBuilder
from app.session_hardening import harden_session_document
from app.utils import get_field, parse_ts

logger = logging.getLogger(__name__)


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            break
        yield chunk


class SessionWriter:
    def __init__(self, client: OpenSearch, settings: Settings, builder: SessionBuilder):
        self.client = client
        self.settings = settings
        self.builder = builder

    def index_for_doc(self, doc: dict[str, Any]) -> str:
        first_seen = parse_ts(get_field(doc, "session.first_seen")) or parse_ts(doc.get("@timestamp")) or datetime.utcnow()
        return f"{self.settings.target_index_prefix}-{first_seen:%Y.%m.%d}"

    def existing_by_id(self, ids: list[str]) -> dict[str, tuple[str, dict[str, Any]]]:
        if not ids:
            return {}
        existing: dict[str, tuple[str, dict[str, Any]]] = {}
        for id_chunk in chunks(ids, 100):
            body = {
                "size": len(id_chunk),
                "query": {"ids": {"values": id_chunk}},
                "_source": True,
            }
            try:
                response = self.client.search(index=f"{self.settings.target_index_prefix}-*", body=body, ignore=[404])
            except Exception:
                OPENSEARCH_ERRORS.inc()
                logger.exception("existing_session_lookup_failed")
                raise
            for hit in response.get("hits", {}).get("hits", []):
                existing[str(hit.get("_id"))] = (str(hit.get("_index")), hit.get("_source", {}))
        return existing

    def bulk_upsert(self, docs: list[dict[str, Any]]) -> dict[str, int]:
        if not docs:
            return {"created_count": 0, "updated_count": 0, "upserted": 0}

        ids = [str(get_field(doc, "session.id")) for doc in docs if get_field(doc, "session.id")]
        existing = self.existing_by_id(ids)
        actions = []
        created = 0
        updated = 0
        for doc in docs:
            doc_id = str(get_field(doc, "session.id"))
            if not doc_id:
                continue
            existing_entry = existing.get(doc_id)
            if existing_entry:
                target_index, existing_doc = existing_entry
                final_doc = self.builder.merge_existing(existing_doc, doc)
                updated += 1
            else:
                target_index = self.index_for_doc(doc)
                final_doc = doc
                created += 1
            final_doc = harden_session_document(final_doc)

            actions.append(
                {
                    "_op_type": "index",
                    "_index": target_index,
                    "_id": doc_id,
                    "_source": final_doc,
                }
            )

        if self.settings.dry_run:
            logger.info("dry_run_bulk_upsert", extra={"sessions": len(actions), "created_count": created, "updated_count": updated})
            return {"created_count": created, "updated_count": updated, "upserted": len(actions)}

        try:
            success, errors = helpers.bulk(
                self.client,
                actions,
                chunk_size=self.settings.bulk_size,
                request_timeout=120,
                raise_on_error=False,
            )
            if errors:
                OPENSEARCH_ERRORS.inc(len(errors))
                logger.error("bulk_upsert_errors", extra={"error_count": len(errors), "sample": errors[:3]})
            SESSIONS_UPSERTED.inc(success)
            SESSIONS_CREATED.inc(created)
            SESSIONS_UPDATED.inc(updated)
            try:
                self.client.indices.refresh(index=f"{self.settings.target_index_prefix}-*", ignore_unavailable=True)
                logger.info("session_indices_refreshed_after_bulk", extra={"target_index_prefix": self.settings.target_index_prefix})
            except Exception:
                logger.warning("session_refresh_after_bulk_failed", exc_info=True)
            return {"created_count": created, "updated_count": updated, "upserted": success}
        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("bulk_upsert_failed")
            raise
