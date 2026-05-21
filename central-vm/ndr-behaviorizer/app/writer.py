from __future__ import annotations

import logging
from datetime import datetime
from itertools import islice
from typing import Any, Iterable

from opensearchpy import OpenSearch, helpers

from app.config import Settings
from app.metrics import BEHAVIORS_WRITTEN, FINDINGS_WRITTEN, OPENSEARCH_ERRORS
from app.utils import get_field, parse_ts

logger = logging.getLogger(__name__)


def chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            break
        yield chunk


def _as_float_list(value: Any) -> list[float]:
    if not isinstance(value, list):
        return []
    out: list[float] = []
    for item in value:
        try:
            out.append(float(item or 0))
        except Exception:
            out.append(0.0)
    return out


def _same_feature_vector(a: dict[str, Any], b: dict[str, Any]) -> bool:
    a_names = get_field(a, "ml.feature_names") or []
    b_names = get_field(b, "ml.feature_names") or []
    if a_names != b_names:
        return False

    a_vec = _as_float_list(get_field(a, "ml.feature_vector") or [])
    b_vec = _as_float_list(get_field(b, "ml.feature_vector") or [])

    if len(a_vec) != len(b_vec):
        return False

    return all(abs(x - y) < 1e-9 for x, y in zip(a_vec, b_vec))


class BehaviorWriter:
    def __init__(self, client: OpenSearch, settings: Settings):
        self.client = client
        self.settings = settings

    def behavior_index_for_doc(self, doc: dict[str, Any]) -> str:
        window_start = parse_ts(get_field(doc, "behavior.window_start")) or parse_ts(doc.get("@timestamp")) or datetime.utcnow()
        return f"{self.settings.target_index_prefix}-{window_start:%Y.%m.%d}"

    def finding_index_for_doc(self, doc: dict[str, Any]) -> str:
        ts = parse_ts(doc.get("@timestamp")) or datetime.utcnow()
        return f"{self.settings.findings_index_prefix}-{ts:%Y.%m.%d}"

    def _load_existing_behavior_docs(self, docs: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        requests = []

        for doc in docs:
            doc_id = str(get_field(doc, "behavior.id") or "")
            if not doc_id:
                continue
            requests.append({"_index": self.behavior_index_for_doc(doc), "_id": doc_id})

        if not requests:
            return {}

        existing: dict[tuple[str, str], dict[str, Any]] = {}

        try:
            for req_chunk in chunks(requests, 500):
                response = self.client.mget(
                    body={"docs": req_chunk}
                )

                for item in response.get("docs", []):
                    if not item.get("found"):
                        continue

                    idx = item.get("_index")
                    doc_id = item.get("_id")
                    src = item.get("_source") or {}

                    if idx and doc_id:
                        existing[(str(idx), str(doc_id))] = src

        except Exception:
            logger.warning("load_existing_behaviors_failed", exc_info=True)

        return existing

    def _preserve_ml_state_if_safe(self, incoming: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
        if not existing:
            return incoming

        incoming_status = str(get_field(incoming, "ml.scoring_status", "") or "")
        existing_status = str(get_field(existing, "ml.scoring_status", "") or "")

        # If the ML service is writing a scored document, always let it overwrite.
        if incoming_status == "scored":
            return incoming

        # If behaviorizer is rewriting a behavior that was already scored, do not downgrade it
        # back to not_scored if the feature vector did not change.
        if existing_status == "scored" and _same_feature_vector(incoming, existing):
            incoming["ml"] = existing.get("ml", incoming.get("ml", {}))
            incoming["score"] = existing.get("score", incoming.get("score", {}))
            incoming.setdefault("behaviorizer", {})["ml_state_preserved"] = True
            logger.info(
                "preserved_existing_ml_state",
                extra={
                    "behavior_id": get_field(incoming, "behavior.id"),
                    "scoring_status": existing_status,
                },
            )
            return incoming

        # If the feature vector changed, keep the incoming not_scored state.
        # That allows ndr-behavior-ml to score the updated behavior again.
        if existing_status == "scored" and not _same_feature_vector(incoming, existing):
            logger.info(
                "behavior_features_changed_resetting_ml_state",
                extra={
                    "behavior_id": get_field(incoming, "behavior.id"),
                    "previous_status": existing_status,
                    "new_status": incoming_status,
                },
            )

        return incoming

    def bulk_upsert_behaviors(self, docs: list[dict[str, Any]]) -> int:
        if not docs:
            return 0

        existing_docs = self._load_existing_behavior_docs(docs)

        actions = []
        for doc in docs:
            doc_id = str(get_field(doc, "behavior.id") or "")
            if not doc_id:
                continue

            index = self.behavior_index_for_doc(doc)
            existing = existing_docs.get((index, doc_id))
            doc = self._preserve_ml_state_if_safe(doc, existing)

            actions.append({
                "_op_type": "index",
                "_index": index,
                "_id": doc_id,
                "_source": doc,
            })

        if self.settings.dry_run:
            logger.info("dry_run_behavior_bulk", extra={"behaviors": len(actions)})
            return len(actions)

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
                logger.error("behavior_bulk_errors", extra={"error_count": len(errors), "sample": errors[:3]})

            BEHAVIORS_WRITTEN.inc(success)

            try:
                self.client.indices.refresh(index=f"{self.settings.target_index_prefix}-*", ignore_unavailable=True)
                logger.info("behavior_indices_refreshed_after_bulk", extra={"target_index_prefix": self.settings.target_index_prefix})
            except Exception:
                logger.warning("behavior_refresh_after_bulk_failed", exc_info=True)

            return int(success)

        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("behavior_bulk_failed")
            raise

    def bulk_index_findings(self, docs: list[dict[str, Any]]) -> int:
        if not docs:
            return 0

        actions = []
        for doc in docs:
            behavior_id = get_field(doc, "behavior.id", "unknown")
            doc_id = str(get_field(doc, "finding.dedup_id") or f"{behavior_id}|{get_field(doc, 'finding.type', 'finding')}")
            actions.append({
                "_op_type": "index",
                "_index": self.finding_index_for_doc(doc),
                "_id": doc_id,
                "_source": doc,
            })

        if self.settings.dry_run:
            logger.info("dry_run_finding_bulk", extra={"findings": len(actions)})
            return len(actions)

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
                logger.error("finding_bulk_errors", extra={"error_count": len(errors), "sample": errors[:3]})

            FINDINGS_WRITTEN.inc(success)
            return int(success)

        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("finding_bulk_failed")
            raise
