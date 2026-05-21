from __future__ import annotations

import json
import sys
from typing import Any

from app.config import load_settings
from app.opensearch_client import create_client
from app.utils import get_field


def _count(client, index: str, query: dict[str, Any] | None = None) -> int:
    response = client.count(index=index, body={"query": query or {"match_all": {}}}, params={"ignore_unavailable": "true", "allow_no_indices": "true"})
    return int(response.get("count", 0) or 0)


def _terms(client, index: str, field: str, size: int = 10) -> list[dict[str, Any]]:
    response = client.search(
        index=index,
        body={"size": 0, "aggs": {"values": {"terms": {"field": field, "size": size, "missing": "__missing__"}}}},
        params={"ignore_unavailable": "true", "allow_no_indices": "true"},
    )
    return response.get("aggregations", {}).get("values", {}).get("buckets", [])


def main() -> int:
    settings = load_settings()
    client = create_client(settings)
    index = f"{settings.target_index_prefix}-*"
    metrics: dict[str, Any] = {}
    metrics["BEHAVIOR_COUNT"] = _count(client, index)
    metrics["MISSING_FEATURE_VECTOR"] = _count(client, index, {"bool": {"must_not": [{"exists": {"field": "ml.feature_vector"}}]}})
    metrics["MISSING_FEATURE_NAMES"] = _count(client, index, {"bool": {"must_not": [{"exists": {"field": "ml.feature_names"}}]}})
    metrics["MISSING_ENTITY"] = _count(client, index, {"bool": {"must_not": [{"exists": {"field": "behavior.entity"}}]}})
    metrics["MISSING_WINDOW"] = _count(client, index, {"bool": {"should": [{"bool": {"must_not": [{"exists": {"field": "behavior.window_start"}}]}}, {"bool": {"must_not": [{"exists": {"field": "behavior.window_end"}}]}}], "minimum_should_match": 1}})
    metrics["MISSING_QUALITY"] = _count(client, index, {"bool": {"must_not": [{"exists": {"field": "quality.data_quality_score"}}]}})
    # session_refs is mapped as nested. A plain top-level exists query on
    # evidence.session_refs.id does not reliably match parent documents in
    # OpenSearch, so validate rollback evidence with a nested query plus the
    # parent-level session_ref_count.
    metrics["MISSING_EVIDENCE_REFS"] = _count(
        client,
        index,
        {
            "bool": {
                "filter": [{"term": {"ml.ready": True}}],
                "should": [
                    {"bool": {"must_not": [{"exists": {"field": "evidence.session_ref_count"}}]}},
                    {"range": {"evidence.session_ref_count": {"lte": 0}}},
                    {
                        "bool": {
                            "must_not": [
                                {
                                    "nested": {
                                        "path": "evidence.session_refs",
                                        "query": {"exists": {"field": "evidence.session_refs.id"}},
                                        "ignore_unmapped": True,
                                    }
                                }
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
    )
    metrics["NOISY_ENTITY_ML_READY"] = _count(client, index, {"bool": {"filter": [{"term": {"ml.ready": True}}], "should": [{"term": {"behavior.entity": "0.0.0.0"}}, {"term": {"behavior.entity": "::"}}], "minimum_should_match": 1}})
    metrics["ML_READY_COUNT"] = _count(client, index, {"term": {"ml.ready": True}})
    metrics["FEATURE_COMPLETE_COUNT"] = _count(client, index, {"term": {"quality.feature_complete": True}})

    sample = client.search(index=index, body={"size": 100, "query": {"match_all": {}}, "_source": ["behavior.id", "ml.feature_vector", "ml.feature_names", "ml.vector_length", "quality.warnings", "evidence"]}, params={"ignore_unavailable": "true", "allow_no_indices": "true"})
    bad_vector = 0
    warning_counter: dict[str, int] = {}
    for hit in sample.get("hits", {}).get("hits", []):
        doc = hit.get("_source", {})
        names = get_field(doc, "ml.feature_names") or []
        vector = get_field(doc, "ml.feature_vector") or []
        expected = int(get_field(doc, "ml.vector_length", len(names)) or len(names))
        if len(names) != len(vector) or len(vector) != expected:
            bad_vector += 1
        for warning in get_field(doc, "quality.warnings", []) or []:
            warning_counter[str(warning)] = warning_counter.get(str(warning), 0) + 1
    metrics["BAD_VECTOR_LENGTH"] = bad_vector
    metrics["NOT_ENOUGH_DATA_WINDOWS"] = _count(client, index, {"term": {"ml.scoring_status": "not_enough_training_data"}})
    metrics["TOP_BEHAVIOR_TYPES"] = _terms(client, index, "behavior.type")
    metrics["TOP_FEATURE_SET"] = _terms(client, index, "behavior.feature_set")
    metrics["TOP_ENTITIES"] = _terms(client, index, "behavior.entity")
    metrics["TOP_WARNINGS"] = sorted(({"value": k, "count": v} for k, v in warning_counter.items()), key=lambda x: -x["count"])[:10]
    findings_index = f"{settings.findings_index_prefix}-*"
    metrics["FINDING_COUNT"] = _count(client, findings_index)
    metrics["FINDINGS_MISSING_DEDUP_ID"] = _count(client, findings_index, {"bool": {"must_not": [{"exists": {"field": "finding.dedup_id"}}]}})

    print(json.dumps(metrics, indent=2, sort_keys=True))
    critical = metrics["BEHAVIOR_COUNT"] > 0 and any(metrics[key] for key in ["MISSING_FEATURE_VECTOR", "MISSING_FEATURE_NAMES", "BAD_VECTOR_LENGTH", "MISSING_ENTITY", "MISSING_WINDOW", "MISSING_QUALITY", "NOISY_ENTITY_ML_READY"])
    return 2 if critical else 0


if __name__ == "__main__":
    sys.exit(main())
