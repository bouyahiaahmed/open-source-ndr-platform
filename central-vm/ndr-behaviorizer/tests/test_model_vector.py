from __future__ import annotations

from app.model import build_feature_matrix, train_isolation_forest


def test_build_feature_matrix_uses_ready_vectors_only():
    docs = [
        {"ml": {"ready": True, "feature_names": ["a", "b"], "feature_vector": [1, 2]}},
        {"ml": {"ready": False, "feature_names": ["a", "b"], "feature_vector": [3, 4]}},
    ]
    matrix, names = build_feature_matrix(docs)
    assert names == ["a", "b"]
    assert matrix == [[1.0, 2.0]]


def test_ml_not_crashing_with_too_few_samples():
    docs = [{"ml": {"ready": True, "feature_names": ["a"], "feature_vector": [1]}}]
    result = train_isolation_forest(docs, min_rows=20)
    assert result["status"] == "not_enough_training_data"
    assert result["row_count"] == 1
