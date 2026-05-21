from __future__ import annotations

import logging
import pickle
from datetime import timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from opensearchpy import OpenSearch

from app.config import Settings
from app.utils import get_field, isoformat, parse_ts, utc_now

logger = logging.getLogger(__name__)


def _csv_set(value: str | None) -> set[str]:
    return {x.strip().lower() for x in (value or "").split(",") if x.strip()}


def build_feature_matrix(behavior_docs: list[dict[str, Any]]) -> tuple[list[list[float]], list[str]]:
    rows: list[list[float]] = []
    feature_names: list[str] = []
    for doc in behavior_docs:
        if get_field(doc, "ml.ready") is not True:
            continue
        names = [str(x) for x in (get_field(doc, "ml.feature_names") or [])]
        vector = get_field(doc, "ml.feature_vector") or []
        if not names or len(names) != len(vector):
            continue
        if not feature_names:
            feature_names = names
        if names != feature_names:
            continue
        try:
            rows.append([float(x or 0) for x in vector])
        except (TypeError, ValueError):
            continue
    return rows, feature_names


def _lazy_sklearn():
    from sklearn.ensemble import IsolationForest  # type: ignore
    from sklearn.pipeline import Pipeline  # type: ignore
    from sklearn.preprocessing import RobustScaler  # type: ignore
    import numpy as np  # type: ignore

    return IsolationForest, Pipeline, RobustScaler, np


def train_isolation_forest(behavior_docs: list[dict[str, Any]], contamination: float = 0.05, min_rows: int = 20) -> dict[str, Any]:
    rows, feature_names = build_feature_matrix(behavior_docs)
    if len(rows) < min_rows:
        return {"status": "not_enough_training_data", "row_count": len(rows), "feature_names": feature_names, "model": None}
    try:
        IsolationForest, Pipeline, RobustScaler, np = _lazy_sklearn()
    except Exception as exc:
        logger.warning("sklearn_unavailable", exc_info=True)
        return {"status": "model_dependency_unavailable", "row_count": len(rows), "feature_names": feature_names, "model": None, "error": str(exc)}

    model = Pipeline([
        ("scale", RobustScaler(with_centering=True, with_scaling=True, quantile_range=(10.0, 90.0))),
        ("iforest", IsolationForest(n_estimators=300, contamination=contamination, random_state=42)),
    ])

    matrix = np.asarray(rows, dtype=float)
    model.fit(matrix)
    baseline = np.median(matrix, axis=0).tolist() if len(rows) else []

    return {
        "status": "trained",
        "row_count": len(rows),
        "feature_names": feature_names,
        "model": model,
        "matrix": matrix,
        "baseline": baseline,
    }


def score_behaviors(behavior_docs: list[dict[str, Any]], model_bundle: dict[str, Any]) -> list[dict[str, Any]]:
    if model_bundle.get("status") != "trained" or model_bundle.get("model") is None:
        return behavior_docs

    IsolationForest, Pipeline, RobustScaler, np = _lazy_sklearn()
    model = model_bundle["model"]
    feature_names = list(model_bundle.get("feature_names") or [])

    if model_bundle.get("baseline") is not None:
        baseline = np.asarray(model_bundle.get("baseline"), dtype=float)
    else:
        baseline = np.median(model_bundle.get("matrix"), axis=0) if model_bundle.get("matrix") is not None else None

    scored: list[dict[str, Any]] = []

    for doc in behavior_docs:
        names = [str(x) for x in (get_field(doc, "ml.feature_names") or [])]
        vector = get_field(doc, "ml.feature_vector") or []

        if get_field(doc, "ml.ready") is not True or names != feature_names or len(vector) != len(feature_names):
            scored.append(doc)
            continue

        row = np.asarray([[float(x or 0) for x in vector]], dtype=float)
        prediction = int(model.predict(row)[0])
        raw_score = float(-model.score_samples(row)[0])
        anomaly_score = round(max(0.0, min(1.0, 1.0 / (1.0 + pow(2.718281828, -raw_score)))), 6)
        is_anomaly = prediction == -1

        top_features = []
        if baseline is not None:
            deviations = []
            for idx, name in enumerate(feature_names):
                base = float(baseline[idx])
                value = float(row[0][idx])
                deviations.append((abs(value - base), name, value, base))

            for _, name, value, base in sorted(deviations, reverse=True)[:5]:
                if value != base:
                    top_features.append({
                        "name": name,
                        "value": value,
                        "baseline": round(base, 6),
                        "deviation": round(value - base, 6),
                    })

        doc.setdefault("ml", {})
        doc["ml"].update({
            "model_name": "robust_scaled_isolation_forest",
            "model_version": f"{get_field(doc, 'behavior.feature_set')}_iforest_v1",
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "scored_at": isoformat(utc_now()),
            "scoring_status": "scored",
            "top_features": top_features,
        })

        doc.setdefault("score", {})
        doc["score"]["ml"] = anomaly_score
        doc["score"]["final"] = round(anomaly_score * 100, 2)

        if is_anomaly:
            doc["score"]["severity"] = "high" if anomaly_score >= 0.9 else "medium"
            doc["score"]["reasons"] = [f"high_{f['name']}" for f in top_features[:3]] or ["ml_behavior_anomaly"]
        else:
            doc["score"]["severity"] = "none"
            doc["score"]["reasons"] = []

        scored.append(doc)

    return scored


class BehaviorModelService:
    def __init__(self, client: "OpenSearch", settings: Settings):
        self.client = client
        self.settings = settings

    def _artifact_path(self) -> Path:
        return Path(self.settings.ml_model_artifact_path)

    def _artifact_is_stale(self, trained_at: str | None) -> bool:
        if self.settings.ml_force_retrain:
            return True

        if not trained_at:
            return True

        trained_dt = parse_ts(trained_at)
        if trained_dt is None:
            return True

        if trained_dt.tzinfo is None:
            trained_dt = trained_dt.replace(tzinfo=timezone.utc)

        age = (utc_now() - trained_dt).total_seconds()
        return age >= int(self.settings.ml_retrain_interval_seconds)

    def _load_model_artifact(self) -> dict[str, Any] | None:
        path = self._artifact_path()

        if not path.exists():
            logger.info("ml_model_artifact_missing", extra={"path": str(path)})
            return None

        try:
            with path.open("rb") as f:
                data = pickle.load(f)

            trained_at = data.get("trained_at")

            if self._artifact_is_stale(trained_at):
                logger.info(
                    "ml_model_artifact_stale",
                    extra={
                        "path": str(path),
                        "trained_at": trained_at,
                        "retrain_interval_seconds": self.settings.ml_retrain_interval_seconds,
                    },
                )
                return None

            model = data.get("model")
            feature_names = data.get("feature_names") or []

            if model is None or not feature_names:
                logger.warning("ml_model_artifact_invalid", extra={"path": str(path)})
                return None

            logger.info(
                "ml_model_artifact_loaded",
                extra={"path": str(path), "trained_at": trained_at, "feature_count": len(feature_names)},
            )

            return {
                "status": "trained",
                "model": model,
                "feature_names": feature_names,
                "baseline": data.get("baseline"),
                "row_count": int(data.get("training_rows", 0) or 0),
                "trained_at": trained_at,
                "source": "artifact",
            }

        except Exception:
            logger.warning("load_model_artifact_failed", exc_info=True)
            return None

    def _feedback_statuses_for_behaviors(self, behavior_ids: list[str]) -> dict[str, str]:
        ids = [x for x in dict.fromkeys(behavior_ids) if x]

        if not ids:
            return {}

        try:
            response = self.client.search(
                index=f"{self.settings.findings_index_prefix}-*",
                body={
                    "size": min(len(ids), 10000),
                    "query": {"terms": {"behavior.id": ids}},
                    "sort": [{"finding.created_at": {"order": "desc", "unmapped_type": "date"}}],
                    "_source": ["behavior.id", "finding.status"],
                },
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )

            statuses: dict[str, str] = {}

            for hit in response.get("hits", {}).get("hits", []):
                src = hit.get("_source", {})
                bid = str(get_field(src, "behavior.id", "") or "")
                status = str(get_field(src, "finding.status", "") or "").lower()

                if bid and status and bid not in statuses:
                    statuses[bid] = status

            return statuses

        except Exception:
            logger.warning("load_feedback_statuses_failed", exc_info=True)
            return {}

    def load_training_docs(self, exclude_behavior_ids: set[str] | None = None) -> list[dict[str, Any]]:
        exclude_behavior_ids = exclude_behavior_ids or set()

        try:
            response = self.client.search(
                index=f"{self.settings.target_index_prefix}-*",
                body={
                    "size": self.settings.ml_training_max_docs,
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"ml.ready": True}},
                                {"range": {"quality.data_quality_score": {"gte": self.settings.ml_training_min_quality_score}}},
                                {"term": {"ml.scoring_status": "scored"}},
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": [
                        "@timestamp",
                        "behavior.*",
                        "quality.data_quality_score",
                        "ml.feature_names",
                        "ml.feature_vector",
                        "ml.ready",
                        "ml.scoring_status",
                    ],
                },
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )

            docs = [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]
            docs = [
                d for d in docs
                if str(get_field(d, "behavior.id", "") or "") not in exclude_behavior_ids
            ]

            excluded_statuses = _csv_set(self.settings.training_excluded_feedback_statuses)

            if excluded_statuses and docs:
                ids = [str(get_field(d, "behavior.id", "") or "") for d in docs]
                feedback = self._feedback_statuses_for_behaviors(ids)
                docs = [
                    d for d in docs
                    if feedback.get(str(get_field(d, "behavior.id", "") or ""), "").lower() not in excluded_statuses
                ]

            return docs

        except Exception:
            logger.warning("load_training_docs_failed", exc_info=True)
            return []

    def score_current_docs(self, current_docs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        if not self.settings.ml_enabled:
            return current_docs, [], {"status": "disabled"}

        current_ids = {
            str(get_field(doc, "behavior.id", "") or "")
            for doc in current_docs
            if get_field(doc, "behavior.id")
        }

        model_bundle = self._load_model_artifact()

        if model_bundle is None:
            training_docs = self.load_training_docs(exclude_behavior_ids=current_ids)
            model_bundle = train_isolation_forest(
                training_docs,
                self.settings.ml_contamination,
                self.settings.ml_min_training_rows,
            )

            if model_bundle.get("status") == "trained":
                model_bundle["source"] = "new_training"
                self._save_model_artifact(model_bundle)
                self._write_model_metadata(model_bundle, current_docs)

        if model_bundle.get("status") != "trained":
            for doc in current_docs:
                doc.setdefault("ml", {})["scoring_status"] = str(model_bundle.get("status"))
                doc.setdefault("score", {})["reasons"] = [str(model_bundle.get("status"))]

            return current_docs, [], model_bundle

        scored_docs = score_behaviors(current_docs, model_bundle)
        findings = self._build_findings(scored_docs) if self.settings.findings_enabled else []

        return scored_docs, findings, model_bundle

    def _save_model_artifact(self, model_bundle: dict[str, Any]) -> None:
        model = model_bundle.get("model")

        if model is None:
            return

        try:
            path = self._artifact_path()
            path.parent.mkdir(parents=True, exist_ok=True)

            with path.open("wb") as f:
                pickle.dump(
                    {
                        "model": model,
                        "feature_names": model_bundle.get("feature_names"),
                        "baseline": model_bundle.get("baseline"),
                        "trained_at": isoformat(utc_now()),
                        "training_rows": int(model_bundle.get("row_count", 0) or 0),
                        "model_type": "robust_scaled_isolation_forest",
                    },
                    f,
                )

            logger.info(
                "ml_model_artifact_saved",
                extra={"path": str(path), "training_rows": int(model_bundle.get("row_count", 0) or 0)},
            )

        except Exception:
            logger.warning("save_model_artifact_failed", exc_info=True)

    def _write_model_metadata(self, model_bundle: dict[str, Any], scored_docs: list[dict[str, Any]]) -> None:
        try:
            feature_set = str(get_field(scored_docs[0], "behavior.feature_set", self.settings.feature_set)) if scored_docs else self.settings.feature_set

            doc = {
                "@timestamp": isoformat(utc_now()),
                "model": {
                    "name": "robust_scaled_isolation_forest",
                    "version": f"{feature_set}_iforest_v1",
                    "feature_set": feature_set,
                    "model_type": "IsolationForest",
                    "training_rows": int(model_bundle.get("row_count", 0) or 0),
                    "contamination": self.settings.ml_contamination,
                    "training_min_quality_score": self.settings.ml_training_min_quality_score,
                    "artifact_path": self.settings.ml_model_artifact_path,
                    "source": model_bundle.get("source", "unknown"),
                },
            }

            self.client.index(index="ndr-ml-models", id=f"{feature_set}_isolation_forest_latest", body=doc, refresh=False)

        except Exception:
            logger.warning("write_model_metadata_failed", exc_info=True)

    def _existing_finding_status(self, dedup_id: str) -> str | None:
        try:
            response = self.client.search(
                index=f"{self.settings.findings_index_prefix}-*",
                body={
                    "size": 1,
                    "query": {"term": {"finding.dedup_id": dedup_id}},
                    "sort": [{"finding.created_at": {"order": "desc", "unmapped_type": "date"}}],
                    "_source": ["finding.status"],
                },
                params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            )

            hits = response.get("hits", {}).get("hits", [])

            if not hits:
                return None

            status = get_field(hits[0].get("_source", {}), "finding.status")
            return str(status).lower() if status else None

        except Exception:
            logger.warning("existing_finding_status_lookup_failed", exc_info=True)
            return None

    def _build_findings(self, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        suppressed_statuses = _csv_set(self.settings.finding_suppressed_statuses)

        for doc in docs:
            if get_field(doc, "ml.is_anomaly") is not True:
                continue

            anomaly_score = float(get_field(doc, "ml.anomaly_score", 0.0) or 0.0)

            # Security-driven finding gate:
            # Keep ML scores on behaviors, but only create SOC findings when
            # the anomaly is strong OR has security-relevant indicators.
            security_indicators = []

            def _num(path: str) -> float:
                try:
                    return float(get_field(doc, path, 0) or 0)
                except Exception:
                    return 0.0

            if _num("features.dns_txt_count") > 0:
                security_indicators.append("dns_txt_queries")
            if _num("features.dns_long_query_count") > 0:
                security_indicators.append("long_dns_queries")
            if _num("features.dns_nxdomain_ratio") >= 0.5 and _num("features.dns_session_count") >= 20:
                security_indicators.append("high_dns_nxdomain_ratio")
            if _num("features.ssh_session_count") >= 10:
                security_indicators.append("ssh_activity_burst")
            if _num("features.ssh_auth_attempt_sum") >= 10:
                security_indicators.append("ssh_auth_attempt_burst")
            if _num("features.unique_destination_port_count") >= 100:
                security_indicators.append("many_destination_ports")
            if _num("features.notice_count") > 0:
                security_indicators.append("zeek_notice_present")
            if _num("features.weird_count") > 0:
                security_indicators.append("zeek_weird_present")
            if _num("features.tls_invalid_cert_count") > 0:
                security_indicators.append("tls_invalid_cert")
            if _num("features.tls_self_signed_count") > 0:
                security_indicators.append("tls_self_signed_cert")
            if _num("features.tls_expired_cert_count") > 0:
                security_indicators.append("tls_expired_cert")
            if _num("features.files_total_bytes_sum") >= 10000000:
                security_indicators.append("large_file_transfer")

            strong_ml = anomaly_score >= 0.70
            security_relevant_ml = anomaly_score >= 0.62 and len(security_indicators) > 0

            if not (strong_ml or security_relevant_ml):
                logger.info(
                    "finding_suppressed_low_security_relevance",
                    extra={
                        "behavior_id": get_field(doc, "behavior.id"),
                        "anomaly_score": anomaly_score,
                        "top_features": get_field(doc, "ml.top_features", []),
                    },
                )
                continue

            doc.setdefault("score", {})
            existing_reasons = get_field(doc, "score.reasons", []) or []
            doc["score"]["security_indicators"] = security_indicators
            doc["score"]["security_relevant"] = bool(security_indicators)
            doc["score"]["reasons"] = list(dict.fromkeys(existing_reasons + security_indicators))

            behavior_id = str(get_field(doc, "behavior.id", "unknown"))
            dedup_id = f"{behavior_id}|ml_behavior_anomaly"
            existing_status = self._existing_finding_status(dedup_id)

            if existing_status in suppressed_statuses:
                logger.info(
                    "finding_suppressed_by_analyst_feedback",
                    extra={"dedup_id": dedup_id, "status": existing_status},
                )
                continue

            anomaly_score = float(get_field(doc, "ml.anomaly_score", 0.0) or 0.0)
            severity = str(get_field(doc, "score.severity", "medium") or "medium")
            finding_status = existing_status or "new"

            finding = {
                "@timestamp": get_field(doc, "@timestamp") or isoformat(utc_now()),
                "finding": {
                    "type": "ml_behavior_anomaly",
                    "severity": severity,
                    "confidence": anomaly_score,
                    "status": finding_status,
                    "dedup_id": dedup_id,
                    "created_at": isoformat(utc_now()),
                },
                "behavior": {
                    "id": behavior_id,
                    "entity": get_field(doc, "behavior.entity"),
                    "sensor": get_field(doc, "behavior.sensor"),
                    "window_start": get_field(doc, "behavior.window_start"),
                    "window_end": get_field(doc, "behavior.window_end"),
                    "feature_set": get_field(doc, "behavior.feature_set"),
                },
                "score": {
                    "ml": anomaly_score,
                    "statistical": get_field(doc, "score.statistical"),
                    "final": get_field(doc, "score.final"),
                },
                "reasons": get_field(doc, "score.reasons", []) or ["ml_behavior_anomaly"],
                "evidence": {
                    "behavior_index": f"{self.settings.target_index_prefix}-*",
                    "behavior_id": behavior_id,
                    "session_ref_count": get_field(doc, "evidence.session_ref_count", 0),
                    "session_refs_truncated": get_field(doc, "evidence.session_refs_truncated", False),
                    "session_refs": get_field(doc, "evidence.session_refs", []) or [],
                },
                "ml": {
                    "anomaly_score": get_field(doc, "ml.anomaly_score"),
                    "is_anomaly": get_field(doc, "ml.is_anomaly"),
                    "model_name": get_field(doc, "ml.model_name"),
                    "model_version": get_field(doc, "ml.model_version"),
                    "top_features": get_field(doc, "ml.top_features", []) or [],
                },
                "human": {
                    "summary": (
                        f"ML behavior anomaly detected for host {get_field(doc, 'behavior.entity', 'unknown')} "
                        f"during {get_field(doc, 'behavior.window_start', 'unknown_start')} to {get_field(doc, 'behavior.window_end', 'unknown_end')} "
                        f"with severity {get_field(doc, 'score.severity', 'unknown')} "
                        f"and anomaly score {get_field(doc, 'ml.anomaly_score', 'unknown')}. "
                        + (
                            "Main drivers: "
                            + ", ".join([
                                str(f.get("name"))
                                for f in (get_field(doc, "ml.top_features", []) or [])[:5]
                                if isinstance(f, dict) and f.get("name") is not None
                            ])
                            + "."
                            if get_field(doc, "ml.top_features", []) else
                            "Review ml.top_features for the main drivers."
                        )
                    )
                },
            }

            findings.append(finding)

        return findings
