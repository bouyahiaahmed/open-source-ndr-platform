from __future__ import annotations

import json
import logging
import signal
import sys
import threading
from typing import Any

import uvicorn
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.config import Settings, load_settings
from app.metrics import PROCESSING_FAILURES, READY
from app.model import BehaviorModelService
from app.opensearch_client import create_client, ping_or_raise
from app.utils import isoformat, utc_now
from app.writer import BehaviorWriter

logger = logging.getLogger("ndr_behavior_ml")
_stop = threading.Event()
_ready = False


def configure_logging() -> None:
    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            payload: dict[str, Any] = {
                "timestamp": isoformat(utc_now()),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }

            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)

            for key, value in record.__dict__.items():
                if key.startswith("_") or key in {
                    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg",
                    "name", "pathname", "process", "processName", "relativeCreated",
                    "stack_info", "thread", "threadName",
                }:
                    continue

                try:
                    json.dumps(value, default=str)
                    payload[key] = value
                except TypeError:
                    payload[key] = str(value)

            return json.dumps(payload, default=str)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def create_app() -> FastAPI:
    app = FastAPI(title="ndr-behavior-ml", version="0.2.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(response: Response) -> dict[str, str]:
        if not _ready:
            response.status_code = 503
            return {"status": "not_ready"}
        return {"status": "ready"}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


def run_api(settings: Settings) -> None:
    uvicorn.run(create_app(), host=settings.http_host, port=settings.http_port, log_level="warning")


def install_signal_handlers() -> None:
    def handle_signal(signum: int, frame: Any) -> None:
        logger.info("shutdown_requested", extra={"signal": signum})
        _stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)


def load_unscored_behaviors(client: Any, settings: Settings) -> list[dict[str, Any]]:
    response = client.search(
        index=f"{settings.target_index_prefix}-*",
        body={
            "size": settings.read_page_size,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"ml.ready": True}},
                        {"range": {"quality.data_quality_score": {"gte": settings.ml_training_min_quality_score}}},
                    ],
                    "must_not": [
                        {"term": {"ml.scoring_status": "scored"}}
                    ],
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}
            ],
        },
        params={
            "ignore_unavailable": "true",
            "allow_no_indices": "true",
        },
    )

    return [hit.get("_source", {}) for hit in response.get("hits", {}).get("hits", [])]


def process_once(settings: Settings, client: Any, writer: BehaviorWriter, model_service: BehaviorModelService) -> dict[str, int | str]:
    docs = load_unscored_behaviors(client, settings)

    if not docs:
        logger.info("ml_no_unscored_behaviors_waiting")
        return {
            "behaviors_read": 0,
            "behaviors_scored": 0,
            "findings_written": 0,
            "model_status": "waiting_for_unscored_behaviors",
        }

    scored_docs, findings, model_bundle = model_service.score_current_docs(docs)
    behaviors_written = writer.bulk_upsert_behaviors(scored_docs)
    findings_written = writer.bulk_index_findings(findings)
    model_status = str(model_bundle.get("status", "unknown"))

    logger.info(
        "ml_processing_finished",
        extra={
            "behaviors_read": len(docs),
            "behaviors_scored": behaviors_written,
            "findings_written": findings_written,
            "model_status": model_status,
            "model_source": model_bundle.get("source", "unknown"),
        },
    )

    return {
        "behaviors_read": len(docs),
        "behaviors_scored": behaviors_written,
        "findings_written": findings_written,
        "model_status": model_status,
    }


def main() -> None:
    configure_logging()
    install_signal_handlers()

    settings = load_settings()

    api_thread = threading.Thread(target=run_api, args=(settings,), daemon=True)
    api_thread.start()

    global _ready

    client = create_client(settings)
    ping_or_raise(client)

    writer = BehaviorWriter(client, settings)
    model_service = BehaviorModelService(client, settings)

    _ready = True
    READY.set(1)

    logger.info(
        "ndr_behavior_ml_ready",
        extra={
            "target_index_prefix": settings.target_index_prefix,
            "model_path": settings.ml_model_artifact_path,
        },
    )

    while not _stop.is_set():
        try:
            process_once(settings, client, writer, model_service)
        except Exception:
            PROCESSING_FAILURES.inc()
            logger.exception("ml_processing_iteration_failed")

        if settings.run_once:
            break

        _stop.wait(settings.poll_interval_seconds)

    READY.set(0)
    _ready = False


if __name__ == "__main__":
    main()
