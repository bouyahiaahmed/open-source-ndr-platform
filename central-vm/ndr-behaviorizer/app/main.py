from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from datetime import timedelta
from typing import Any

import uvicorn
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.aggregator import BehaviorAggregator, entity_for_doc, get_event_time
from app.checkpoint import Checkpoint, CheckpointStore
from app.config import Settings, load_settings
from app.feature_registry import load_feature_spec
from app.metrics import PROCESSING_FAILURES, READY
from app.model import BehaviorModelService
from app.opensearch_client import create_client, ping_or_raise
from app.reader import SessionReader
from app.utils import floor_time, isoformat, parse_ts, utc_now
from app.writer import BehaviorWriter

logger = logging.getLogger("ndr_behaviorizer")
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
                    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName", "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name", "pathname", "process", "processName", "relativeCreated", "stack_info", "thread", "threadName",
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
    app = FastAPI(title="ndr-behaviorizer", version="0.1.0")

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



def affected_behavior_windows(settings: Settings, hits: list[dict[str, Any]]) -> list[dict[str, str | None]]:
    """Return affected entity/sensor/15m windows from incremental session hits."""
    windows: dict[tuple[str, str | None, str], dict[str, str | None]] = {}

    for hit in hits:
        doc = hit.get("_source", hit)
        entity, sensor, _entity_type = entity_for_doc(doc, settings)

        if not entity:
            continue

        event_time = parse_ts(get_event_time(doc, settings))

        if not event_time:
            continue

        window_start_dt = floor_time(event_time, settings.behavior_window_seconds)
        window_end_dt = window_start_dt + timedelta(seconds=settings.behavior_window_seconds)

        window_start_iso = isoformat(window_start_dt)
        window_end_iso = isoformat(window_end_dt)

        if not window_start_iso or not window_end_iso:
            continue

        key = (str(entity), sensor, window_start_iso)
        windows[key] = {
            "entity": str(entity),
            "sensor": sensor,
            "window_start": window_start_iso,
            "window_end": window_end_iso,
        }

    return sorted(
        windows.values(),
        key=lambda x: (str(x.get("window_start") or ""), str(x.get("sensor") or ""), str(x.get("entity") or "")),
    )

def process_once(
    settings: Settings,
    checkpoint_store: CheckpointStore,
    reader: SessionReader,
    aggregator: BehaviorAggregator,
    writer: BehaviorWriter,
    model_service: BehaviorModelService,
) -> dict[str, int | str]:
    checkpoint = checkpoint_store.load()
    start = checkpoint_store.compute_window_start(checkpoint)
    end = utc_now()
    logger.info("behavior_processing_window_started", extra={"start": isoformat(start), "end": isoformat(end)})

    hits = list(reader.read_window(start, end))
    if not hits:
        logger.info("behavior_processing_window_empty_waiting_for_source", extra={"start": isoformat(start), "end": isoformat(end)})
        return {"documents_read": 0, "behaviors_written": 0, "findings_written": 0, "model_status": "waiting_for_source"}
    affected_windows = affected_behavior_windows(settings, hits)
    full_hits: list[dict[str, Any]] = []

    for window in affected_windows:
        full_hits.extend(
            list(
                reader.read_entity_event_window(
                    entity=str(window["entity"]),
                    sensor=window.get("sensor"),
                    window_start_iso=str(window["window_start"]),
                    window_end_iso=str(window["window_end"]),
                )
            )
        )

    logger.info(
        "behavior_full_window_rehydration_finished",
        extra={
            "incremental_documents_read": len(hits),
            "affected_windows": len(affected_windows),
            "full_documents_read": len(full_hits),
        },
    )

    if not full_hits:
        logger.warning(
            "behavior_full_window_rehydration_empty_falling_back_to_incremental_hits",
            extra={"incremental_documents_read": len(hits), "affected_windows": len(affected_windows)},
        )
        full_hits = hits

    behaviors = aggregator.aggregate_hits(full_hits)
    findings: list[dict[str, Any]] = []
    model_status = "disabled"
    if settings.ml_enabled and behaviors:
        behaviors, findings, model_bundle = model_service.score_current_docs(behaviors)
        model_status = str(model_bundle.get("status", "unknown"))

    behaviors_written = writer.bulk_upsert_behaviors(behaviors)
    findings_written = writer.bulk_index_findings(findings)
    checkpoint_store.save(
        Checkpoint(
            last_successful_timestamp=end,
            documents_read=len(hits),
            behaviors_written=behaviors_written,
            findings_written=findings_written,
            failures=0,
            service_version=settings.service_version,
        )
    )
    logger.info(
        "behavior_processing_window_finished",
        extra={"documents_read": len(hits), "behaviors_written": behaviors_written, "findings_written": findings_written, "model_status": model_status},
    )
    return {
        "documents_read": len(hits),
        "behaviors_written": behaviors_written,
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
    checkpoint_store = CheckpointStore(client, settings)
    checkpoint_store.ensure_state_index()
    spec = load_feature_spec(settings.feature_config_path)
    reader = SessionReader(client, settings)
    aggregator = BehaviorAggregator(settings, spec)
    writer = BehaviorWriter(client, settings)
    model_service = BehaviorModelService(client, settings)
    _ready = True
    READY.set(1)
    logger.info("ndr_behaviorizer_ready", extra={"feature_set": spec.feature_set, "source_index_pattern": settings.source_index_pattern})

    while not _stop.is_set():
        try:
            process_once(settings, checkpoint_store, reader, aggregator, writer, model_service)
        except Exception:
            PROCESSING_FAILURES.inc()
            logger.exception("behavior_processing_iteration_failed")
        if settings.run_once:
            break
        _stop.wait(settings.poll_interval_seconds)
    READY.set(0)
    _ready = False


if __name__ == "__main__":
    main()
