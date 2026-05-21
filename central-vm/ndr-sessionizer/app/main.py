from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime
from typing import Any

import uvicorn
from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.checkpoint import Checkpoint, CheckpointStore
from app.config import Settings, load_settings
from app.metrics import OPENSEARCH_ERRORS, RAW_EVENTS_SKIPPED, READY
from app.opensearch_client import create_client, ping_or_raise
from app.reader import ZeekReader
from app.session_builder import SessionBuilder
from app.writer import SessionWriter
from app.utils import isoformat, parse_ts, utc_now

logger = logging.getLogger("ndr_sessionizer")
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
    app = FastAPI(title="ndr-sessionizer", version="0.1.0")

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


def process_once(settings: Settings, checkpoint_store: CheckpointStore, reader: ZeekReader, builder: SessionBuilder, writer: SessionWriter) -> dict[str, int]:
    checkpoint = checkpoint_store.load()
    start = checkpoint_store.compute_window_start(checkpoint)
    end = utc_now()
    logger.info("processing_window_started", extra={"start": isoformat(start), "end": isoformat(end)})

    hits = list(reader.read_window(start, end))
    if not hits:
        logger.info("processing_window_empty_waiting_for_source", extra={"start": isoformat(start), "end": isoformat(end)})
        return {"documents_read": 0, "sessions_upserted": 0, "failures": 0}
    groups = builder.group_hits(hits)
    sessions = []
    malformed = 0
    for group_key, group_hits in groups.items():
        try:
            session = builder.build_from_group(group_hits)
            if session:
                sessions.append(session)
        except Exception:
            malformed += len(group_hits)
            RAW_EVENTS_SKIPPED.inc(len(group_hits))
            logger.exception("session_build_failed", extra={"group_key": group_key})

    result = writer.bulk_upsert(sessions)
    checkpoint_store.save(
        Checkpoint(
            last_successful_timestamp=end,
            documents_read=len(hits),
            sessions_updated=result.get("upserted", 0),
            failures=malformed,
            service_version=settings.service_version,
        )
    )
    logger.info(
        "processing_window_completed",
        extra={
            "documents_read": len(hits),
            "groups": len(groups),
            "sessions_upserted": result.get("upserted", 0),
            "created_count": result.get("created", 0),
            "updated_count": result.get("updated", 0),
            "failures": malformed,
        },
    )
    return {"documents_read": len(hits), "sessions_upserted": result.get("upserted", 0), "failures": malformed}


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
    reader = ZeekReader(client, settings)
    builder = SessionBuilder(settings)
    writer = SessionWriter(client, settings, builder)
    _ready = True
    READY.set(1)
    logger.info(
        "ndr_sessionizer_started",
        extra={
            "source_index_pattern": settings.source_index_pattern,
            "target_index_prefix": settings.target_index_prefix,
            "state_index": settings.state_index,
            "dry_run": settings.dry_run,
            "run_once": settings.run_once,
        },
    )

    while not _stop.is_set():
        try:
            process_once(settings, checkpoint_store, reader, builder, writer)
        except Exception:
            OPENSEARCH_ERRORS.inc()
            logger.exception("processing_loop_failed")
        if settings.run_once:
            break
        _stop.wait(settings.poll_interval_seconds)

    READY.set(0)
    _ready = False
    logger.info("ndr_sessionizer_stopped")


if __name__ == "__main__":
    main()
