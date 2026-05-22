from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

from app import __version__
from app.config import settings
from app.models import Status
from app.validator import Validator
from app import storage

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ndr_validator")

_latest: dict[str, Any] | None = None
_scan_lock = asyncio.Lock()
_scheduler_task: asyncio.Task | None = None
_stop_event = asyncio.Event()

scan_counter = Counter("ndr_validator_scans_total", "Total validator scans", ["status"])
validator_score = Gauge("ndr_validator_score", "Latest validator score")
check_status = Gauge("ndr_validator_check_status", "Latest check status: ok=0 unknown=1 warn=2 crit=3", ["component", "check_id"])
_STATUS_NUM = {"ok": 0, "unknown": 1, "warn": 2, "crit": 3}


def _record_metrics(payload: dict[str, Any]) -> None:
    status = str(payload.get("status", "unknown"))
    scan_counter.labels(status=status).inc()
    validator_score.set(float(payload.get("score", 0)))
    for check in payload.get("checks", []):
        check_status.labels(component=check.get("component", "unknown"), check_id=check.get("id", "unknown")).set(_STATUS_NUM.get(check.get("status"), 1))


async def run_scan() -> dict[str, Any]:
    global _latest
    async with _scan_lock:
        logger.info("validator_scan_started")
        summary = await Validator().run()
        payload = summary.to_dict()
        _latest = payload
        _record_metrics(payload)
        logger.info("validator_scan_finished", extra={"status": payload["status"], "score": payload["score"], "duration_ms": payload["duration_ms"]})
        return payload


async def scheduler() -> None:
    # First scan immediately after startup.
    while not _stop_event.is_set():
        try:
            await run_scan()
        except Exception:
            logger.exception("scheduled_scan_failed")
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=settings.scrape_interval_seconds)
        except asyncio.TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _latest, _scheduler_task
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    storage.init_db()
    _latest = storage.latest_scan()
    _scheduler_task = asyncio.create_task(scheduler())
    yield
    _stop_event.set()
    if _scheduler_task:
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
    storage.close_db()


app = FastAPI(
    title="NDR Validator",
    description="Standalone validator and UI for Zeek → Vector → Data Prepper → OpenSearch → sessions → behaviors → ML → ElastAlert.",
    version=__version__,
    lifespan=lifespan,
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index() -> HTMLResponse:
    with open(os.path.join(static_dir, "index.html"), "r", encoding="utf-8") as handle:
        return HTMLResponse(handle.read())


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/readyz")
async def readyz(response: Response) -> dict[str, Any]:
    ready = _latest is not None
    if not ready:
        response.status_code = 503
    return {"ready": ready, "version": __version__}


@app.get("/api/summary")
async def api_summary() -> JSONResponse:
    global _latest
    if _latest is None:
        _latest = await run_scan()
    return JSONResponse(_latest)


@app.post("/api/run")
async def api_run() -> JSONResponse:
    payload = await run_scan()
    return JSONResponse(payload)


@app.get("/api/checks")
async def api_checks() -> JSONResponse:
    payload = _latest or storage.latest_scan()
    return JSONResponse({"checks": [] if not payload else payload.get("checks", [])})


@app.get("/api/history")
async def api_history(limit: int = 100) -> JSONResponse:
    return JSONResponse({"history": storage.history(limit=max(1, min(limit, 500)))})


@app.get("/api/config")
async def api_config() -> JSONResponse:
    return JSONResponse(settings.safe_dict())


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest().decode("utf-8"), media_type=CONTENT_TYPE_LATEST)
