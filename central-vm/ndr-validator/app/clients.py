from __future__ import annotations

import json
import os
import socket
import time
from typing import Any

import httpx

from app.config import settings


class HTTPProbeError(RuntimeError):
    pass


def _auth(user: str = "", password: str = "") -> httpx.BasicAuth | None:
    if user and password:
        return httpx.BasicAuth(user, password)
    return None


async def fetch(
    url: str,
    *,
    method: str = "GET",
    auth: httpx.BasicAuth | None = None,
    verify: bool | str = False,
    headers: dict[str, str] | None = None,
    json_body: Any | None = None,
    timeout: float | None = None,
) -> tuple[int, str, float, dict[str, str]]:
    start = time.perf_counter()
    async with httpx.AsyncClient(verify=verify, timeout=timeout or settings.request_timeout_seconds, follow_redirects=False) as client:
        response = await client.request(method, url, auth=auth, headers=headers, json=json_body)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return response.status_code, response.text, elapsed_ms, dict(response.headers)


async def tcp_connect(host: str, port: int, timeout: float | None = None) -> float:
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout or settings.request_timeout_seconds):
        pass
    return (time.perf_counter() - start) * 1000


class OpenSearchClient:
    def __init__(self) -> None:
        self.base_url = settings.opensearch_url.rstrip("/")
        self.auth = _auth(settings.opensearch_user, settings.opensearch_password)
        self.verify = settings.verify_for("opensearch")
        self.timeout = settings.request_timeout_seconds

    async def request(self, method: str, path: str, *, body: Any | None = None, params: dict[str, Any] | None = None) -> tuple[int, Any, float]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        start = time.perf_counter()
        async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout, follow_redirects=False) as client:
            response = await client.request(method, url, auth=self.auth, json=body, params=params)
        elapsed_ms = (time.perf_counter() - start) * 1000
        try:
            payload = response.json()
        except Exception:
            payload = response.text
        return response.status_code, payload, elapsed_ms

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> tuple[int, Any, float]:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, *, body: Any | None = None, params: dict[str, Any] | None = None) -> tuple[int, Any, float]:
        return await self.request("POST", path, body=body, params=params)

    async def count(self, index: str, query: dict[str, Any] | None = None) -> tuple[int | None, float, dict[str, Any]]:
        body = {"query": query or {"match_all": {}}}
        code, payload, elapsed = await self.post(
            f"/{index}/_count",
            body=body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        if code >= 400:
            return None, elapsed, {"http_status": code, "payload": payload}
        return int(payload.get("count", 0)), elapsed, payload

    async def search(self, index: str, body: dict[str, Any], *, size: int | None = None) -> tuple[int, dict[str, Any] | str, float]:
        if size is not None:
            body = dict(body)
            body["size"] = size
        return await self.post(
            f"/{index}/_search",
            body=body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )

    async def latest_timestamp(self, index: str, field: str = "@timestamp") -> tuple[str | None, float, dict[str, Any]]:
        body = {
            "size": 1,
            "query": {"exists": {"field": field}},
            "sort": [{field: {"order": "desc", "unmapped_type": "date"}}],
            "_source": [field, "sensor", "sensor.name", "log_type", "network.protocol", "source.ip", "destination.ip"],
        }
        code, payload, elapsed = await self.search(index, body)
        if code >= 400 or not isinstance(payload, dict):
            return None, elapsed, {"http_status": code, "payload": payload}
        hits = payload.get("hits", {}).get("hits", [])
        if not hits:
            return None, elapsed, payload
        source = hits[0].get("_source", {})
        return source.get(field), elapsed, {"hit": source}

    async def terms(self, index: str, field: str, *, minutes: int = 60, size: int = 20) -> tuple[list[dict[str, Any]], float, dict[str, Any]]:
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}},
            "aggs": {"values": {"terms": {"field": field, "size": size, "missing": "__missing__"}}},
        }
        code, payload, elapsed = await self.search(index, body)
        if code >= 400 or not isinstance(payload, dict):
            return [], elapsed, {"http_status": code, "payload": payload}
        return payload.get("aggregations", {}).get("values", {}).get("buckets", []), elapsed, payload

    async def missing_field_percent(self, index: str, field: str, *, minutes: int = 60) -> tuple[float | None, int, int, float, dict[str, Any]]:
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lte": "now"}}},
            "aggs": {
                "present": {"filter": {"exists": {"field": field}}},
            },
        }
        code, payload, elapsed = await self.search(index, body)
        if code >= 400 or not isinstance(payload, dict):
            return None, 0, 0, elapsed, {"http_status": code, "payload": payload}
        total = int(payload.get("hits", {}).get("total", {}).get("value", 0))
        present = int(payload.get("aggregations", {}).get("present", {}).get("doc_count", 0))
        if total <= 0:
            return None, 0, 0, elapsed, payload
        missing = total - present
        return (missing / total) * 100.0, missing, total, elapsed, payload


async def docker_get(path: str) -> tuple[int, Any, float]:
    if not os.path.exists(settings.docker_socket):
        raise FileNotFoundError(settings.docker_socket)
    start = time.perf_counter()
    transport = httpx.AsyncHTTPTransport(uds=settings.docker_socket)
    async with httpx.AsyncClient(transport=transport, timeout=settings.request_timeout_seconds) as client:
        response = await client.get(f"http://docker{path}")
    elapsed_ms = (time.perf_counter() - start) * 1000
    try:
        return response.status_code, response.json(), elapsed_ms
    except Exception:
        return response.status_code, response.text, elapsed_ms


basic_auth = _auth
