from __future__ import annotations

from pathlib import Path
from typing import Any

from opensearchpy import OpenSearch, RequestsHttpConnection

from app.config import Settings


def create_client(settings: Settings) -> OpenSearch:
    ca_certs = settings.opensearch_ca_cert
    if ca_certs and not Path(ca_certs).exists():
        raise FileNotFoundError(f"OpenSearch CA certificate not found: {ca_certs}")
    return OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(settings.opensearch_username, settings.opensearch_password),
        use_ssl=settings.opensearch_url.startswith("https"),
        verify_certs=settings.opensearch_verify_certs,
        ca_certs=ca_certs,
        ssl_show_warn=not settings.opensearch_verify_certs,
        timeout=60,
        max_retries=3,
        retry_on_timeout=True,
        connection_class=RequestsHttpConnection,
    )


def ping_or_raise(client: OpenSearch) -> None:
    if not client.ping():
        raise RuntimeError("OpenSearch ping failed")


def index_exists(client: OpenSearch, index_pattern: str) -> bool:
    try:
        return bool(client.indices.exists(index=index_pattern, params={"allow_no_indices": "false"}))
    except Exception:
        return False


def safe_count(client: OpenSearch, index: str, body: dict[str, Any] | None = None) -> int:
    response = client.count(index=index, body=body or {}, params={"ignore_unavailable": "true", "allow_no_indices": "true"})
    return int(response.get("count", 0) or 0)
