from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from opensearchpy import OpenSearch, RequestsHttpConnection

from app.config import Settings

logger = logging.getLogger(__name__)


def create_client(settings: Settings) -> OpenSearch:
    ca_certs = settings.opensearch_ca_cert
    if ca_certs and not Path(ca_certs).exists():
        raise FileNotFoundError(f"OpenSearch CA certificate not found: {ca_certs}")

    client = OpenSearch(
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
    return client


def ensure_index(client: OpenSearch, index: str, mappings: dict[str, Any] | None = None) -> None:
    if client.indices.exists(index=index):
        return
    body: dict[str, Any] = {}
    if mappings:
        body["mappings"] = mappings
    client.indices.create(index=index, body=body or None)


def ping_or_raise(client: OpenSearch) -> None:
    if not client.ping():
        raise RuntimeError("OpenSearch ping failed")
