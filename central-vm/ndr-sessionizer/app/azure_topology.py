from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AzureSubnet:
    spoke: str
    vnet: str
    subnet: str
    network: ipaddress._BaseNetwork


def _split_items(value: str | None) -> list[str]:
    if not value:
        return []
    return [x.strip() for x in value.replace("\n", ";").split(";") if x.strip()]


def _parse_subnets() -> list[AzureSubnet]:
    """Parse AZURE_SUBNETS.

    Supported formats:
      spoke:vnet:subnet:cidr
      spoke/vnet/subnet=cidr

    Example:
      hub:hub-vnet:firewall:10.50.0.0/24;spoke1:spoke1-vnet:app:10.51.1.0/24
    """
    entries: list[AzureSubnet] = []
    raw = os.getenv("AZURE_SUBNETS", "")
    for item in _split_items(raw):
        try:
            if "=" in item:
                left, cidr = item.split("=", 1)
                parts = [p.strip() for p in left.split("/")]
            else:
                parts = [p.strip() for p in item.split(":")]
                cidr = parts[3] if len(parts) >= 4 else ""
                parts = parts[:3]

            if len(parts) != 3 or not cidr:
                continue

            spoke, vnet, subnet = parts
            entries.append(
                AzureSubnet(
                    spoke=spoke,
                    vnet=vnet,
                    subnet=subnet,
                    network=ipaddress.ip_network(cidr.strip(), strict=False),
                )
            )
        except Exception:
            continue

    entries.sort(key=lambda x: x.network.prefixlen, reverse=True)
    return entries


AZURE_SUBNETS = _parse_subnets()


def getn(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def setn(obj: dict[str, Any], path: str, value: Any) -> None:
    cur = obj
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def classify_ip(value: Any) -> dict[str, Any]:
    if not value:
        return {"local": None, "scope": "unknown"}

    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return {"ip": str(value), "local": None, "scope": "invalid"}

    is_internal = ip.is_private or ip.is_loopback or ip.is_link_local

    for item in AZURE_SUBNETS:
        if ip in item.network:
            return {
                "ip": str(ip),
                "local": True,
                "scope": "azure_private",
                "spoke": item.spoke,
                "vnet": item.vnet,
                "subnet": item.subnet,
                "subnet_cidr": str(item.network),
            }

    if is_internal:
        return {
            "ip": str(ip),
            "local": True,
            "scope": "private_unknown",
        }

    return {
        "ip": str(ip),
        "local": False,
        "scope": "external",
    }


def _same(a: dict[str, Any], b: dict[str, Any], key: str) -> bool | None:
    av = a.get(key)
    bv = b.get(key)
    if not av or not bv:
        return None
    return av == bv


def enrich_azure_topology(doc: dict[str, Any]) -> None:
    src = classify_ip(getn(doc, "source.ip"))
    dst = classify_ip(getn(doc, "destination.ip"))

    setn(doc, "cloud.provider", "azure")

    if src.get("local") is not None:
        setn(doc, "source.local", bool(src.get("local")))
    if dst.get("local") is not None:
        setn(doc, "destination.local", bool(dst.get("local")))

    for side, data in (("source", src), ("destination", dst)):
        for key in ("scope", "spoke", "vnet", "subnet", "subnet_cidr"):
            if data.get(key) not in (None, ""):
                setn(doc, f"cloud.azure.{side}.{key}", data.get(key))

    src_local = src.get("local") is True
    dst_local = dst.get("local") is True

    same_subnet = _same(src, dst, "subnet_cidr")
    same_spoke = _same(src, dst, "spoke")
    same_vnet = _same(src, dst, "vnet")

    if src_local and dst_local:
        if same_subnet is True:
            scope = "same_subnet"
        elif same_spoke is True:
            scope = "same_spoke_cross_subnet"
        elif same_vnet is True:
            scope = "same_vnet_cross_subnet"
        elif same_spoke is False:
            scope = "cross_spoke"
        else:
            scope = "internal_unknown"

        direction = "internal"
        asset = src
        asset_side = "source"

    elif src_local and not dst_local:
        scope = "outbound_external"
        direction = "outbound"
        asset = src
        asset_side = "source"

    elif not src_local and dst_local:
        scope = "inbound_external"
        direction = "inbound"
        asset = dst
        asset_side = "destination"

    else:
        scope = "external_external"
        direction = "external_or_unknown"
        asset = {}
        asset_side = "unknown"

    setn(doc, "network.direction", direction)
    setn(doc, "network.scope", scope)

    if same_subnet is not None:
        setn(doc, "network.same_subnet", same_subnet)
    if same_spoke is not None:
        setn(doc, "network.same_spoke", same_spoke)
    if same_vnet is not None:
        setn(doc, "network.same_vnet", same_vnet)

    if asset.get("ip"):
        setn(doc, "network.asset.ip", asset.get("ip"))
        setn(doc, "network.asset.side", asset_side)

        for key in ("spoke", "vnet", "subnet", "subnet_cidr", "scope"):
            if asset.get(key) not in (None, ""):
                setn(doc, f"network.asset.{key}", asset.get(key))
