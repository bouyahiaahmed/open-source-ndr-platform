# ndr-flow-collector

Lightweight firewall NetFlow/IPFIX collector for the NDR stack.

It receives firewall flow telemetry from pfSense/OPNsense/Palo Alto-style exporters, decodes it with GoFlow2, normalizes it into an ECS-like NDR schema, and indexes it into OpenSearch under:

```text
ndr-flows-YYYY.MM.dd
```

## Architecture

```text
pfSense / Palo Alto / firewall
        ↓ UDP/2055 NetFlow v9 or IPFIX
ndr-flow-collector container
        ├── GoFlow2 decodes NetFlow/IPFIX to JSON
        └── Python normalizer sends bulk JSON to OpenSearch
        ↓
OpenSearch index: ndr-flows-*
```

## Quick standalone run on the hub VM

Use this when OpenSearch is already reachable from the hub on `https://127.0.0.1:9200` or `https://localhost:9200`.

```bash
cd ndr-flow-collector

export OS_URL="https://127.0.0.1:9200"
export OS_USER="admin"
export OS_PASS="admin"
export OS_VERIFY_SSL="false"
export FLOW_OBSERVER_VENDOR="pfsense"

./scripts/run-standalone.sh
```

Check logs:

```bash
docker logs -f ndr-flow-collector
```

In pfSense `softflowd`, configure:

```text
Enable: yes
Interface: WAN
Host: <hub-ip>
Port: 2055
NetFlow version: 9
```

To force flows to appear faster from pfSense shell:

```sh
ls /var/run/softflowd*
softflowctl -c /var/run/softflowd.WAN.ctl expire-all
```

If the control file has another name, use that file instead.

## Verify OpenSearch

```bash
export OS_URL="https://127.0.0.1:9200"
export OS_USER="admin"
export OS_PASS="admin"
export OS_VERIFY_SSL="false"

./scripts/query-ndr-flows.sh
```

Or directly:

```bash
curl -k -u admin:admin "https://127.0.0.1:9200/ndr-flows-*/_count?pretty"
```

## Integrate inside central-vm

Recommended folder placement:

```text
central-vm/
├── docker/
│   └── docker-compose.yml
├── certs/
│   └── ca/ca.crt
└── ndr-flow-collector/
```

Then copy the service block from:

```text
docker-compose.central-vm.snippet.yml
```

into:

```text
central-vm/docker/docker-compose.yml
```

The snippet assumes your OpenSearch service is named:

```text
os-node-1
```

and that your Docker network is named:

```text
ndr-net
```

If your compose file uses another network name, change the `networks` section accordingly.

Then run from `central-vm`:

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d --build ndr-flow-collector
```

Check logs:

```bash
docker logs -f ndr-flow-collector
```

## Environment variables

| Variable | Default | Meaning |
|---|---:|---|
| `FLOW_COLLECTOR_PORT` | `2055` | UDP port for NetFlow/IPFIX |
| `FLOW_LISTEN` | `netflow://:2055` | GoFlow2 listener URL |
| `OS_URL` | `https://127.0.0.1:9200` | OpenSearch endpoint |
| `OS_USER` | `admin` | OpenSearch username |
| `OS_PASS` | `admin` | OpenSearch password |
| `OS_VERIFY_SSL` | `false` | Verify OpenSearch TLS cert |
| `OS_CA_CERT` | empty | CA certificate path when TLS verification is enabled |
| `OS_INDEX_PREFIX` | `ndr-flows` | Index prefix |
| `APPLY_TEMPLATE_ON_START` | `true` | Auto-create/update `ndr-flows-template` |
| `BULK_SIZE` | `100` | Bulk indexing batch size |
| `BULK_FLUSH_SECONDS` | `5` | Max seconds before flushing a partial batch |
| `FLOW_OBSERVER_VENDOR` | `pfsense` | `observer.vendor` value; later use `paloalto` |
| `FLOW_OBSERVER_TYPE` | `firewall` | `observer.type` value |
| `NDR_ENV` | `lab` | Environment tag |
| `KEEP_RAW_GOFLOW` | `true` | Preserve raw GoFlow2 event under `goflow2` |

## Normalized fields

Example indexed document:

```json
{
  "@timestamp": "2026-05-10T20:38:01Z",
  "event": {
    "dataset": "firewall.netflow",
    "module": "ndr-flow-collector",
    "kind": "event",
    "category": ["network"],
    "type": ["connection"]
  },
  "observer": {
    "type": "firewall",
    "vendor": "pfsense",
    "ip": "192.168.25.135"
  },
  "source": {
    "ip": "192.168.25.129",
    "port": 51821
  },
  "destination": {
    "ip": "178.62.250.107",
    "port": 123
  },
  "network": {
    "transport": "udp",
    "iana_number": "17",
    "bytes": 76,
    "packets": 1,
    "direction": "outbound"
  },
  "netflow": {
    "version": "NETFLOW_V9"
  },
  "ndr": {
    "source_type": "firewall_netflow",
    "collector": "goflow2",
    "env": "lab"
  }
}
```

## OpenSearch Dashboards

Create a data view:

```text
Name: ndr-flows-*
Time field: @timestamp
```

Useful Discover columns:

```text
@timestamp
observer.vendor
observer.ip
source.ip
source.port
destination.ip
destination.port
network.transport
network.direction
network.bytes
network.packets
netflow.version
ndr.collector
```

## Notes for Palo Alto later

For Palo Alto, keep the same collector and change only:

```text
FLOW_OBSERVER_VENDOR=paloalto
```

Then configure Palo Alto NetFlow export to send NetFlow v9 to:

```text
<hub-ip>:2055/udp
```

The collector does not depend on pfSense-specific logic. It receives standard NetFlow/IPFIX decoded by GoFlow2.
