# OpenSearch Dev Tools commands

Create/refresh template:

```json
PUT _index_template/ndr-flows-template
{
  "index_patterns": ["ndr-flows-*"],
  "priority": 350,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "source.ip": { "type": "ip" },
        "destination.ip": { "type": "ip" },
        "source.port": { "type": "integer" },
        "destination.port": { "type": "integer" },
        "network.bytes": { "type": "long" },
        "network.packets": { "type": "long" },
        "network.transport": { "type": "keyword" },
        "observer.vendor": { "type": "keyword" },
        "observer.ip": { "type": "ip" },
        "ndr.source_type": { "type": "keyword" },
        "ndr.collector": { "type": "keyword" }
      }
    }
  }
}
```

Count flows:

```json
GET ndr-flows-*/_count
```

Show latest flows:

```json
GET ndr-flows-*/_search
{
  "size": 20,
  "sort": [
    { "@timestamp": "desc" }
  ],
  "_source": [
    "@timestamp",
    "observer.vendor",
    "observer.ip",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.transport",
    "network.direction",
    "network.bytes",
    "network.packets",
    "netflow.version",
    "ndr.source_type",
    "ndr.collector"
  ]
}
```

Check mapping:

```json
GET ndr-flows-*/_field_caps?fields=@timestamp,source.ip,destination.ip,source.port,destination.port,network.bytes,network.packets,observer.vendor,observer.ip,netflow.version,ndr.collector
```
