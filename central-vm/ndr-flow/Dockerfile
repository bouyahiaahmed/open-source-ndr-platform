# ndr-flow-collector
# Lightweight NetFlow/IPFIX collector for NDR stacks.
# Builds GoFlow2 from source, runs it, normalizes decoded JSON, and indexes to OpenSearch.

FROM golang:1.23-bookworm AS builder
RUN go install github.com/netsampler/goflow2/v2/cmd/goflow2@latest

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates bash curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/goflow2 /usr/local/bin/goflow2

WORKDIR /app
COPY app/ /app/
COPY mappings/ /app/mappings/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /app/*.py

EXPOSE 2055/udp

ENTRYPOINT ["/entrypoint.sh"]
