#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose -f docker-compose.standalone.yml up -d --build

echo "ndr-flow-collector started. Logs:"
echo "  docker logs -f ndr-flow-collector"
echo
echo "Send pfSense softflowd NetFlow v9 to:"
echo "  <hub-ip>:2055/udp"
