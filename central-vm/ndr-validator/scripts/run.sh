#!/usr/bin/env bash
set -euo pipefail
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit it before production use."
fi
docker compose -f docker-compose.standalone.yml up -d --build
echo "NDR Validator UI: http://localhost:${VALIDATOR_PORT:-8000}"
