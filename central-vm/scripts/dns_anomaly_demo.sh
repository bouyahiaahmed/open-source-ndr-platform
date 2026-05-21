#!/usr/bin/env bash
set -euo pipefail

DNS_SERVER="${1:-10.51.3.10}"
DOMAIN_SUFFIX="${2:-ndr-demo.invalid}"
COUNT="${3:-400}"

echo "[+] DNS anomaly demo"
echo "[+] DNS server: $DNS_SERVER"
echo "[+] Domain suffix: $DOMAIN_SUFFIX"
echo "[+] Queries: $COUNT"

for i in $(seq 1 "$COUNT"); do
  LABEL="$(python3 - <<'PY'
import random, string
alphabet = string.ascii_lowercase + string.digits
print(''.join(random.choice(alphabet) for _ in range(55)))
PY
)"
  q="${LABEL}.${i}.${DOMAIN_SUFFIX}"

  dig @"$DNS_SERVER" "$q" TXT +time=1 +tries=1 >/dev/null 2>&1 || true
  sleep 0.15
done

echo "[+] Done."
