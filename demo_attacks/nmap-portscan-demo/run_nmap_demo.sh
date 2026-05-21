#!/usr/bin/env bash
set -euo pipefail

need_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "[-] Missing required environment variable: $name" >&2
    exit 1
  fi
}

need_var "TARGET_IP"

SCAN_PORTS="${SCAN_PORTS:-1-1000}"
SCAN_TYPE="${SCAN_TYPE:-connect}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ISO_TS="$(date --iso-8601=seconds)"

mkdir -p "$OUTPUT_DIR"

XML_FILE="${OUTPUT_DIR}/${TARGET_IP}_${TIMESTAMP}.xml"
TXT_FILE="${OUTPUT_DIR}/${TARGET_IP}_${TIMESTAMP}.txt"
JSON_FILE="${OUTPUT_DIR}/${TARGET_IP}_${TIMESTAMP}.json"

echo "[*] NDR Nmap port-scan demo"
echo "[*] Target: ${TARGET_IP}"
echo "[*] Ports: ${SCAN_PORTS}"
echo "[*] Scan type: ${SCAN_TYPE}"
echo "[*] Output: ${JSON_FILE}"
echo

if [[ "$SCAN_TYPE" == "syn" ]]; then
  NMAP_SCAN_FLAG="-sS"
else
  NMAP_SCAN_FLAG="-sT"
fi

set +e
nmap \
  -Pn \
  -n \
  "$NMAP_SCAN_FLAG" \
  -p "$SCAN_PORTS" \
  --max-retries 1 \
  --host-timeout 120s \
  -oX "$XML_FILE" \
  -oN "$TXT_FILE" \
  "$TARGET_IP"

NMAP_EXIT=$?
set -e

python3 - "$JSON_FILE" "$ISO_TS" "$TARGET_IP" "$SCAN_PORTS" "$SCAN_TYPE" "$NMAP_EXIT" "$TXT_FILE" <<'PY'
import json
import sys
from pathlib import Path

json_file, run_ts, target_ip, ports, scan_type, exit_code, txt_file = sys.argv[1:]

txt = Path(txt_file).read_text(encoding="utf-8", errors="replace") if Path(txt_file).exists() else ""

open_ports = []
closed_ports = []
filtered_ports = []

for line in txt.splitlines():
    line = line.strip()
    if not line or line.startswith("PORT"):
        continue
    if "/tcp" in line:
        parts = line.split()
        if len(parts) >= 2:
            port = parts[0]
            state = parts[1]
            if state == "open":
                open_ports.append(port)
            elif state == "closed":
                closed_ports.append(port)
            elif state == "filtered":
                filtered_ports.append(port)

doc = {
    "scenario": "nmap_portscan_demo",
    "timestamp": run_ts,
    "target": {
        "ip": target_ip,
        "ports": ports
    },
    "scan": {
        "type": scan_type,
        "nmap_exit_code": int(exit_code)
    },
    "summary": {
        "open_ports_count": len(open_ports),
        "closed_ports_count": len(closed_ports),
        "filtered_ports_count": len(filtered_ports),
        "open_ports": open_ports[:50],
        "closed_ports_sample": closed_ports[:50],
        "filtered_ports_sample": filtered_ports[:50]
    }
}

Path(json_file).write_text(json.dumps(doc, indent=2), encoding="utf-8")
PY

echo
echo "[✔] Nmap demo finished"
echo "[✔] JSON results saved: $JSON_FILE"

exit 0
