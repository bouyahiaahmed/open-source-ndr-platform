#!/usr/bin/env bash
set -euo pipefail

need_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "[-] Missing required environment variable: $name" >&2
    exit 1
  fi
}

need_var "VICTIM_IP"
need_var "SSH_PORT"
need_var "GOOD_USER"
need_var "GOOD_PASS"

TOTAL_ATTEMPTS="${TOTAL_ATTEMPTS:-12}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
BAD_PASSWORD="${BAD_PASSWORD:-wrongpassword}"
DO_VALID_LOGIN="${DO_VALID_LOGIN:-true}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"

BAD_USERS_CSV="${BAD_USERS:-root,admin,test,ubuntu,azureuser,user,guest,oracle,postgres,deploy,support,backup}"

IFS=',' read -r -a BAD_USERS_ARRAY <<< "$BAD_USERS_CSV"

mkdir -p "$OUTPUT_DIR"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ISO_TS="$(date --iso-8601=seconds)"
OUTFILE="${OUTPUT_DIR}/${VICTIM_IP}_${TIMESTAMP}.json"
TMP_JSONL="$(mktemp)"

cleanup() {
  rm -f "$TMP_JSONL"
}
trap cleanup EXIT

echo "[*] NDR SSH brute-force demo"
echo "[*] Target: ${VICTIM_IP}:${SSH_PORT}"
echo "[*] Bad attempts: ${TOTAL_ATTEMPTS}"
echo "[*] Valid login after bad attempts: ${DO_VALID_LOGIN}"
echo "[*] Output file: ${OUTFILE}"
echo

record_attempt() {
  local username="$1"
  local password_label="$2"
  local status="$3"
  local command="$4"
  local output="$5"

  python3 - "$TMP_JSONL" "$username" "$password_label" "$status" "$command" "$output" <<'PY'
import json
import sys
from datetime import datetime, timezone

jsonl_path, username, password_label, status, command, output = sys.argv[1:]

entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "username": username,
    "password": password_label,
    "status": status,
    "command": command,
    "output": output.strip()
}

with open(jsonl_path, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
PY
}

for i in $(seq 1 "$TOTAL_ATTEMPTS"); do
  index=$(( (i - 1) % ${#BAD_USERS_ARRAY[@]} ))
  USERNAME="${BAD_USERS_ARRAY[$index]}"

  echo "[*] Attempt ${i}/${TOTAL_ATTEMPTS}: ${USERNAME}:${BAD_PASSWORD}"

  SSH_OUTPUT="$(
    sshpass -p "$BAD_PASSWORD" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o LogLevel=ERROR \
      -o ConnectTimeout=5 \
      -p "$SSH_PORT" \
      "${USERNAME}@${VICTIM_IP}" "exit" 2>&1 || true
  )"

  if echo "$SSH_OUTPUT" | grep -qiE "permission denied|authentication failed|denied"; then
    STATUS="failed"
  else
    STATUS="error"
  fi

  record_attempt "$USERNAME" "$BAD_PASSWORD" "$STATUS" "ssh exit" "$SSH_OUTPUT"

  sleep "$SLEEP_SECONDS"
done

if [[ "$DO_VALID_LOGIN" == "true" ]]; then
  echo
  echo "[*] Trying valid credentials: ${GOOD_USER}/[REDACTED]"

  VALID_OUTPUT="$(
    sshpass -p "$GOOD_PASS" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o LogLevel=ERROR \
      -o ConnectTimeout=5 \
      -p "$SSH_PORT" \
      "${GOOD_USER}@${VICTIM_IP}" "printf 'NDR_SSH_SUCCESS_%s\n' \"\$(whoami)\"" 2>&1 || true
  )"

  if echo "$VALID_OUTPUT" | grep -q "NDR_SSH_SUCCESS_${GOOD_USER}"; then
    VALID_STATUS="success"
  else
    VALID_STATUS="failed"
  fi

  record_attempt "$GOOD_USER" "[REDACTED]" "$VALID_STATUS" "ssh whoami" "$VALID_OUTPUT"
fi

python3 - "$OUTFILE" "$ISO_TS" "$VICTIM_IP" "$SSH_PORT" "$TMP_JSONL" <<'PY'
import json
import sys

outfile, run_ts, victim_ip, port, jsonl_path = sys.argv[1:]

attempts = []
with open(jsonl_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            attempts.append(json.loads(line))

success = any(a["status"] == "success" for a in attempts)
failed = sum(1 for a in attempts if a["status"] == "failed")
errors = sum(1 for a in attempts if a["status"] == "error")

final_doc = {
    "scenario": "ssh_bruteforce_demo",
    "timestamp": run_ts,
    "target": {
        "ip": victim_ip,
        "port": int(port),
        "service": "ssh"
    },
    "summary": {
        "total_attempts": len(attempts),
        "failed_attempts": failed,
        "error_attempts": errors,
        "successful_login": success
    },
    "attempts": attempts
}

with open(outfile, "w", encoding="utf-8") as f:
    json.dump(final_doc, f, indent=2)
PY

echo
echo "[✔] JSON results saved: $OUTFILE"
