#!/usr/bin/env sh
set -eu

OS_URL="${OS_URL:-https://opensearch:9200}"
OS_USER="${OS_USER:-admin}"
OS_PASS="${OS_PASS:-admin}"
CA_CERT="${CA_CERT:-/certs/ca/ca.crt}"

TEMPLATE_NAME="${TEMPLATE_NAME:-zeek-logs-template-v1}"
TEMPLATE_FILE="${TEMPLATE_FILE:-/templates/zeek-logs-template-v1.json}"

echo "============================================================"
echo "OpenSearch template bootstrap"
echo "OS_URL=${OS_URL}"
echo "TEMPLATE_NAME=${TEMPLATE_NAME}"
echo "TEMPLATE_FILE=${TEMPLATE_FILE}"
echo "CA_CERT=${CA_CERT}"
echo "============================================================"

if [ ! -f "$CA_CERT" ]; then
  echo "ERROR: CA certificate not found at: $CA_CERT"
  exit 1
fi

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "ERROR: Template file not found at: $TEMPLATE_FILE"
  exit 1
fi

echo "Waiting for OpenSearch to become healthy..."

attempt=1
max_attempts=60

until curl -sS --fail \
  --cacert "$CA_CERT" \
  -u "$OS_USER:$OS_PASS" \
  "$OS_URL/_cluster/health?wait_for_status=yellow&timeout=5s" \
  > /tmp/opensearch-health.json
do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "ERROR: OpenSearch did not become ready after ${max_attempts} attempts."
    echo "Last health response, if any:"
    cat /tmp/opensearch-health.json 2>/dev/null || true
    exit 1
  fi

  echo "OpenSearch not ready yet. Attempt ${attempt}/${max_attempts}..."
  attempt=$((attempt + 1))
  sleep 5
done

echo "OpenSearch is reachable."
cat /tmp/opensearch-health.json
echo

echo "Applying index template: ${TEMPLATE_NAME}"

curl -sS --fail \
  --cacert "$CA_CERT" \
  -u "$OS_USER:$OS_PASS" \
  -H "Content-Type: application/json" \
  -X PUT "$OS_URL/_index_template/$TEMPLATE_NAME" \
  --data-binary "@$TEMPLATE_FILE" \
  > /tmp/template-apply-response.json

echo "Template apply response:"
cat /tmp/template-apply-response.json
echo

echo "Verifying template exists..."

curl -sS --fail \
  --cacert "$CA_CERT" \
  -u "$OS_USER:$OS_PASS" \
  "$OS_URL/_index_template/$TEMPLATE_NAME" \
  > /tmp/template-get-response.json

if ! grep -q "$TEMPLATE_NAME" /tmp/template-get-response.json; then
  echo "ERROR: Template was not found after applying it."
  cat /tmp/template-get-response.json
  exit 1
fi

echo "Template exists."

echo "Simulating template against all Zeek sink index names..."

for index_name in \
  zeek-logs-2099.01.01 \
  zeek-conn-2099.01.01 \
  zeek-dns-2099.01.01 \
  zeek-http-2099.01.01 \
  zeek-ssl-2099.01.01 \
  zeek-files-2099.01.01 \
  zeek-weird-2099.01.01 \
  zeek-notice-2099.01.01 \
  zeek-dce_rpc-2099.01.01 \
  zeek-smb-2099.01.01 \
  zeek-kerberos-2099.01.01 \
  zeek-x509-2099.01.01 \
  zeek-ntlm-2099.01.01 \
  zeek-ssh-2099.01.01 \
  zeek-ftp-2099.01.01 \
  zeek-ldap-2099.01.01 \
  zeek-other-2099.01.01
do
  echo "Simulating template for index: $index_name"

  curl -sS --fail \
    --cacert "$CA_CERT" \
    -u "$OS_USER:$OS_PASS" \
    -H "Content-Type: application/json" \
    -X POST "$OS_URL/_index_template/_simulate_index/$index_name" \
    > "/tmp/template-simulate-${index_name}.json"

  if ! grep -q '"orig_h"' "/tmp/template-simulate-${index_name}.json"; then
    echo "ERROR: Simulation for $index_name does not include id.orig_h mapping."
    cat "/tmp/template-simulate-${index_name}.json"
    exit 1
  fi

  if ! grep -q '"resp_h"' "/tmp/template-simulate-${index_name}.json"; then
    echo "ERROR: Simulation for $index_name does not include id.resp_h mapping."
    cat "/tmp/template-simulate-${index_name}.json"
    exit 1
  fi

  if ! grep -q '"ip"' "/tmp/template-simulate-${index_name}.json"; then
    echo "ERROR: Simulation for $index_name does not include IP mappings."
    cat "/tmp/template-simulate-${index_name}.json"
    exit 1
  fi

  if ! grep -q '"log_type"' "/tmp/template-simulate-${index_name}.json"; then
    echo "ERROR: Simulation for $index_name does not include log_type mapping."
    cat "/tmp/template-simulate-${index_name}.json"
    exit 1
  fi
done

echo "Template simulation succeeded for all Zeek sink index names."

echo "============================================================"
echo "OpenSearch template applied successfully."
echo "Covered index patterns:"
echo "  - zeek-logs-*"
echo "  - zeek-conn-*"
echo "  - zeek-dns-*"
echo "  - zeek-http-*"
echo "  - zeek-ssl-*"
echo "  - zeek-files-*"
echo "  - zeek-weird-*"
echo "  - zeek-notice-*"
echo "  - zeek-dce_rpc-*"
echo "  - zeek-smb-*"
echo "  - zeek-kerberos-*"
echo "  - zeek-x509-*"
echo "  - zeek-ntlm-*"
echo "  - zeek-ssh-*"
echo "  - zeek-ftp-*"
echo "  - zeek-ldap-*"
echo "  - zeek-other-*"
echo "Data Prepper can now safely create all Zeek indices."
echo "============================================================"
