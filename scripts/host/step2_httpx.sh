#!/bin/bash
# Step 2 MODO HOST — HTTPX probe web (binario ProjectDiscovery httpx-pd)
# Uso: step2_httpx.sh <TARGET>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
httpx-pd -l "$EVID/open_ports.txt" \
  -o "$EVID/httpx.json" \
  -json \
  -timeout 10 \
  -retries 1 \
  -t 5
jq -r '.url // empty' "$EVID/httpx.json" | grep -E '^https?://' > "$EVID/web_endpoints.txt"
echo "STEP2_HOST_OK urls=$(wc -l < "$EVID/web_endpoints.txt")"