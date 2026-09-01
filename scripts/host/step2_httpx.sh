#!/bin/bash
# Step 2 MODO HOST — HTTPX probe web (binario ProjectDiscovery httpx-pd)
# Uso: step2_httpx.sh <TARGET>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
# R5: timeout/retries/threads resueltos desde config/stealth.yaml (prohibido hardcodear)
TO=$(awk '/^httpx_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RT=$(awk '/^httpx_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TH=$(awk '/^httpx_threads:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TO="${TO:-10}"; RT="${RT:-1}"; TH="${TH:-5}"
httpx-pd -l "$EVID/open_ports.txt" \
  -o "$EVID/httpx.json" \
  -json \
  -timeout "$TO" \
  -retries "$RT" \
  -t "$TH"
jq -r '.url // empty' "$EVID/httpx.json" | grep -E '^https?://' > "$EVID/web_endpoints.txt"
echo "STEP2_HOST_OK urls=$(wc -l < "$EVID/web_endpoints.txt")"