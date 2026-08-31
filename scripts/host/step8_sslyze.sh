#!/bin/bash
# Step 8 MODO HOST — SSLyze (1 por puerto https, secuencial)
# Uso: step8_sslyze.sh <TARGET> <HTTPS_PORT>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; PORT="$2"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
sslyze "${TARGET}:${PORT}" \
  --json_out "$EVID/sslyze_${PORT}.json" \
  --quiet \
  --certinfo
echo "STEP8_HOST_OK port=${PORT}"