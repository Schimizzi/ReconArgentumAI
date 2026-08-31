#!/bin/bash
# Step 5 MODO HOST — Nikto (1 por endpoint web, secuencial)
# Uso: step5_nikto.sh <TARGET> <URL> <PORT>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; URL="$2"; PORT="$3"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
nikto -h "$URL" -Format json \
  -o "$EVID/nikto_${PORT}.json" \
  -Tuning 123b \
  -maxtime 30s \
  -nocheck
echo "STEP5_HOST_OK port=${PORT}"