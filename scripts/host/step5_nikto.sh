#!/bin/bash
# Step 5 MODO HOST — Nikto (1 por endpoint web, secuencial)
# Uso: step5_nikto.sh <TARGET> <URL> <PORT>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; URL="$2"; PORT="$3"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
# R5: maxtime resuelto desde config/stealth.yaml (prohibido hardcodear)
MXT=$(awk '/^nikto_maxtime_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
MXT="${MXT:-30}"
nikto -h "$URL" -Format json \
  -o "$EVID/nikto_${PORT}.json" \
  -Tuning 123b \
  -maxtime "${MXT}s" \
  -nocheck
echo "STEP5_HOST_OK port=${PORT}"