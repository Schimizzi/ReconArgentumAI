#!/bin/bash
# Step 4 MODO HOST — Nuclei (set default filtrado por severidad)
# Uso: step4_nuclei.sh <TARGET>
# Requiere templates de nuclei (descarga automática en el 1er run: nuclei -ut).
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
if [ ! -s "$EVID/web_endpoints.txt" ]; then echo "web_endpoints.txt vacío → skipped"; exit 1; fi
nuclei -l "$EVID/web_endpoints.txt" \
  -o "$EVID/nuclei.json" \
  -jsonl \
  -rl 5 \
  -timeout 10 \
  -bs 5 \
  -s critical,high,medium
echo "STEP4_HOST_OK findings=$(wc -l < "$EVID/nuclei.json")"