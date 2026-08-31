#!/bin/bash
# Step 3 MODO HOST — Nmap -sC -sV detallado SOLO sobre puertos abiertos
# Uso: step3_nmap_detailed.sh <TARGET>
# Modo Host: -sT + -sC -sV (sin raw sockets).
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
PORTS=$(sed 's/.*://' "$EVID/open_ports.txt" | paste -sd, -)
if [ -z "${PORTS}" ]; then echo "open_ports.txt vacío"; exit 1; fi
nmap -sT -sC -sV -p "${PORTS}" \
  -T2 --max-rate 30 -Pn \
  -oX "$EVID/nmap_detailed.xml" \
  -oN "$EVID/nmap_detailed.txt" \
  "$TARGET"
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_detailed.xml" "$EVID/nmap_detailed.json"
echo "STEP3_HOST_OK ports=${PORTS}"