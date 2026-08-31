#!/bin/bash
# Step 1 MODO HOST — Nmap port scan (TCP connect, sin root)
# Uso: step1_nmap_ports.sh <TARGET>
# Modo Host: usa -sT (Connect Scan) porque el host no tiene raw sockets sin sudo.
# Workaround -oJ (nmap 7.99 arm64 de Kali): no aplica al host (nmap 7.991), pero se
# mantiene el mismo flujo -oX/-oN/-oG + json derivado para consistencia de evidencia.
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
rm -f "$EVID"/nmap_ports.* "$EVID/open_ports.txt"
nmap -sT -T2 --max-rate 30 \
  --top-ports 1000 --open -Pn \
  -oX "$EVID/nmap_ports.xml" \
  -oN "$EVID/nmap_ports.txt" \
  -oG "$EVID/nmap_ports.gnmap" \
  "$TARGET"
NMAP_EXIT=$?
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_ports.xml" "$EVID/nmap_ports.json"
echo "STEP1_HOST_EXIT=$NMAP_EXIT JSON_DERIVED_ok"