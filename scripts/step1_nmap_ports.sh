#!/bin/bash
# Step 1 — Nmap port scan (comando APROBADO en Fase 0)
# Uso: step1_nmap_ports.sh <TARGET>
set -uo pipefail
TARGET="$1"
EVID="/workspace/evidence/$TARGET"
mkdir -p "$EVID"
nmap -sS -T2 --max-rate 30 \
  --top-ports 1000 --open -Pn \
  -oX "$EVID/nmap_ports.xml" \
  -oN "$EVID/nmap_ports.txt" \
  -oG "$EVID/nmap_ports.gnmap" \
  "$TARGET"
NMAP_EXIT=$?
# Workaround bug -oJ (nmap 7.99 arm64 de Kali): derivar JSON desde el XML.
python3 /workspace/scripts/xml_to_nmap_json.py "$EVID/nmap_ports.xml" "$EVID/nmap_ports.json"
echo "STEP1_EXIT=$NMAP_EXIT JSON_DERIVED_ok"
