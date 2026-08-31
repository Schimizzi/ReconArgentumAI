#!/bin/bash
# Post-proceso Step 1 (MODO HOST) — extraer puertos abiertos desde nmap_ports.json
# Uso: post_step1_open_ports.sh <TARGET>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
if [ ! -s "$EVID/nmap_ports.json" ]; then
  echo "ERROR: $EVID/nmap_ports.json vacio o ausente" >&2; exit 1
fi
jq -r '(.scan | keys[]) as $t | .scan[$t].tcp | to_entries[] |
  select(.value.state == "open") | "\($t):\(.key)"' "$EVID/nmap_ports.json" > "$EVID/open_ports.txt"
if [ -s "$EVID/open_ports.txt" ]; then
  echo "open_ports.txt ($(wc -l < "$EVID/open_ports.txt") puertos):"
  cat "$EVID/open_ports.txt"
else
  echo "open_ports.txt VACIO — sin puertos abiertos"
fi