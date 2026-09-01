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
# RE-MODIFICADO en cierre de Fase 0 (2026-08-31): SIN -T ni --max-rate (aprobado por el
# usuario). Timing/rate = defaults de Nmap. variable nmap_timing_template_detailed SIN USO.
# BUG DETECTADO 2026-08-31: en Nmap 7.991 (Homebrew/macOS) `-oJ` + `-oN` → "Can't use -oN
# multiple times or with -oA". FIX: usar -oX + -oN y derivar el JSON del XML (igual que Step 1).
nmap -sT -sC -sV -p "${PORTS}" \
  -Pn \
  -oX "$EVID/nmap_detailed.xml" \
  -oN "$EVID/nmap_detailed.txt" \
  "$TARGET"
# Derivar JSON del XML (workaround -oJ roto en este build)
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_detailed.xml" "$EVID/nmap_detailed.json"
echo "STEP3_HOST_OK ports=${PORTS}"