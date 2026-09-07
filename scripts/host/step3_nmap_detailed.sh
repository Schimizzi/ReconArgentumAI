#!/bin/bash
# Step 3 UNIFICADO - Nmap -sC -sV detallado SOLO sobre puertos abiertos
# Uso: step3_nmap_detailed.sh <IP>
# UNIFICACIÓN KALI/DOCKER (2026-09-07): scan type autodetectado igual que Step 1
# (EUID==0 → -sS; si no → -sT). Mismo script en host, VM Kali y contenedor.
# RUN#9 (2026-09-05): RESTAURADO el comportamiento funcional del MODO HOST.
#   BUG YAML nmap_timing_template_detailed: "T3" con comillas; -T$TMPL generaba
#   -TT3 (inválido). Fix: SIN -T ni --max-rate (timing default de Nmap = T3).
# BUG Nmap 7.991: -oJ + -oN -> "Can't use -oN multiple times or with -oA". FIX: -oX + -oN + JSON derivado.
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
PORTS=$(sed 's/.*://' "$EVID/open_ports.txt" | paste -sd, -)
if [ -z "${PORTS}" ]; then echo "open_ports.txt vacio"; exit 1; fi
if [ "$(id -u)" -eq 0 ]; then SCAN="-sS"; else SCAN="-sT"; fi
"nmap" "$SCAN" -sC -sV -p "${PORTS}" \
  -Pn \
  -oX "$EVID/nmap_detailed.xml" \
  -oN "$EVID/nmap_detailed.txt" \
  "$TARGET"
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_detailed.xml" "$EVID/nmap_detailed.json"
echo "STEP3_HOST_OK scan=${SCAN} ports=${PORTS} timing default=T3 aprobado"
