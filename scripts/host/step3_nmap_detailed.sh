#!/bin/bash
# Step 3 MODO HOST - Nmap -sC -sV detallado SOLO sobre puertos abiertos
# Uso: step3_nmap_detailed.sh <TARGET>
# RUN#9 (2026-09-05): RESTAURADO el comportamiento funcional del MODO HOST.
#   El YAML nmap_timing_template_detailed: "T3" incluye comillas; -T$TMPL generaba
#   -TT3 (inválido) -> "Unknown timing mode (-T argument)". Fix: SIN -T ni --max-rate
#   (timing default de Nmap = T3, que es EXACTAMENTE el valor aprobado en RUN#8 para
#   el Step 3; ver approved_commands.md). Comentario RUN#8 step3 volaba igual.
# BUG Nmap 7.991: -oJ + -oN -> "Can't use -oN multiple times or with -oA". FIX: -oX + -oN + JSON derivado.
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
PORTS=$(sed 's/.*://' "$EVID/open_ports.txt" | paste -sd, -)
if [ -z "${PORTS}" ]; then echo "open_ports.txt vacio"; exit 1; fi
nmap -sT -sC -sV -p "${PORTS}" \
  -Pn \
  -oX "$EVID/nmap_detailed.xml" \
  -oN "$EVID/nmap_detailed.txt" \
  "$TARGET"
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_detailed.xml" "$EVID/nmap_detailed.json"
echo "STEP3_HOST_OK ports=${PORTS} (timing default=T3 aprobado)"
