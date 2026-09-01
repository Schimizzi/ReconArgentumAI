#!/bin/bash
# Step 1 MODO HOST — Nmap port scan COMPLETO (TCP connect, sin root)
# Uso: step1_nmap_ports.sh <TARGET>
# Modo Host: usa -sT (Connect Scan) porque el host no tiene raw sockets sin sudo.
# Aprobado Fase 0 DREAMCO-2026 (2026-08-31): -p 1-65535 (todos los puertos) +
# timing/rate resueltos de config/stealth.yaml (R5: nada hardcodeado).
# Workaround -oJ (nmap 7.99 arm64 de Kali): no aplica al host (nmap 7.991), pero se
# mantiene el mismo flujo -oX/-oN/-oG + json derivado para consistencia de evidencia.
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
rm -f "$EVID"/nmap_ports.* "$EVID/open_ports.txt"
# R5: timing/rate/retries/rtt resueltos desde config/stealth.yaml (2026-08-31: T5 / rate 5000 /
# retries 1 / rtt 200-800ms por pedido de rapidez del usuario).
NMAP_T=$(awk '/^nmap_timing_template:/ {gsub(/"/,"",$2); print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_RATE=$(awk '/^nmap_max_rate:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_RETRIES=$(awk '/^nmap_max_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_INIT_RTT=$(awk '/^nmap_initial_rtt_timeout_ms:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_MAX_RTT=$(awk '/^nmap_max_rtt_timeout_ms:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_T="${NMAP_T:-T5}"; NMAP_RATE="${NMAP_RATE:-5000}"; NMAP_RETRIES="${NMAP_RETRIES:-1}"
NMAP_INIT_RTT="${NMAP_INIT_RTT:-200}"; NMAP_MAX_RTT="${NMAP_MAX_RTT:-800}"
# ${NMAP_T#T} quita el prefijo "T" → -T5 (nmap exige la forma -T<número>)
# Cobertura: --top-ports 1000 (RE-MODIFICADO 2026-08-31 por usuario: "scan más rápido".
# El full 1-65535 con -sT sobre VPN de 15ms RTT tardaba >5min por puertos filtrados.
# Top-1000 = baseline original del pipeline; suficiente para recon de infra.)
nmap -sT --top-ports 1000 -T${NMAP_T#T} --max-rate "$NMAP_RATE" \
  --max-retries "$NMAP_RETRIES" \
  --initial-rtt-timeout "${NMAP_INIT_RTT}ms" \
  --max-rtt-timeout "${NMAP_MAX_RTT}ms" \
  --open -Pn \
  -oX "$EVID/nmap_ports.xml" \
  -oN "$EVID/nmap_ports.txt" \
  -oG "$EVID/nmap_ports.gnmap" \
  "$TARGET"
NMAP_EXIT=$?
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_ports.xml" "$EVID/nmap_ports.json"
echo "STEP1_HOST_EXIT=$NMAP_EXIT JSON_DERIVED_ok"