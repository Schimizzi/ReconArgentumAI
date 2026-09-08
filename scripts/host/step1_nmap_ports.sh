#!/bin/bash
# Step 1 UNIFICADO — Nmap port scan COMPLETO (scan type autodetectado)
# Uso: step1_nmap_ports.sh <IP>
# UNIFICACIÓN KALI/DOCKER (2026-09-07): el scan type se resuelve automáticamente:
#   - EUID == 0 (root: VM Kali, contenedor del Dockerfile) → -sS (SYN, raw sockets)
#   - EUID != 0 (host macOS sin sudo)                        → -sT (TCP Connect)
# Así el MISMO script corre en host, VM Kali y contenedor, sin editar comandos.
# MODIFICADO PERMANENTE RUN#8 (MODE HOST, Fase 0 aprobada por el usuario):
#   - Se ELIMINAN -T5 y --max-rate del paso del 1 (timing/rate default de Nmap).
#   - Se agrega -n (sin resolución DNS).
# MODIFICADO CLIENTE (2026-09-07, pedido del usuario): el Step 1 escanea con la
#   lista `clienteP` de config/stealth.yaml (98 puertos de este cliente) en lugar
#   de --top-ports 1000. Si clienteP no existe/vacía -> fallback a --top-ports 1000.
# Workaround -oJ (nmap 7.99 arm64 de Kali): deriva JSON desde XML con
# scripts/xml_to_nmap_json.py (consistencia de evidencia en todos los modos).
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
rm -f "$EVID"/nmap_ports.* "$EVID/open_ports.txt"
# Scan type autodetectado por privilegios (R5: nada hardcodeado en el comando base).
if [ "$(id -u)" -eq 0 ]; then SCAN="-sS"; else SCAN="-sT"; fi
# R5: retries/rtt resueltos desde config/stealth.yaml (prohibido hardcodear).
NMAP_RETRIES=$(awk '/^nmap_max_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_INIT_RTT=$(awk '/^nmap_initial_rtt_timeout_ms:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_MAX_RTT=$(awk '/^nmap_max_rtt_timeout_ms:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
NMAP_RETRIES="${NMAP_RETRIES:-1}"
NMAP_INIT_RTT="${NMAP_INIT_RTT:-200}"; NMAP_MAX_RTT="${NMAP_MAX_RTT:-800}"
# Cobertura (CLIENTE 2026-09-07): usa la lista `clienteP` desde config/stealth.yaml.
#   - Si clienteP está definido -> nmap -p <clienteP> (98 puertos del cliente).
#   - Si no -> fallback a --top-ports 1000 (baseline Fase 0).
# -n = sin resolución DNS (MODIFICADO PERMANENTE RUN#8 a pedido del usuario).
CLIENTE_PORTS=$(awk '/^clienteP:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
if [ -n "${CLIENTE_PORTS:-}" ]; then
  PORT_ARGS=(-p "$CLIENTE_PORTS")
  PORT_LABEL="lista-clienteP ($(awk -F, '{print NF}' <<<"$CLIENTE_PORTS") puertos)"
else
  PORT_ARGS=(--top-ports 1000)
  PORT_LABEL="--top-ports 1000 (fallback)"
fi
nmap "$SCAN" "${PORT_ARGS[@]}" -Pn -n \
  --max-retries "$NMAP_RETRIES" \
  --initial-rtt-timeout "${NMAP_INIT_RTT}ms" \
  --max-rtt-timeout "${NMAP_MAX_RTT}ms" \
  --open \
  -oX "$EVID/nmap_ports.xml" \
  -oN "$EVID/nmap_ports.txt" \
  -oG "$EVID/nmap_ports.gnmap" \
  "$TARGET"
NMAP_EXIT=$?
python3 "$WORKSPACE/scripts/xml_to_nmap_json.py" "$EVID/nmap_ports.xml" "$EVID/nmap_ports.json"
echo "STEP1_HOST_EXIT=$NMAP_EXIT JSON_DERIVED_ok ports=$PORT_LABEL"