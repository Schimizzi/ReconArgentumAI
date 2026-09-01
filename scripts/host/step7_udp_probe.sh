#!/bin/bash
# Step 7 aux — PROBE UDP 69 (TFTP) — OPTIMIZACIÓN MULTIPROTOCOLO 2026-08-31
# Uso: step7_udp_probe.sh <TARGET>
# Decide si el puerto 69/UDP está abierto para habilitar el modo `tftp` de Gobuster.
# R5: rate/retries/rtt resueltos desde config/stealth.yaml (NUNCA hardcodeados).
# Evidencia: <EVID>/udp_69.gnmap (output crudo) + readiness detectado por el runner
#            (grep de "69/udp.*open").
set -uo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
# R5: puerto, rate y retries desde config/stealth.yaml
UDPPORT=$(awk '/^nmap_udp_probe_port:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
UDPPORT="${UDPPORT:-69}"
RATE=$(awk '/^nmap_max_rate:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RETRIES=$(awk '/^nmap_max_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RATE="${RATE:-5000}"; RETRIES="${RETRIES:-1}"
nmap -sU -p "$UDPPORT" -Pn --max-rate "$RATE" --max-retries "$RETRIES" \
  -oG "$EVID/udp_69.gnmap" "$TARGET" >/dev/null 2>&1
# reporta 0 si abierto, 1 si no (para el runner)
if grep -qE "${UDPPORT}/udp.*open" "$EVID/udp_69.gnmap" 2>/dev/null; then
  echo "STEP7_UDP_OPEN port=$UDPPORT"
  exit 0
else
  echo "STEP7_UDP_CLOSED port=$UDPPORT"
  exit 1
fi