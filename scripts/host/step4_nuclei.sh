#!/bin/bash
# Step 4 MODO HOST — Nuclei (set default filtrado por severidad) — OPTIMIZACIÓN MULTIPROTOCOLO
# Uso: step4_nuclei.sh <TARGET>
# INPUT: open_ports.txt (IP:PORT por línea) — NO web_endpoints.txt.
# Nuclei es multiprotocolo: aplica plantillas de RED/SSH/DNS/TLS a todos los puertos abiertos
# y las web a los puertos HTTP(S). Se ejecuta SIEMPRE que haya ≥1 puerto abierto.
# Requiere templates de nuclei (descarga automática en el 1er run: nuclei -ut).
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
if [ ! -s "$EVID/open_ports.txt" ]; then echo "open_ports.txt vacío → skipped_no_ports"; exit 1; fi
# R5: rate/timeout/bulk/retries/max-host-error/concurrency resueltos desde config/stealth.yaml
# (RUN#3 2026-08-31: ACELERADO por usuario — timeout 5, retries 0, mhe 3, rl 100, c 25)
RL=$(awk '/^nuclei_rate_limit:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TO=$(awk '/^nuclei_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
BS=$(awk '/^nuclei_bulk_size:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RT=$(awk '/^nuclei_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
MHE=$(awk '/^nuclei_max_host_error:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
CC=$(awk '/^nuclei_concurrency:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RL="${RL:-100}"; TO="${TO:-5}"; BS="${BS:-15}"; RT="${RT:-0}"; MHE="${MHE:-3}"; CC="${CC:-25}"
nuclei -l "$EVID/open_ports.txt" \
  -o "$EVID/nuclei.json" \
  -jsonl \
  -rl "$RL" \
  -timeout "$TO" \
  -retries "$RT" \
  -mhe "$MHE" \
  -bs "$BS" \
  -c "$CC" \
  -s critical,high,medium
echo "STEP4_HOST_OK findings=$(wc -l < "$EVID/nuclei.json")"