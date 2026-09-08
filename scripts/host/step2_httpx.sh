#!/bin/bash
# Step 2 MODO HOST — HTTPX probe web (binario ProjectDiscovery httpx-pd)
# Uso: step2_httpx.sh <TARGET>
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
# R5: timeout/retries/threads resueltos desde config/stealth.yaml (prohibido hardcodear)
TO=$(awk '/^httpx_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
RT=$(awk '/^httpx_retries:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TH=$(awk '/^httpx_threads:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TO="${TO:-10}"; RT="${RT:-1}"; TH="${TH:-5}"
# Resolución del binario de probe HTTP (prioridad: httpx-toolkit → httpx-pd → httpx).
# En Kali Linux el binario de ProjectDiscovery se llama `httpx-toolkit` (Kali renombra
# los binarios PD que chocan con paquetes Python). En macOS/contenedor Docker se usa
# `httpx-pd`. El `httpx` del PATH (cliente HTTP de Python) NUNCA sirve para probe: solo
# se acepta como fallback si realmente soporta `-l` (o sea, es el PD real).
HTT=""
if command -v httpx-toolkit >/dev/null 2>&1; then HTT=httpx-toolkit
elif command -v httpx-pd >/dev/null 2>&1; then HTT=httpx-pd
elif command -v httpx >/dev/null 2>&1 && httpx -h 2>&1 | grep -qE -- '-l,| -list'; then HTT=httpx
fi
if [ -z "$HTT" ]; then
  echo "ERROR: no se encontró httpx-toolkit / httpx-pd (ProjectDiscovery)." >&2
  echo "       El 'httpx' del PATH en Kali es el cliente Python y NO sirve para probe." >&2
  echo "       Instalá el binario PD: go install github.com/projectdiscovery/httpx/cmd/httpx@latest" >&2
  exit 1
fi
"$HTT" -l "$EVID/open_ports.txt" \
  -o "$EVID/httpx.json" \
  -json \
  -timeout "$TO" \
  -retries "$RT" \
  -t "$TH"
# FIX KALI 2026-09-07 (RUN#12 Prisma): dedupe con sort -u. HTTPX sigue redirects por
# default (ej. 80→443) y registra la MISMA dirección final 2 veces (evidencia
# 10.2.0.28: httpx.json con 2 entradas https://IP:443). Sin dedupe, los Steps 5 (Nikto)
# y 7 (Gobuster) escaneaban por duplicado (≈12 min extra por target).
jq -r '.url // empty' "$EVID/httpx.json" | grep -E '^https?://' | sort -u > "$EVID/web_endpoints.txt"
echo "STEP2_HOST_OK binario=$HTT urls=$(wc -l < "$EVID/web_endpoints.txt")"