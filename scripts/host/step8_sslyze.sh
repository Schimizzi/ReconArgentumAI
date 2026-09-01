#!/bin/bash
# Step 8 MODO HOST — SSLyze (1 por puerto TLS, secuencial) — OPTIMIZACIÓN MULTIPROTOCOLO
# Uso: step8_sslyze.sh <TARGET> <TLS_PORT> [tls|starttls] [STARTTLS_PROTO]
#   tls       → handshake TLS directo (https, imaps, smtps, ldaps, 443, 993, 990, ...)
#   starttls  → STARTTLS sobre servicio plano (rdp, smtp, imap, pop3, ftp, ldap, postgres)
# Evidencia: sslyze_<port>.json en <EVID>.
set -euo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; PORT="$2"
MODE="${3:-tls}"; STARTPROTO="${4:-}"
EVID="$WORKSPACE/evidence/$TARGET"
mkdir -p "$EVID"
ARGS=()
if [ "$MODE" = "starttls" ] && [ -n "$STARTPROTO" ]; then
  ARGS+=(--starttls "$STARTPROTO")
fi
# FIX RUN#5 (2026-09-01): en Bash 3.2 (macOS) + set -u, "${ARGS[@]}" con array
# vacio → "unbound variable" y el puerto TLS directo quedaba SIN escanear (visto: 8443 t1,  ​5986 t5).
# "${ARGS[@]+"${ARGS[@]}"}}" expande a cero args si el array está vacio(compat Bash 3.2/4.x).
sslyze "${TARGET}:${PORT}" \
  "${ARGS[@]+"${ARGS[@]}"}" \
  --json_out "$EVID/sslyze_${PORT}.json" \
  --quiet \
  --certinfo
echo "STEP8_HOST_OK port=${PORT} mode=${MODE} starttls=${STARTPROTO:-}"