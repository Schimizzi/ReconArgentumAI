#!/bin/bash
# Step 7 MODO HOST — Gobuster (multiprotocolo) — OPTIMIZACIÓN MULTIPROTOCOLO 2026-08-31
# Uso: step7_gobuster.sh <TARGET> <URL|DOMINIO|IP> <PORT|0> <MODE>
#   MODE=dir  → gobuster dir  sobre URL web
#   MODE=dns  → gobuster dns  sobre dominio (target es un dominio, no IP)
#   MODE=tftp → gobuster tftp sobre IP (puerto 69/UDP abierto)
# MODIFICADO RUN#3 (2026-08-31): CUTOFF de tiempo (gobuster_max_seconds desde
# stealth.yaml; default 180). Si gobuster no termina antes del cutoff se mata el
# proceso y se devuelve FAIL (el runner marca failed y continúa). Motivación:
# servers web que NO responden a dict requests (timeouts en ~23.7k requests =
# horas) bloquearon el step7 en 10.10.10.154/153.
# EVOLUCIÓN del subshell con wait: la evidencia gobuster_*.txt se escribe igual.
set -uo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; ARG="$2"; PORT="$3"; MODE="$4"
EVID="$WORKSPACE/evidence/$TARGET"
WEB_LIST="${HOME}/Documents/SecLists/Discovery/Web-Content/common.txt"
DNS_LIST="${HOME}/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
TH=$(awk '/^gobuster_threads:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TO=$(awk '/^gobuster_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
CUT=$(awk '/^gobuster_max_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml")
TH="${TH:-3}"; TO="${TO:-10}"; CUT="${CUT:-180}"

# run_cutoff: ejecuta "$@" con cutoff; si vence, mata gobuster (y cualquier hijo)
# y devuelve 1 (FAIL). FIX huérfanos: kill indirecto al subshell dejaba gobuster vivo;
# ahora pkill -9 del binario gobuster del modo en curso (R3: solo hay 1 por vez).
run_cutoff() {
  local rcfile="$EVID/.go_rc" waited=0
  rm -f "$rcfile"
  ( "$@" ; echo "$?" > "$rcfile" ) &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 5
    waited=$((waited + 5))
    if [ "$waited" -ge "$CUT" ]; then
      pkill -9 -f "gobuster ${MODE}" 2>/dev/null
      kill -9 "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      echo "STEP7_HOST_TIMEOUT_ENFORCED cutoff=${CUT}s (server no respondio a dict requests)" >&2
      rm -f "$rcfile"
      return 1
    fi
  done
  wait "$pid" 2>/dev/null
  local rc=1
  [ -f "$rcfile" ] && rc=$(cat "$rcfile")
  rm -f "$rcfile"
  return "$rc"
}

case "$MODE" in
  dir)
    if [ ! -s "$WEB_LIST" ]; then echo "ERROR: wordlist web no encontrada en $WEB_LIST" >&2; exit 1; fi
    if ! run_cutoff gobuster dir \
      -u "$ARG" \
      -w "$WEB_LIST" \
      -o "$EVID/gobuster_${PORT}.txt" \
      -t "$TH" \
      --timeout "${TO}s" \
      -s 200,204,301,307,403 \
      -b '' \
      --force \
      -x txt,bak,old,zip; then
      echo "STEP7_HOST_FAIL mode=dir port=${PORT}" >&2
      exit 1
    fi
    echo "STEP7_HOST_OK mode=dir port=${PORT}"
    ;;
  dns)
    if [ ! -s "$DNS_LIST" ]; then echo "ERROR: wordlist dns no encontrada en $DNS_LIST" >&2; exit 1; fi
    DOMAIN=$(printf '%s' "$ARG" | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||; s|[/?#].*$||')
    if ! run_cutoff gobuster dns \
      -d "$DOMAIN" \
      -w "$DNS_LIST" \
      -o "$EVID/gobuster_dns.txt" \
      -t "$TH" \
      --timeout "${TO}s"; then
      echo "STEP7_HOST_FAIL mode=dns domain=$DOMAIN" >&2
      exit 1
    fi
    echo "STEP7_HOST_OK mode=dns domain=$DOMAIN"
    ;;
  tftp)
    if [ ! -s "$WEB_LIST" ]; then echo "ERROR: wordlist web no encontrada en $WEB_LIST" >&2; exit 1; fi
    if [ "$PORT" != "0" ] && [ "$PORT" != "69" ]; then
      echo "NOTA: modo tftp llamada con PORT=$PORT (esperado 69/UDP)" >&2
    fi
    if ! run_cutoff gobuster tftp \
      -s "$ARG" \
      -w "$WEB_LIST" \
      -o "$EVID/gobuster_tftp.txt" \
      -t "$TH" \
      --timeout "${TO}s"; then
      echo "STEP7_HOST_FAIL mode=tftp host=$ARG" >&2
      exit 1
    fi
    echo "STEP7_HOST_OK mode=tftp host=$ARG"
    ;;
  *)
    echo "ERROR: MODE desconocido '$MODE' (dir|dns|tftp)" >&2
    exit 1
    ;;
esac