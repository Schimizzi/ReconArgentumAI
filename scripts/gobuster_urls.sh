#!/bin/bash
# gobuster_urls.sh — Lista plana de URLs para inyectar en scripts con curl
# Lee TODOS los CLIENTE/*/outputs/gobuster_*.txt y genera, en la raiz de CLIENTE/
# (o en $2 si se pasa), un archivo con una URL completa por linea: <scheme>://<IP>:<PORT>/<path>
#
# Uso: gobuster_urls.sh [PROYECTO] [SALIDA]
#   PROYECTO  directorio raiz con los outputs/ por target (default: CLIENTE)
#   SALIDA    archivo de salida (default: <PROYECTO>/gobuster_urls_curl.txt)
#
# Cada URL se reconstruye cruzando:
#   path   -> 1a columna de cada linea gobuster_<PORT>.txt (se ignoran banners/comentarios)
#   IP     -> nombre del directorio target  (10.155.10.15_vuln -> 10.155.10.15)
#   PORT   -> nombre del archivo            (gobuster_8089.txt  -> 8089)
#   scheme -> http por defecto; https si httpx.json (outputs/ o evidence/<IP>/)
#             confirma el puerto como https.
set -euo pipefail
WORKSPACE="$(pwd)"
PROY="${1:-CLIENTE}"
OUT="${2:-$PROY/gobuster_urls_curl.txt}"

: > "$OUT"

for f in "$PROY"/*/outputs/gobuster_*.txt; do
  [ -f "$f" ] || continue
  tgt=$(basename "$(dirname "$(dirname "$f")")")
  ip=${tgt%%_*}
  port=$(basename "$f" | sed -E 's/^gobuster_([0-9]+)\.txt$/\1/')

  # scheme desde httpx.json (outputs/ o evidence/<IP>/ como fallback)
  H=""
  if [ -f "$PROY/$tgt/outputs/httpx.json" ]; then
    H="$PROY/$tgt/outputs/httpx.json"
  elif [ -f "$WORKSPACE/evidence/$ip/httpx.json" ]; then
    H="$WORKSPACE/evidence/$ip/httpx.json"
  fi
  scheme=http
  if [ -n "$H" ] && grep -q "\"url\":\"https://$ip:$port" "$H"; then
    scheme=https
  fi

  # cada linea gobuster: <path> <rest>; se descartan banners/vacíos
  while read -r path rest; do
    [ -n "$path" ] || continue
    case "$path" in
      \#*|Running|Starting) continue ;;
    esac
    echo "$scheme://$ip:$port/$path"
  done < "$f"
done | sort -u > "$OUT"

echo "OK: $(wc -l < "$OUT") URLs unicas en $OUT"