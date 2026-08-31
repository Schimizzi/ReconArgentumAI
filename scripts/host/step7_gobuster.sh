#!/bin/bash
# Step 7 MODO HOST — Gobuster dir (1 por endpoint web, secuencial)
# Uso: step7_gobuster.sh <TARGET> <URL> <PORT>
# Wordlist: descarga common.txt de SecLists a tools/ cache si no existe.
set -uo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"; URL="$2"; PORT="$3"
EVID="$WORKSPACE/evidence/$TARGET"
WORDLIST="$WORKSPACE/tools/seclists_common.txt"
mkdir -p "$WORKSPACE/tools"
if [ ! -s "$WORDLIST" ]; then
  echo "Descargando wordlist common.txt de SecLists…"
  curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o "$WORDLIST"
fi
gobuster dir \
  -u "$URL" \
  -w "$WORDLIST" \
  -o "$EVID/gobuster_${PORT}.txt" \
  -t 3 \
  --timeout 10s \
  -s 200,204,301,307,403 \
  -b '' \
  --force \
  -x txt,bak,old,zip
echo "STEP7_HOST_OK port=${PORT}"