#!/bin/bash
# Step 6 MODO HOST — WhatWeb (fingerprinting tech)
# Uso: step6_whatweb.sh <TARGET>
# WhatWeb NO tiene fórmula Homebrew: se instala por git clone en tools/WhatWeb.
# El script usa el binario local si `whatweb` no está en el PATH.
# NOTA (verificado 2026-08-30 en v0.6.4): -a solo acepta 1, 3 o 4. NO existe -a 2.
set -uo pipefail
WORKSPACE="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WORKSPACE/evidence/$TARGET"
WWBIN="$(command -v whatweb || echo "$WORKSPACE/tools/WhatWeb/whatweb")"
if [ ! -x "$WWBIN" ]; then echo "ERROR: whatweb no encontrado (instalarlo en tools/WhatWeb)"; exit 1; fi
if [ ! -s "$EVID/web_endpoints.txt" ]; then echo "web_endpoints.txt vacío → skipped"; exit 1; fi
rm -f "$EVID/whatweb.json"   # WhatWeb --log-json es append-only; limpiar antes
"$WWBIN" -i "$EVID/web_endpoints.txt" \
  --log-json="$EVID/whatweb.json" \
  -a 1 \
  --open-timeout 10 \
  --read-timeout 20 \
  --max-threads 5
echo "STEP6_HOST_OK (binario: $WWBIN)"