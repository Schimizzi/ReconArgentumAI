#!/bin/bash
# ===========================================================================
# run_target.sh — Orquestador MODO HOST por target (DAG 8 steps / 7 tools)
# Uso: run_target.sh <TARGET_IP>
# Respeta R1 (scope), R3 (delays 30s entre tools), R4 (evidencia completa),
# y el retry 1x de la spec (§5). Genera evidence/<target> + manifest.json.
# ===========================================================================
set -uo pipefail
WS="${WORKSPACE:-$(pwd)}"
TARGET="$1"
EVID="$WS/evidence/$TARGET"

# --- R1: target en scope ----------------------------------------------------
in_scope=0
jq -e --arg ip "$TARGET" '.authorized_targets[] | select(.ip == $ip)' "$WS/config/scope.json" >/dev/null 2>&1 && in_scope=1
excluded=0
jq -e --arg ip "$TARGET" '.excluded_ips[] | select(. == $ip)' "$WS/config/scope.json" >/dev/null 2>&1 && excluded=1
if [ "$in_scope" -eq 0 ] || [ "$excluded" -eq 1 ]; then
  echo "❌ R1-FAIL: $TARGET no está en scope o está excluido. Abortando." >&2
  exit 1
fi

mkdir -p "$EVID"

# R3 hardening (FIX 2026-08-31): lock por target. Dos run_target.sh concurrentes sobre
# el mismo target corrompieron web_endpoints.txt (URL leída como "40.50:443") y la
# evidencia nikto. mkdir es atómico: si el lock ya existe, la 2ª instancia aborta.
LOCKDIR="$EVID/.run.lock"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "❌ R3-FAIL ($(date +%H:%M:%S)): otro pipeline está corriendo sobre $TARGET. Abortando (lock $LOCKDIR)." >&2
  exit 1
fi
trap 'rm -rf "$LOCKDIR"' EXIT

STARTED=$(date +"%Y-%m-%dT%H:%M:%S%z")
DELAY_TOOLS=$(grep '^delay_between_tools_seconds' "$WS/config/stealth.yaml" | awk '{print $2}')
DELAY_TOOLS="${DELAY_TOOLS:-30}"
TARGET_ID=$(jq -r --arg ip "$TARGET" '.authorized_targets[] | select(.ip == $ip) | .id' "$WS/config/scope.json" 2>/dev/null | head -1)
TARGET_ID="${TARGET_ID:-$TARGET}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Parser robusto de puerto desde URL. FIX 2026-08-31: la regex anterior tomaba dígitos
# de la IP (ej. "150" de 10.150.40.50) generando archivos nikto_150.json.
url_port() {
  case "$1" in
    http://*:*)  echo "$1" | sed -E 's|^http://[^:]+:([0-9]+).*|\1|' ;;
    https://*:*) echo "$1" | sed -E 's|^https://[^:]+:([0-9]+).*|\1|' ;;
    http://*)    echo 80 ;;
    https://*)   echo 443 ;;
    *) echo 80 ;;
  esac
}

run_nikto_cutoff() {
  # Watchdog para nikto: algunos servers HTTP (ej. ESXi httpd) IGNORAN -maxtime y
  # cuelgan >5min (RUN#6/7). Cutoff = nikto_maxtime_seconds x3 (R5, no hardcodeado).
  local rcf="$EVID/.nikto_rc" waited=0
  local base=$(awk '/^nikto_maxtime_seconds:/ {print $2; exit}' "$WS/config/stealth.yaml")
  base="${base:-30}"
  local cut=$((base * 3))
  rm -f "$rcf"
  ( "$@" ; echo "$?" > "$rcf" ) &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 5; waited=$((waited+5))
    if [ "$waited" -ge "$cut" ]; then
      pkill -9 -f "nikto -h" 2>/dev/null; kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      echo "NIKTO_WATCHDOG_KILL timeout=${cut}s (server ignoro -maxtime)" >&2
      rm -f "$rcf"; return 1
    fi
  done
  wait "$pid" 2>/dev/null; local rc=1
  [ -f "$rcf" ] && rc=$(cat "$rcf")
  rm -f "$rcf"; return "$rc"
}

run_retry() {
  local name="$1"; shift
  if "$@" >>"$EVID/_step.log" 2>&1; then
    echo OK
  else
    echo "[$(date +%H:%M:%S)] [WARN] $name fallo en 1er intento; retry 1x..." >&2
    sleep 5
    if "$@" >>"$EVID/_step.log" 2>&1; then echo OK_RETRY; else echo FAIL; fi
  fi
}

# ---- Step 1: Nmap port scan --------------------------------------------------
log "Step 1/8 - Nmap port scan --top-ports 1000 (-sT, -Pn -n, timing/rate default de Nmap) sobre $TARGET"
R1=$(run_retry nmap_ports bash "$WS/scripts/host/step1_nmap_ports.sh" "$TARGET")

# ---- Post-proceso Step 1: open_ports.txt -------------------------------------
if [ ! -s "$EVID/nmap_ports.json" ]; then
  # el JSON puede no haberse derivado; generarlo desde el XML si existe
  python3 "$WS/scripts/xml_to_nmap_json.py" "$EVID/nmap_ports.xml" "$EVID/nmap_ports.json" 2>/dev/null || true
fi
jq -r '(.scan | keys[]) as $t | .scan[$t].tcp | to_entries[] |
  select(.value.state == "open") | "\($t):\(.key)"' "$EVID/nmap_ports.json" 2>/dev/null > "$EVID/open_ports.txt" || true

NPORTS=$(wc -l < "$EVID/open_ports.txt" 2>/dev/null || echo 0)
if [ "$NPORTS" -eq 0 ]; then
  log "ℹ️  Sin puertos abiertos (--top-ports 1000) → target incomplete."
  cat > "$EVID/manifest.json" <<EOF
{
  "target": "$TARGET",
  "target_id": "$TARGET_ID",
  "started_at": "$STARTED",
  "status": "incomplete",
  "notes": "Sin puertos abiertos (--top-ports 1000 aprobado, Step 1). Steps 2-8 skipped (Service-Based Routing).",
  "tools_executed": [
    {"step": 1, "tool": "nmap_ports", "status": "$R1", "output": ["nmap_ports.json", "nmap_ports.xml", "nmap_ports.txt", "nmap_ports.gnmap", "open_ports.txt"]},
    {"step": 2, "tool": "httpx", "status": "skipped_no_ports", "output": []},
    {"step": 3, "tool": "nmap_detailed", "status": "skipped_no_ports", "output": []},
    {"step": 4, "tool": "nuclei", "status": "skipped_no_ports", "output": []},
    {"step": 5, "tool": "nikto", "status": "skipped_no_web", "output": []},
    {"step": 6, "tool": "whatweb", "status": "skipped", "output": []},
    {"step": 7, "tool": "gobuster", "status": "skipped_no_web", "output": []},
    {"step": 8, "tool": "sslyze", "status": "skipped_no_tls", "output": []}
  ],
  "out_of_scope_findings": [],
  "errors": []
}
EOF
  echo "TARGET_FASE1_INCOMPLETE $TARGET"
  exit 0
fi
log "✅ Puertos abiertos: $(tr '\n' ' ' < "$EVID/open_ports.txt")"
sleep "$DELAY_TOOLS"
# ---- Step 2: HTTPX probe -----------------------------------------------------
log "Step 2/8 — HTTPX probe web"
R2=$(run_retry httpx bash "$WS/scripts/host/step2_httpx.sh" "$TARGET")

# post-proceso: web_endpoints.txt desde httpx.json
if [ -s "$EVID/httpx.json" ]; then
  jq -r '.url // empty' "$EVID/httpx.json" 2>/dev/null | grep -E '^https?://' > "$EVID/web_endpoints.txt" || true
fi
WURLS=$(wc -l < "$EVID/web_endpoints.txt" 2>/dev/null || echo 0)
log "✅ Endpoints web: ${WURLS}"
sleep "$DELAY_TOOLS"

# ---- Step 3: Nmap detallado (siempre, sobre open_ports) ----------------------
log "Step 3/8 — Nmap -sT -sC -sV detallado (solo puertos abiertos)"
R3=$(run_retry nmap_detailed bash "$WS/scripts/host/step3_nmap_detailed.sh" "$TARGET")
# ---- Steps 4-8: Service-Based Routing (Optimización Multiprotocolo 2026-08-31) ----
web_on() { [ "${WURLS:-0}" -gt 0 ]; }

STATUS4=skipped_no_ports; STATUS5=skipped_no_web; STATUS6=skipped
STATUS7=skipped_no_web; STATUS8=skipped_no_tls
OUT4='[]'; OUT5='[]'; OUT6='[]'; OUT7='[]'; OUT8='[]'

# ---- Step 4: Nuclei — SIEMPRE (multiprotocolo) sobre open_ports.txt ----------------
# Nuclei ya NO depende de web_endpoints.txt. Apunta a IP:PORT para aplicar plantillas
# de red/SSH/DNS/TLS además de las web. (Optimización Multiprotocolo 2026-08-31)
if [ "$NPORTS" -gt 0 ]; then
  log "Step 4/8 — Nuclei (multiprotocolo, sobre open_ports.txt)"
  R4=$(run_retry nuclei bash "$WS/scripts/host/step4_nuclei.sh" "$TARGET")
  STATUS4=success; [ "$R4" = FAIL ] && STATUS4=failed
  sleep "$DELAY_TOOLS"
else
  STATUS4=skipped_no_ports
fi

if web_on; then
  log "Step 5/8 — Nikto (solo web, por endpoint, secuencial)"
  STATUS5=success
  # FIX ROOT-CAUSE 2026-08-31: cargar las URLs UNA vez a un array ANTES del loop.
  # Un `while read < archivo` compartia el fd con los hijos (nikto lee stdin) y el
  # offset avanzaba -> lineas 'tornadas' (ej. '.155.10.15:8085'). Con array (construido
  # en parent shell, compatible bash 3.2) no hay fd compartido con los hijos.
  URLS=()
  while IFS= read -r _u; do URLS+=("$_u"); done < "$EVID/web_endpoints.txt"
  for URL in "${URLS[@]}"; do
    # FIX 2026-08-31: validar URL antes de pasarla a nikto. Una línea corrupta (ej.
    # "40.50:443") nunca debe generar evidencia hacia un host mutilado.
    case "$URL" in
      http://*|https://*) : ;;
      *)
        log "⚠️  [step5] URL malformada en web_endpoints.txt → omitida y documentada: '$URL'"
        echo "[step5] URL malformada omitida: $URL" >> "$EVID/_errors.log"
        STATUS5=failed
        continue ;;
    esac
    PORT=$(url_port "$URL")
    log "  → nikto $URL (puerto $PORT)"
    R=$(run_retry "nikto:$URL" run_nikto_cutoff bash "$WS/scripts/host/step5_nikto.sh" "$TARGET" "$URL" "$PORT" </dev/null)
    [ "$R" = FAIL ] && STATUS5=failed
  done < "$EVID/web_endpoints.txt"
  sleep "$DELAY_TOOLS"

  log "Step 6/8 — WhatWeb: SALTADO por usuario (Fase 0 DREAMCO-2026; no instalado)"
  STATUS6=skipped   # SALTADO por usuario (approved_commands.md); no se ejecuta
  sleep "$DELAY_TOOLS"
else
  STATUS5=skipped_no_web
  STATUS6=skipped
fi

# ---- Step 7: Gobuster — multi-modo dir/dns/tftp ------------------------------------
log "Step 7/8 — Gobuster (Service-Based: dir si web, dns si dominio, tftp si UDP69)"
STATUS7=skipped_no_web
RAN7=0; FAILED7=0

# es_IP(): detectar IP cruda vs dominio
es_IP() { echo "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; }

# -- Modo DNS: solo si el target es un dominio (no IP cruda) --
if ! es_IP "$TARGET"; then
  log "  → gobuster dns $TARGET (target es dominio)"
  R=$(run_retry "gobuster:dns" bash "$WS/scripts/host/step7_gobuster.sh" "$TARGET" "$TARGET" "0" "dns" </dev/null)
  RAN7=1
  if [ "$R" = FAIL ]; then FAILED7=1; fi
else
  log "  → gobuster dns: skipped (target es IP, no dominio)"
  [ "$STATUS7" = "skipped_no_web" ] && STATUS7=skipped_no_domain
fi
sleep "$DELAY_TOOLS"

# -- Modo TFTP: probe UDP 69 (si está habilitado en stealth.yaml) --
UDPPROBE=$(awk '/^udp_probe_enabled:/ {print $2; exit}' "$WS/config/stealth.yaml")
UDPPROBE="${UDPPROBE:-true}"
if [ "$UDPPROBE" = "true" ] && es_IP "$TARGET"; then
  log "  → probe UDP 69 (TFTP)"
  if bash "$WS/scripts/host/step7_udp_probe.sh" "$TARGET" >>"$EVID/_step.log" 2>&1; then
    log "    → UDP 69 abierto: gobuster tftp $TARGET"
    R=$(run_retry "gobuster:tftp" bash "$WS/scripts/host/step7_gobuster.sh" "$TARGET" "$TARGET" "69" "tftp" </dev/null)
    RAN7=1
    if [ "$R" = FAIL ]; then FAILED7=1; fi
  else
    log "    → UDP 69 cerrado/filtrado"
    [ "$STATUS7" = "skipped_no_web" ] && STATUS7=skipped_no_tftp
  fi
else
  [ "$STATUS7" = "skipped_no_web" ] && STATUS7=skipped_no_tftp
fi
sleep "$DELAY_TOOLS"

# -- Modo DIR: solo si hay Web --
if web_on; then
  URLS=()
  while IFS= read -r _u; do URLS+=("$_u"); done < "$EVID/web_endpoints.txt"
  for URL in "${URLS[@]}"; do
    case "$URL" in
      http://*|https://*) : ;;
      *)
        log "⚠️  [step7] URL malformada en web_endpoints.txt → omitida y documentada: '$URL'"
        echo "[step7] URL malformada omitida: $URL" >> "$EVID/_errors.log"
        FAILED7=1
        continue ;;
    esac
    PORT=$(url_port "$URL")
    log "  → gobuster dir $URL (puerto $PORT)"
    R=$(run_retry "gobuster:$URL" bash "$WS/scripts/host/step7_gobuster.sh" "$TARGET" "$URL" "$PORT" "dir" </dev/null)
    RAN7=1
    [ "$R" = FAIL ] && FAILED7=1
  done < "$EVID/web_endpoints.txt"
fi
sleep "$DELAY_TOOLS"

# Estado final de Gobuster: si corrió algún modo → success|failed; si ninguno → skipped_*
if [ "$RAN7" -eq 1 ]; then
  if [ "$FAILED7" -eq 1 ]; then STATUS7=failed; else STATUS7=success; fi
elif [ "$FAILED7" -eq 1 ]; then
  STATUS7=failed
fi

# ---- Step 8: SSLyze — puertos TLS detectados por Nmap (Step 3) ----------------------
log "Step 8/8 — SSLyze (puertos TLS del Step 3, Service-Based)"
STATUS8=skipped_no_tls
TLS_LINES=$(python3 "$WS/scripts/host/detect_tls_ports.py" "$EVID" --with-starttls 2>/dev/null || true)
if [ -n "$TLS_LINES" ]; then
  STATUS8=success
  while IFS=' ' read -r TPORT TSVC TMODE TSTARTPROTO; do
    [ -z "$TPORT" ] && continue
    log "  → sslyze $TARGET:$TPORT (${TMODE} ${TSTARTPROTO})"
    R=$(run_retry "sslyze:$TPORT" bash "$WS/scripts/host/step8_sslyze.sh" "$TARGET" "$TPORT" "$TMODE" "$TSTARTPROTO" </dev/null)
    [ "$R" = FAIL ] && STATUS8=failed
  done <<< "$TLS_LINES"
fi
sleep "$DELAY_TOOLS"
# ---- Manifest ----------------------------------------------------------------
STATE1=success; [ "$R1" = FAIL ] && STATE1=failed
STATE2=success; [ "$R2" = FAIL ] && STATE2=failed
STATE3=success; [ "$R3" = FAIL ] && STATE3=failed
COMPLETED=$(date +"%Y-%m-%dT%H:%M:%S%z")

# errors: array (schema spec §6). Se llena si existe _errors.log (líneas reales de error).
if [ -s "$EVID/_errors.log" ]; then
  ERRORS_JSON=$(python3 -c 'import json,sys; print(json.dumps([l.strip() for l in open(sys.argv[1],"r",errors="ignore").readlines() if l.strip()], indent=False))' "$EVID/_errors.log")
else
  ERRORS_JSON="[]"
fi

mkjson() {
  # FIX 2026-08-31: la versión anterior dejaba un elemento "" colgado. Esta versión
  # normaliza (sin trailing space) y produce un array JSON limpio.
  _OUT=$(cd "$EVID" && ls $1 2>/dev/null | sed '/^$/d' | tr '
' ' ' | sed 's/[[:space:]]*$//')
  if [ -z "${_OUT:-}" ]; then printf '[]'; return; fi
  printf '["%s"]' "$(printf '%s' "$_OUT" | sed 's/ /","/g')"
}
OUT1=$(mkjson 'nmap_ports.* open_ports.txt')
OUT2=$(mkjson 'httpx.json web_endpoints.txt')
OUT3=$(mkjson 'nmap_detailed.*')
OUT4=$(mkjson 'nuclei.json'); OUT5=$(mkjson 'nikto_*.json')
OUT6=$(mkjson 'whatweb.json'); OUT7=$(mkjson 'gobuster_*.txt udp_69.gnmap'); OUT8=$(mkjson 'sslyze_*.json')

cat > "$EVID/manifest.json" <<EOF
{
  "target": "$TARGET",
  "target_id": "$TARGET_ID",
  "started_at": "$STARTED",
  "completed_at": "$COMPLETED",
  "tools_executed": [
    {"step": 1, "tool": "nmap_ports", "status": "$STATE1", "output": $OUT1},
    {"step": 2, "tool": "httpx", "status": "$STATE2", "output": $OUT2},
    {"step": 3, "tool": "nmap_detailed", "status": "$STATE3", "output": $OUT3},
    {"step": 4, "tool": "nuclei", "status": "$STATUS4", "output": $OUT4},
    {"step": 5, "tool": "nikto", "status": "$STATUS5", "output": $OUT5},
    {"step": 6, "tool": "whatweb", "status": "$STATUS6", "output": $OUT6},
    {"step": 7, "tool": "gobuster", "status": "$STATUS7", "output": $OUT7},
    {"step": 8, "tool": "sslyze", "status": "$STATUS8", "output": $OUT8}
  ],
  "out_of_scope_findings": [],
  "errors": $ERRORS_JSON
}
EOF
log "✅ Manifest: $EVID/manifest.json"
echo "TARGET_FASE1_DONE $TARGET"