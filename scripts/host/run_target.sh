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
STARTED=$(date +"%Y-%m-%dT%H:%M:%S%z")
DELAY_TOOLS=$(grep '^delay_between_tools_seconds' "$WS/config/stealth.yaml" | awk '{print $2}')
DELAY_TOOLS="${DELAY_TOOLS:-30}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

run_retry() {
  local name="$1"; shift
  if "$@" >>"$EVID/_step.log" 2>&1; then
    echo OK
  else
    log "⚠️  $name falló (1er intento); retry 1x…"
    sleep 5
    if "$@" >>"$EVID/_step.log" 2>&1; then echo OK_RETRY; else echo FAIL; fi
  fi
}

# ---- Step 1: Nmap port scan --------------------------------------------------
log "Step 1/8 — Nmap port scan (-sT, top-1000) sobre $TARGET"
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
  log "ℹ️  Sin puertos abiertos en top-1000 → target incomplete."
  cat > "$EVID/manifest.json" <<EOF
{
  "target": "$TARGET",
  "started_at": "$STARTED",
  "status": "incomplete",
  "notes": "Sin puertos abiertos en top-1000 (Step 1). Steps 2-8 skipped_no_web.",
  "tools_executed": [
    {"step": 1, "tool": "nmap_ports", "status": "$R1", "output": ["nmap_ports.json", "nmap_ports.xml", "nmap_ports.txt", "nmap_ports.gnmap", "open_ports.txt"]},
    {"step": 2, "tool": "httpx", "status": "skipped_no_web", "output": []},
    {"step": 3, "tool": "nmap_detailed", "status": "skipped_no_web", "output": []},
    {"step": 4, "tool": "nuclei", "status": "skipped_no_web", "output": []},
    {"step": 5, "tool": "nikto", "status": "skipped_no_web", "output": []},
    {"step": 6, "tool": "whatweb", "status": "skipped_no_web", "output": []},
    {"step": 7, "tool": "gobuster", "status": "skipped_no_web", "output": []},
    {"step": 8, "tool": "sslyze", "status": "skipped_no_web", "output": []}
  ]
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
# ---- Steps 4-8: web-only ------------------------------------------------------
web_on() { [ "${WURLS:-0}" -gt 0 ]; }

STATUS4=skipped_no_web; STATUS5=skipped_no_web; STATUS6=skipped_no_web
STATUS7=skipped_no_web; STATUS8=skipped_no_web
OUT4='[]'; OUT5='[]'; OUT6='[]'; OUT7='[]'; OUT8='[]'

if web_on; then
  log "Step 4/8 — Nuclei (severity critical,high,medium)"
  R4=$(run_retry nuclei bash "$WS/scripts/host/step4_nuclei.sh" "$TARGET")
  STATUS4=success; [ "$R4" = FAIL ] && STATUS4=failed
  sleep "$DELAY_TOOLS"

  log "Step 5/8 — Nikto (por endpoint, secuencial)"
  STATUS5=success
  while IFS= read -r URL; do
    PORT=$(echo "$URL" | sed -E 's|^https?://[^:]*:?([0-9]+).*|\1|')
    if [ "$URL" = "$PORT" ]; then
      case "$URL" in http*) PORT=80;; https*) PORT=443;; esac
    fi
    log "  → nikto $URL (puerto $PORT)"
    R=$(run_retry "nikto:$URL" bash "$WS/scripts/host/step5_nikto.sh" "$TARGET" "$URL" "$PORT")
    [ "$R" = FAIL ] && STATUS5=failed
  done < "$EVID/web_endpoints.txt"
  sleep "$DELAY_TOOLS"

  log "Step 6/8 — WhatWeb"
  R6=$(run_retry whatweb bash "$WS/scripts/host/step6_whatweb.sh" "$TARGET")
  STATUS6=success; [ "$R6" = FAIL ] && STATUS6=failed
  sleep "$DELAY_TOOLS"

  log "Step 7/8 — Gobuster dir (por endpoint, secuencial)"
  STATUS7=success
  while IFS= read -r URL; do
    PORT=$(echo "$URL" | sed -E 's|^https?://[^:]*:?([0-9]+).*|\1|')
    if [ "$URL" = "$PORT" ]; then
      case "$URL" in http*) PORT=80;; https*) PORT=443;; esac
    fi
    log "  → gobuster $URL (puerto $PORT)"
    R=$(run_retry "gobuster:$URL" bash "$WS/scripts/host/step7_gobuster.sh" "$TARGET" "$URL" "$PORT")
    [ "$R" = FAIL ] && STATUS7=failed
  done < "$EVID/web_endpoints.txt"
  sleep "$DELAY_TOOLS"

  log "Step 8/8 — SSLyze (solo puertos https)"
  STATUS8=skipped_no_web
  HTTPS_PORTS=$(grep -E '^https://' "$EVID/web_endpoints.txt" | sed -E 's|^https?://[^:]*:?([0-9]+).*|\1|' | sort -u)
  if [ -n "$HTTPS_PORTS" ]; then
    STATUS8=success
    for P in $HTTPS_PORTS; do
      log "  → sslyze $TARGET:$P"
      R=$(run_retry "sslyze:$P" bash "$WS/scripts/host/step8_sslyze.sh" "$TARGET" "$P")
      [ "$R" = FAIL ] && STATUS8=failed
    done
  fi
fi
sleep "$DELAY_TOOLS"
# ---- Manifest ----------------------------------------------------------------
STATE1=success; [ "$R1" = FAIL ] && STATE1=failed
STATE2=success; [ "$R2" = FAIL ] && STATE2=failed
STATE3=success; [ "$R3" = FAIL ] && STATE3=failed
COMPLETED=$(date +"%Y-%m-%dT%H:%M:%S%z")

mkjson() {
  _OUT=$(cd "$EVID" && ls $1 2>/dev/null | tr '\n' ' ' | sed 's/ /","/g; s/^/["/; s/"$/"]/')
  printf '%s' "${_OUT:-[]}"
}
OUT1=$(mkjson 'nmap_ports.* open_ports.txt')
OUT2=$(mkjson 'httpx.json web_endpoints.txt')
OUT3=$(mkjson 'nmap_detailed.*')
OUT4=$(mkjson 'nuclei.json'); OUT5=$(mkjson 'nikto_*.json')
OUT6=$(mkjson 'whatweb.json'); OUT7=$(mkjson 'gobuster_*.txt'); OUT8=$(mkjson 'sslyze_*.json')

cat > "$EVID/manifest.json" <<EOF
{
  "target": "$TARGET",
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
  "errors": $(test -s "$EVID/_errors.log" && echo "true" || echo "[]")
}
EOF
log "✅ Manifest: $EVID/manifest.json"
echo "TARGET_FASE1_DONE $TARGET"