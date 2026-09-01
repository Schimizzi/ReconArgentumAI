#!/bin/bash
# =============================================================================
# run_fase1_run3.sh — Runner maestro FASE 1 RUN#3 (DREAMCO-2026, 13 targets)
# Recorre authorized_targets[] de config/scope.json EN ORDEN, secuencial (R3),
# con delay entre targets desde config/stealth.yaml. Por target invoca
# run_target.sh <IP> (8 steps, delays entre tools, retry 1x, manifest.json).
# Log por target: logs/fase1_<IP>.log.
# Uso: run_fase1_run3.sh [--dry-run]
# =============================================================================
set -uo pipefail
WS="${WORKSPACE:-$(pwd)}"
LOGS="$WS/logs"
mkdir -p "$LOGS"
DRY=""
[ "${1:-}" = "--dry-run" ] && DRY=1

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Solo los targets de authorized_targets (R1): el orden sale del propio scope.json
TARGETS=()
while IFS= read -r _t; do TARGETS+=("$_t"); done < <(jq -r '.authorized_targets[].ip' "$WS/config/scope.json")
DELAY_TG=$(awk '/^delay_between_targets_minutes:/ {print $2; exit}' "$WS/config/stealth.yaml")
DELAY_TG="${DELAY_TG:-5}"

log "===> RUN#3 FASE1 $(date '+%Y-%m-%d %H:%M:%S') — ${#TARGETS[@]} targets"
previous=""
for T in "${TARGETS[@]}"; do
  # R1 re-check contra scope actual (any() para booleano ÚNICO sobre el stream)
  in_scope=$(jq -e --arg ip "$T" 'any(.authorized_targets[]; .ip == $ip)' "$WS/config/scope.json" >/dev/null 2>&1 && echo 1 || echo 0)
  excluded=$(jq -e --arg ip "$T" 'any(.excluded_ips[]; . == $ip)' "$WS/config/scope.json" >/dev/null 2>&1 && echo 1 || echo 0)
  if [ "$in_scope" -ne 1 ] || [ "$excluded" -eq 1 ]; then
    log "R1-FAIL para ${T} (no en authorized_targets o excluido) - SKIPPED y documentado"
    continue
  fi

  # Delay entre targets (no aplica antes del primero). Bash 3.2 (macOS): usar
  # SOLO ASCII en logs con ${VAR} (bytes unicode pegados a $var = "unbound variable").
  if [ -n "$previous" ] && [ -z "$DRY" ]; then
    log "Delay ${DELAY_TG} min entre targets (stealth.yaml) antes de ${T} ..."
    sleep $((DELAY_TG * 60))
  fi

  log ">>> TARGET ${T} - run_target.sh"
  if [ -n "$DRY" ]; then
    log "  (dry-run) bash ${WS}/scripts/host/run_target.sh ${T} >> ${LOGS}/fase1_${T}.log"
  else
    bash "$WS/scripts/host/run_target.sh" "$T" >>"$LOGS/fase1_${T}.log" 2>&1
    rc=$?
    log "<<< TARGET ${T} termino con rc=${rc} - log ${LOGS}/fase1_${T}.log"
  fi
  previous="$T"
done
log "===> RUN#3 FASE1 COMPLETO $(date '+%H:%M:%S'). Revisa manifests en evidence/*/."