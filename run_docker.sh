#!/bin/bash
# =============================================================================
# run_docker.sh — Lanzador del pipeline en MODO DOCKER (contenedor Kali)
# Use ESTE modo para targets EXTERNOS (Internet).
# ⚠️ NO use Docker Desktop/mac para escanear la LAN local (la VM no ve la LAN:
#    raw sockets y NAT no propagan bien el tráfico; ver logs/fase1_run.md y
#    tools/nmap_help.md). Para LAN → run_host.sh.
#
# UNIFICACIÓN KALI/DOCKER (2026-09-07): se agrega el modo AUTOMÁTICO sin LLM.
#   run_docker.sh --auto            → ejecuta el **Agente 1 (Fase 1) completo**
#                                     (runnable maestro scripts/host/run_fase1_run3.sh)
#                                     dentro del contenedor, SIN necesitar un LLM.
#   run_docker.sh --auto-target IP  → ejecuta Fase 1 solo para esa IP (run_target.sh).
#   run_docker.sh                   → (default) aplica: sólo engrega las
#                                     instrucciones del Orchestrator (LLM / manual).
# =============================================================================
set -u
WORKSPACE="${PWD}"
MODE="${1:-manual}"
DRYRUN=""
# --dry-run puede ir como 2º o 3º argumento (ej: --auto --dry-run / --auto-target IP --dry-run)
for _a in "$@"; do [ "$_a" = "--dry-run" ] && DRYRUN="--dry-run"; done
echo "===[ ReconArgentumAI — MODO DOCKER ]==========================="
echo "WORKSPACE: ${WORKSPACE}"

# 1) Imagen buildada?
echo ""
echo "--- Verificando imagen Docker ---"
if docker images --format '{{.Repository}}' 2>/dev/null | grep -qx 'recon-argento-stepai'; then
  echo "  OK  imagen recon-argento-stepai:latest presente."
else
  echo "  ⚠️  Imagen no encontrada. Construyendo (varios minutos)…"
  docker compose build || { echo "Build falló."; exit 1; }
fi

# 2) Sanity de tools dentro de la imagen (9 tools del Agente 1 + jq)
# En modo automático: si la imagen es vieja (falta smbclient/ping), se rebuilda UNA vez
# y se reintenta el sanity antes de fallar.
sanity_ok() {
  docker compose run --rm -T pentest bash -c \
    'for t in nmap httpx-pd nuclei nikto whatweb gobuster sslyze smbclient ping jq; do
       command -v $t >/dev/null 2>&1 && echo "  OK $t -> $(command -v $t)" || echo "  FALTA $t"; done'
}
echo ""
echo "--- 🔍 Sanity check (9 tools + jq) ---"
if ! sanity_ok; then
  if [ "$MODE" = "--auto" ] || [ "$MODE" = "--auto-target" ]; then
    echo "⚠️  Imagen sin las tools del Agente 1 (o imagen vieja). Reconstruyendo UNA vez…"
    docker compose build || { echo "Build falló."; exit 1; }
    sanity_ok || { echo "Sanity falló aun tras rebuild (binario faltante)."; exit 1; }
  else
    echo "Sanity falló (binario faltante en la imagen). Rebuild con: docker compose build"
    exit 1
  fi
fi

run_fase1_auto() {
  local title="$1"; shift
  local args=("$@")
  echo ""
  echo ">>> $title"
  if [ -n "$DRYRUN" ]; then
    echo "  (dry-run) docker compose run --rm -T -e WORKSPACE=/workspace pentest bash ${args[*]}"
    return 0
  fi
  # WORKSPACE=/workspace resuelve los paths relativos del master runner
  # (el volumen ./:/workspace del compose monta el repo en /workspace).
  docker compose run --rm -T \
    -e WORKSPACE=/workspace \
    pentest bash "${args[@]}"
  echo "  rc=$?"
}

case "$MODE" in
  --auto)
    if [ -n "$DRYRUN" ]; then
      run_fase1_auto "Fase 1 completa (todos los targets)" "scripts/host/run_fase1_run3.sh" "--dry-run"
    else
      run_fase1_auto "Fase 1 completa (todos los targets)" "scripts/host/run_fase1_run3.sh"
    fi
    ;;
  --auto-target)
    [ $# -lt 2 ] && { echo "Uso: run_docker.sh --auto-target <IP> [--dry-run]"; exit 2; }
    run_fase1_auto "Fase 1 → target ${2}" "scripts/host/run_target.sh" "${2}"
    ;;
  *)
    echo ""
    echo "✅ Entorno MODO DOCKER listo."
    echo ""
    echo ">>> CÓMO USAR ESTE MODO:"
    echo "   ·  SIN LLM (Agente 1 automático):"
    echo "        ./run_docker.sh --auto                    # Fase 1 completa, todos los targets"
    echo "        ./run_docker.sh --auto-target 1.2.3.4     # Fase 1 solo para esa IP"
    echo "   ·  CON LLM (Orchestrator en Cline):"
    echo "        1. Abrí la extensión de Cline en ${WORKSPACE}."
    echo "        2. scope.json con los targets EXTERNOS autorizados (config/scope.json)."
    echo "        3. Prompt: \"Iniciá la Fase 1 del pipeline en MODO DOCKER\"."
    echo "    Sesión interactiva:  docker compose run --rm pentest bash"
    echo ""
    echo "NOTA: en este modo Nmap usa -sS (raw sockets, contenedor corre como root)."
    echo "      En LAN local prefiera MODO HOST (./run_host.sh)."
    echo "==================================================================="
    ;;
esac