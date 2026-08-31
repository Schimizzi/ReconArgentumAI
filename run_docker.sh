#!/bin/bash
# =============================================================================
# run_docker.sh — Lanzador del pipeline en MODO DOCKER (contenedor Kali)
# Use ESTE modo para targets EXTERNOS (Internet).
# ⚠️ NO use Docker Desktop/mac para escanear la LAN local (la VM no ve la LAN:
#    raw sockets y NAT no propagan bien el tráfico; ver logs/fase1_run.md y
#    tools/nmap_help.md). Para LAN → run_host.sh.
# =============================================================================
set -u
WORKSPACE="${PWD}"
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

# 2) Sanity de tools dentro de la imagen
echo ""
echo "--- Sanity check (8 binaries) ---"
docker compose run --rm -T pentest bash -c 'for t in nmap httpx nuclei nikto whatweb gobuster sslyze jq; do command -v $t >/dev/null 2>&1 && echo "  OK $t" || echo "  FALTA $t"; done'

# 3) Instrucciones para el Orchestrator (Cline)
echo ""
echo "✅ Entorno MODO DOCKER listo."
echo ""
echo ">>> CÓMO ARRANCAR EL PIPELINE EN ESTE MODO:"
echo "    1. Abrí Cline en ${WORKSPACE}."
echo "    2. scope.json con los targets EXTERNOS autorizados (config/scope.json)."
echo "    3. Ejecutá el prompt:"
echo "       \"Iniciá la Fase 1 del pipeline en MODO DOCKER usando docker compose run --rm pentest\""
echo "    4. Para una sesión interactiva:  docker compose run --rm pentest bash"
echo ""
echo "NOTA: en este modo Nmap usa -sS (raw sockets); los scripts usan el workaround -oJ"
echo "      (scripts/step1_nmap_ports.sh). En LAN local prefiera MODO HOST (run_host.sh)."
echo "==================================================================="