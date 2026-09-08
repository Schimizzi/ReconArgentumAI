#!/bin/bash
# =============================================================================
# run_host.sh — Lanzador del pipeline en MODO HOST (macOS)
# Use ESTE modo para escanear tu LAN local (Docker Desktop/mac no ve la LAN).
# Arquitectura híbrida: este modo corre las 9 tools DIRECTAMENTE en el host.
# =============================================================================
set -u
WORKSPACE="${PWD}"
export PATH="$HOME/.local/bin:$PATH"   # sslyze (pipx)
echo "===[ ReconArgentumAI — MODO HOST ]============================"
echo "WORKSPACE: ${WORKSPACE}"

# 1) Verificar herramientas del host
echo ""
echo "--- Verificando tools del host ---"
MISSING=()
for t in nmap nuclei nikto whatweb gobuster sslyze smbclient jq python3; do
  if [ "$t" = "whatweb" ] && [ -x "$WORKSPACE/tools/WhatWeb/whatweb" ]; then
    echo "  OK  whatweb(local) -> $WORKSPACE/tools/WhatWeb/whatweb"
  elif command -v "$t" >/dev/null 2>&1; then
    echo "  OK  $t -> $(command -v "$t")"
  else
    MISSING+=("$t"); echo "  FALTA $t"
  fi
done
# HTTPX de probe (ProjectDiscovery): prioridad `httpx-toolkit` → `httpx-pd` → `httpx`.
# En Kali Linux el binario PD se llama `httpx-toolkit`; en macOS/contenedor `httpx-pd`.
# El `httpx` del PATH (cliente Python) solo se acepta si soporta `-l` (PD real).
if command -v httpx-toolkit >/dev/null 2>&1; then
  echo "  OK  httpx-toolkit -> $(command -v httpx-toolkit)"
elif command -v httpx-pd >/dev/null 2>&1; then
  echo "  OK  httpx-pd -> $(command -v httpx-pd)"
elif command -v httpx >/dev/null 2>&1 && httpx -h 2>&1 | grep -qE -- '-l,| -list'; then
  echo "  OK  httpx (probe PD) -> $(command -v httpx)"
else
  MISSING+=("httpx-toolkit/httpx-pd"); echo "  FALTA httpx-toolkit/httpx-pd (binario de probe ProjectDiscovery; el 'httpx' del PATH es el cliente Python)"
fi
if [ "${#MISSING[@]}" -gt 0 ]; then
  echo ""
  echo "❌ Faltan herramientas. Instalá con:"
  echo "    brew install nikto gobuster pipx"
  echo "    pipx install sslyze"
  echo "    (whatweb: git clone en tools/WhatWeb + gem install addressable -v 2.8.7)"
  echo "    O ejecutá: scripts/install_host_tools.sh"
  exit 1
fi

# 2) Estado de red (LAN)
echo ""
echo "--- Red LAN (192.168.8.0/24) ---"
echo "IP en0 del host: $(ipconfig getifaddr en0 2>/dev/null || echo 'sin en0 / sin IP')"
GW="$1"
echo "Conectividad a $GW: $(nc -vz -G 3 -w 3 "$GW" 22 2>&1 | head -1 || true)"

# 3) Instrucciones para el Orchestrator (Cline) + modo automático SIN LLM
echo ""
echo "✅ Entorno MODO HOST listo."
echo ""
echo ">>> CÓMO ARRANCAR EL PIPELINE EN ESTE MODO:"
echo "   ·  SIN LLM (Agente 1 automático — verificar preflight y lanzar):"
echo "        bash scripts/host/preflight_run.sh              # check de tools + wordlists"
echo "        WORKSPACE=\${WORKSPACE:-$(pwd)} bash scripts/host/run_fase1_run3.sh"
echo "        #  → Fase 1 completa (10 steps) para todos los targets de scope.json, sin LLM."
echo "        #  → Target puntual:  bash scripts/host/run_target.sh <IP>"
echo "   ·  CON LLM (Orchestrator en Cline):"
echo "       1. Abrí Cline en ${WORKSPACE} (o pedile que abra el proyecto)."
echo "       2. scope.json ya debe contener los targets autorizados (config/scope.json)."
echo "       3. Ejecutá el prompt:"
echo "          \"Iniciá la Fase 1 del pipeline en MODO HOST\""
echo ""
echo "NOTA: en MODO HOST sin root Nmap autodetecta -sT (Connect Scan); con root (-sS)."
echo "      scripts de MODO HOST en scripts/host/ · de MODO DOCKER en scripts/ (contenedor)."
echo "==================================================================="