#!/bin/bash
# =============================================================================
# install_souls.sh — Instala los perfiles Hermes (SOUL) de ReconArgentumAI
# -----------------------------------------------------------------------------
# Copia SOULs/{orchestrator,recon,analyst,reporter}/SOUL.md a
# ~/.hermes/bots/<agente>/SOUL.md reemplazando el WORKSPACE original del autor
# por el directorio actual del proyecto clonado.
#
# El repositorio original se mantiene INTACTO. Solo se instalan copias.
#
# Uso: bash scripts/install_souls.sh
# =============================================================================
set -u

# --- Detectar WORKSPACE: raíz del proyecto (directorio padre de scripts/) -----
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Ruta absoluta original incrustada en los SOULs (la del autor en el repo)
ORIG_WS="/Users/claudio/Recon_Workspace/ReconArgentumAI"
HERMES_BOTS="$HOME/.hermes/bots"

AGENTS=(orchestrator recon analyst reporter)

log() { echo "[install_souls] $*"; }

# --- Pre-checks ---------------------------------------------------------------
[ -d "$WS/SOULs" ] || { echo "❌ No encuentro SOULs/ en $WS. ¿Ejecutás desde la raíz del repo?"; exit 1; }
[ -d "$HERMES_BOTS" ] || mkdir -p "$HERMES_BOTS"

log "WORKSPACE detectado: $WS"
log "Hermes bots dir:    $HERMES_BOTS"
if [ "$WS" != "$ORIG_WS" ]; then
    log "Ruta original del repo ($ORIG_WS) será reemplazada por: $WS"
else
    log "La ruta coincide con la original. No hay reemplazo necesario."
fi
echo

# --- Instalar cada perfil -----------------------------------------------------
FAIL=0
for agent in "${AGENTS[@]}"; do
    src="$WS/SOULs/$agent/SOUL.md"
    dst="$HERMES_BOTS/$agent/SOUL.md"

    if [ ! -f "$src" ]; then
        log "❌ Falta el SOUL de '$agent': $src"
        FAIL=1
        continue
    fi

    mkdir -p "$HERMES_BOTS/$agent"

    if [ "$WS" = "$ORIG_WS" ]; then
        # Misma ruta que el autor original: copia directa (no hay nada que reemplazar)
        cp "$src" "$dst"
        log "✅ '$agent' instalado → $dst (ruta original coincide con la local)"
    else
        # Reemplazo de la ruta original por la local (solo en la copia instalada)
        sed "s|$ORIG_WS|$WS|g" "$src" > "$dst"
        if grep -q "$ORIG_WS" "$dst"; then
            # Si aún queda la ruta original, algo quedó sin tokenizar
            log "⚠️  '$agent': la copia instalada aún contiene la ruta original (¿hay yaml con \\$WS?)"
        else
            log "✅ '$agent' instalado → $dst (ruta reemplazada a $WS)"
        fi
    fi
done
echo

# --- Resumen final ------------------------------------------------------------
if [ "$FAIL" -eq 0 ]; then
    log "✅ Perfiles installados. Probar con:"
    log "   hermes --in ~/.hermes/bots/recon -z \"IDIOMA: ESPAÑOL. ¿Cuál es tu rol?\" chat"
    exit 0
else
    log "❌ Hubo errores. Revisá los mensajes anteriores."
    exit 1
fi