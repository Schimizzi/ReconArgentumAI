#!/bin/bash
# =============================================================================
# install_souls.sh — Instala perfiles Hermes para ReconArgentumAI
# -----------------------------------------------------------------------------
# Crea perfiles Hermes dedicados (orchestrator, recon, analyst, reporter),
# instala su SOUL.md reemplazando el WORKSPACE original del autor por la
# ruta local del proyecto clonado.
#
# El repositorio original se mantiene INTACTO. Solo se modifican los perfiles.
#
# Requiere: Hermes Agent instalado (hermes CLI en PATH)
# Uso: bash scripts/install_souls.sh
# =============================================================================
set -u

WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORIG_WS="/Users/claudio/Recon_Workspace/ReconArgentumAI"
AGENTS=(orchestrator recon analyst reporter)

log() { echo "[install_souls] $*"; }

# --- Pre-checks ---------------------------------------------------------------
[ -d "$WS/SOULs" ] || { echo "❌ No encuentro SOULs/ en $WS."; exit 1; }
command -v hermes >/dev/null 2>&1 || { echo "❌ hermes no está en PATH."; exit 1; }

log "WORKSPACE: $WS"
echo

# --- Crear/actualizar perfiles ------------------------------------------------
for agent in "${AGENTS[@]}"; do
    log "📦 Procesando perfil '$agent'..."

    if [ ! -d "$HOME/.hermes/profiles/$agent" ]; then
        hermes profile create "$agent" --clone --no-alias 2>&1 | sed 's/^/   /'
        if [ $? -ne 0 ]; then
            log "❌ Error creando perfil '$agent'."
            continue
        fi
        log "   Perfil '$agent' creado."
    else
        log "   Perfil '$agent' ya existe. Actualizando SOUL.md..."
    fi

    src="$WS/SOULs/$agent/SOUL.md"
    dst="$HOME/.hermes/profiles/$agent/SOUL.md"

    if [ ! -f "$src" ]; then
        log "❌ Falta SOUL.md de '$agent': $src"
        continue
    fi

    if [ "$WS" = "$ORIG_WS" ]; then
        cp "$src" "$dst"
        log "✅ '$agent': instalado (ruta local coincide con la del autor)"
    else
        sed "s|$ORIG_WS|$WS|g" "$src" > "$dst"
        if grep -q "$ORIG_WS" "$dst"; then
            log "⚠️  '$agent': la copia aún tiene la ruta original"
        else
            log "✅ '$agent': instalado (ruta reemplazada a $WS)"
        fi
    fi
done

# --- Master prompt del Orchestrator (flujo Cline / Roo Code) -------------------
# La copia de trabajo (.cline/master_prompt.md) es LOCAL (.gitignore); se crea
# desde la plantilla versionada y sanitizada.
MP_SRC="$WS/.cline/master_prompt.md.template"
MP_DST="$WS/.cline/master_prompt.md"
if [ -f "$MP_SRC" ]; then
    if [ ! -f "$MP_DST" ]; then
        cp "$MP_SRC" "$MP_DST"
        log "✅ master_prompt.md creado desde la plantilla (flujo Cline/Roo Code)"
    else
        log "ℹ️  master_prompt.md ya existe — no se sobrescribe"
    fi
else
    log "⚠️  Falta $MP_SRC — el flujo Cline/Roo Code no tendrá master prompt"
fi

# --- Resumen ------------------------------------------------------------------
echo
log "═══════════════════════════════════════════════════════"
log "  Instalación completada."
log ""
log "  Perfiles:"
log "    hermes -p orchestrator   — Orquestador del pipeline"
log "    hermes -p recon          — Fase 1 (escaneo)"
log "    hermes -p analyst        — Fase 2 (CVEs + plan explot.)"
log "    hermes -p reporter       — Fase 4-5 (consolidación + QA)"
log ""
log "  Prueba: hermes -p recon -z '¿Cuál es tu rol?' chat"
log ""
log "  Master prompt (Cline/Roo): .cline/master_prompt.md"
log "═══════════════════════════════════════════════════════"