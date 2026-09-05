#!/bin/bash
# =============================================================================
# cleanup_engagement.sh — Limpia todo lo generado por el engagement del cliente
# actual y deja el repo limpio listo para el próximo cliente.
#
# QUÉ LIMPIA:
#   evidence/  reports/  plans/  cve_research/  logs/  CLIENTE/   (y outputs/
#   en la raíz, si existe)                                    -> se eliminan
#   config/approved_commands.md                              -> se elimina
#   config/scope.json                                        -> se restaura
#     desde config/scope.json.template (plantilla sin datos reales)
#   scripts/**/__pycache__/                                  -> se elimina
#
# QUÉ NO TOCA: código fuente, specs/, openspec/, tools/, scripts/*.md,
#   config/stealth.yaml, config/scope.json.template, .cline/, .clinerules/,
#   .git/ ni el README.md del proyecto.
#
# USO:
#   bash scripts/cleanup_engagement.sh                       # dry-run (default)
#   bash scripts/cleanup_engagement.sh --yes                 # ejecuta (pide confirmación)
#   bash scripts/cleanup_engagement.sh --force               # ejecuta sin preguntar
#   bash scripts/cleanup_engagement.sh --yes --keep-config   # no toca config/
#   bash scripts/cleanup_engagement.sh --yes --no-recreate   # no recrea carpetas vacías
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../scripts
WS="$(cd "${SCRIPT_DIR}/.." && pwd)"                          # raíz del proyecto

# ---------------------------------------------------------------------------
# 0. Flags de control
# ---------------------------------------------------------------------------
DRY=1          # 1 = simulación (default), 0 = ejecución real
CONFIRM=1      # 1 = pedir confirmación interactiva al ejecutar
KEEP_CONFIG=0  # 1 = no tocar config/approved_commands.md ni config/scope.json
NO_RECREATE=0  # 1 = no recrear las carpetas vacías al final

for arg in "$@"; do
  case "$arg" in
    --dry-run)     DRY=1 ;;
    --yes)         DRY=0 ;;
    --force)       DRY=0; CONFIRM=0 ;;
    --keep-config) KEEP_CONFIG=1 ;;
    --no-recreate) NO_RECREATE=1 ;;
    -h|--help)
      echo "Uso: bash scripts/cleanup_engagement.sh [OPCIONES]"
      echo ""
      echo "Opciones:"
      echo "  (sin flags)       Simulación (--dry-run): muestra el plan, no borra nada."
      echo "  --yes             Ejecuta la limpieza (pide confirmación Y/N)."
      echo "  --force           Ejecuta sin pedir confirmación."
      echo "  --keep-config     No toca config/approved_commands.md ni config/scope.json."
      echo "  --no-recreate     No recrea las carpetas vacías al final."
      echo "  --dry-run         Fuerza la simulación (comportamiento por defecto)."
      echo "  -h, --help        Este mensaje."
      exit 0
      ;;
    *)
      echo "❌ Argumento desconocido: $arg (usá -h para ayuda)." >&2
      exit 2
      ;;
  esac
done

# ---------------------------------------------------------------------------
# 1. Verificaciones de seguridad
# ---------------------------------------------------------------------------
# 1.1) Raíz correcta del proyecto (evita borrar un directorio equivocado)
if [ ! -d "$WS/scripts" ] || [ ! -d "$WS/config" ]; then
  echo "❌ Raíz de proyecto no reconocida: $WS" >&2
  echo "   (no contiene scripts/ y config/). Abortando." >&2
  exit 1
fi

# 1.2) Pipeline activo -> abortar (run_target.sh deja un lock por target)
ACTIVE=$(find "$WS/evidence" -type d -name .run.lock 2>/dev/null | head -1)
if [ -n "$ACTIVE" ]; then
  echo "❌ Pipeline activo detectado: $ACTIVE" >&2
  echo "   Esperá a que termine el escaneo o eliminá el lock a mano antes de limpiar." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Candidatos a limpiar (solo los que existen)
# ---------------------------------------------------------------------------
CANDIDATOS=()
NOMBRES=()   # etiqueta amigable para el listado del plan

add_candidato() {
  # $1 = path absoluto, $2 = etiqueta de display
  [ -e "$1" ] || return 0
  CANDIDATOS+=("$1")
  NOMBRES+=("$2")
}

add_candidato "$WS/evidence"           "evidence/  — evidencia cruda del recon (Fase 1)"
add_candidato "$WS/reports"            "reports/  — informes finales (Agente 5, Fase 3)"
add_candidato "$WS/plans"              "plans/  — planes de explotación (Agente 3, Fase 2)"
add_candidato "$WS/cve_research"       "cve_research/  — investigación CVEs (Agente 4, Fase 2)"
add_candidato "$WS/logs"               "logs/  — bitácoras de ejecución (Fase 1)"
add_candidato "$WS/CLIENTE"            "CLIENTE/  — entregables consolidados (Fase 4)"
add_candidato "$WS/outputs"            "outputs/  — consolidado en la raíz (si existe)"

HAS_SCOPE=0
HAVE_SCOPE_TMPL=0
if [ "$KEEP_CONFIG" -eq 0 ]; then
  if [ -f "$WS/config/approved_commands.md" ]; then
    CANDIDATOS+=("$WS/config/approved_commands.md")
    NOMBRES+=("config/approved_commands.md  — comandos aprobados (se regenera en Fase 0)")
  fi
  if [ -f "$WS/config/scope.json" ]; then
    HAS_SCOPE=1
    CANDIDATOS+=("$WS/config/scope.json")
    NOMBRES+=("config/scope.json  — alcance del engagement (se restaura de la plantilla)")
  fi
  [ -f "$WS/config/scope.json.template" ] && HAVE_SCOPE_TMPL=1
fi

# Caches de Python bajo scripts/
PYCACHES=()
while IFS= read -r d; do PYCACHES+=("$d"); done < <(find "$WS/scripts" -type d -name __pycache__ 2>/dev/null)

if [ "${#CANDIDATOS[@]}" -eq 0 ] && [ "${#PYCACHES[@]}" -eq 0 ] && [ "$HAS_SCOPE" -eq 0 ]; then
  echo "🎉 Nada para limpiar. El proyecto ya está listo para el próximo cliente."
  exit 0
fi
# ---------------------------------------------------------------------------
# 3. Mostrar el plan (siempre, sea dry-run o ejecución)
# ---------------------------------------------------------------------------
human_kb() {   # $1 = KB -> legible
  local kb=$1
  if [ "$kb" -ge 1048576 ]; then
    awk "BEGIN{printf \"%.1f GB\", $kb/1048576}"
  elif [ "$kb" -ge 1024 ]; then
    awk "BEGIN{printf \"%.1f MB\", $kb/1024}"
  else
    echo "${kb} KB"
  fi
}

TOTAL_KB=0
if [ "${#CANDIDATOS[@]}" -gt 0 ]; then
  for p in "${CANDIDATOS[@]}"; do
    kb=$(du -sk "$p" 2>/dev/null | awk '{print $1}')
    TOTAL_KB=$((TOTAL_KB + ${kb:-0}))
  done
fi
if [ "${#PYCACHES[@]}" -gt 0 ]; then
  for d in "${PYCACHES[@]}"; do
    kb=$(du -sk "$d" 2>/dev/null | awk '{print $1}')
    TOTAL_KB=$((TOTAL_KB + ${kb:-0}))
  done
fi

echo "=============================================================="
echo "  🧹 cleanup_engagement.sh — ReconArgentumAI"
echo "  Workspace : $WS"
if [ "$DRY" -eq 1 ]; then
  echo "  Modo      : --dry-run (simulación: NO borra nada)"
else
  echo "  Modo      : ejecución real"
fi
echo "=============================================================="
echo ""
echo "Plan de limpieza:"
if [ "${#NOMBRES[@]}" -gt 0 ]; then
  for i in "${!NOMBRES[@]}"; do
    printf "   🗑️  %-58s %s\n" "${NOMBRES[$i]}" "$(du -sh "${CANDIDATOS[$i]}" 2>/dev/null | awk '{print $1}')"
  done
fi
if [ "${#PYCACHES[@]}" -gt 0 ]; then
  printf "   🗑️  %-58s %s\n" "scripts/**/__pycache__/  — caches de Python (${#PYCACHES[@]} carpetas)" ""
fi
echo ""
echo "  Espacio total a liberar : $(human_kb "$TOTAL_KB")"
if [ "$HAVE_SCOPE_TMPL" -eq 1 ]; then
  echo "  config/scope.json        → se RESTAURARÁ desde config/scope.json.template"
elif [ "$HAS_SCOPE" -eq 1 ]; then
  echo "  ⚠️  ATENCIÓN: no existe config/scope.json.template — scope.json se eliminará sin respaldo."
fi
echo ""

if [ "$DRY" -eq 1 ]; then
  echo "ℹ️  Simulación: no se borró nada. Ejecutá con --yes (o --force) para limpiar de verdad."
  exit 0
fi

# Confirmación interactiva (solo si --yes sin --force)
if [ "$CONFIRM" -eq 1 ]; then
  read -r -p "⚠️  ¿Eliminar PERMANENTEMENTE ${#CANDIDATOS[@]} elemento(s)? [y/N] " r
  case "$r" in
    y|Y|s|S) ;;
    *) echo "Cancelado."; exit 0 ;;
  esac
fi

# ---------------------------------------------------------------------------
# 4. Ejecutar la limpieza
# ---------------------------------------------------------------------------
echo ""
echo "Limpiando..."
if [ "${#CANDIDATOS[@]}" -gt 0 ]; then
  for p in "${CANDIDATOS[@]}"; do
    if [ "$p" = "$WS/config/scope.json" ]; then
      # scope.json no se borra: se restaura desde la plantilla (o se elimina si no hay)
      if [ "$HAVE_SCOPE_TMPL" -eq 1 ]; then
        cp "$WS/config/scope.json.template" "$WS/config/scope.json" &&
          echo "   ♻️  config/scope.json restaurado desde scope.json.template"
      else
        rm -f "$WS/config/scope.json" &&
          echo "   ⚠️  config/scope.json ELIMINADO (no había scope.json.template)"
      fi
      continue
    fi
    rm -rf "$p" && echo "   🗑️  $p"
  done
fi
if [ "${#PYCACHES[@]}" -gt 0 ]; then
  for d in "${PYCACHES[@]}"; do
    rm -rf "$d" && echo "   🗑️  $d"
  done
fi

# ---------------------------------------------------------------------------
# 5. Recrear carpetas vacías (por defecto) y resumen final
# ---------------------------------------------------------------------------
if [ "$NO_RECREATE" -eq 0 ]; then
  for d in evidence reports plans cve_research logs CLIENTE; do
    mkdir -p "$WS/$d"
  done
  echo "   📁 Carpetas vacías recreadas: evidence/ reports/ plans/ cve_research/ logs/ CLIENTE/"
else
  echo "   ⏭️  --no-recreate: no se recrearon las carpetas vacías"
fi

echo ""
echo "=============================================================="
echo "  ✅ Limpieza completada — listo para el próximo cliente."
echo "=============================================================="