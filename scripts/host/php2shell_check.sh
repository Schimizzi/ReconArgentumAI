#!/bin/bash
# ---------------------------------------------------------------------------
# php2shell_check.sh — Verificación en CAMPO de PHP2Shell
#   CVE-2026-109618 / CVE-2026-109619 (RCE no autenticado en PHP 5.4–8.5)
#
# NO es un step del DAG de recon: se ejecuta a mano DESDE LA VM (con VPN) por
# target. Escribe todo en evidence/<target>/php2shell_* para que después lo lea
# `scripts/php2shell_audit.py` (que sigue siendo la fuente del CK-10).
#
# Uso:
#   php2shell_check.sh --target 10.10.12.127 --target-id 10.10.12.127 --passive
#   php2shell_check.sh --target 10.10.10.204 --modes passive,fingerprint
#   php2shell_check.sh --target 10.10.13.102 --detect --authorized
#   php2shell_check.sh --host-check            # correr EN el servidor PHP
#   php2shell_check.sh --self-test             # valida la tabla de clasificación
#
# Modos:
#   --passive      (default) curl -sS/-I a rutas estándar. Solo lectura. APROBADO.
#   --fingerprint  intenta revelar la versión de PHP donde el banner está oculto
#                  (IIS/Drupal). Requiere aprobación por target.
#   --detect       prueba NO DESTRUCTIVA del path OOM (request multipart) y
#                  observación de señales. Requiere --authorized.
#   --host-check   chequeo local (php -v, backports del vendor, config de sesión).
#
# NUNCA ejecuta shell remoto, NUNCA sube archivos, NUNCA exfiltra datos.
# Exit: 0 = sin afectados | 2 = versión afectada/EOL | 1 = error de uso
# ---------------------------------------------------------------------------
set -uo pipefail

WORKSPACE="${WORKSPACE:-$(pwd)}"
SELF="$(basename "$0")"
ADVISORY_ID="php2shell-2026-10-21"
ADVISORY_CVES="CVE-2026-109618 CVE-2026-109619"

TARGET=""; TARGET_ID=""; EVID=""; PORTS="80,443"; MODES="passive"; AUTHORIZED=0

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }

# R5: timeouts desde config/stealth.yaml (nunca hardcodeados)
TO=$(awk '/^php2shell_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml" 2>/dev/null)
[ -z "${TO:-}" ] && TO=$(awk '/^httpx_timeout_seconds:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml" 2>/dev/null)
TO="${TO:-10}"
MAXPATHS=$(awk '/^php2shell_max_paths:/ {print $2; exit}' "$WORKSPACE/config/stealth.yaml" 2>/dev/null)
MAXPATHS="${MAXPATHS:-6}"

while [ $# -gt 0 ]; do
  case "$1" in
    --target)      TARGET="$2"; shift 2 ;;
    --target-id)   TARGET_ID="$2"; shift 2 ;;
    --ev-dir)      EVID="$2"; shift 2 ;;
    --ports)       PORTS="$2"; shift 2 ;;
    --modes)       MODES="$2"; shift 2 ;;
    --passive)     MODES="passive"; shift ;;
    --fingerprint) MODES="passive,fingerprint"; shift ;;
    --detect)      MODES="passive,detect"; shift ;;
    --authorized)  AUTHORIZED=1; shift ;;
    --host-check)  MODES="host-check"; shift ;;
    --self-test)   MODES="self-test"; shift ;;
    -h|--help)     usage 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Clasificación (tabla del advisory: parches 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
# ---------------------------------------------------------------------------
php2shell_status() {
  local v="$1" branch patched lo
  case "$v" in ""|unknown|none) echo "unknown_version"; return ;; esac
  case "$v" in
    *.*.*) branch="${v%.*}" ;;
    *)     branch="$v" ;;
  esac
  case "$branch" in
    8.2) patched="8.2.35" ;;
    8.3) patched="8.3.36" ;;
    8.4) patched="8.4.27" ;;
    8.5) patched="8.5.12" ;;
    *)   patched="" ;;
  esac
  if [ -n "$patched" ]; then
    [ "$v" = "$patched" ] && { echo "patched"; return; }
    lo=$(printf '%s\n%s\n' "$v" "$patched" | sort -V | head -1)
    [ "$lo" = "$v" ] && echo "affected" || echo "patched"
    return
  fi
  lo=$(printf '%s\n%s\n' "$v" "8.2.0" | sort -V | head -1)
  [ "$lo" = "$v" ] && echo "eol_sin_parche" || echo "not_affected_branch"
}

self_test() {
  echo
  echo "🧪 Self-test de clasificación PHP2Shell ($SELF)"
  local fails=0 cases="5.4.16:eol_sin_parche 7.4.33:eol_sin_parche 8.1.29:eol_sin_parche \
8.2.31:affected 8.2.34:affected 8.2.35:patched 8.3.35:affected 8.3.36:patched \
8.4.26:affected 8.4.27:patched 8.5.11:affected 8.5.12:patched 8.2.33:affected"
  local c v exp got
  for c in $cases; do
    v="${c%%:*}"; exp="${c##*:}"; got="$(php2shell_status "$v")"
    if [ "$got" = "$exp" ]; then
      printf '  ✅ PHP %-8s → %-16s (esperado %s)\n' "$v" "$got" "$exp"
    else
      printf '  ❌ PHP %-8s → %-16s (esperado %s)\n' "$v" "$got" "$exp"; fails=$((fails+1))
    fi
  done
  echo
  if [ "$fails" -eq 0 ]; then echo "  Resultado: OK"; else echo "  Resultado: $fails FALLOS"; fi
  echo
  [ "$fails" -eq 0 ] && return 0 || return 1
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
TMPD=""
init_tmp() { TMPD="$(mktemp -d 2>/dev/null || echo "/tmp/php2shell.$$")"; mkdir -p "$TMPD"; }
clean_tmp() { [ -n "$TMPD" ] && rm -rf "$TMPD"; }

scheme_for() {
  case "$1" in 443|8443|9443|4443|10443) echo "https" ;; *) echo "http" ;; esac
}

# Rastreo: hace UN request y devuelve el http_code (headers a $2, body a $3)
probe() {
  local url="$1" hdr="$2" body="$3"
  curl -sS -k -m "$TO" -A "Mozilla/5.0 (ReconArgentumAI php2shell-check)" \
       -D "$hdr" -o "$body" -w '%{http_code}' "$url" 2>"$TMPD/curl.err"
}

echo_headers() {
  local f="$1"
  [ -f "$f" ] || return 0
  grep -iE '^(server|x-powered-by|set-cookie|x-aspnet-version|x-generator):' "$f" 2>/dev/null || true
}

collect_versions() {
  # Extrae PHP x.y.z SOLO de headers (Server:, X-Powered-By:) — nunca del cuerpo.
  # Fix 2026-10-22: extraer del cuerpo produjo falsos positivos en los Drupal/IIS
  # (p.ej. /INSTALL.txt dice "PHP 5.3.0 or higher" → se reportó 5.3.0 como si fuera
  # la versión instalada). Además, el cuerpo no se guarda en la evidencia, así que
  # ese dato quedaba NO verificable. Los headers SÍ están en el archivo de evidencia.
  local f="$1" v
  [ -f "$f" ] || return 0
  while read -r v; do
    [ -z "$v" ] && continue
    case " ${VERSIONS[*]:-} " in *" $v "*) ;; *) VERSIONS+=("$v") ;; esac
  done < <(grep -iE '^(server|x-powered-by):' "$f" 2>/dev/null \
             | grep -viE 'requir|or higher|or later|minimum|at least' \
             | grep -Eoi 'PHP[/ ]?v?[0-9]+\.[0-9]+(\.[0-9]+)?' \
             | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -V -u)
}

detect_sapi() {
  local f="$1"
  # Nota: grep en macOS/BSD no interpreta bien [^\r\n] en ERE → se usa .*
  # (grep trabaja línea por línea, por lo que . nunca cruza el final de línea).
  if grep -qiE '^server:.*PHP/' "$f" 2>/dev/null; then
    echo "mod_php (Server header con PHP/ → modulo Apache; riesgo MAXIMO)"
  elif grep -qiE '^x-powered-by:.*PHP' "$f" 2>/dev/null; then
    echo "php-fpm / proxy probable (solo X-Powered-By)"
  else
    echo "desconocido"
  fi
}

# ---------------------------------------------------------------------------
# MODO PASSIVE (solo lectura)
# ---------------------------------------------------------------------------
run_passive() {
  local out="$EVID/php2shell_passive.txt"
  : > "$out"
  echo "# PHP2Shell check — modo passive — $(date -u +%Y-%m-%dT%H:%M:%SZ) — $TARGET" >> "$out"
  local port base url code i
  for port in ${PORTS//,/ }; do
    base="$(scheme_for "$port")://$TARGET:$port"
    i=0
    for url in "$base/" "$base/index.php" "$base/phpinfo.php" "$base/install.php" \
               "$base/cron.php" "$base/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"; do
      i=$((i+1)); [ "$i" -gt "$MAXPATHS" ] && break
      code=$(probe "$url" "$TMPD/h" "$TMPD/b")
      {
        echo "## GET $url -> HTTP ${code:-000}"
        echo_headers "$TMPD/h"
        grep -Eoi 'PHPSESSID=[^;[:space:]]+' "$TMPD/h" 2>/dev/null || true
      } >> "$out"
      collect_versions "$TMPD/h"
      if grep -qiE 'PHP Version|phpinfo\(\)' "$TMPD/b" 2>/dev/null; then
        echo "## (phpinfo expuesto en $url)" >> "$out"
      fi
      sleep 1
    done
  done
  echo "  → evidencia: ${out#$WORKSPACE/}"
}

# ---------------------------------------------------------------------------
# MODO FINGERPRINT (revelar versión donde el banner está oculto: IIS/Drupal)
# ---------------------------------------------------------------------------
run_fingerprint() {
  local out="$EVID/php2shell_fingerprint.txt"
  : > "$out"
  echo "# PHP2Shell check — modo fingerprint — $(date -u +%Y-%m-%dT%H:%M:%SZ) — $TARGET" >> "$out"
  local port base url code
  for port in ${PORTS//,/ }; do
    base="$(scheme_for "$port")://$TARGET:$port"
    for url in "$base/CHANGELOG.txt" "$base/core/CHANGELOG.txt" "$base/INSTALL.txt" \
               "$base/README.txt" "$base/index.php?s=phpinfo" \
               "$base/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"; do
      code=$(probe "$url" "$TMPD/h" "$TMPD/b")
      {
        echo "## GET $url -> HTTP ${code:-000}"
        echo_headers "$TMPD/h"
      } >> "$out"
      if grep -qiE '^Drupal [0-9]' "$TMPD/b" 2>/dev/null; then
        DLINE=$(head -1 "$TMPD/b" | tr -d '\r')
        DVER=$(printf '%s' "$DLINE" | grep -Eoi '^Drupal[ /-]?[0-9]+(\.[0-9]+)*' | grep -Eo '[0-9]+(\.[0-9]+)*' | head -1)
        echo "## Drupal detectado: $DLINE" >> "$out"
        # Línea NO-comentario y verificable, para que el auditor pueda citarla
        # (el cuerpo del CHANGELOG no se persiste: sin esto, la versión no era auditable).
        if [ -n "${DVER:-}" ]; then
          echo "Drupal-Version: $DVER  (fuente: CHANGELOG.txt; CMS EOL -> requiere migracion)" >> "$out"
        fi
        echo "   (Drupal 7 exige PHP 5.x-7.x -> ambas ramas EOL en PHP2Shell)" >> "$out"
      fi
      collect_versions "$TMPD/h"
      sleep 1
    done
    # detección de SAPI en infraestructura Windows: 9000 (FPM) no aplica a IIS,
    # pero sí un proxy FastCGI local. Se documenta, no se escanea red interna.
    echo "## SAPI: revisar en el server (IIS → PHP via FastCGI; Linux → mod_php o FPM 9000)" >> "$out"
  done
  echo "  → evidencia: ${out#$WORKSPACE/}"
}

# ---------------------------------------------------------------------------
# MODO DETECT (no destructivo; requiere --authorized)
# ---------------------------------------------------------------------------
run_detect() {
  local out="$EVID/php2shell_detect.txt"
  : > "$out"
  {
    echo "# PHP2Shell check — modo detect (NO destructivo) — $(date -u +%Y-%m-%dT%H:%M:%SZ) — $TARGET"
    echo "# NO se envía payload de shell, ni comandos, ni archivos. Solo se observan respuestas."
  } >> "$out"
  local port base res longid
  for port in ${PORTS//,/ }; do
    base="$(scheme_for "$port")://$TARGET:$port"
    res=$(curl -sS -k -m "$TO" -o "$TMPD/b" -w 'HTTP %{http_code} | %{time_total}s' \
          -F "PHP_SESSION_UPLOAD_PROGRESS=php2shell-probe-$$" \
          -F "file=@/dev/null;filename=probe.txt;type=text/plain" \
          "$base/index.php" 2>>"$out")
    {
      echo "## POST multipart (session.upload_progress) $base/index.php -> ${res:-sin respuesta}"
      grep -Eoi 'Allowed memory size[^<]{0,120}|memory[ _]limit[^<]{0,120}|Fatal error[^<]{0,120}' \
        "$TMPD/b" 2>/dev/null | head -3 || true
    } >> "$out"
    longid="php2shell$(printf 'A%.0s' $(seq 1 200))%00"
    res=$(curl -sS -k -m "$TO" -o /dev/null -w 'HTTP %{http_code}' \
          -H "Cookie: PHPSESSID=$longid" "$base/" 2>>"$out")
    echo "## GET con PHPSESSID largo + percent-encoded -> ${res:-sin respuesta}" >> "$out"
    sleep 1
  done
  {
    echo "## Interpretación: 500 / timeout / fatal de memoria tras multipart ⇒ posible"
    echo "## path OOM del advisory. NO confirma RCE ni implica compromiso."
    echo "## Revisar en el server: logs de PHP (memory limit), dmesg/segfaults, reinicios de workers."
  } >> "$out"
  echo "  → evidencia: ${out#$WORKSPACE/}"
}

# ---------------------------------------------------------------------------
# MODO HOST-CHECK (correr EN el servidor PHP: backports y configuración)
# ---------------------------------------------------------------------------
run_host_check() {
  local out="$EVID/php2shell_hostcheck.txt"
  {
    echo "# PHP2Shell host-check — $(date -u +%Y-%m-%dT%H:%M:%SZ) — host: $(hostname 2>/dev/null || echo '?')"
    echo "## php -v"; (php -v 2>&1 | head -3) || echo "(php no encontrado)"
    echo "## config relevante (mitigación temporal)"
    php -i 2>/dev/null | grep -E '^(session\.upload_progress|memory_limit|post_max_size)' || echo "(no disponible)"
    echo "## SAPI en este server"
    (apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || true) | grep -i php || echo "(sin módulo php visible → probable FPM/FastCGI)"
    php-fpm -v 2>/dev/null | head -2 || true
    echo "## backport del vendor (RPM)"
    rpm -q --changelog php 2>/dev/null | grep -iE 'CVE-2026-10961[89]' | head -5 || echo "(sin coincidencias o sin rpm)"
    echo "## paquetes PHP instalados"
    rpm -qa 2>/dev/null | grep -iE '^php' | head -20 || true
    dpkg -l 2>/dev/null | grep -iE 'php' | head -20 || true
    echo "## Resumen (líneas canónicas para el auditor)"
    local pv sapi
    pv=$(php -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "${pv:-}" ]; then echo "PHP-Version: $pv"; else echo "PHP-Version: "; fi
    if (apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || true) | grep -qi php; then
      sapi="mod_php (Apache)"
    elif command -v php-fpm >/dev/null 2>&1; then
      sapi="php-fpm"
    else
      sapi="desconocido"
    fi
    echo "PHP-SAPI: $sapi"
  } > "$out" 2>&1
  echo "  → evidencia: ${out#$WORKSPACE/}"
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
VERSIONS=()

main() {
  if [ "$MODES" = "self-test" ]; then self_test; exit $?; fi
  init_tmp
  trap clean_tmp EXIT

  if [ "$MODES" = "host-check" ]; then
    # El host-check corre DENTRO del servidor: su salida NO es evidencia de un target,
    # va a logs/ (si no, contamina el barrido de evidence/ y el reporte global).
    EVID="${EVID:-$WORKSPACE/logs/php2shell_hostcheck}"
    mkdir -p "$EVID"
    run_host_check
    exit 0
  fi

  [ -z "$TARGET" ] && { echo "ERROR: --target es obligatorio" >&2; usage 1; }
  TARGET_ID="${TARGET_ID:-$TARGET}"
  EVID="${EVID:-$WORKSPACE/evidence/$TARGET}"
  mkdir -p "$EVID" || { echo "ERROR: no se pudo crear $EVID" >&2; exit 1; }

  echo
  echo "🐚 PHP2Shell check — target $TARGET ($TARGET_ID) — modos: $MODES"
  echo "   timeout=${TO}s max_paths=${MAXPATHS} puertos=$PORTS"
  case ",$MODES," in *,passive,*) run_passive ;; esac
  case ",$MODES," in *,fingerprint,*) run_fingerprint ;; esac
  case ",$MODES," in *,detect,*)
      if [ "$AUTHORIZED" -eq 1 ]; then run_detect
      else echo "  ⛔ --detect requiere --authorized (autorización explícita por target). SALTADO."; fi ;;
  esac

  local version="" status="unknown_version" sapi="desconocido"
  if [ "${#VERSIONS[@]}" -gt 0 ]; then
    version="${VERSIONS[0]}"
    status="$(php2shell_status "$version")"
  fi
  sapi="$(detect_sapi "$EVID/php2shell_passive.txt")"
  local versions_str="${VERSIONS[*]:-}"

  local next
  case "$status" in
    affected)       next="Actualizar a 8.2.35/8.3.36/8.4.27/8.5.12 (o backport del vendor) y reiniciar workers. Mitigacion temporal: session.upload_progress=Off." ;;
    eol_sin_parche) next="Rama EOL sin release del proyecto: migrar o aislar. Verificar backport del vendor (--host-check)." ;;
    patched)        next="Version parcheada: confirmar el fix en el changelog del paquete y reiniciar workers." ;;
    *)              next="Version no visible: correr --fingerprint y/o --host-check. Si no se obtiene, reportar 'Desconocida' (no asumir)." ;;
  esac

  local files
  files=$(ls "$EVID"/php2shell_* 2>/dev/null | sed "s#$WORKSPACE/##g" | tr '\n' ' ')

  cat > "$EVID/php2shell_result.json" <<EOF
{
  "target": "$TARGET",
  "target_id": "$TARGET_ID",
  "checked_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tool": "php2shell_check.sh",
  "modes": "$MODES",
  "advisory_id": "$ADVISORY_ID",
  "advisory_cves": ["CVE-2026-109618", "CVE-2026-109619"],
  "php": {
    "versions_detected": "$versions_str",
    "version": "$version",
    "status": "$status",
    "sapi_hint": "$sapi"
  },
  "evidence_files": "$files",
  "next_steps": "$next"
}
EOF

  {
    echo "PHP2Shell — resumen de campo"
    echo "target: $TARGET"
    echo "fecha: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "modos: $MODES"
    echo "versiones PHP detectadas: ${versions_str:-ninguna}"
    echo "estado: $status"
    echo "sapi probable: $sapi"
    echo "siguiente paso: $next"
  } > "$EVID/php2shell_summary.txt"

  case "$status" in
    affected|eol_sin_parche) echo "  🔴 PHP ${version:-?} → $status" ;;
    patched)                 echo "  🟢 PHP ${version:-?} → patched" ;;
    *)                       echo "  🟡 versión no detectada (unknown_version)" ;;
  esac
  echo "  → resultado: ${EVID#$WORKSPACE/}/php2shell_result.json"
  echo "  → despues: python3 $WORKSPACE/scripts/php2shell_audit.py --target-ip $TARGET   (QA: CK-10)"
  echo
  case "$status" in
    affected|eol_sin_parche) exit 2 ;;
    *) exit 0 ;;
  esac
}

main "$@"
