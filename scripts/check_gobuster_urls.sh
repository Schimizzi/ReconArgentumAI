#!/bin/bash
# =============================================================================
# check_gobuster_urls.sh — Batería de checks HTTP pasivos (solo curl) POR TARGET
# =============================================================================
# Ejecuta comandos curl contra las URLs descubiertas por Gobuster y documenta
# los resultados EN LA CARPETA de cada target (CLIENTE/<IP>_vuln/outputs/).
#
# MODO RECOMENDADO:
#   scripts/check_gobuster_urls.sh --target <IP>
#   scripts/check_gobuster_urls.sh --all            # todos con gobuster_*.txt
#   scripts/check_gobuster_urls.sh [-u FILE] [-o DIR]   # legado (lista global)
#
# POR TARGET hace:
#   1. Resuelve la carpeta CLIENTE/<IP>_* con outputs/.
#   2. Si ya existe outputs/gobuster_evidence.txt (o .json) -> SKIP; solo el
#      --force re-escanear. No sobrescribe lo ya hecho por otra VPN.
#   3. Reconstruye sus URLs desde outputs/gobuster_<port>.txt.
#   4. PRECHECK DE CONECTIVIDAD (probe TCP a la base de la 1a URL):
#      - Sin alcanzar: NO genera hallazgos. Solo deja evidencia de la corrida
#        en CLIENTE/gobuster_checks_RAW.txt y unreachable.txt, y pasa al siguiente.
#      - Con alcanzar: procesa las URLs y escribe por target:
#          outputs/gobuster_evidence.txt         hallazgos (lo lee el Agente 6)
#          outputs/gobuster_evidence.json        idem en JSON (parser generico)
#          outputs/gobuster_commands_outputs.txt EVIDENCIA HUMANA: cada comando
#                                              curl con su salida completa
#                                              (NO lo consume el Agente 6).
#
# Stealth: timeout/UA navegador, --http1.1, sin seguir redirects, sin payload.
# No ejecuta exploits. Severidades ORIENTATIVAS; decision del analista.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
STEALTH="$WORKSPACE/config/stealth.yaml"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TIMEOUT="$(awk '/^curl_timeout_seconds:/ {print $2; exit}' "$STEALTH" 2>/dev/null)"; TIMEOUT="${TIMEOUT:-8}"
CONNECT_TIMEOUT="$(awk '/^curl_connect_timeout_seconds:/ {print $2; exit}' "$STEALTH" 2>/dev/null)"; CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-4}"
DELAY="$(awk '/^curl_delay_seconds:/ {print $2; exit}' "$STEALTH" 2>/dev/null)"; DELAY="${DELAY:-0.2}"

TARGET_BASE="$WORKSPACE/CLIENTE"
OUTDIR="$WORKSPACE/CLIENTE/gobuster_checks"
ARCH=""
MODE="legacy"
TARGET_IP=""
ALL=0
FORCE=0
CHECK_CONN=1
LIMIT=""
DRY=0
KEEP=0
VERBOSE=0
DO_CORS=0
DO_WEBDAV=0
ONLY=""

c_FINGERPRINT=1; c_HEADERS=1; c_VERSIONS=1; c_METHODS=1
c_TRACE=1; c_LISTING=1; c_PATTERNS=1; c_CORS=0; c_WEBDAV=0
usage(){
  cat <<'EOF'
Uso:
  scripts/check_gobuster_urls.sh --target <IP>   [flags]
  scripts/check_gobuster_urls.sh --all            [flags]
  scripts/check_gobuster_urls.sh [-u ARCHIVO] [-o DIR] [flags]   # legado

Flags:
  -t --target IP        procesar SOLO ese target
  -a --all              procesar todos los targets con gobuster_*.txt
  -f --force            re-escanear aunque ya exista evidence (regenera)
     --no-connectivity-check  saltar el precheck de conectividad
  (modo legado)
  -u --urls FILE         archivo de urls (default CLIENTE/gobuster_urls_curl.txt)
  -o --out DIR           directorio de salida (default CLIENTE/gobuster_checks)
  (comunes)
     --timeout N         --max-time de curl [default stealth.yaml]
     --connect-timeout N
     --delay N           espera entre URLs (seg; 0 off)
     --only A,B,C        correr SOLO esos checks
     --no-CHECK          quitar un check (HEADERS|VERSIONS|METHODS|TRACE|LISTING|PATTERNS)
     --cors              habilitar CORS
     --webdav            habilitar WEBDAV
     --limit N           limitar URLs (solo legado)
     --keep-raw          conservar temporales
     --dry-run           no ejecutar; imprimir comandos
  -v --verbose
  -h --help
EOF
  exit "${1:-0}"
}

declare -a POS_ARGS
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target) MODE="target"; TARGET_IP="$2"; shift 2 ;;
    -a|--all)    MODE="all"; ALL=1; shift ;;
    -f|--force)  FORCE=1; shift ;;
    --no-connectivity-check) CHECK_CONN=0; shift ;;
    -u|--urls)   ARCH="$2"; MODE="legacy"; shift 2 ;;
    -o|--out)    OUTDIR="$2"; shift 2 ;;
    --timeout)   TIMEOUT="$2"; shift 2 ;;
    --connect-timeout) CONNECT_TIMEOUT="$2"; shift 2 ;;
    --delay)     DELAY="$2"; shift 2 ;;
    --only)      ONLY="$2"; shift 2 ;;
    --cors)      DO_CORS=1; c_CORS=1; shift ;;
    --webdav)    DO_WEBDAV=1; c_WEBDAV=1; shift ;;
    --no-*) ck="$(printf '%s' "${1#--no-}" | tr '[:lower:]' '[:upper:]')"
            case "$ck" in
              HEADERS)  c_HEADERS=0   ;; VERSIONS) c_VERSIONS=0 ;;
              METHODS)  c_METHODS=0   ;; TRACE)    c_TRACE=0   ;;
              LISTING)  c_LISTING=0   ;; PATTERNS) c_PATTERNS=0 ;;
              *) echo "ERROR: --no-$ck desconocido" >&2; usage 1 ;;
            esac; shift ;;
    --limit)     LIMIT="$2"; shift 2 ;;
    --keep-raw)  KEEP=1; shift ;;
    --dry-run)   DRY=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -h|--help)   usage 0 ;;
    --) shift; while [ $# -gt 0 ]; do POS_ARGS+=("$1"); shift; done ;;
    -*) echo "ERROR: opción desconocida: $1" >&2; usage 1 ;;
    *)  POS_ARGS+=("$1"); shift ;;
  esac
done
[ -n "$ONLY" ] && if [ -n "$ONLY" ]; then
  # --only: reset de defaults y activar solo lo pedido
  c_FINGERPRINT=0; c_HEADERS=0; c_VERSIONS=0; c_METHODS=0
  c_TRACE=0;       c_LISTING=0;  c_PATTERNS=0; c_CORS=0;     c_WEBDAV=0
  IFS=',' read -r -a CHK <<< "$ONLY"
  for c in "${CHK[@]}"; do
    c="$(printf '%s' "$c" | tr '[:lower:]' '[:upper:]')"
    case "$c" in
      FINGERPRINT) c_FINGERPRINT=1 ;; HEADERS) c_HEADERS=1 ;;
      VERSIONS)    c_VERSIONS=1    ;; METHODS) c_METHODS=1 ;;
      TRACE)       c_TRACE=1       ;; LISTING) c_LISTING=1 ;;
      PATTERNS)    c_PATTERNS=1    ;; CORS)    c_CORS=1    ;;
      WEBDAV)      c_WEBDAV=1      ;;
      *) echo "ERROR: check desconocido en --only: $c" >&2; usage 1 ;;
    esac
  done
fi
[ "$ALL" = 1 ] && MODE="all"
# ---- helpers ----
log(){ [ "$VERBOSE" = 1 ] && echo "[*] $*" >&2; }
warn(){ echo "[!] $*" >&2; }

esc_json(){ python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))'; }

# Ofusca credenciales/tokens antes de escribir evidencias (patrón repo: ***)
mask_credentials(){
  sed -E \
    -e 's/(password|passwd|pwd|secret|api[_-]?key|client[_ -]?secret|access[_ -]?token|auth[_ -]?token|authorization)[ =:]+[^&<>; ]{6,}/***/gi' \
    -e 's/-----BEGIN[[:space:]]*(RSA[[:space:]]+)?PRIVATE KEY-----/***/g' \
    -e 's/(AKIA|ASIA)[0-9A-Z]{10,}/***/g'
}
# add_finding SEVERIDAD CHECK TITULO URL MSG [PORT]  -> escribe las salidas
# La severidad NO se escribe en gobuster_evidence.* (evidencia que consume el
# Agente 6): el script solo marca el tipo de hallazgo; la gravedad la decide el
# analista/reporter. Solo el RAW de corrida conserva la etiqueta orientativa.
add_finding(){
  local sev="$1" chk="$2" titulo="$3" u="$4" msg="$5"
  local port_e="${6:-}"
  [ -n "$port_e" ] || port_e="null"
  msg="$(printf '%s' "$msg" | mask_credentials)"
  titulo="$(printf '%s' "$titulo" | mask_credentials)"
  # evidencia para el Agente 6: sin severidad (CHECK<TAB>URL<TAB>DETALLE)
  printf '%s\t%s\t%s\n' "$chk" "$u" "$msg" >> "$FIND_TXT"
  {
    printf '{"title":%s,"description":%s,"url":%s,"check":%s,"port":%s,"source":"gobuster_checks"}\n' \
      "$(printf '%s' "$titulo" | esc_json)" \
      "$(printf '%s' "$msg" | esc_json)" \
      "$(printf '%s' "$u" | esc_json)" \
      "$(printf '%s' "$chk" | esc_json)" \
      "$port_e"
  } >> "$FIND_JSONL"
  # RAW de corrida: conserva la etiqueta orientativa para el analista humano
  printf '  [%s] %s | %s\n' "$sev" "$chk" "$u" >> "$RAW"
  printf '      %s\n' "$msg" >> "$RAW"
}

delay_wait(){
  [ "$DELAY" = "0" ] && return
  python3 -c 'import time,sys; time.sleep(float(sys.argv[1]))' "$DELAY" 2>/dev/null || sleep "$DELAY"
}

# hdr_val ARCHIVO_HEADERS NOMBRE_LOWERCASE -> valor del header (o nada)
hdr_val(){
  tr -d '\r' < "$1" | awk -F': ' -v h="$2" '
    tolower($1)==h { idx=index($0,":"); v=substr($0,idx+2); sub(/^[ \t]+/,"",v); print v; exit }'
}
# http_get URL  -> GET_CODE GET_CTYPE GET_SIZE GET_REDIR GET_EFF GET_RC
# Además registra el comando y la salida completa en $CMD_FILE (evidencia humana).
http_get(){
  GET_RC=0
  curl -sS -k --compressed --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -o "$TMP/get_body" -D "$TMP/get_hdrs" \
    -w '%{http_code}\t%{content_type}\t%{size_download}\t%{redirect_url}\t%{url_effective}' \
    "$1" > "$TMP/get_meta" 2>"$TMP/get_err" || GET_RC=$?
  IFS=$'\t' read -r GET_CODE GET_CTYPE GET_SIZE GET_REDIR GET_EFF < "$TMP/get_meta" || true
  GET_CODE="${GET_CODE:-}"; GET_CTYPE="${GET_CTYPE:-}"
  GET_SIZE="${GET_SIZE:-0}"; GET_REDIR="${GET_REDIR:-}"; GET_EFF="${GET_EFF:-}"
  touch "$TMP/get_body" "$TMP/get_hdrs" "$TMP/get_err" "$TMP/get_meta"
  # evidencia humana con comando + salida completa (headers + body)
  if [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ]; then
    {
      printf '\n## GET %s\n' "$1"
      printf '$ curl -sS -k --compressed --http1.1 --connect-timeout %s --max-time %s -A "%s" %s\n' \
        "$CONNECT_TIMEOUT" "$TIMEOUT" "$UA" "$1"
      printf -- '--- headers (%s) ---\n' "$GET_CODE"
      cat "$TMP/get_hdrs" 2>/dev/null
      printf -- '--- body (size %s) ---\n' "$GET_SIZE"
      cat "$TMP/get_body" 2>/dev/null
      printf '%s\n' '--- end ---'
    } >> "$CMD_FILE"
  fi
}

# fetch_url URL  -> F_CODE F_RC (GET simple)
fetch_url(){
  F_RC=0
  curl -sS -k --compressed --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -o "$TMP/f_body" -D "$TMP/f_hdrs" -w '%{http_code}' "$1" > "$TMP/f_meta" 2>/dev/null || F_RC=$?
  F_CODE="$(cat "$TMP/f_meta" 2>/dev/null || true)"
  touch "$TMP/f_body" "$TMP/f_hdrs" "$TMP/f_meta"
}

# options_allow URL -> valor de Allow: (o nada)
options_allow(){
  curl -sS -k --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -X OPTIONS -D - -o /dev/null "$1" 2>/dev/null \
    | tr -d '\r' | awk 'tolower($1)=="allow:" { idx=index($0,":"); v=substr($0,idx+2); sub(/^[ \t]+/,"",v); print v; exit }'
}

# trace_body URL -> imprime el body crudo (vacío si falla)
trace_body(){
  curl -sS -k --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -X TRACE -H "X-Trace-Marker: RecArgXST-$$" "$1" 2>/dev/null || true
}

# webdav_code URL -> status code de PROPFIND Depth:0
webdav_code(){
  curl -sS -k --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -X PROPFIND -H 'Depth: 0' -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true
}
# ---------------------------------------------------------------------------
# Checks individuales. Reciben URL y usan las funciones curl definidas arriba.
# Cada uno termina en ~done y solo agrega findings si corresponde.
# ---------------------------------------------------------------------------

# soft404_size BASE(scheme://host:port) -> tamaño del body 404 del origen (cacheado)
soft404_size(){
  local base="$1" sz
  if [ -f "$CACHE404" ] && grep -q "^${base}$" "$CACHE404"; then
    sz="$(awk -F'\t' -v b="$base" '$1==b {print $2; exit}' "$CACHE404")"
    echo "${sz:-0}"
    return
  fi
  local rnd="RecArg404-$$-${RANDOM}"
  local body="$TMP/f404_body"
  curl -sS -k --compressed --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
    -A "$UA" -o "$body" -w '%{size_download}' "$base/$rnd" 2>/dev/null > "$TMP/f404_sz" || true
  sz="$(cat "$TMP/f404_sz" 2>/dev/null || echo 0)"
  [ -n "$sz" ] || sz=0
  printf '%s\t%s\n' "$base" "$sz" >> "$CACHE404"
  echo "$sz"
}

# check_fingerprint URL -> status/title/redirect/soft404 (usa GET_* del loop)
check_fingerprint(){
  local port_e="${GET_EFF:-}"
  port_e="$(printf '%s' "$port_e" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
  [ -n "$port_e" ] || port_e="null"
  {
    printf '[FINGERPRINT] | %s\n' "$1"
    printf '    STATUS=%s CTYPE=%s SIZE=%s REDIR=%s RC=%s\n' \
      "$GET_CODE" "$GET_CTYPE" "$GET_SIZE" "${GET_REDIR:-}" "$GET_RC"
  } >> "$RAW"
  [ -n "$GET_REDIR" ] && add_finding info FINGERPRINT "Redirect detectado" \
    "$1" "Redirige a: $GET_REDIR" "$port_e"
  case "$GET_CODE" in
    5*) add_finding low FINGERPRINT "HTTP 5xx en ruta descubierta" \
        "$1" "Respuesta $GET_CODE (posible error interno expuesto)" "$port_e" ;;
    4*) [ "$GET_CODE" = 404 ] || add_finding low FINGERPRINT "HTTP $GET_CODE en ruta descubierta" \
        "$1" "Respuesta $GET_CODE (acceso restringido o ruta no pública)" "$port_e" ;;
  esac
  # título de página
  local title
  title="$(grep -oiE '<title[^>]*>[^<]*' "$TMP/get_body" 2>/dev/null | head -1 \
    | sed -E 's/<title[^>]*>//i')"
  [ -n "$title" ] && add_finding info FINGERPRINT "Titulo de página" \
    "$1" "title: $title" "$port_e"
  # soft-404: 200 pero body igual al 404 canónico del origen
  if [ "$GET_CODE" = 200 ]; then
    local base sz404
    base="$(printf '%s' "$1" | sed -E 's#^(https?://[^/]+).*$#\1#')"
    [ -n "$base" ] && [ "$base" != "$1" ] || base="$1"
    sz404="$(soft404_size "$base")"
    if [ -n "$sz404" ] && [ "$sz404" -gt 0 ] && [ "$GET_SIZE" = "$sz404" ]; then
      add_finding low FINGERPRINT "Posible soft-404 (200 con body de 404)" \
        "$1" "size=$GET_SIZE igual al body 404 del origen" "$port_e"
    fi
  fi
  check_fingerprint_done=1
}
# check_headers URL -> security headers ausentes + headers reveladores (usa GET_* del loop)
# Se reporta UNA vez por sitio (host:puerto): los headers son del servidor, no del path.
check_headers(){
  # Si este sitio ya fue analizado en otro path, no duplicamos (única fuente por sitio).
  site_seen "HEADERS" "$(site_key "$1")" && { check_headers_done=1; return 0; }
  # Los headers que importan se leen de la RAÍZ del sitio (site_fetch cachea).
  site_fetch "$1"
  local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
  [ -n "$port_e" ] || port_e="null"
  # headers presentes en minúscula (desde la raíz del sitio)
  local hds
  hds="$(tr -d '\r' < "$TMP/site_hdrs" | awk -F': ' 'tolower($1) ~ /^[a-z0-9-]+$/ {print tolower($1)}' | sort -u)"
  {
    printf '[HEADERS] | %s\n' "$(site_base "$1")/"
    tr -d '\r' < "$TMP/site_hdrs" | head -40
  } >> "$RAW"
  # security headers ausentes según scheme
  local shdr
  for shdr in content-security-policy x-frame-options x-content-type-options referrer-policy permissions-policy; do
    printf '%s\n' "$hds" | grep -qx "$shdr" || \
      add_finding low HEADERS "Falta header de seguridad: $shdr" "$1" "No se envía $shdr" "$port_e"
  done
  if printf '%s' "$1" | grep -q '^https://'; then
    printf '%s\n' "$hds" | grep -qx 'strict-transport-security' || \
      add_finding low HEADERS "Falta header de seguridad: strict-transport-security" \
        "$1" "No se envía HSTS (esquema HTTPS)" "$port_e"
  fi
  # headers que revelan infraestructura (SOLO los que no son "versión"; esos van a VERSIONS)
  local leak hval
  for leak in x-varnish; do
    hval="$(hdr_val "$TMP/site_hdrs" "$leak")"
    [ -n "$hval" ] && add_finding low HEADERS "Header revela software/framework: $leak" \
      "$1" "$leak: $hval" "$port_e"
  done
  check_headers_done=1
}

# check_versions URL -> fingerprint de software con versión.
# Se reporta UNA vez por sitio y se lee de la RAÍZ (site_fetch) para capturar el
# Server completo (ej. "Microsoft-IIS/10.0") y headers de framework con versión
# (X-AspNetMvc-Version, X-AspNet-Version, X-Powered-By) sin perderlos en redirects.
check_versions(){
  # Si este sitio ya fue analizado en otro path, no duplicamos.
  site_seen "VERSIONS" "$(site_key "$1")" && { check_versions_done=1; return 0; }
  site_fetch "$1"
  local base="$(site_base "$1")/"
  local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
  [ -n "$port_e" ] || port_e="null"
  # Server header COMPLETO (literal, sin recortar: Microsoft-IIS/10.0)
  local srv
  srv="$(hdr_val "$TMP/site_hdrs" "server")"
  [ -n "$srv" ] && add_finding info VERSIONS "Software identificado (Server header)" \
    "$base" "Server: $srv" "$port_e"
  # Headers de versión del framework, con su valor literal
  local h hval
  for h in x-powered-by x-aspnet-version x-aspnetmvc-version x-runtime; do
    hval="$(hdr_val "$TMP/site_hdrs" "$h")"
    [ -n "$hval" ] && add_finding info VERSIONS "Tecnología/versión identificada ($h)" \
      "$base" "$h: $hval" "$port_e"
  done
  # generator meta, powered by, footers comunes en body (raíz del sitio)
  local v
  v="$(grep -oiE '<meta[^>]*name="generator"[^>]*content="[^"]*"' "$TMP/site_body" 2>/dev/null | head -1)"
  if [ -n "$v" ]; then
    v="$(printf '%s' "$v" | sed -E 's/.*content="([^"]*)"/\1/')"
    [ -n "$v" ] && add_finding info VERSIONS "CMS/framework por <meta generator>" \
      "$base" "generator: $v" "$port_e"
  fi
  check_versions_done=1
}
# check_methods URL -> OPTIONS: métodos peligrosos permitidos
check_methods(){
  local meth
  meth="$(options_allow "$1")"
  [ -n "$meth" ] && [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ] && {
    { printf '\n## OPTIONS %s\n' "$1"
      printf '$ curl -X OPTIONS %s\n' "$1"
      printf -- '--- Allow ---\n%s\n--- end ---\n' "$meth"
    } >> "$CMD_FILE"; }
  local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
  [ -n "$port_e" ] || port_e="null"
  [ -n "$meth" ] || { check_methods_done=1; return; }
  printf '[METHODS] Allowed | %s: %s\n' "$1" "$meth" >> "$RAW"
  # 1) métodos destructivos/riesgosos
  for m in PUT DELETE PATCH; do
    if printf '%s' "$meth" | grep -qiw "$m"; then
      add_finding high METHODS "Método $m permitido" \
        "$1" "OPTIONS Allow incluye $m (puede permitir modificar/borrar recursos)" "$port_e"
    fi
  done
  for m in PROPFIND MKCOL COPY MOVE LOCK; do
    if printf '%s' "$meth" | grep -qiw "$m"; then
      add_finding medium METHODS "Método WebDAV $m permitido" \
        "$1" "OPTIONS Allow incluye $m" "$port_e"
    fi
  done
  # 2) TRACE en Allow: potencial XST (el check TRACE confirma si refleja)
  if printf '%s' "$meth" | grep -qiw 'TRACE'; then
    add_finding low METHODS "TRACE listado en Allow (verificar XST)" \
      "$1" "OPTIONS Allow incluye TRACE (el check TRACE confirma si refleja)" "$port_e"
  fi
  check_methods_done=1
}

# check_trace URL -> TRACE refleja X-Trace-Marker => XST
check_trace(){
  local b m
  b="$(trace_body "$1")"
  [ -n "$b" ] && [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ] && {
    { printf '\n## TRACE %s\n' "$1"
      printf '$ curl -X TRACE %s\n' "$1"
      printf '%s\n' '--- body ---'
      printf '%s\n' "$b" | head -c 400
      printf '%s\n' '--- end ---'
    } >> "$CMD_FILE"; }
  [ -n "$b" ] || { check_trace_done=1; return; }
  m="$(printf '%s' "$b" | grep -o 'RecArgXST-[0-9]*' | head -1)"
  if [ -n "$m" ]; then
    local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
    [ -n "$port_e" ] || port_e="null"
    add_finding medium TRACE "TRACE habilitado (posible XST)" \
      "$1" "El cuerpo de TRACE refleja el encabezado X-Trace-Marker: $m" "$port_e"
  fi
  check_trace_done=1
}

# check_listing URL -> directory listing visible (usa GET_* del loop)
check_listing(){
  [ "$GET_CODE" = 200 ] || { check_listing_done=1; return; }
  if grep -aEiq 'Index of|Parent Directory|\[DIR\]|Directory listing|Last modified' "$TMP/get_body"; then
    local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
    [ -n "$port_e" ] || port_e="null"
    add_finding medium LISTING "Posible directory listing" \
      "$1" "El body muestra marcas de listado de directorio (Index of / [DIR])" "$port_e"
  fi
  check_listing_done=1
}

# check_patterns URL -> credenciales, errores reveladores, phpinfo, rutas sensibles
check_patterns(){
  local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
  [ -n "$port_e" ] || port_e="null"
  # 1) ruta sensible por propio nombre (backup, .git, .env, config, phpMyAdmin...)
  if printf '%s' "$1" | grep -qiE '\.(git|env|bak|backup|sql|zip|tar|gz|log|conf|ini|yml|yaml|json)$|(^|/)(\.git|\.env|config|admin|phpmyadmin|manager|console|backup|test|dev|old)(/|$)'; then
    add_finding medium PATTERNS "Ruta de interés por nombre" \
      "$1" "El path descubierto sugiere archivo/directorio sensible" "$port_e"
  fi
  # 2) credenciales/secretos en body
  local hit
  hit="$(grep -aoiE '(password|passwd|pwd|secret|api[_ -]?key|client[_ -]?secret|access[_ -]?token|auth[_ -]?token|BEGIN (RSA )?PRIVATE KEY|AKIA[0-9A-Z]{10,})[=: ]+[A-Za-z0-9_./+=%-]{6,}' "$TMP/get_body" 2>/dev/null | head -1)"
  if [ -n "$hit" ]; then
    add_finding high PATTERNS "Credencial/secret en el body" \
      "$1" "Snippet: $(printf '%s' "$hit" | mask_credentials | head -c 160)" "$port_e"
  fi
  # 3) errores reveladores / stack traces / SQL
  hit="$(grep -aoiE 'Fatal error|Parse error|Warning:|SQLSTATE|Stack trace|Traceback|syntax error|Uncaught [A-Za-z]+|exception.*at [A-Za-z0-9_.]+\(|phpinfo\(|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$TMP/get_body" 2>/dev/null | head -1)"
  if [ -n "$hit" ]; then
    add_finding medium PATTERNS "Error/debug revelador en el body" \
      "$1" "Coincidencia: $(printf '%s' "$hit" | head -c 160)" "$port_e"
  fi
  check_patterns_done=1
}

# check_cors URL -> CORS reflejado (débil) + allow-credentials
check_cors(){
  curl -sS -k --compressed --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -H "Origin: https://evil-RecArg-$$.example" -D "$TMP/cors_hdrs" -o /dev/null "$1" 2>/dev/null || true
  [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ] && {
    { printf '\n## CORS %s\n' "$1"
      printf '$ curl -H "Origin: https://evil-RecArg-$$.example" %s\n' "$1"
      printf '%s\n' '--- headers ---'
      cat "$TMP/cors_hdrs" 2>/dev/null
      printf '%s\n' '--- end ---'
    } >> "$CMD_FILE"; }
  local acao acac
  acao="$(hdr_val "$TMP/cors_hdrs" "access-control-allow-origin")"
  acac="$(hdr_val "$TMP/cors_hdrs" "access-control-allow-credentials")"
  if [ -n "$acao" ] && printf '%s' "$acao" | grep -q "evil-RecArg"; then
    local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
    [ -n "$port_e" ] || port_e="null"
    if printf '%s' "$acac" | grep -qi 'true'; then
      add_finding medium CORS "CORS refleja origin + Allow-Credentials" \
        "$1" "ACAO=$acao + ACAC=$acac (permite leer respuestas autenticadas cross-origin)" "$port_e"
    else
      add_finding low CORS "CORS refleja origin arbitrario" \
        "$1" "ACAO=$acao (sin Allow-Credentials)" "$port_e"
    fi
  fi
  check_cors_done=1
}

# check_webdav URL -> PROPFIND Depth:0 207 Multi-Status
check_webdav(){
  local code
  code="$(webdav_code "$1")"
  [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ] && {
    { printf '\n## WEBDAV PROPFIND %s\n' "$1"
      printf '$ curl -X PROPFIND -H "Depth: 0" %s\n' "$1"
      printf '--- HTTP %s ---\n' "$code"
      printf '%s\n' '--- end ---'
    } >> "$CMD_FILE"; }
  if [ "$code" = 207 ] || [ "$code" = 201 ]; then
    local port_e="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^:/]+):?([0-9]*).*#\2#')"
    [ -n "$port_e" ] || port_e="null"
    add_finding medium WEBDAV "WebDAV habilitado (PROPFIND responde $code)" \
      "$1" "PROPFIND Depth:0 devuelve $code (listado/propiedades de recursos)" "$port_e"
  fi
  check_webdav_done=1
}

# =============================================================================
# INICIALIZACIÓN GLOBAL DE LA CORRIDA
# =============================================================================
N_OK=0; N_SKIP=0; N_NOCONN=0; N_FINDINGS=0; N_URLS=0
declare -a URLS
# Sitios (host:puerto) cuyos headers/versiones YA fueron reportados: los checks
# de sitio (HEADERS, VERSIONS) solo se reportan UNA vez por host:puerto; los
# demás paths de ese mismo sitio se omiten (evita cientos de duplicados).
declare -a SITES_REPORTED

# site_key URL -> host:puerto (sin path) — normaliza para el registro de duplicados.
# Si la URL no trae puerto explícito, usa el puerto por defecto del esquema.
site_key(){
  local k
  k="$(printf '%s' "$1" | sed -E 's#^[a-z]+://([^/]+)/?.*#\1#')"
  if printf '%s' "$k" | grep -q ':'; then
    printf '%s' "$k"
  elif printf '%s' "$1" | grep -q '^https://'; then
    printf '%s:443' "$k"
  else
    printf '%s:80' "$k"
  fi
}

# site_seen CHECK URL -> 0 si (CHECK + host:puerto) ya fue reportado, 1 si es nuevo.
# Cada check de sitio (HEADERS, VERSIONS) se reporta UNA vez por host:puerto; el
# registro es por (check, sitio) para que un check no bloquee al otro.
site_seen(){
  local key="$1|$2" s
  for s in "${SITES_REPORTED[@]:-}"; do
    [ "$s" = "$key" ] && return 0
  done
  SITES_REPORTED+=("$key")
  return 1
}

# site_base URL -> scheme://host:puerto (sin path, sin barra final) — base del sitio.
site_base(){
  local scheme rest
  scheme="${1%%://*}"
  rest="${1#*://}"
  rest="${rest%%/*}"
  printf '%s://%s' "$scheme" "$rest"
}

# site_fetch URL -> hace GET/HEAD a la RAÍZ del sitio (una sola vez por corrida,
# cachado por host:puerto) y deja $TMP/site_hdrs y $TMP/site_body con la respuesta.
# Motivo: los headers de versión del servidor (Server, X-AspNetMvc-Version,
# X-AspNet-Version, X-Powered-By) se capturan mejor en la raíz; la primera ruta de
# gobuster suele redirigir (301) y pierde esos headers.
site_fetch(){
  local base="$1" k url
  k="$(site_key "$base")"
  # si ya se muestreó este sitio en esta corrida, no repetir
  if [ -f "$CACHE_SITE" ] && grep -qx "^$k$" "$CACHE_SITE" 2>/dev/null; then
    return 0
  fi
  url="$(site_base "$base")/"
  curl -sS -k --compressed --http1.1 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" -A "$UA" \
    -o "$TMP/site_body" -D "$TMP/site_hdrs" \
    -w '%{http_code}' "$url" > "$TMP/site_meta" 2>/dev/null || true
  touch "$TMP/site_body" "$TMP/site_hdrs" "$TMP/site_meta"
  # evidencia humana: comando + respuesta de la raíz del sitio
  if [ "$DRY" = 0 ] && [ -n "${CMD_FILE:-}" ]; then
    {
      printf '\n## SITE-ROOT %s\n' "$url"
      printf '$ curl -sS -k --compressed --http1.1 --connect-timeout %s --max-time %s -A "%s" %s\n' \
        "$CONNECT_TIMEOUT" "$TIMEOUT" "$UA" "$url"
      printf -- '--- headers ---\n'
      cat "$TMP/site_hdrs" 2>/dev/null
      printf '%s\n' '--- end ---'
    } >> "$CMD_FILE"
  fi
  printf '%s\n' "$k" >> "$CACHE_SITE"
}

mkdir -p "$OUTDIR"
TMP="$OUTDIR/.tmp.$$"; mkdir -p "$TMP"
RAW="$OUTDIR/gobuster_checks_RAW.txt"
UNREACH="$OUTDIR/gobuster_checks_unreachable.txt"
FIND_TXT=""; FIND_JSON=""; FIND_JSONL=""      # se reasignan por target
CMD_FILE=""                                   # evidencia humana por target
OK_URLS="$TMP/ok_urls"
CACHE404="$TMP/404.cache"
CACHE_SITE="$TMP/site_fetched.cache"
[ "$DRY" = 0 ] && { : > "$RAW"; : > "$UNREACH"; : > "$OK_URLS"; : > "$CACHE404"; : > "$CACHE_SITE"; }

# =============================================================================
# build_urls TARGET_DIR IP -> llena el array global URLS
# =============================================================================
build_urls(){
  local tdir="$1" ip="$2" f port scheme
  URLS=()
  for f in "$tdir"/outputs/gobuster_*.txt; do
    [ -f "$f" ] || continue; [ -s "$f" ] || continue
    port=$(basename "$f" | sed -E 's/^gobuster_([0-9]+)\.txt$/\1/')
    scheme=http
    if [ -f "$tdir/outputs/httpx.json" ] && grep -q "\"https://$ip:$port" "$tdir/outputs/httpx.json"; then
      scheme=https
    fi
    while read -r path rest; do
      [ -n "$path" ] || continue
      case "$path" in \#*|Running|Finished) continue ;; esac
      URLS+=("$scheme://$ip:$port/$path")
    done < "$f"
  done
  # dedupe y orden (LC_ALL=C evita 'Illegal byte sequence' en macOS con bytes no-UTF8)
  URLS=( $(printf '%s\n' "${URLS[@]:-}" | LC_ALL=C sort -u | grep -v '^$') )
}

# =============================================================================
# precheck_conn URL_BASE -> 0 si la conexión TCP/web responde (probe silencioso)
# =============================================================================
precheck_conn(){
  curl -s -k --http1.1 --connect-timeout "$CONNECT_TIMEOUT" \
    --max-time "$TIMEOUT" -o /dev/null "$1" 2>/dev/null
}

# =============================================================================
# process_url URL — un GET + todos los checks habilitados (target o legado)
# =============================================================================
process_url(){
  local url="$1" local_err
  [ "$DRY" = 1 ] && { echo "  # $url"; return 0; }
  N_URLS=$((N_URLS+1))
  http_get "$url"
  if [ -n "$GET_RC" ] && [ "$GET_RC" != 0 ] || [ -z "$GET_CODE" ] || [ "$GET_CODE" = "000" ]; then
    local_err="$(head -n 1 "$TMP/get_err" 2>/dev/null)"
    printf 'UNREACHABLE\t%s\t%s\n' "$url" "${local_err:-rc=$GET_RC}" >> "$UNREACH"
    printf '  [SIN_CONEXION] %s | %s\n' "$url" "${local_err:-}" >> "$RAW"
    delay_wait
    return 0
  fi
  printf '%s\n' "$url" >> "$OK_URLS"
  [ "$c_FINGERPRINT" = 1 ] && check_fingerprint "$url"
  [ "$c_HEADERS"     = 1 ] && check_headers "$url"
  [ "$c_VERSIONS"    = 1 ] && check_versions "$url"
  [ "$c_METHODS"     = 1 ] && check_methods "$url"
  [ "$c_TRACE"       = 1 ] && check_trace "$url"
  [ "$c_LISTING"     = 1 ] && check_listing "$url"
  [ "$c_PATTERNS"    = 1 ] && check_patterns "$url"
  [ "$c_CORS"        = 1 ] && check_cors "$url"
  [ "$c_WEBDAV"      = 1 ] && check_webdav "$url"
  delay_wait
}

# =============================================================================
# run_one_target IP — el corazón del modo por target
# =============================================================================
run_one_target(){
  local ip="$1" tdir outd nfind d
  # Patrón exacto ${ip}_* para no confundir prefijos (ej. 10.155.10.150 vs 10.155.10.15);
  # se elige la primera carpeta que tenga outputs/.
  tdir=""
  for d in "$TARGET_BASE"/"${ip}"_*; do
    [ -d "$d/outputs" ] && { tdir="$d"; break; }
  done
  [ -n "$tdir" ] || { echo "  [ERROR] $ip: no hay carpeta ${ip}_* con outputs/ en CLIENTE."; return 0; }
  outd="$tdir/outputs"

  # 2- SKIP si ya escaneado (para no sobrescribir lo hecho con otra VPN).
  if [ -f "$outd/gobuster_evidence.txt" ] || [ -f "$outd/gobuster_evidence.json" ]; then
    if [ "$FORCE" = 1 ]; then
      echo "  [!FORCE] $ip: reescaneando evidencia previa"
      rm -f "$outd/gobuster_evidence.txt" "$outd/gobuster_evidence.json"
    else
      echo "  [SKIP] $ip: ya escaneado (gobuster_evidence.*). Usa --force para reescanear."
      N_SKIP=$((N_SKIP+1))
      return 0
    fi
  fi

  # 3- URLs del target
  build_urls "$tdir" "$ip"
  [ "${#URLS[@]}" -ge 1 ] || { echo "  [SKIP] $ip: sin gobuster URLs que revisar"; return 0; }

  # 4- PRECHECK DE CONECTIVIDAD ANTES DE ESCRIBIR NADA
  if [ "$CHECK_CONN" = 1 ] && [ "$DRY" = 0 ]; then
    if ! precheck_conn "${URLS[0]}"; then
      printf 'SIN_CONEXION\t%s\t%s\n' "$ip" "target no alcanzable en esta corrida (VPN del rango?)" >> "$UNREACH"
      printf '  [SIN_CONEXION] target=%s url=%s\n' "$ip" "${URLS[0]}" >> "$RAW"
      echo "  [NO_CONEX] $ip: sin conectividad en esta corrida. No generé hallazgos."
      N_NOCONN=$((N_NOCONN+1))
      return 0
    fi
    echo "  [OK-CONN] $ip: precheck de conectividad superado"
  fi

  # 5- salidas POR TARGET (variable globales que usan checks/add_finding)
  FIND_TXT="$outd/gobuster_evidence.txt"
  FIND_JSON="$outd/gobuster_evidence.json"
  FIND_JSONL="$TMP/evidence_${ip}.jsonl"
  CMD_FILE="$outd/gobuster_commands_outputs.txt"
  : > "$FIND_TXT"; : > "$FIND_JSONL"
  {
    echo "# gobuster_commands_outputs — $ip ($(date '+%Y-%m-%d %H:%M:%S'))"
    echo "# Guarda CADA comando curl ejecutado y su salida completa."
    echo "# Es EVIDENCIA PARA AUDITORÍA HUMANA; NO lo consume el Agente 6."
  } >> "$CMD_FILE"

  # 6- procesar cada URL
  for url in "${URLS[@]}"; do
    [ "$DRY" = 1 ] && { echo "  # $url"; continue; }
    process_url "$url"
  done
  [ "$DRY" = 1 ] && return 0

  # 7- concluir: evidence.txt (cabecera + hallazgos) + evidence.json
  {
    printf '# Inspecciones gobuster - %s (%s)\n' "$ip" "$(date '+%Y-%m-%d %H:%M:%S')"
    cat "$FIND_TXT" 2>/dev/null
  } > "$FIND_TXT.tmp"; mv "$FIND_TXT.tmp" "$FIND_TXT"
  {
    printf '[\n'; first=1
    while IFS= read -r line; do
      [ -n "$line" ] || continue; [ "$first" = 1 ] || printf ',\n'
      printf '%s' "$line"; first=0
    done < "$FIND_JSONL"
    printf '\n]\n'
  } > "$FIND_JSON"

  nfind=$(wc -l < "$FIND_TXT" 2>/dev/null || echo 0)
  N_FINDINGS=$((N_FINDINGS + nfind))
  echo "  [OK] $ip: $nfind hallazgos en outputs/gobuster_evidence* + commands_outputs.txt"
  N_OK=$((N_OK+1))
}
# =============================================================================
# run_all: recorrer todos los targets de CLIENTE con gobuster_*.txt
# =============================================================================
run_all(){
  local d ip
  for d in "$TARGET_BASE"/*/; do
    [ -d "$d/outputs" ] || continue
    ls "$d/outputs"/gobuster_*.txt >/dev/null 2>&1 || continue
    ip="$(basename "$d")"; ip="${ip%%_*}"
    echo ">>> target: $ip"
    run_one_target "$ip"
  done
}

# =============================================================================
# run_legacy: lista plana global (compatibilidad con el modo antiguo)
# =============================================================================
run_legacy(){
  local n=0 url
  echo "MODO LEGACY: $ARCH"
  [ -f "$ARCH" ] || { echo "ERROR: no existe $ARCH" >&2; exit 1; }
  FIND_TXT="$OUTDIR/gobuster_checks_findings.txt"
  FIND_JSON="$OUTDIR/gobuster_checks_findings.json"
  FIND_JSONL="$TMP/findings.jsonl"
  : > "$FIND_TXT"; : > "$FIND_JSONL"
  while IFS= read -r url; do
    [ -n "$url" ] || continue
    case "$url" in \#*) continue ;; esac
    process_url "$url"
    [ -z "$LIMIT" ] || { n=$((n+1)); [ "$n" -ge "$LIMIT" ] && break; }
  done < "$ARCH"
  [ "$DRY" = 1 ] && return 0
  {
    printf '[\n'; first=1
    while IFS= read -r line; do
      [ -n "$line" ] || continue; [ "$first" = 1 ] || printf ',\n'
      printf '%s' "$line"; first=0
    done < "$FIND_JSONL"
    printf '\n]\n'
  } > "$FIND_JSON"
}

# ---------- ORQUESTACIÓN SEGÚN MODO ----------
case "$MODE" in
  target|one)
    [ -n "$TARGET_IP" ] || { echo "ERROR: falta --target <IP>" >&2; usage 1; }
    echo ">>> target: $TARGET_IP"
    run_one_target "$TARGET_IP"
    ;;
  all)
    run_all
    ;;
  *)
    if [ -n "$ARCH" ]; then run_legacy; else echo "ERROR: usa --target <IP>, --all o --urls <archivo>" >&2; usage 1; fi
    ;;
esac

# ---------- resumen final ----------
if [ "$DRY" = 0 ]; then
  echo ""
  echo "============================================================"
  echo "RESUMEN: OK=$N_OK | SKIP=$N_SKIP | SIN_CONEXION=$N_NOCONN | hallazgos=$N_FINDINGS"
  [ "$N_SKIP" -gt 0 ] && echo "  SKIP: ya escaneados (no se sobrescriben). --force para reescanear."
  [ "$N_NOCONN" -gt 0 ] && echo "  SIN_CONEXION: conectá la VPN del rango pendiente y volvé a correr."
  echo "  RAW:      $RAW"
  echo "  UNREACH:  $UNREACH"
else
  echo "DRY-RUN: nada ejecutado; arriba las URLs que correrían."
  echo "  modo=$MODE target=$TARGET_IP all=$ALL check_conn=$CHECK_CONN"
fi
[ "$KEEP" = 0 ] && rm -rf "$TMP" 2>/dev/null || true

