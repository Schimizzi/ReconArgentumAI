#!/bin/bash
# =============================================================================
# hydra_audit.sh — Auditoría MANUAL de autenticación por fuerza bruta (Hydra)
# =============================================================================
# Uso:
#   scripts/hydra_audit.sh --all [--services ftp,ssh] [--force] [--dry-run]
#   scripts/hydra_audit.sh <IP> [<servicio>] [--port PORT] [--force] [--dry-run]
#   scripts/hydra_audit.sh <IP> <servicio> -L users.txt -P pass.txt ...
#
# QUÉ HACE (NO está integrado a la Fase 1 del pipeline: es MANUAL, bajo demanda):
#   1. Respeta el alcance (R1): solo targets de config/scope.json no excluidos.
#   2. En modo --all recorre TODOS los targets autorizados × TODOS sus puertos
#      auditables (mapeo puerto → módulo Hydra), de forma SECUENCIAL y con los
#      delays de stealth de config/stealth.yaml. Arranca SIN confirmación.
#   3. Por servicio ejecuta hydra con un LÍMITE de intentos (default 25, desde
#      stealth.yaml: hydra_max_attempts) y clasifica en tres estados:
#        VULNERABLE     → hydra encontró un login válido (evidencia conservada).
#        NO_VULNERABLE  → hydra probó la lista COMPLETA sin bloqueos y sin
#                         login válido → no se atribuye vulnerabilidad.
#        INCONCLUSO     → hydra NO pudo terminar la lista (timeout, [ERROR],
#                         bloqueo "too many bad logins", watchdog, etc.).
#   4. Todo el output verboso (-v) de CADA ejecución queda en logs/hydra.log
#      (append acumulado, nunca se borra): comando, resultado y hallazgo.
#
# Guardrails:
#   R1 — Solo targets autorizados (config/scope.json).
#   R2 — Solo evidencia de credenciales débiles; nunca explota el acceso y no
#        continúa más allá del primer login débil encontrado (-f).
#   R4 — Evidencia del hallazgo completa en evidence/<IP>/.
#   R5 — Threads/timeout/límite de intentos/sin wait desde config/stealth.yaml
#        (nada hardcodeado en los comandos).
# =============================================================================
set -uo pipefail

WS="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$WS/logs"
LOG="$LOG_DIR/hydra.log"
SUMMARY_FILE=""
mkdir -p "$LOG_DIR"

# ---- Config desde config/stealth.yaml (R5) -----------------------------------
cfg() { awk -v k="$1" 'index($0,k":")==1 {print $2; exit}' "$WS/config/stealth.yaml"; }
H_THREADS="${hydra_threads:-$(cfg hydra_threads)}";        H_THREADS="${H_THREADS:-4}"
H_WAIT="${hydra_wait_seconds:-$(cfg hydra_wait_seconds)}"; H_WAIT="${H_WAIT:-2}"
H_CUTOFF="${hydra_service_cutoff_seconds:-$(cfg hydra_service_cutoff_seconds)}"; H_CUTOFF="${H_CUTOFF:-120}"
H_MAX_ATT="${hydra_max_attempts:-$(cfg hydra_max_attempts)}"; H_MAX_ATT="${H_MAX_ATT:-25}"
DELAY_TOOLS=$(cfg delay_between_tools_seconds);     DELAY_TOOLS="${DELAY_TOOLS:-30}"
DELAY_TARGET=$(cfg delay_between_targets_minutes);  DELAY_TARGET="${DELAY_TARGET:-5}"

# ---- Herramientas requeridas --------------------------------------------------
HYDRA_BIN="$(command -v hydra 2>/dev/null || true)"
if [ -z "$HYDRA_BIN" ]; then
  echo "❌ hydra no está instalado." >&2
  echo "   host/macOS:     brew install hydra    (o: bash scripts/install_host_tools.sh)" >&2
  echo "   VM Kali/Docker: sudo apt-get install hydra" >&2
  exit 1
fi

# ---- Estado / opciones ---------------------------------------------------------
ALL=0; DRY=0; FORCE=0
USER_SPEC=(); PASS_SPEC=(); COMBOS_SPEC=""
SINGLE_USER=""; SINGLE_PASS=""
SERVICES_FILTER=""; PORT=""; FORM_SPEC=""
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --all)            ALL=1; shift ;;
    --dry-run)        DRY=1; shift ;;
    --force)          FORCE=1; shift ;;
    -L)               shift; USER_SPEC=(-L "$1"); shift ;;
    -l)               shift; SINGLE_USER="$1"; shift ;;
    -P)               shift; PASS_SPEC=(-P "$1"); shift ;;
    -p)               shift; SINGLE_PASS="$1"; shift ;;
    -C)               shift; COMBOS_SPEC="$1"; shift ;;
    --services)       shift; SERVICES_FILTER="$1"; shift ;;
    -s|--port)        shift; PORT="$1"; shift ;;
    -m|--form)        shift; FORM_SPEC="$1"; shift ;;
    -*)               echo "Opción desconocida: $1" >&2; exit 1 ;;
    *)                POSITIONAL+=("$1"); shift ;;
  esac
done

DEFAULT_PASS_FILE="$WS/tools/seclists_common.txt"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/hydra_audit.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

log(){ echo "[$(date +%H:%M:%S)] $*"; }
die(){ echo "❌ $*" >&2; exit 1; }
# wc -l devuelve espacios a la izquierda; helper que los elimina ("" si no existe)
lines(){ wc -l < "$1" 2>/dev/null | tr -d ' '; }

# ---- R1: alcance (config/scope.json) ------------------------------------------
in_scope() {
  local ip="$1"
  jq -e --arg ip "$ip" '.authorized_targets[] | select(.ip == $ip)' "$WS/config/scope.json" >/dev/null 2>&1 || return 1
  if jq -e --arg ip "$ip" '.excluded_ips[] | select(. == $ip)' "$WS/config/scope.json" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

# Imprime las IPs autorizadas y NO excluidas (una por línea).
load_targets() {
  jq -r '.authorized_targets[].ip' "$WS/config/scope.json" 2>/dev/null | \
  while read -r ip; do
    [ -z "$ip" ] && continue
    in_scope "$ip" && echo "$ip"
  done
}

# ---- Tabla puerto → módulo Hydra (modules verificados en hydra 9.7) -------------
svc_for_port() {
  case "$1" in
    21)      echo ftp ;;
    22)      echo ssh ;;
    23)      echo telnet ;;
    25)      echo smtp ;;
    80)      echo http-get ;;
    110)     echo pop3 ;;
    139|445) echo smb ;;
    143)     echo imap ;;
    161)     echo snmp ;;
    389)     echo ldap3 ;;
    443)     echo https-get ;;
    465)     echo smtps ;;
    587)     echo smtp ;;
    636)     echo ldap3 ;;
    990)     echo ftps ;;
    993)     echo imaps ;;
    995)     echo pop3s ;;
    1433)    echo mssql ;;
    1521)    echo oracle-listener ;;
    3306)    echo mysql ;;
    3389)    echo rdp ;;
    5060)    echo sip ;;
    5432)    echo postgres ;;
    5900)    echo vnc ;;
    6379)    echo redis ;;
    8080|8081) echo http-get ;;
    8443)    echo https-get ;;
    *)       echo "" ;;
  esac
}

default_port_for() {
  case "$1" in
    ftp) echo 21;;        ssh) echo 22;;       telnet) echo 23;;    smtp) echo 25;;
    http-get) echo 80;;   pop3) echo 110;;     smb) echo 445;;      imap) echo 143;;
    snmp) echo 161;;      ldap3) echo 389;;    https-get) echo 443;; smtps) echo 465;;
    ftps) echo 990;;      imaps) echo 993;;    pop3s) echo 995;;    mssql) echo 1433;;
    oracle-listener) echo 1521;; mysql) echo 3306;; rdp) echo 3389;; sip) echo 5060;;
    postgres) echo 5432;; vnc) echo 5900;;     redis) echo 6379;;
    http-post-form) echo 80;; https-post-form) echo 443;;
    *) echo "";;
  esac
}

# Filtro --services  (vacío = todos)
svc_allowed() {
  local svc="$1" f
  [ -z "$SERVICES_FILTER" ] && return 0
  IFS=',' read -ra _svcs <<< "$SERVICES_FILTER"
  for f in "${_svcs[@]}"; do [ "$f" = "$svc" ] && return 0; done
  return 1
}

# ---- Puertos auditables de un target (desde la evidencia del pipeline) ---------
# Imprime "<PUERTO> <SERVICIO>" por línea; rc=1 si no hay evidencia (Fase 1 previa).
auditable_services() {
  local ip="$1" evid="$WS/evidence/$ip" port svc list=""
  if [ -s "$evid/open_ports.txt" ]; then
    list=$(sed 's/.*://' "$evid/open_ports.txt" | sort -un)
  elif [ -s "$evid/nmap_detailed.xml" ]; then
    list=$(python3 - "$evid/nmap_detailed.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
except Exception:
    sys.exit(0)
out = []
for p in tree.iter('port'):
    if p.get('protocol') != 'tcp':
        continue
    st = p.find('state')
    if st is None or st.get('state') != 'open':
        continue
    out.append(int(p.get('portid')))
print('\n'.join(str(x) for x in sorted(set(out))))
PY
)
  else
    return 1
  fi
  [ -z "$list" ] && return 0
  while read -r port; do
    [ -z "$port" ] && continue
    svc="$(svc_for_port "$port")"
    [ -z "$svc" ] && continue
    svc_allowed "$svc" || continue
    echo "$port $svc"
  done <<< "$list"
}

# ---- Credenciales con límite de intentos (solo evidencia, R5) -------------------
# Setea CRED_ARGS (array) y ATTEMPTS_N por servicio. El límite hydra_max_attempts
# (default 25) trunca la lista que corresponda y avisa. snmp/redis solo usan
# contraseña (community string / AUTH), no usuario.
build_creds() {
  local svc="$1" pass_only=0 users_n=0 pass_n=0 orig=0
  case "$svc" in snmp|redis) pass_only=1;; esac
  CRED_ARGS=(); ATTEMPTS_N=0

  # -C archivo login:pass (aplica igual a todos los servicios)
  if [ -n "$COMBOS_SPEC" ]; then
    local cn; cn="$(lines "$COMBOS_SPEC")"; cn="${cn:-0}"
    if [ "$cn" -gt "$H_MAX_ATT" ]; then
      head -n "$H_MAX_ATT" "$COMBOS_SPEC" > "$TMP/combos.lst"
      COMBOS_SPEC="$TMP/combos.lst"; cn="$H_MAX_ATT"
      echo "  ⚠️  -C excede ${H_MAX_ATT} líneas → truncado a ${H_MAX_ATT} (solo evidencia)" >&2
    fi
    ATTEMPTS_N="$cn"; CRED_ARGS=(-C "$COMBOS_SPEC")
    return 0
  fi

  # usuarios
  local u_args=()
  if [ "$pass_only" -eq 1 ]; then
    u_args=()
  elif [ -n "$SINGLE_USER" ]; then
    u_args=(-l "$SINGLE_USER"); users_n=1
  elif [ ${#USER_SPEC[@]} -gt 0 ]; then
    u_args=("${USER_SPEC[@]}"); users_n="$(lines "${USER_SPEC[1]}")"; users_n="${users_n:-1}"
  else
    printf '%s\n' root admin test guest user > "$TMP/users.lst"
    u_args=(-L "$TMP/users.lst"); users_n=5
  fi
  [ "$users_n" -lt 1 ] && users_n=1

  # passwords
  local p_args=()
  if [ -n "$SINGLE_PASS" ]; then
    p_args=(-p "$SINGLE_PASS"); pass_n=1
  elif [ ${#PASS_SPEC[@]} -gt 0 ]; then
    p_args=("${PASS_SPEC[@]}"); pass_n="$(lines "${PASS_SPEC[1]}")"; pass_n="${pass_n:-1}"
  else
    p_args=(-P "$DEFAULT_PASS_FILE"); pass_n="$(lines "$DEFAULT_PASS_FILE")"; pass_n="${pass_n:-1}"
  fi
  [ "$pass_n" -lt 1 ] && pass_n=1

  ATTEMPTS_N=$((users_n * pass_n))
  if [ "$ATTEMPTS_N" -gt "$H_MAX_ATT" ]; then
    if [ "$pass_n" -gt 1 ] && [ "$pass_n" -gt $(( H_MAX_ATT / users_n )) ]; then
      orig="$pass_n"
      local maxp=$(( H_MAX_ATT / users_n )); [ "$maxp" -lt 1 ] && maxp=1
      head -n "$maxp" "${p_args[1]}" > "$TMP/pass.trunc"
      p_args=(-P "$TMP/pass.trunc"); pass_n="$maxp"
      echo "  ⚠️  intentos (${users_n}×${orig}) > ${H_MAX_ATT} → passwords truncadas a ${maxp} (solo evidencia)" >&2
    elif [ "$users_n" -gt 1 ] && [ "${#u_args[@]}" -gt 0 ]; then
      local maxu=$(( H_MAX_ATT / pass_n )); [ "$maxu" -lt 1 ] && maxu=1
      head -n "$maxu" "${u_args[1]}" > "$TMP/users.trunc"
      u_args=(-L "$TMP/users.trunc"); users_n="$maxu"
      echo "  ⚠️  intentos > ${H_MAX_ATT} → usuarios truncados a ${maxu} (solo evidencia)" >&2
    fi
  fi
  ATTEMPTS_N=$((users_n * pass_n))
  [ "$ATTEMPTS_N" -lt 1 ] && ATTEMPTS_N=1
  CRED_ARGS=( "${u_args[@]}" "${p_args[@]}" )
  return 0
}

# ---- Target para hydra según módulo ----------------------------------------------
build_target() {
  local ip="$1" svc="$2" port="${3:-}"
  case "$svc" in
    http-get)
      TARGET="http://${ip}${port:+:${port}}/" ;;
    https-get)
      TARGET="https://${ip}${port:+:${port}}/" ;;
    http-post-form|https-post-form)
      [ -z "$FORM_SPEC" ] && die "$svc requiere -m 'URL:datos:F/MARCADOR' (ej. -m '/login.php:user=^USER^&pass=^PASS^:F=incorrecto')"
      TARGET="$ip" ;;
    *)
      TARGET="${svc}://${ip}${port:+:${port}}" ;;
  esac
}

# ---- Ejecución de hydra con watchdog (R5: cutoff desde stealth.yaml) -------------
run_hydra() {
  local rcfile="$TMP/.hydra_rc" pid waited=0
  CUT=0
  rm -f "$rcfile" "$TMP/raw.out" "$TMP/found.txt" 2>/dev/null
  ( "$@"  > "$TMP/raw.out" 2>&1; echo "$?" > "$rcfile" ) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    sleep 5; waited=$((waited+5))
    if [ "$waited" -ge "$H_CUTOFF" ]; then
      CUT=1
      kill -TERM "$pid" 2>/dev/null; kill -KILL "$pid" 2>/dev/null
      pkill -9 -P "$pid" 2>/dev/null
      echo "  ✋ watchdog: ${svc} cortado a los ${H_CUTOFF}s (ataque incompleto → INCONCLUSO)" >&2
      break
    fi
  done
  wait "$pid" 2>/dev/null
  RC=0
  [ -f "$rcfile" ] && RC="$(cat "$rcfile")"
  [ "$CUT" -eq 1 ] && RC=1
  rm -f "$rcfile"
}

# ---- Clasificación en 3 estados (no se confía solo en el rc de hydra) ------------
classify() {
  STATE=""; FIND_CREDS=""; FIN_REASON=""
  # VULNERABLE: hydra -o escribe los pares encontrados (determinístico)
  if [ -s "$TMP/found.txt" ]; then
    STATE="VULNERABLE"
    FIND_CREDS="$(tr '\n' ' ' < "$TMP/found.txt" | sed 's/[[:space:]]*$//')"
    return 0
  fi
  if [ "$CUT" -eq 1 ]; then
    STATE="INCONCLUSO"; FIN_REASON="watchdog ${H_CUTOFF}s: hydra no terminó la lista"
    return 0
  fi
  if [ "$RC" -ne 0 ]; then
    STATE="INCONCLUSO"; FIN_REASON="hydra rc=${RC} (no completó la lista)"
    return 0
  fi
  if grep -qiE '\[ERROR\]|timed out|timeout|too many bad logins|not bruteable|connection refused|name or service not known|no route to host|socket' "$TMP/raw.out"; then
    STATE="INCONCLUSO"
    FIN_REASON="$(grep -iE '\[ERROR\]|timed out|timeout|too many bad logins|not bruteable|connection refused|name or service not known|no route to host' "$TMP/raw.out" | head -1 | sed 's/^[[:space:]]*//')"
    return 0
  fi
  if grep -q 'finished at' "$TMP/raw.out" || grep -q 'successfully completed' "$TMP/raw.out"; then
    STATE="NO_VULNERABLE"; FIN_REASON="lista completa probada (${ATTEMPTS_N} intentos) sin login válido"
    return 0
  fi
  STATE="INCONCLUSO"; FIN_REASON="salida inesperada (sin marcador de fin de ataque)"
  return 0
}

# ---- Log central: TODO el verbose de TODAS las ejecuciones (append, nunca se borra)
write_log() {
  {
    echo ""
    echo "=== HYDRA RUN $(date -u +%Y-%m-%dT%H:%M:%SZ) target=${ip} service=${svc} port=${port} result=${STATE} ==="
    echo "cmd: ${CMD[*]}"
    echo "attempts: ${ATTEMPTS_N}"
    echo "resultado: ${STATE}"
    [ -n "${FIND_CREDS:-}" ] && echo "hallazgo: ${FIND_CREDS}"
    [ -n "${FIN_REASON:-}" ] && echo "detalle: ${FIN_REASON}"
    echo "--- salida verbosa (hydra -v) ---"
    [ -f "$TMP/raw.out" ] && cat "$TMP/raw.out"
    echo "=== FIN RUN ==="
  } >> "$LOG"
}

# ---- Evidencia SOLO en hallazgo (VULNERABLE) -------------------------------------
write_evidence() {
  local evid="$WS/evidence/$ip"
  mkdir -p "$evid"
  {
    echo "HYDRA AUDIT $(date -u +%Y-%m-%dT%H:%M:%SZ) target=$ip service=$svc port=$port"
    echo "resultado: $STATE"
    echo "credenciales encontradas (SOLO evidencia interna):"
    cat "$TMP/found.txt"
    echo ""
    echo "--- salida verbosa ---"
    cat "$TMP/raw.out"
  } > "$evid/hydra_${svc}_${port}.txt"
  echo "  📁 Evidencia: $evid/hydra_${svc}_${port}.txt"
  # Copia a CLIENTE/<target>/outputs si existe → el Agente 6 lo detecta en la próxima corrida
  local d
  for d in "$WS/CLIENTE/$ip/outputs" "$WS"/CLIENTE/${ip}_*/outputs; do
    [ -d "$d" ] && { cp "$evid/hydra_${svc}_${port}.txt" "$d/" 2>/dev/null && \
      echo "  → copia a $d/ (Agente 6 lo toma automáticamente)"; break; }
  done
}

# ---- Auditoría de UN servicio sobre UN target --------------------------------------
audit_service() {
  ip="$1"; svc="$2"; port="${3:-}"
  [ -z "$port" ] && port="$(default_port_for "$svc")"
  # no-clobber: evidencia previa intacta salvo --force
  local evfile="$WS/evidence/$ip/hydra_${svc}_${port}.txt"
  if [ -s "$evfile" ] && [ "$FORCE" -eq 0 ]; then
    echo "[$ip] ${port}/${svc} → SKIP (evidencia previa $evfile; usa --force para re-auditar)"
    [ -n "$SUMMARY_FILE" ] && echo "$ip $port $svc SKIP" >> "$SUMMARY_FILE"
    return 0
  fi
  build_target "$ip" "$svc" "$port"
  build_creds "$svc" || return 1

  local tuse="$H_THREADS"
  case "$svc" in rdp) tuse=1;; esac   # RDP: conexiones en serie (estable)

  if [ "$DRY" -eq 1 ]; then
    # echo ampliado: mostramos el comando que se ejecutaría (con -o resuelto)
    echo "[DRY] hydra ${CRED_ARGS[*]} -t $tuse -w $H_WAIT -f -v -o <EVID>/hydra_${svc}_${port}.txt $TARGET"
    [ -n "$SUMMARY_FILE" ] && echo "$ip $port $svc DRY" >> "$SUMMARY_FILE"
    return 0
  fi

  CMD=( "$HYDRA_BIN" "${CRED_ARGS[@]}" -t "$tuse" -w "$H_WAIT" -f -v -o "$TMP/found.txt" )
  [ -n "$FORM_SPEC" ] && CMD+=( -m "$FORM_SPEC" )
  CMD+=( "$TARGET" )

  echo "[$ip] ${port}/${svc} · hydra con ${ATTEMPTS_N} intentos máx. (${CRED_ARGS[*]}), -t $tuse"
  run_hydra "${CMD[@]}"
  classify
  write_log

  case "$STATE" in
    VULNERABLE)
      echo "  🟥 [VULNERABLE] $ip:$port ($svc) → login válido: ${FIND_CREDS}"
      write_evidence ;;
    NO_VULNERABLE)
      echo "  🟩 [NO_VULNERABLE] $ip:$port ($svc) → $FIN_REASON" ;;
    INCONCLUSO)
      echo "  🟧 [INCONCLUSO] $ip:$port ($svc) → $FIN_REASON" ;;
  esac
  [ -n "$SUMMARY_FILE" ] && echo "$ip $port $svc $STATE" >> "$SUMMARY_FILE"
  return 0
}

# ---- Todos los servicios auditables de un target ------------------------------------
run_target_audit() {
  local ip="$1" aud port svc
  aud="$(auditable_services "$ip")" || {
    echo "[$ip] no_evidence (falta evidence/$ip/open_ports.txt o nmap_detailed.xml — corré la Fase 1 primero)"
    return 0
  }
  if [ -z "$aud" ]; then
    echo "[$ip] no_auditable (sin puertos con módulo hydra en la evidencia)"
    [ -n "$SUMMARY_FILE" ] && echo "$ip - - no_auditable" >> "$SUMMARY_FILE"
    return 0
  fi
  while read -r port svc; do
    audit_service "$ip" "$svc" "$port"
    [ "$DRY" -eq 0 ] && sleep "$DELAY_TOOLS"
  done <<< "$aud"
}

# ============================= MAIN =================================================
KNOWN_SVCS="ftp ftps ssh telnet smtp smtps http-get https-get http-post-form https-post-form pop3 pop3s imap imaps smb smb2 ldap3 mssql mysql postgres oracle-listener rdp vnc redis snmp sip"
if [ "$ALL" -eq 1 ]; then
  [ -s "$WS/config/scope.json" ] || die "no existe config/scope.json"
  TARGETS="$(load_targets)"
  [ -z "$TARGETS" ] && die "config/scope.json sin authorized_targets (o todos excluidos)."
  N=$(printf '%s\n' "$TARGETS" | grep -c . )
  echo "📋 HYDRA --all SIN CONFIRMACIÓN: $N targets autorizados · límite ${H_MAX_ATT} intentos/servicio · log: $LOG"
  SUMMARY_FILE="$TMP/summary.txt"; : > "$SUMMARY_FILE"
  I=0
  for ip in $TARGETS; do
    I=$((I+1))
    log "TARGET $I/$N: $ip"
    run_target_audit "$ip"
    if [ "$I" -lt "$N" ] && [ "$DRY" -eq 0 ]; then
      log "  → delay entre targets: ${DELAY_TARGET} min"
      sleep $((DELAY_TARGET * 60))
    fi
  done
  echo ""
  echo "═══════════ RESUMEN HYDRA (detalle completo en $LOG) ═══════════"
  column -t "$SUMMARY_FILE" 2>/dev/null || cat "$SUMMARY_FILE"
else
  # Modo target puntual
  [ ${#POSITIONAL[@]} -eq 0 ] && \
    die "Uso: bash scripts/hydra_audit.sh <IP> [<servicio>] [opciones]  |  bash scripts/hydra_audit.sh --all [--services ...]"
  ip="${POSITIONAL[0]}"
  in_scope "$ip" || die "R1-FAIL: $ip no está en scope o está excluido (config/scope.json)."
  svc_in="${POSITIONAL[1]:-}"
  if [ -n "$svc_in" ]; then
    case " $KNOWN_SVCS " in *" $svc_in "*) : ;; *) die "servicio '$svc_in' no soportado (válidos: $KNOWN_SVCS)" ;; esac
    audit_service "$ip" "$svc_in" "$PORT"
  else
    SUMMARY_FILE="$TMP/summary.txt"; : > "$SUMMARY_FILE"
    run_target_audit "$ip"
    echo ""
    echo "═══════════ RESUMEN HYDRA (detalle completo en $LOG) ═══════════"
    column -t "$SUMMARY_FILE" 2>/dev/null || cat "$SUMMARY_FILE"
  fi
fi
echo ""
echo "✅ Log con TODAS las ejecuciones (verbose): $LOG"
exit 0