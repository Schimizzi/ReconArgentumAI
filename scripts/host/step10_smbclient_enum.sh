#!/bin/bash
# =============================================================================
# step10_smbclient_enum.sh — Enumeración de recursos compartidos SMB (139/445)
# =============================================================================
# Uso: scripts/host/step10_smbclient_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check]
#      scripts/host/step10_smbclient_enum.sh --all [PROYECTO] [--force] [--no-ping-check]
#   TARGET   IP del objetivo con SMB (o el nombre de su carpeta en PROYECTO)
#   PROYECTO directorio base con outputs/ por target (default: CLIENTE)
#   --all    enumerar TODOS los targets de PROY que tengan nmap_detailed.xml
#   --force  re-enumerar y sobrescribir evidencia ya existente
#            (default: NO-CLOBBER — si outputs/smbclient_shares.txt ya existe,
#            se avisa [SKIP] y NO se toca nada; lo mismo por cada share).
#   --no-ping-check  saltar el gate de conectividad ICMP (no recomendado).
#
# Gate de conectividad (default): si el target NO responde a ping → NO se
# ejecuta ningún comando smbclient contra él (skipped_no_ping). El timeout del
# ping sale de config/stealth.yaml (smbclient_ping_timeout_seconds).
#
# Lee los puertos abiertos desde <PROYECTO>/<TARGET>/outputs/nmap_detailed.xml
# (el mismo XML que deja el Step 3 y que organize_project.py copia a outputs/).
# Si TCP 139 o 445 está abierto → enumera shares vía null session (-N):
#   1. smbclient -L //TARGET -N          → lista de shares
#      (evidencia: outputs/smbclient_shares.txt)
#   2. por cada share tipo Disk accesible → smbclient //TARGET/<share> -N -c 'ls'
#      (evidencia: outputs/smbclient_<share>.txt)
# Si no hay 139/445 → mensaje skipped_no_smb y NO genera tráfico sobre el target.
# La evidencia (smbclient_shares.txt y smbclient_<share>.txt) SOLO se conserva
# cuando la corrida produce login anónimo (Anonymous login) o shares accesibles;
# si no, se elimina (ruido sin hallazgo).
#
# Guardrails:
#   R2 — Solo lectura/listado, sin credenciales ni exploits (nunca monta ni escribe).
#   R4 — Evidencia cruda COMPLETA en <PROYECTO>/<TARGET>/outputs/ (inmutable en disco).
#   R5 — Timeout resuelto desde config/stealth.yaml (smbclient_timeout_seconds).
#   R3 — Secuencial: un share a la vez, sin paralelismo.
# =============================================================================
set -uo pipefail

# Este script vive en scripts/host/ (a 2 niveles de la raíz del repo).
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ALL=0
TARGET=""
PROY="CLIENTE"
FORCE=0
PING_CHECK=1
EV_DIR=""          # modo pipeline: directorio de evidencia directo (evidence/<IP>/)

POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--all)          ALL=1 ; shift ;;
    -f|--force)        FORCE=1 ; shift ;;
    --no-clobber)      FORCE=0 ; shift ;;
    --no-ping-check)   PING_CHECK=0 ; shift ;;
    # MODO PIPELINE: --ev-dir <DIR> apunta directo a un dir de evidencia
    # (ej. evidence/<IP>/), en lugar de resolver la carpeta CLIENTE/<IP>_*/outputs.
    # El XML de entrada es <DIR>/nmap_detailed.xml y las salidas van a <DIR>/.
    --ev-dir)
      shift; EV_DIR="${1:-}"; shift ;;
    -*)                echo "Opción desconocida: $1" >&2; exit 1 ;;
    *)                 POSITIONAL+=("$1"); shift ;;
  esac
done
TARGET="${POSITIONAL[0]:-}"
if [ "$ALL" -eq 1 ]; then
  # En modo --all el primer posicional es el PROYECTO (opcional)
  PROY="${POSITIONAL[0]:-CLIENTE}"
  TARGET=""
else
  PROY="${POSITIONAL[1]:-CLIENTE}"
fi
if { [ "$ALL" -eq 1 ] && [ "${#POSITIONAL[@]}" -gt 1 ]; } || \
   { [ "$ALL" -ne 1 ] && [ "${#POSITIONAL[@]}" -gt 2 ]; }; then
  echo "ERROR: demasiados argumentos posicionales: ${POSITIONAL[*]}" >&2
  exit 1
fi

# Directorio base del proyecto. PROY puede ser una carpeta del WORKSPACE
# (default "CLIENTE") o una ruta absoluta.
if [[ "$PROY" == /* ]]; then
  BASE="$PROY"
else
  BASE="$WORKSPACE/$PROY"
fi

# --- Modo --all: enumerar TODOS los targets de PROY con evidencia de Step 3 ---
# y dejar un resumen acumulado (patrón iis_shortname_checks):
#   <PROY>/smbclient_checks/smbclient_summary.txt
if [ "$ALL" -eq 1 ]; then
  if [ -n "$TARGET" ]; then
    echo "ERROR: --all no puede combinarse con un TARGET" >&2
    exit 1
  fi
  FLAGS=()
  [ "$FORCE" -eq 1 ] && FLAGS+=(--force)
  [ "$PING_CHECK" -eq 0 ] && FLAGS+=(--no-ping-check)

  NTARGETS=0
  N_DONE=0; N_VULN=0; N_ANON=0; N_NOPING=0; N_NOSMB=0; N_SKIP=0; N_ERR=0
  ROWS=""

  echo "== step10_smbclient_enum --all sobre $BASE =="
  for d in "$BASE"/*/; do
    [ -d "$d/outputs" ] || continue
    [ -s "$d/outputs/nmap_detailed.xml" ] || continue
    t=$(basename "$d")
    NTARGETS=$((NTARGETS+1))
    echo "===== TARGET $t ====="
    # capturar la salida del hijo para poder registrar el resumen
    # ${FLAGS[@]+...} : idiom bash 3.2 para expandir array posiblemente vacío con set -u
    out=$(bash "$0" "$t" "$PROY" ${FLAGS[@]+"${FLAGS[@]}"} 2>&1)
    rc=$?
    printf '%s\n' "$out"
    [ "$rc" -ne 0 ] && echo "rc=$? (target falló)"

    # --- parsear el estado del target para el resumen -------------------------
    estado=""; ports=""; sdisk=""; acc=""
    if printf '%s\n' "$out" | grep -q 'STEP_SMBCLIENT_DONE'; then
      estado=ejecutado
      ports=$(printf '%s\n' "$out" | sed -n 's/.* ports=\([0-9,]*\).*/\1/p' | head -1)
      sdisk=$(printf '%s\n' "$out"   | sed -n 's/.* shares_disk=\([0-9]*\).*/\1/p' | head -1)
      acc=$(printf '%s\n' "$out"     | sed -n 's/.* accesibles=\([0-9]*\).*/\1/p' | head -1)
    elif printf '%s\n' "$out" | grep -q 'skipped_no_ping:'; then
      estado=no_ping
    elif printf '%s\n' "$out" | grep -q 'skipped_no_smb:'; then
      estado=no_smb
    elif printf '%s\n' "$out" | grep -q '\[SKIP\]'; then
      estado=skip_existente
    else
      estado=error
      N_ERR=$((N_ERR+1))
    fi

    # detalle: línea de status (anonymous/denied) o primer share Disk accesible
    det="-"
    anon=no
    if [ -s "$d/outputs/smbclient_shares.txt" ]; then
      det=$(grep -E 'Anonymous login|session setup failed|NT_STATUS_|SMB1 disabled|tree connect' \
            "$d/outputs/smbclient_shares.txt" 2>/dev/null | head -1)
      if printf '%s' "$det" | grep -q 'Anonymous login'; then
        anon=si
      fi
      if [ -z "$det" ]; then
        sh="$(awk '$2 == "Disk" {print $1}' "$d/outputs/smbclient_shares.txt" 2>/dev/null | head -1)"
        [ -n "$sh" ] && det="share=$sh"
      fi
    fi
    [ -z "$det" ] && det="-"
    det=$(printf '%s' "$det" | tr '\t' ' ')
    [ -n "$acc" ] && [ "$acc" -gt 0 ] 2>/dev/null && det="$det | ACCESIBLE=$acc"

    # línea del resumen (newline literal preservado por bash 3.2)
    line=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
      "$t" "$estado" "${ports:-0}" "${sdisk:-0}" "${acc:-0}" "$anon" "$det")
    ROWS="${ROWS}${line}
"

    # contadores
    case "$estado" in
      ejecutado)   N_DONE=$((N_DONE+1)) ;;
      no_ping)     N_NOPING=$((N_NOPING+1)) ;;
      no_smb)      N_NOSMB=$((N_NOSMB+1)) ;;
      skip_existente) N_SKIP=$((N_SKIP+1)) ;;
    esac
    if [ "${acc:-0}" -gt 0 ] 2>/dev/null; then
      N_VULN=$((N_VULN+1))
    fi
    if [ "$anon" = "si" ]; then
      N_ANON=$((N_ANON+1))
    fi
    sleep 1
  done

  # --- resumen acumulado (append, conserva corridas previas — patrón iis) -----
  CHECKS="$BASE/smbclient_checks"
  mkdir -p "$CHECKS"
  SUM="$CHECKS/smbclient_summary.txt"
  NOW=$(date '+%Y-%m-%d %H:%M:%S')
  # evaluar existencia ANTES de la redirección >> (que crea el archivo)
  existed=0
  [ -f "$SUM" ] && existed=1
  {
    if [ "$existed" -eq 1 ]; then
      printf '# (corrida previa conservada)\n'
    else
      printf '# Resumen step10_smbclient_enum (log acumulado por corrida; no se borran corridas previas)\n'
    fi
    printf '# ===== corrida %s | total targets: %d =====\n' "$NOW" "$NTARGETS"
    printf '# target\testado\tports\tshares_disk\taccesibles\tanon_login\tdetalle\n'
    printf '%s' "$ROWS"
    printf '# TOTAL: ejecutados=%d | con_vuln=%d | anon_login=%d | no_ping=%d | no_smb=%d | skip_existente=%d\n' "$N_DONE" "$N_VULN" "$N_ANON" "$N_NOPING" "$N_NOSMB" "$N_SKIP"
  } >> "$SUM"
  echo "SMBCLIENT_ALL_DONE"
  echo "Resumen: $SUM"
  exit 0
fi

if [ -z "$TARGET" ] && [ -z "$EV_DIR" ]; then
  echo "Uso: scripts/host/step10_smbclient_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check]" >&2
  echo "     scripts/host/step10_smbclient_enum.sh --all [PROYECTO] [--force] [--no-ping-check]" >&2
  echo "     scripts/host/step10_smbclient_enum.sh --ev-dir <DIR> [--force] [--no-ping-check]  (modo pipeline)" >&2
  echo "  TARGET   IP del objetivo (o su carpeta en \$PROY)" >&2
  echo "  PROYECTO directorio base con outputs/ por target (default: CLIENTE)" >&2
  echo "  --all    enumerar todos los targets de PROY con nmap_detailed.xml" >&2
  echo "  --force  re-enumerar y sobrescribir evidencia ya existente (default: no-clobber)" >&2
  echo "  --no-ping-check  NO verificar conectividad ICMP antes de smbclient (default: sí)" >&2
  echo "  --ev-dir DIR  apuntar directo a un dir de evidencia (ej. evidence/<IP>)" >&2
  exit 1
fi

# IP real: si se pasó una carpeta con sufijo (10.0.0.1_vuln), usar solo la IP.
IP="${TARGET%%_*}"

# --- Modo pipeline (--ev-dir): TGT_DIR = el propio dir de evidencia ----------
# El pipeline escribe en evidence/<IP> (nmap_detailed.xml va directo ahí, sin
# subcarpeta outputs/). Se salta toda la resolución por sufijos de CLIENTE/.
if [ -n "$EV_DIR" ]; then
  TGT_DIR="${EV_DIR%/}"
  [ -z "$IP" ] && IP="$(basename "$TGT_DIR")"
  [ -z "$TARGET" ] && TARGET="$IP"
  echo "→ $TGT_DIR (modo pipeline --ev-dir)"
  SUFIX_MSG=""
else
# Resolver la carpeta real del target (organize_project.py renombra las
# carpetas de CLIENTE/ con sufijo _vuln / _no_vuln, igual que en
# check_gobuster_urls.sh). Orden:
#   1. exacta         → CLIENTE/<TARGET>/outputs   (ya venía con sufijo)
#   2. con sufijo     → CLIENTE/<IP>_*/outputs     (IP pura → buscar la carpeta)
#   3. plana fallback → CLIENTE/<IP>/outputs       (carpeta sin renombrar)
TGT_DIR=""
SUFIX_MSG=""
if [ -d "$BASE/$TARGET/outputs" ]; then
  TGT_DIR="$BASE/$TARGET/outputs"
else
  # patrón exacto ${IP}_* (evita confundir prefijos: 10.155.10.15 vs .150)
  for d in "$BASE"/"${IP}"_*; do
    [ -d "$d/outputs" ] || continue
    TGT_DIR="$d/outputs"
    SUFIX_MSG=" (carpeta: $(basename "$d"))"
    break
  done
fi
if [ -z "$TGT_DIR" ] && [ -d "$BASE/$IP/outputs" ]; then
  TGT_DIR="$BASE/$IP/outputs"
  SUFIX_MSG=" (carpeta plana: $IP)"
fi
fi  # end if --ev-dir (modo pipeline vs legacy CLIENTE/)

if [ -z "$TGT_DIR" ]; then
  echo "ERROR: no existe outputs/ para '$TARGET' en $BASE (¿corriste scripts/organize_project.py?)" >&2
  echo "  Carpetas encontradas con esa IP:" >&2
  ls -d "$BASE"/"${IP}"* 2>/dev/null || echo "  (ninguna)" >&2
  exit 1
fi
[ -n "$SUFIX_MSG" ] && echo "→ $TGT_DIR$SUFIX_MSG"

XML="$TGT_DIR/nmap_detailed.xml"
if [ ! -s "$XML" ]; then
  echo "ERROR: no existe $XML (evidencia del Step 3)" >&2
  exit 1
fi

# R5: timeout por operación (smbclient -t) resuelto desde stealth.yaml
STEALTH="$WORKSPACE/config/stealth.yaml"
SMB_TIMEOUT="$(awk '/^smbclient_timeout_seconds:/ {print $2; exit}' "$STEALTH" 2>/dev/null)"
SMB_TIMEOUT="${SMB_TIMEOUT:-10}"
PING_TO="$(awk '/^smbclient_ping_timeout_seconds:/ {print $2; exit}' "$STEALTH" 2>/dev/null)"
PING_TO="${PING_TO:-2}"

# ping_alive: 1 ping de un solo intento. Portable:
#   macOS ping -W  <timeout> en MILISEGUNDOS (-o: corta en la 1a respuesta)
#   Linux ping -W  <timeout> en SEGUNDOS
ping_alive() {
  case "$(uname -s)" in
    Darwin) ping -c 1 -W $((PING_TO * 1000)) -o "$1" >/dev/null 2>&1 ;;
    *)      ping -c 1 -W "$PING_TO" "$1" >/dev/null 2>&1 ;;
  esac
}

# --- 1. Detectar SMB (TCP 139/445) en el XML del Step 3 -------------------
SMB_PORTS=$(python3 - "$XML" <<'PY'
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
open_ports = []
for p in tree.iter('port'):
    st = p.find('state')
    if st is None or st.get('state') != 'open':
        continue
    if p.get('protocol') != 'tcp':
        continue
    if p.get('portid') in ('139', '445'):
        open_ports.append(p.get('portid'))
print(','.join(sorted(set(open_ports))))
PY
)

if [ -z "${SMB_PORTS:-}" ]; then
  echo "skipped_no_smb: $TARGET no tiene puertos SMB (139/445) abiertos según $XML"
  exit 0
fi
echo "SMB detectado en $TARGET (IP $IP): TCP ${SMB_PORTS}"

# --- 1bis. Gate de conectividad: si no responde a ping, NO ejecutar smbclient ---
# (decisión del operador: targets que no responden al ping no se tocan)
if [ "$PING_CHECK" -eq 1 ]; then
  if ping_alive "$IP"; then
    echo "> ping OK ($IP)"
  else
    echo "skipped_no_ping: $IP no responde a ping (timeout ${PING_TO}s). No se ejecuta smbclient."
    exit 0
  fi
fi

# --- 2. Listado de shares (null session, solo lectura) -----------------------
SHARES_LIST="$TGT_DIR/smbclient_shares.txt"

# no-clobber: si ya existe la evidencia de shares, NO se sobrescribe (solo --force)
if [ -s "$SHARES_LIST" ] && [ "$FORCE" -ne 1 ]; then
  echo "[SKIP] $TARGET: ya existe $SHARES_LIST (evidencia previa intacta). Usa --force para re-enumerar."
  exit 0
fi

echo "> smbclient -L //$IP -N (null session, timeout ${SMB_TIMEOUT}s)"
smbclient -L "//$IP" -N -t "$SMB_TIMEOUT" > "$SHARES_LIST" 2>&1 \
  || echo "  ⚠️  -L devolvió rc=$? — la salida cruda quedó en smbclient_shares.txt (puede ser null session rechazada)" >&2

# --- 3. Contenido de cada share tipo Disk accesible --------------------------
DISK_SHARES="$(awk '$2 == "Disk" && $1 != "" {print $1}' "$SHARES_LIST" 2>/dev/null | sort -u)"
ACCESSIBLE=0
if [ -n "$DISK_SHARES" ]; then
  while IFS= read -r share; do
    [ -z "$share" ] && continue
    SAFE=$(printf '%s' "$share" | tr '/\\:*?"<>|' '_')
    OUT_SHARE="$TGT_DIR/smbclient_${SAFE}.txt"
    # no-clobber por share: si ya hay evidencia de este share, no se sobrescribe
    if [ -s "$OUT_SHARE" ] && [ "$FORCE" -ne 1 ]; then
      echo "  [SKIP] ${share}: ya existe $OUT_SHARE (no-clobber). Usa --force para re-enumerar."
      continue
    fi
    echo "> smbclient //$IP/$share -N -c 'ls'"
    if smbclient "//$IP/$share" -N -t "$SMB_TIMEOUT" -c 'ls' > "$OUT_SHARE" 2>&1; then
      ACCESSIBLE=$((ACCESSIBLE+1))
    else
      echo "  ⚠️  ${share}: null session denegada o share no accesible. Detalle crudo en smbclient_${SAFE}.txt" >&2
    fi
  done <<< "$DISK_SHARES"
else
  echo "  (sin shares de tipo Disk en la lista — posible null session denegada o sin shares)"
fi

# --- 4. Conservar evidencia SOLO si hay login anónimo o shares accesibles ----
# El archivo smbclient_shares.txt (y los por-share) solo se conserva cuando la
# corrida produce un resultado útil: null session habilitada (Anonymous login)
# o al menos un share Disk accesible. Sin eso, el archivo es ruido sin hallazgo
# y se elimina (excepto si `--no-clobber` + evidencia previa → se va por [SKIP]).
CALIFICA=0
grep -q 'Anonymous login' "$SHARES_LIST" 2>/dev/null && CALIFICA=1
[ "${ACCESSIBLE:-0}" -gt 0 ] 2>/dev/null && CALIFICA=1

N_DISK=$( [ -n "$DISK_SHARES" ] && printf '%s\n' "$DISK_SHARES" | grep -c . || echo 0 )
echo "STEP_SMBCLIENT_DONE $TARGET ports=${SMB_PORTS} shares_disk=${N_DISK} accesibles=${ACCESSIBLE}"
if [ "$CALIFICA" -eq 1 ]; then
  echo "Evidencia: $TGT_DIR/smbclient_shares.txt + smbclient_<share>.txt → detectada por el Agente 6 en la próxima corrida."
else
  rm -f "$SHARES_LIST" "$TGT_DIR"/smbclient_*.txt
  echo "smbclient: $TARGET sin login anónimo ni shares accesibles → evidencia NO conservada"
fi