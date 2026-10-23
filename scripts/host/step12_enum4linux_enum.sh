#!/bin/bash
# =============================================================================
# step12_enum4linux_enum.sh — Enumeración AD anónima con enum4linux (Step 12)
# =============================================================================
# Uso: scripts/host/step12_enum4linux_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check] [--rid]
#      scripts/host/step12_enum4linux_enum.sh --all [PROYECTO] [--force] [--no-ping-check]
#      scripts/host/step12_enum4linux_enum.sh --ev-dir <DIR> [--force] [--no-ping-check] [--rid]
#   TARGET   IP del objetivo (o el nombre de su carpeta en PROYECTO)
#   PROYECTO directorio base con outputs/ por target (default: CLIENTE)
#   --all    enumerar TODOS los targets de PROYECTO con nmap_detailed.xml (secuencial)
#   --ev-dir DIR  modo pipeline: leer/escribir directo en evidence/<IP>/
#   --force  re-enumerar y sobrescribir evidencia existente (default: NO-CLOBBER)
#   --no-ping-check  saltar el gate de conectividad ICMP
#   --rid    habilita RID cycling (-R/-r). OPT-IN: requiere aprobación en Fase 0.
#
# PLATAFORMA: este step SOLO corre en Linux (VM Debian/Kali o contenedor). En macOS
# (uname -s = Darwin) se saltea SIN generar tráfico (status skipped_unsupported_os).
#
# Gate Service-Based: solo si TCP 139/445 están abiertos (enum4linux-ng aborta si no
# puede establecer sesión SMB). Sin 139/445 → skipped_no_smb, sin tráfico.
#
# Guardrails:
#   R2 — Solo lectura y anónimo: NUNCA credenciales (-u/-p/-H/-K) ni -A (Aggressive).
#   R4 — Evidencia cruda COMPLETA en <DIR>/enum4linux.txt (1a línea = comando).
#   R5 — Timeout desde config/stealth.yaml (enum4linux_timeout_seconds).
#   R3 — Secuencial: un target a la vez, sin paralelismo.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ALL=0
TARGET=""
PROY="CLIENTE"
FORCE=0
PING_CHECK=1
RID=0
EV_DIR=""

POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--all)          ALL=1 ; shift ;;
    -f|--force)        FORCE=1 ; shift ;;
    --no-clobber)      FORCE=0 ; shift ;;
    --no-ping-check)   PING_CHECK=0 ; shift ;;
    --rid)             RID=1 ; shift ;;
    --ev-dir)          shift; EV_DIR="${1:-}"; shift ;;
    -*)                echo "Opción desconocida: $1" >&2; exit 1 ;;
    *)                 POSITIONAL+=("$1"); shift ;;
  esac
done
TARGET="${POSITIONAL[0]:-}"
if [ "$ALL" -eq 1 ]; then
  PROY="${POSITIONAL[0]:-CLIENTE}"
  TARGET=""
else
  PROY="${POSITIONAL[1]:-CLIENTE}"
fi

# --- Guard de plataforma: enum4linux NO se ejecuta en macOS ------------------
if [ "$(uname -s)" = "Darwin" ]; then
  echo "skipped_unsupported_os: enum4linux no se ejecuta en macOS (Darwin). Usar VM Linux/Debian o el contenedor."
  exit 0
fi

# --- Directorio base del proyecto (o ruta absoluta) --------------------------
if [[ "$PROY" == /* ]]; then
  BASE="$PROY"
else
  BASE="$WORKSPACE/$PROY"
fi

# --- Modo --all: recorrer targets con nmap_detailed.xml y resumir ----------
if [ "$ALL" -eq 1 ]; then
  FLAGS=()
  [ "$FORCE" -eq 1 ] && FLAGS+=(--force)
  [ "$PING_CHECK" -eq 0 ] && FLAGS+=(--no-ping-check)
  [ "$RID" -eq 1 ] && FLAGS+=(--rid)
  NTARGETS=0; N_DONE=0; N_EVID=0; N_NOSMB=0; N_SKIP=0; N_ERR=0
  ROWS=""
  echo "== step12_enum4linux_enum --all sobre $BASE =="
  for d in "$BASE"/*/; do
    [ -d "$d/outputs" ] || continue
    [ -s "$d/outputs/nmap_detailed.xml" ] || continue
    t=$(basename "$d")
    NTARGETS=$((NTARGETS+1))
    echo "===== TARGET $t ====="
    out=$(bash "$0" "$t" "$PROY" ${FLAGS[@]+"${FLAGS[@]}"} 2>&1)
    printf "%s\\n" "$out"
    estado=""; ports=""; wkg=""
    if printf "%s\\n" "$out" | grep -q "STEP_ENUM4LINUX_DONE"; then
      estado=ejecutado; N_DONE=$((N_DONE+1))
      ports=$(printf "%s\\n" "$out" | sed -n "s/.* ports=\([0-9,]*\).*/\\1/p" | head -1)
      wkg=$(printf "%s\\n" "$out"   | sed -n "s/.* workgroup=\([^ ]*\).*/\\1/p" | head -1)
    elif printf "%s\\n" "$out" | grep -q "skipped_no_ping:"; then
      estado=no_ping
    elif printf "%s\\n" "$out" | grep -q "skipped_no_smb:"; then
      estado=no_smb; N_NOSMB=$((N_NOSMB+1))
    elif printf "%s\\n" "$out" | grep -q "\\[SKIP\\]"; then
      estado=skip_existente; N_SKIP=$((N_SKIP+1))
    else
      estado=error; N_ERR=$((N_ERR+1))
    fi
    [ -s "$d/outputs/enum4linux.txt" ] && N_EVID=$((N_EVID+1))
    ROWS="${ROWS}${t}\\t${estado}\\t${ports:-0}\\t${wkg:-auto}\\n"
    sleep 1
  done
  CHECKS="$BASE/enum4linux_checks"
  mkdir -p "$CHECKS"
  SUM="$CHECKS/enum4linux_summary.txt"
  NOW=$(date "+%Y-%m-%d %H:%M:%S")
  {
    printf "# Resumen step12_enum4linux_enum (log acumulado por corrida; no se borran corridas previas)\\n"
    printf "# ===== corrida %s | total targets: %d =====\\n" "$NOW" "$NTARGETS"
    printf "# target\\testado\\tports\\tworkgroup\\n"
    printf "%b" "$ROWS"
    printf "# TOTAL: ejecutados=%d | con_evidencia=%d | no_smb=%d | skip_existente=%d | error=%d\\n" "$N_DONE" "$N_EVID" "$N_NOSMB" "$N_SKIP" "$N_ERR"
  } >> "$SUM"
  echo "ENUM4LINUX_ALL_DONE"
  echo "Resumen: $SUM"
  exit 0
fi

if [ -z "$TARGET" ] && [ -z "$EV_DIR" ]; then
  echo "Uso: scripts/host/step12_enum4linux_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check] [--rid]" >&2
  echo "     scripts/host/step12_enum4linux_enum.sh --all [PROYECTO] [--force] [--no-ping-check]" >&2
  echo "     scripts/host/step12_enum4linux_enum.sh --ev-dir <DIR> [--force] [--no-ping-check] [--rid]  (modo pipeline)" >&2
  echo "  TARGET   IP del objetivo (o su carpeta en \$PROY)" >&2
  echo "  PROYECTO directorio base con outputs/ por target (default: CLIENTE)" >&2
  echo "  --all    enumerar todos los targets de PROYECTO con nmap_detailed.xml" >&2
  echo "  --force  re-enumerar y sobrescribir evidencia existente (default: no-clobber)" >&2
  echo "  --no-ping-check  NO verificar conectividad ICMP antes de enum4linux (default: si)" >&2
  echo "  --rid    habilita RID cycling (requiere aprobación en Fase 0)" >&2
  exit 1
fi

IP="${TARGET%%_*}"

if [ -n "$EV_DIR" ]; then
  TGT_DIR="${EV_DIR%/}"
  [ -z "$IP" ] && IP="$(basename "$TGT_DIR")"
  [ -z "$TARGET" ] && TARGET="$IP"
  echo "→ $TGT_DIR (modo pipeline --ev-dir)"
else
  TGT_DIR=""; SUFIX_MSG=""
  if [ -d "$BASE/$TARGET/outputs" ]; then
    TGT_DIR="$BASE/$TARGET/outputs"
  else
    for d in "$BASE"/"${IP}"_*; do
      [ -d "$d/outputs" ] || continue
      TGT_DIR="$d/outputs"; SUFIX_MSG=" (carpeta: $(basename "$d"))"; break
    done
  fi
  if [ -z "$TGT_DIR" ] && [ -d "$BASE/$IP/outputs" ]; then
    TGT_DIR="$BASE/$IP/outputs"; SUFIX_MSG=" (carpeta plana: $IP)"
  fi
  [ -n "$SUFIX_MSG" ] && echo "→ $TGT_DIR$SUFIX_MSG"
fi
if [ -z "$TGT_DIR" ]; then
  echo "ERROR: no existe outputs/ para $TARGET en $BASE" >&2
  exit 1
fi

XML="$TGT_DIR/nmap_detailed.xml"
if [ ! -s "$XML" ]; then
  echo "ERROR: no existe $XML (evidencia del Step 3)" >&2
  exit 1
fi

# --- Binario: enum4linux-ng (primario) -> enum4linux (perl, fallback) --------
if command -v enum4linux-ng >/dev/null 2>&1; then
  BIN="enum4linux-ng"; MODE="ng"
elif command -v enum4linux >/dev/null 2>&1; then
  BIN="enum4linux"; MODE="pl"
else
  echo "skipped: no hay enum4linux-ng ni enum4linux en el PATH (instalar: sudo apt install enum4linux-ng)"
  exit 0
fi

# --- R5: timeouts desde config/stealth.yaml (nunca hardcodeados) -----------
STEALTH="$WORKSPACE/config/stealth.yaml"
TO=$(awk "/^enum4linux_timeout_seconds:/ {print \$2; exit}" "$STEALTH" 2>/dev/null)
TO="${TO:-10}"
PING_TO=$(awk "/^smbclient_ping_timeout_seconds:/ {print \$2; exit}" "$STEALTH" 2>/dev/null)
PING_TO="${PING_TO:-2}"

ping_alive() {
  case "$(uname -s)" in
    Darwin) ping -c 1 -W $((PING_TO * 1000)) -o "$1" >/dev/null 2>&1 ;;
    *)      ping -c 1 -W "$PING_TO" "$1" >/dev/null 2>&1 ;;
  esac
}

# --- 1. Detectar SMB (139/445) y workgroup desde el XML del Step 3 ----------
SMB_INFO=$(python3 - "$XML" <<PY
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
ports, wkg = [], ""
for p in tree.iter("port"):
    st = p.find("state")
    if st is None or st.get("state") != "open":
        continue
    if p.get("protocol") == "tcp" and p.get("portid") in ("139", "445"):
        ports.append(p.get("portid"))
for tab in tree.iter("table"):
    if tab.get("key") == "workgroup" and tab.text: wkg = tab.text.strip()
if not wkg:
    for sc in tree.iter("script"):
        txt = sc.get("output") or ""
        if "workgroup: " in txt:
            wkg = txt.split("workgroup: ")[1].split(",")[0].split(")")[0].strip()
            break
if not wkg:
    for sv in tree.iter("service"):
        for attr in (sv.get("extrainfo"), sv.get("product")):
            if attr and "workgroup: " in attr:
                wkg = attr.split("workgroup: ")[1].split(",")[0].split(")")[0].strip()
                break
        if wkg:
            break
print(",".join(sorted(set(ports))))
print(wkg)
PY
)
SMB_PORTS=$(printf "%s\\n" "$SMB_INFO" | sed -n "1p")
WK=$(printf "%s\\n" "$SMB_INFO" | sed -n "2p")

# Fallback de workgroup/dominio: evidencia LDAP previa (ldapsearch*.txt)
if [ -z "${WK:-}" ]; then
  WK=$(grep -hE "^ldapServiceName:" "$TGT_DIR"/ldapsearch*.txt 2>/dev/null | head -1 | sed -n "s/^ldapServiceName:[[:space:]]*\([^:]*\):.*/\\1/p")
fi

if [ -z "${SMB_PORTS:-}" ]; then
  echo "skipped_no_smb: $TARGET no tiene puertos SMB (139/445) abiertos según $XML"
  exit 0
fi
echo "SMB detectado en $TARGET (IP $IP): TCP ${SMB_PORTS}"

# --- 2. Gate de conectividad (si no responde ping, no se ejecuta nada) ------
if [ "$PING_CHECK" -eq 1 ]; then
  if ping_alive "$IP"; then
    echo "> ping OK ($IP)"
  else
    echo "skipped_no_ping: $IP no responde a ping (timeout ${PING_TO}s). No se ejecuta enum4linux."
    exit 0
  fi
fi

# --- 3. Evidencia: no-clobber (o --force) ----------------------------------
OUT_TXT="$TGT_DIR/enum4linux.txt"
if [ -s "$OUT_TXT" ] && [ "$FORCE" -ne 1 ]; then
  echo "[SKIP] $TARGET: ya existe $OUT_TXT (evidencia previa intacta). Usa --force para re-enumerar."
  exit 0
fi

# --- 4. Comando PASIVO y ANÓNIMO (sin credenciales, sin -A) ----------------
ARGS=()
if [ "$MODE" = "ng" ]; then
  ARGS=(-As -oA "$TGT_DIR/enum4linux")
  [ -n "${WK:-}" ] && ARGS+=(-w "$WK")
  ARGS+=(-t "$TO")
  [ "$RID" -eq 1 ] && ARGS+=(-R)
else
  ARGS=(-U -S -G -P -o -l)
  [ -n "${WK:-}" ] && ARGS+=(-w "$WK")
  [ "$RID" -eq 1 ] && ARGS+=(-r)
fi
echo "> $BIN ${ARGS[*]} $IP"
{ echo "$BIN ${ARGS[*]} $IP"; "$BIN" "${ARGS[@]}" "$IP" 2>&1; } > "$OUT_TXT"
RC=$?
[ "$RC" -ne 0 ] && echo "  ⚠️  $BIN devolvió rc=$RC (posible sesión anónima rechazada); salida cruda en $OUT_TXT" >&2

# --- 5. Conservar evidencia SOLO si hay sesión establecida y datos ---------
CALIFICA=0
if ! grep -qiE "Unable to connect|NT_STATUS_LOGON_FAILURE|Connection refused" "$OUT_TXT" 2>/dev/null; then
  if grep -qiE "Target information|session setup|OS information|Password policy|Users|Groups|Shares|LDAP" "$OUT_TXT" 2>/dev/null; then
    CALIFICA=1
  fi
fi
echo "STEP_ENUM4LINUX_DONE $TARGET bin=$BIN ports=${SMB_PORTS} workgroup=${WK:-auto} rid=$RID"
if [ "$CALIFICA" -eq 1 ]; then
  echo "Evidencia: $OUT_TXT (+ enum4linux.json/.yaml) → disponible para revisión manual."
else
  # D (2026-10-22): igual que el Step 10 — se descarta la evidencia cruda (ruido sin
  # hallazgo) pero se conserva la NOTA del rechazo para que el reporte lo documente.
  REASON=$(grep -m3 -iE 'NT_STATUS_[A-Z_]+|Unable to connect|Connection refused' "$OUT_TXT" 2>/dev/null | head -3)
  rm -f "$TGT_DIR"/enum4linux.txt "$TGT_DIR"/enum4linux.json "$TGT_DIR"/enum4linux.yaml
  NOTE="$TGT_DIR/enum4linux_sin_sesion.txt"
  {
    echo "# $BIN ${ARGS[*]} $IP (script -As, sesion nula/anonima)"
    echo "# resultado: sin sesion anonima estable ni datos (sin Target information/users/shares/LDAP)"
    if [ -n "${REASON:-}" ]; then printf '%s\n' "$REASON"; fi
  } > "$NOTE"
  echo "STEP_ENUM4LINUX_NOTE sin_sesion $TARGET -> enum4linux_sin_sesion.txt"
  echo "enum4linux: $TARGET sin sesión anónima ni datos → evidencia cruda NO conservada (nota del rechazo SI conservada)"
fi
