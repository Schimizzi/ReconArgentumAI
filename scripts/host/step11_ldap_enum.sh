#!/bin/bash
# =============================================================================
# step11_ldap_enum.sh — Enumeración LDAP/AD con ldapsearch (Step 11)
# =============================================================================
# Uso: scripts/host/step11_ldap_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check] [--tls] [--ldap-user U --ldap-pass P]
#      scripts/host/step11_ldap_enum.sh --all [PROYECTO] [--force] [--no-ping-check]
#      scripts/host/step11_ldap_enum.sh --ev-dir <DIR> [--force] [--no-ping-check] [--tls] [--ldap-user U --ldap-pass P]
#   TARGET   IP del objetivo (o el nombre de su carpeta en PROYECTO)
#   PROYECTO directorio base con outputs/ por target (default: CLIENTE)
#   --all    enumerar TODOS los targets de PROYECTO con nmap_detailed.xml (secuencial)
#   --ev-dir DIR  modo pipeline: leer/escribir directo en evidence/<IP>/
#   --force  re-enumerar y sobrescribir evidencia existente (default: NO-CLOBBER)
#   --no-ping-check  saltar el gate de conectividad ICMP
#   --tls    forzar LDAPS (636/3269) aunque 389 este abierto
#   --ldap-user / --ldap-pass  MODO CREDENCIALIZADO (OPT-IN: requiere aprobacion en Fase 0).
#                             Sin estos flags corre ANONIMO (default, solo lectura).
#
# PLATAFORMA: corre en Linux y en macOS (ldapsearch esta en /usr/bin en ambos).
#
# Gate Service-Based: solo si TCP 389, 636, 3268 o 3269 esta abierto.
#   Sin esos puertos -> skipped_no_ldap, sin trafico.
#
# Guardrails:
#   R2 — Solo lectura: jamas modifica el directorio (solo ldapsearch -x de consulta).
#   R4 — Evidencia cruda COMPLETA en <DIR>/ldapsearch*.txt (1a linea = comando).
#   R5 — Timeout desde config/stealth.yaml (ldapsearch_timeout_seconds).
#   R3 — Secuencial: un target a la vez, sin paralelismo.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ALL=0
TARGET=""
PROY="CLIENTE"
FORCE=0
PING_CHECK=1
EV_DIR=""
TLS=0
LDAP_USER=""
LDAP_PASS=""

POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--all)          ALL=1 ; shift ;;
    -f|--force)        FORCE=1 ; shift ;;
    --no-clobber)      FORCE=0 ; shift ;;
    --no-ping-check)   PING_CHECK=0 ; shift ;;
    --tls)             TLS=1 ; shift ;;
    --ldap-user)       shift; LDAP_USER="${1:-}"; shift ;;
    --ldap-pass)       shift; LDAP_PASS="${1:-}"; shift ;;
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
  [ "$TLS" -eq 1 ] && FLAGS+=(--tls)
  NTARGETS=0; N_DONE=0; N_EVID=0; N_NOLDAP=0; N_SKIP=0; N_ERR=0
  ROWS=""
  echo "== step11_ldap_enum --all sobre $BASE =="
  for d in "$BASE"/*/; do
    [ -d "$d/outputs" ] || continue
    [ -s "$d/outputs/nmap_detailed.xml" ] || continue
    t=$(basename "$d")
    NTARGETS=$((NTARGETS+1))
    echo "===== TARGET $t ====="
    out=$(bash "$0" "$t" "$PROY" ${FLAGS[@]+"${FLAGS[@]}"} 2>&1)
    printf "%s\\n" "$out"
    estado=""; ports=""; dn=""
    if printf "%s\\n" "$out" | grep -q "STEP_LDAP_DONE"; then
      estado=ejecutado; N_DONE=$((N_DONE+1))
      ports=$(printf "%s\\n" "$out" | sed -n "s/.* ports=\([0-9,]*\).*/\\1/p" | head -1)
      dn=$(printf "%s\\n" "$out" | sed -n "s/.* base_dn=\([^ ]*\).*/\\1/p" | head -1)
    elif printf "%s\\n" "$out" | grep -q "skipped_no_ping:"; then
      estado=no_ping
    elif printf "%s\\n" "$out" | grep -q "skipped_no_ldap:"; then
      estado=no_ldap; N_NOLDAP=$((N_NOLDAP+1))
    elif printf "%s\\n" "$out" | grep -q "\\[SKIP\\]"; then
      estado=skip_existente; N_SKIP=$((N_SKIP+1))
    else
      estado=error; N_ERR=$((N_ERR+1))
    fi
    [ -s "$d/outputs/ldapsearch.txt" ] && N_EVID=$((N_EVID+1))
    ROWS="${ROWS}${t}\\t${estado}\\t${ports:-0}\\t${dn:-none}\\n"
    sleep 1
  done
  CHECKS="$BASE/ldapsearch_checks"
  mkdir -p "$CHECKS"
  SUM="$CHECKS/ldapsearch_summary.txt"
  NOW=$(date "+%Y-%m-%d %H:%M:%S")
  {
    printf "# Resumen step11_ldap_enum (log acumulado por corrida; no se borran corridas previas)\\n"
    printf "# ===== corrida %s | total targets: %d =====\\n" "$NOW" "$NTARGETS"
    printf "# target\\testado\\tports\\tbase_dn\\n"
    printf "%b" "$ROWS"
    printf "# TOTAL: ejecutados=%d | con_evidencia=%d | no_ldap=%d | skip_existente=%d | error=%d\\n" "$N_DONE" "$N_EVID" "$N_NOLDAP" "$N_SKIP" "$N_ERR"
  } >> "$SUM"
  echo "LDAP_ALL_DONE"
  echo "Resumen: $SUM"
  exit 0
fi

if [ -z "$TARGET" ] && [ -z "$EV_DIR" ]; then
  echo "Uso: scripts/host/step11_ldap_enum.sh <TARGET> [PROYECTO] [--force] [--no-ping-check] [--tls] [--ldap-user U --ldap-pass P]" >&2
  echo "     scripts/host/step11_ldap_enum.sh --all [PROYECTO] [--force] [--no-ping-check]" >&2
  echo "     scripts/host/step11_ldap_enum.sh --ev-dir <DIR> [--force] [--no-ping-check] [--tls]  (modo pipeline)" >&2
  echo "  TARGET   IP del objetivo (o su carpeta en \$PROY)" >&2
  echo "  --force / --no-ping-check / --tls  ver cabecera del script" >&2
  echo "  --ldap-user / --ldap-pass  modo credencializado (OPT-IN, aprobado en Fase 0)" >&2
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

# --- Binario: ldapsearch (ldap-utils; presente en Linux y en macOS) ---------
if ! command -v ldapsearch >/dev/null 2>&1; then
  echo "skipped: no hay ldapsearch en el PATH (instalar: sudo apt install ldap-utils)"
  exit 0
fi

# --- R5: timeouts desde config/stealth.yaml (nunca hardcodeados) -----------
STEALTH="$WORKSPACE/config/stealth.yaml"
TO=$(awk "/^ldapsearch_timeout_seconds:/ {print \$2; exit}" "$STEALTH" 2>/dev/null)
TO="${TO:-10}"
PING_TO=$(awk "/^smbclient_ping_timeout_seconds:/ {print \$2; exit}" "$STEALTH" 2>/dev/null)
PING_TO="${PING_TO:-2}"

ping_alive() {
  case "$(uname -s)" in
    Darwin) ping -c 1 -W $((PING_TO * 1000)) -o "$1" >/dev/null 2>&1 ;;
    *)      ping -c 1 -W "$PING_TO" "$1" >/dev/null 2>&1 ;;
  esac
}

# --- Detectar puertos LDAP/GC abiertos (389/636/3268/3269) -----------------
LDAP_PORTS=$(python3 - "$XML" <<PY
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
openp = []
for p in tree.iter("port"):
    st = p.find("state")
    if st is None or st.get("state") != "open":
        continue
    if p.get("protocol") == "tcp" and p.get("portid") in ("389", "636", "3268", "3269"):
        openp.append(p.get("portid"))
print(",".join(sorted(set(openp), key=int)))
PY
)
if [ -z "${LDAP_PORTS:-}" ]; then
  echo "skipped_no_ldap: $TARGET no tiene puertos LDAP/GC (389/636/3268/3269) abiertos según $XML"
  exit 0
fi
echo "LDAP detectado en $TARGET (IP $IP): TCP ${LDAP_PORTS}"

# --- Seleccion del endpoint: 389 -> 3268; con --tls (o si solo hay 636/3269) LDAPS
LDAP_PORT=""
for cand in 389 3268 636 3269; do
  case ",$LDAP_PORTS," in *",$cand,"*) LDAP_PORT="$cand"; break ;; esac
done
if [ "$TLS" -eq 1 ]; then
  case ",$LDAP_PORTS," in
    *",636,"*)  LDAP_PORT=636 ;;
    *",3269,"*) LDAP_PORT=3269 ;;
  esac
fi
URI="ldap://$IP:$LDAP_PORT"
if [ "$LDAP_PORT" = "636" ] || [ "$LDAP_PORT" = "3269" ]; then
  URI="ldaps://$IP:$LDAP_PORT"
  export LDAPTLS_REQCERT=never
fi

# --- Gate de conectividad (si no responde ping, no se ejecuta nada) --------
if [ "$PING_CHECK" -eq 1 ]; then
  if ping_alive "$IP"; then
    echo "> ping OK ($IP)"
  else
    echo "skipped_no_ping: $IP no responde a ping (timeout ${PING_TO}s). No se ejecuta ldapsearch."
    exit 0
  fi
fi

# --- Evidencia principal: no-clobber (o --force) ---------------------------
OUT_TXT="$TGT_DIR/ldapsearch.txt"
if [ -s "$OUT_TXT" ] && [ "$FORCE" -ne 1 ]; then
  echo "[SKIP] $TARGET: ya existe $OUT_TXT (evidencia previa intacta). Usa --force para re-enumerar."
  exit 0
fi

# --- Modo credencializado OPT-IN: password en archivo 0600 (nunca en evidencia)
PWFILE=""
if [ -n "$LDAP_USER" ] && [ -n "$LDAP_PASS" ]; then
  PWFILE="$(mktemp /tmp/.ldap_pw.XXXXXX)"
  chmod 600 "$PWFILE"
  printf "%s" "$LDAP_PASS" > "$PWFILE"
  trap "rm -f $PWFILE" EXIT
fi
AUTH=()
if [ -n "$PWFILE" ]; then
  AUTH=(-D "$LDAP_USER" -y "$PWFILE")
fi

# --- Consulta 1: ROOT DSE (anonima por defecto) ----------------------------
LOPTS=(-o nettimeout="$TO" -o ldif-wrap=no -l "$TO")
CMD1="ldapsearch -x -H $URI -b \"\" -s base -o nettimeout=$TO -o ldif-wrap=no -l $TO"
[ -n "$PWFILE" ] && CMD1="$CMD1 -D $LDAP_USER -y <REDACTED>"
{ echo "$CMD1"; ldapsearch -x -H "$URI" -b "" -s base "${LOPTS[@]}" ${AUTH[@]+"${AUTH[@]}"} 2>&1; } > "$OUT_TXT"
RC=$?
[ "$RC" -ne 0 ] && echo "  ⚠️  ldapsearch (root DSE) rc=$RC; salida cruda en $OUT_TXT" >&2

# --- Extraer base DN y dnsHostName del root DSE ---------------------------
BASE_DN=$(sed -n "s/^defaultNamingContext: //p" "$OUT_TXT" | head -1)
[ -z "$BASE_DN" ] && BASE_DN=$(grep -m1 "^namingContexts: DC=" "$OUT_TXT" 2>/dev/null | sed "s/^namingContexts: //")
DHC=$(sed -n "s/^dnsHostName: //p" "$OUT_TXT" | head -1)

# --- Consulta 2: objeto raiz del dominio (solo si hay base DN) -------------
if [ -n "$BASE_DN" ]; then
  OUT2="$TGT_DIR/ldapsearch_domain.txt"
  if [ ! -s "$OUT2" ] || [ "$FORCE" -eq 1 ]; then
    CMD2="ldapsearch -x -H $URI -b \"$BASE_DN\" -s base (objectClass=*) -o nettimeout=$TO -o ldif-wrap=no -l $TO"
    [ -n "$PWFILE" ] && CMD2="$CMD2 -D $LDAP_USER -y <REDACTED>"
    { echo "$CMD2"; ldapsearch -x -H "$URI" -b "$BASE_DN" -s base "(objectClass=*)" "${LOPTS[@]}" ${AUTH[@]+"${AUTH[@]}"} 2>&1; } > "$OUT2"
    grep -qE "^(dn:|objectClass:)" "$OUT2" || rm -f "$OUT2"
  fi
fi

# --- Modo credencializado (OPT-IN): usuarios y SPN -------------------------
OUTU=""; OUTS=""
if [ -n "$PWFILE" ] && [ -n "$BASE_DN" ]; then
  OUTU="$TGT_DIR/ldapsearch_users.txt"
  CMD3="ldapsearch -x -H $URI -b \"$BASE_DN\" -s sub (objectCategory=person) sAMAccountName cn userAccountControl pwdLastSet -o nettimeout=$TO -D $LDAP_USER -y <REDACTED>"
  { echo "$CMD3"; ldapsearch -x -H "$URI" -b "$BASE_DN" -s sub "(objectCategory=person)" sAMAccountName cn userAccountControl pwdLastSet "${LOPTS[@]}" "${AUTH[@]}" 2>&1; } > "$OUTU"
  grep -q "^sAMAccountName:" "$OUTU" || { rm -f "$OUTU"; OUTU=""; }
  OUTS="$TGT_DIR/ldapsearch_spn.txt"
  CMD4="ldapsearch -x -H $URI -b \"$BASE_DN\" -s sub (servicePrincipalName=*) sAMAccountName servicePrincipalName -o nettimeout=$TO -D $LDAP_USER -y <REDACTED>"
  { echo "$CMD4"; ldapsearch -x -H "$URI" -b "$BASE_DN" -s sub "(servicePrincipalName=*)" sAMAccountName servicePrincipalName "${LOPTS[@]}" "${AUTH[@]}" 2>&1; } > "$OUTS"
  grep -q "^servicePrincipalName:" "$OUTS" || { rm -f "$OUTS"; OUTS=""; }
fi

# --- Conservar el root DSE solo si trajo datos ----------------------------
CALIFICA=0
grep -qE "namingContexts:|rootDomainNamingContext:|dnsHostName:" "$OUT_TXT" 2>/dev/null && CALIFICA=1
MODO=anon; [ -n "$PWFILE" ] && MODO=cred
echo "STEP_LDAP_DONE $TARGET uri=$URI ports=${LDAP_PORTS} base_dn=${BASE_DN:-none} dns_host=${DHC:-none} auth=$MODO"
if [ "$CALIFICA" -eq 1 ]; then
  echo "Evidencia: $OUT_TXT (+ ldapsearch_domain/users/spn si aplica) → disponible para revisión manual."
else
  rm -f "$OUT_TXT" "$TGT_DIR"/ldapsearch_domain.txt "$TGT_DIR"/ldapsearch_users.txt "$TGT_DIR"/ldapsearch_spn.txt
  echo "ldapsearch: $TARGET sin datos (bind anonimo denegado o LDAP sin respuesta) → evidencia NO conservada"
fi
