#!/bin/bash
# =============================================================================
# validate_step11_12.sh - Validacion asistida de los Steps 11 (LDAP) y 12 (Enum4linux)
# =============================================================================
# Uso: scripts/host/validate_step11_12.sh <TARGET> [opciones]
#   <TARGET>            IP del target (se valida contra su dir de evidencia)
#   --ev-dir <DIR>      dir de evidencia (default: <WS>/evidence/<TARGET>)
#   --creds user:pass   prueba el modo credencializado de LDAP + verifica anti-fuga del password
#   --full              ademas corre run_target.sh y valida el manifest de 12 entradas
#   --ping-check        NO saltar el gate ICMP en los steps (default: se salta)
#   --dry-run           muestra que haria, sin ejecutar nada
#
# Salida: [PASS]/[FAIL] por check + RESUMEN: N/M PASS   (exit 1 si hay algun FAIL).
# Garantias: no escribe fuera del dir de evidencia; NUNCA imprime el password.
# =============================================================================
set -uo pipefail

WS="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET=""
EV=""
CREDS=""
FULL=0
PING_SKIP=1
DRY=0
NO_BACKUP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ev-dir)    shift; EV="${1:-}"; shift ;;
    --creds)     shift; CREDS="${1:-}"; shift ;;
    --full)      FULL=1 ; shift ;;
    --ping-check) PING_SKIP=0 ; shift ;;
    --dry-run)   DRY=1 ; shift ;;
    --no-backup) NO_BACKUP=1 ; shift ;;
    -*)          echo "Opcion desconocida: $1" >&2; exit 1 ;;
    *)           TARGET="$1"; shift ;;
  esac
done
if [ -z "$TARGET" ]; then
  echo "Uso: scripts/host/validate_step11_12.sh <TARGET> [--ev-dir DIR] [--creds user:pass] [--full] [--ping-check] [--dry-run]" >&2
  exit 1
fi
[ -z "$EV" ] && EV="$WS/evidence/$TARGET"
PING_FLAG=(--no-ping-check)
[ "$PING_SKIP" -eq 0 ] && PING_FLAG=()
LDAP_USER=""; LDAP_PASS=""
if [ -n "$CREDS" ]; then LDAP_USER="${CREDS%%:*}"; LDAP_PASS="${CREDS#*:}"; fi

N_PASS=0; N_FAIL=0
ok()  { N_PASS=$((N_PASS+1)); echo "  [PASS] $1"; }
no()  { N_FAIL=$((N_FAIL+1)); echo "  [FAIL] $1"; }
warn() { echo "  [WARN] $1"; }
run() { if [ "$DRY" -eq 1 ]; then echo "  (dry-run) $*"; return 0; else "$@"; fi; }


echo "===[ Validacion Steps 11/12 - target $TARGET ]==="
echo "  evidencia: $EV"
[ -n "$CREDS" ] && echo "  modo: credencializado (usuario $LDAP_USER; password oculto)" || echo "  modo: anonimo"
[ "$FULL" -eq 1 ] && echo "  --full: se correra run_target.sh (regenera la evidencia del target)"

# --- V-01: dependencias -----------------------------------------------------
BIN_LDAP=0; command -v ldapsearch >/dev/null 2>&1 && BIN_LDAP=1
BIN_E4L=0
if command -v enum4linux-ng >/dev/null 2>&1 || command -v enum4linux >/dev/null 2>&1; then BIN_E4L=1; fi
if [ "$BIN_LDAP" -eq 1 ] && [ "$BIN_E4L" -eq 1 ]; then
  ok "V-01 dependencias: ldapsearch + enum4linux (ng/enum4linux) presentes"
elif [ "$BIN_LDAP" -eq 1 ]; then
  ok "V-01 dependencias: ldapsearch OK; AVISO: falta enum4linux-ng/enum4linux (Step 12 quedara skipped en Linux)"
else
  no "V-01 dependencias: falta ldapsearch (instalar: sudo apt install ldap-utils)"
fi

# --- V-02: evidencia base ---------------------------------------------------
XML="$EV/nmap_detailed.xml"
HAY_XML=0
if [ -s "$XML" ]; then
  HAY_XML=1; ok "V-02 evidencia base: $XML"
else
  no "V-02 evidencia base: falta $XML (correr el Step 3 sobre el target primero)"
fi

# --- V-03: expectativa derivada del XML (autoadaptativa al target) ----------
LDAP_PORTS=""; SMB_PORTS=""; WK_XML=""
if [ "$HAY_XML" -eq 1 ]; then
  INFO=$(python3 - "$XML" <<PY
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
ldap, smb, wkg = [], [], ""
for p in tree.iter("port"):
    st = p.find("state")
    if st is None or st.get("state") != "open":
        continue
    if p.get("protocol") != "tcp":
        continue
    if p.get("portid") in ("389", "636", "3268", "3269"):
        ldap.append(p.get("portid"))
    if p.get("portid") in ("139", "445"):
        smb.append(p.get("portid"))
for tab in tree.iter("table"):
    if tab.get("key") == "workgroup" and tab.text:
        wkg = tab.text.strip()
if not wkg:
    for sc in tree.iter("script"):
        t = sc.get("output") or ""
        if "workgroup: " in t:
            wkg = t.split("workgroup: ")[1].split(",")[0].split(")")[0].strip()
            break
if not wkg:
    for sv in tree.iter("service"):
        for attr in (sv.get("extrainfo"), sv.get("product")):
            if attr and "workgroup: " in attr:
                wkg = attr.split("workgroup: ")[1].split(",")[0].split(")")[0].strip()
                break
        if wkg:
            break
print(",".join(sorted(set(ldap), key=int)))
print(",".join(sorted(set(smb), key=int)))
print(wkg)
PY
)
  LDAP_PORTS=$(printf "%s\\n" "$INFO" | sed -n "1p")
  SMB_PORTS=$(printf "%s\\n" "$INFO" | sed -n "2p")
  WK_XML=$(printf "%s\\n" "$INFO" | sed -n "3p")
  ok "V-03 expectativa: LDAP=[${LDAP_PORTS:-ninguno}] SMB=[${SMB_PORTS:-ninguno}] workgroup=[${WK_XML:-auto}]"
fi

# --- V-04: Step 11 (LDAP) incremental + gate negativo -----------------------
if [ "$HAY_XML" -eq 1 ] && [ -n "$LDAP_PORTS" ]; then
  LD_ARGS=(--ev-dir "$EV" --force)
  [ "${#PING_FLAG[@]}" -gt 0 ] && LD_ARGS+=(--no-ping-check)
  [ -n "$LDAP_USER" ] && LD_ARGS+=(--ldap-user "$LDAP_USER" --ldap-pass "$LDAP_PASS")
  OUT11=$(run bash "$WS/scripts/host/step11_ldap_enum.sh" "${LD_ARGS[@]}" 2>&1)
  if [ "$DRY" -eq 1 ]; then
    ok "V-04 Step 11: (dry-run) se ejecutaria sobre puertos $LDAP_PORTS"
  elif printf "%s\\n" "$OUT11" | grep -q "STEP_LDAP_DONE"; then
    if [ -s "$EV/ldapsearch.txt" ] && head -1 "$EV/ldapsearch.txt" | grep -q "^ldapsearch"; then
      ok "V-04 Step 11: STEP_LDAP_DONE + ldapsearch.txt (1a linea = comando)"
    else
      no "V-04 Step 11: STEP_LDAP_DONE pero falta ldapsearch.txt o su 1a linea no es el comando"
    fi
    printf "%s\\n" "$OUT11" | grep -q "base_dn=none" && warn "V-04 root DSE sin base DN (bind anonimo denegado: es un hallazgo, no un error)"
  elif printf "%s\\n" "$OUT11" | grep -qE "skipped_no_ping"; then
    ok "V-04 Step 11: skipped_no_ping (target sin respuesta ICMP; reintentar con --no-ping-check)"
  elif printf "%s\\n" "$OUT11" | grep -qE "skipped:"; then
    ok "V-04 Step 11: skipped (binario ldapsearch ausente)"
  else
    no "V-04 Step 11: no imprimio STEP_LDAP_DONE ni un skip conocido -> $(printf "%s" "$OUT11" | head -2 | tr "\\n" " ")"
  fi
elif [ "$HAY_XML" -eq 1 ]; then
  before=$(ls "$EV" 2>/dev/null | wc -l | tr -d " ")
  OUT11=$(run bash "$WS/scripts/host/step11_ldap_enum.sh" --ev-dir "$EV" --force 2>&1)
  if [ "$DRY" -eq 1 ]; then
    ok "V-04 Step 11: (dry-run) deberia dar skipped_no_ldap"
  elif printf "%s\\n" "$OUT11" | grep -q "skipped_no_ldap"; then
    after=$(ls "$EV" 2>/dev/null | wc -l | tr -d " ")
    if [ "$before" = "$after" ]; then ok "V-04 Step 11 (gate negativo): skipped_no_ldap sin archivos nuevos"; else no "V-04 gate negativo: genero archivos sin puertos LDAP"; fi
  else
    no "V-04 Step 11: sin puertos LDAP debio dar skipped_no_ldap"
  fi
fi

# --- V-05: Step 12 (Enum4linux) incremental + gate negativo ------------------
if [ "$HAY_XML" -eq 1 ] && [ -n "$SMB_PORTS" ]; then
  E4_ARGS=(--ev-dir "$EV" --force)
  [ "${#PING_FLAG[@]}" -gt 0 ] && E4_ARGS+=(--no-ping-check)
  OUT12=$(run bash "$WS/scripts/host/step12_enum4linux_enum.sh" "${E4_ARGS[@]}" 2>&1)
  if [ "$DRY" -eq 1 ]; then
    ok "V-05 Step 12: (dry-run) se ejecutaria sobre puertos $SMB_PORTS"
  elif printf "%s\\n" "$OUT12" | grep -q "STEP_ENUM4LINUX_DONE"; then
    ok "V-05 Step 12: STEP_ENUM4LINUX_DONE"
    if [ -n "$WK_XML" ]; then
      printf "%s\\n" "$OUT12" | grep -q "workgroup=$WK_XML" && ok "V-05 workgroup autodetectado del XML: $WK_XML" || warn "V-05 el workgroup no salio del XML ($WK_XML)"
    fi
  elif printf "%s\\n" "$OUT12" | grep -q "skipped_unsupported_os"; then
    ok "V-05 Step 12: skipped_unsupported_os (macOS: correcto, el step es solo Linux)"
  elif printf "%s\\n" "$OUT12" | grep -qE "skipped_no_ping"; then
    ok "V-05 Step 12: skipped_no_ping (target sin respuesta ICMP)"
  elif printf "%s\\n" "$OUT12" | grep -qE "skipped_no_smb|skipped:"; then
    ok "V-05 Step 12: skip correcto (sin 139/445 o sin binario)"
  else
    no "V-05 Step 12: no imprimio STEP_ENUM4LINUX_DONE ni un skip conocido -> $(printf "%s" "$OUT12" | head -2 | tr "\\n" " ")"
  fi
elif [ "$HAY_XML" -eq 1 ]; then
  OUT12=$(run bash "$WS/scripts/host/step12_enum4linux_enum.sh" --ev-dir "$EV" --force 2>&1)
  if [ "$DRY" -eq 1 ]; then ok "V-05 Step 12: (dry-run) deberia dar skipped_no_smb o skipped_unsupported_os";
  elif printf "%s\\n" "$OUT12" | grep -qE "skipped_no_smb|skipped_unsupported_os"; then ok "V-05 Step 12 (gate negativo): sin 139/445 -> skip correcto";
  else no "V-05 Step 12: sin 139/445 debio dar skipped_no_smb (o skipped_unsupported_os en macOS)"; fi
fi

# --- V-06: anti-fuga del password (solo con --creds) ------------------------
if [ -n "$LDAP_PASS" ]; then
  if [ "$DRY" -eq 1 ]; then
    ok "V-06 anti-fuga: (dry-run) se verificaria que el password no este en la evidencia"
  else
    LEAK=$(grep -rl -- "$LDAP_PASS" "$EV" 2>/dev/null | wc -l | tr -d " ")
    if [ "$LEAK" = "0" ]; then ok "V-06 anti-fuga: el password NO aparece en $EV"; else no "V-06 anti-fuga: el password aparece en $LEAK archivo(s)"; fi
    if ls /tmp/.ldap_pw.* >/dev/null 2>&1; then no "V-06 anti-fuga: quedo un archivo temporal /tmp/.ldap_pw.*"; else ok "V-06 anti-fuga: sin archivos temporales de password"; fi
    if [ -n "$LDAP_PORTS" ]; then
      if [ -s "$EV/ldapsearch_users.txt" ] || [ -s "$EV/ldapsearch_spn.txt" ]; then
        ok "V-06 modo credencializado: genero ldapsearch_users.txt / ldapsearch_spn.txt"
      else
        warn "V-06 modo credencializado: no se generaron users/spn (bind rechazado o sin permisos)"
      fi
    fi
  fi
else
  echo "  [SKIP] V-06 anti-fuga: no se paso --creds (modo anonimo)"
fi

# --- V-07: integracion completa (--full) -----------------------------------
if [ "$FULL" -eq 1 ]; then
  IN_SCOPE=$(jq -e --arg ip "$TARGET" "any(.authorized_targets[]; .ip == \$ip)" "$WS/config/scope.json" >/dev/null 2>&1 && echo 1 || echo 0)
  if [ "$IN_SCOPE" != "1" ]; then
    no "V-07 --full: $TARGET no esta en config/scope.json (R1): no se corre el pipeline"
  else
    # E (2026-10-22): backup AUTOMATICO antes de regenerar la evidencia. Tras un
    # --full, CK-02 no distingue archivos NUEVOS de viejos (el manifest usa globs),
    # así que un step `failed` puede quedar "cubierto" por evidencia de runs previos.
    if [ "$NO_BACKUP" -eq 1 ]; then
      echo "  (aviso) --full regenera la evidencia de $TARGET SIN backup (--no-backup)"
    else
      BK="/tmp/backup_${TARGET}_$(date +%Y%m%d_%H%M%S)"
      if cp -r "$EV" "$BK" 2>/dev/null; then
        echo "  (info) backup de la evidencia previa: $BK (usar --no-backup para omitirlo)"
      else
        echo "  (aviso) no se pudo crear el backup en $BK (revisar permisos)"
      fi
    fi
    LOGF=$(mktemp)
    run bash "$WS/scripts/host/run_target.sh" "$TARGET" > "$LOGF" 2>&1
    if [ "$DRY" -eq 1 ]; then
      ok "V-07 --full: (dry-run) se correria run_target.sh"
    else
      MP="$EV/manifest.json"
      NSTEPS=$(jq ".tools_executed | length" "$MP" 2>/dev/null || echo 0)
      if [ "$NSTEPS" = "12" ]; then ok "V-07 manifest: 12 entradas"; else no "V-07 manifest: $NSTEPS entradas (se esperaban 12)"; fi
      T11=$(jq -r ".tools_executed[] | select(.step==11) | .tool" "$MP" 2>/dev/null)
      T12=$(jq -r ".tools_executed[] | select(.step==12) | .tool" "$MP" 2>/dev/null)
      if [ "$T11" = "ldap_enum" ]; then ok "V-07 manifest: step 11 = ldap_enum"; else no "V-07 manifest: step 11 = $T11 (se esperaba ldap_enum)"; fi
      if [ "$T12" = "enum4linux" ]; then ok "V-07 manifest: step 12 = enum4linux"; else no "V-07 manifest: step 12 = $T12 (se esperaba enum4linux)"; fi
      NLOGS=$(grep -c "Step [0-9]*/12" "$LOGF" 2>/dev/null); NLOGS=${NLOGS:-0}
      if [ "$NLOGS" -ge 12 ] 2>/dev/null; then ok "V-07 orquestador: $NLOGS lineas Step N/12 en la salida"; else no "V-07 orquestador: $NLOGS lineas Step N/12 (se esperaban >=12)"; fi
      if [ -s "$EV/_step.log" ]; then ok "V-07 _step.log del target presente"; else no "V-07 falta $EV/_step.log"; fi
      rm -f "$LOGF"
    fi
  fi
else
  echo "  [SKIP] V-07 integracion: usar --full para correr run_target.sh y validar el manifest"
fi

echo ""
TOTAL=$((N_PASS+N_FAIL))
echo "  RESUMEN:  $N_PASS/$TOTAL PASS  |  $N_FAIL/$TOTAL FAIL"
if [ "$N_FAIL" -eq 0 ]; then
  echo ">>> VALIDATE_STEP11_12_OK | PASS=$N_PASS | TARGET=$TARGET"
  exit 0
else
  echo ">>> VALIDATE_STEP11_12_FAIL | FAIL=$N_FAIL | TARGET=$TARGET"
  exit 1
fi
