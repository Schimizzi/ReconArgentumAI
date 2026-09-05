#!/bin/bash
# preflight_run.sh - Verificaciones previas a FASE 1 (RUN#9).
set -uo pipefail
WS="${WORKSPACE:-$(pwd)}"
fail=0
echo "===[ Preflight FASE 1 - $(date '+%Y-%m-%d %H:%M:%S') ]==="
for d in evidence logs plans cve_research reports; do
  mkdir -p "$WS/$d"
  [ -d "$WS/$d" ] || { echo "FALTA dir: $d"; fail=1; }
done
for t in nmap httpx-pd nuclei nikto gobuster sslyze jq python3; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "  OK  $t -> $(command -v "$t")"
  else
    echo "  FALTA $t"; fail=1
  fi
done
WEB_LIST="${HOME}/Documents/SecLists/Discovery/Web-Content/common.txt"
DNS_LIST="${HOME}/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
for wl in "$WEB_LIST" "$DNS_LIST"; do
  if [ -s "$wl" ]; then
    echo "  OK  wordlist: $wl ($(wc -l < "$wl" | tr -d ' ') lineas)"
  else
    echo "  FALTA wordlist: $wl"; fail=1
  fi
done
if [ ! -s "$WS/config/scope.json" ] || [ ! -s "$WS/config/stealth.yaml" ]; then
  echo "FALTA config/scope.json o config/stealth.yaml"; fail=1
else
  TARGETS=()
  while IFS= read -r _t; do TARGETS+=("$_t"); done < <(jq -r '.authorized_targets[].ip' "$WS/config/scope.json")
  for T in "${TARGETS[@]}"; do
    if jq -e --arg ip "$T" 'any(.excluded_ips[]; . == $ip)' "$WS/config/scope.json" >/dev/null 2>&1; then
      echo "  EXCLUIDO (R1): $T - NUNCA se escanea"; continue
    fi
    if ping -c 1 -W 2 "$T" >/dev/null 2>&1; then
      echo "  OK  target $T responde ICMP"
    else
      echo "  WARN target $T no responde ICMP (se continua; -Pn contemplado)"
    fi
  done
  [ "${#TARGETS[@]}" -gt 0 ] || { echo "Sin authorized_targets en scope.json"; fail=1; }
fi
LOCKS=$(ls -d "$WS"/evidence/*/.run.lock 2>/dev/null | wc -l | tr -d ' ')
if [ "$LOCKS" -gt 0 ]; then
  echo "  WARN $LOCKS lock(s) activos en evidence/*/.run.lock (R3)"
fi
if [ "$fail" -eq 0 ]; then
  echo "===[ Preflight: OK ]==="
else
  echo "===[ Preflight: ERRORES - corregir y relanzar ]==="
fi
exit "$fail"
