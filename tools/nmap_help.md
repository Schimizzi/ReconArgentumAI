# NMAP — Reference Help
## Versión: contenedor Docker = **7.99** (Kali rolling arm64) · Host macOS = **7.991** (Homebrew)
## Fuente: `nmap --help` + `nmap --version` (2026-08-30). En el contenedor /usr/bin/nmap es el wrapper de Kali sobre /usr/lib/nmap/nmap.
## ⚠️ ENTORNO / MODOS:
##   - **MODO HOST (macOS, LAN local):** Nmap usa **`-sT`** (TCP Connect) — no requiere
##     root/raw sockets. `-sS` sin sudo NO funciona en macOS ("requires root privileges").
##   - **MODO DOCKER (contenedor Kali, targets externos):** usa `-sS` (raw sockets, funciona solo
##     en Linux real / VM con bridge; ⚠️ Docker Desktop/mac NO ve la LAN local del host).
##   - **BUG `-oJ` (verificado 2026-08-30):** en el binario aarch64 de Kali (7.99+dfsg-1kali1)
##     el JSON output `-oJ` está ROTO (no escribe archivo y corrompe el parseo de outputs).
##     WORKAROUND: usar `-oX` + `-oN` + `-oG` y derivar el JSON del XML con
##     `scripts/xml_to_nmap_json.py` (en HOST se mantiene por consistencia de evidencia).

## FLAGS DE TIMING (Stealth)
- `-T0` Paranoid. 5 min entre probes. (demasiado lento para casi todo)
- `-T1` Sneaky. 0.5s entre probes. ← usar si IDS/EDR agresivo
- `-T2` Polite. 0.2s entre probes. ← RESUELTO de {{nmap_timing_template}} (Fase 0: T2)
- `-T3` Normal (default). 0.1s entre probes.
- `-T4` Aggressive. 5ms entre probes.
- `-T5` Insane. Más rápido; muy detectable.
- `--max-rate <N>` No enviar más de N packets/segundo. ← resuelto de {{nmap_max_rate}} (Fase 0: 30)
- `--min-rate <N>` No enviar menos de N packets/segundo.
- `--max-retries <n>` Limitar retransmisiones de probes.
- `--host-timeout <time>` Abandonar un host tras este tiempo.
- `--scan-delay <time>` Fuerza delay mínimo entre probes.
- `--min-rtt-timeout/--initial-rtt-timeout <time>` Ajustar timeouts de RTT.

## FLAGS DE ESCANEO
- `-sS` SYN scan (half-open). **Solo MODO DOCKER** (requiere raw sockets).
- `-sT` TCP connect scan. **MODO HOST por defecto** (completa handshakes; sin root).
- `-sA` ACK scan (mapeo de firewalls).
- `-sU` UDP scan (lento; cuidadoso con stealth).
- `-p <range>` Rango de puertos: `-p22`, `-p1-65535`, `-p U:53,T:80-88`, `-p top-1000`.
- `--top-ports <n>` Escanear los n puertos más comunes. Step 1 ACTUAL: usa la lista `-p <clienteP>` de `config/stealth.yaml` (98 puertos del cliente) en lugar de `--top-ports 1000` (baseline Fase 0).
- `-F` Fast mode (menos puertos que el default).
- `--exclude-ports <range>` Excluir puertos.
- `--open` Mostrar SOLO puertos abiertos (reduce ruido de output).
- `-Pn` Tratar todos los hosts como online (skippear host discovery).
- `-n` No hacer resolución DNS.

## DETECCIÓN DE SERVICIOS/SCRIPTS
- `-sV` Detección de versión de servicio.
- `--version-intensity <0-9>` Intensidad de probing (9 = todos los probes).
- `-sC` Ejecutar scripts NSE default.
- `--script=<categorías>` Ej: `--script=vuln`, `--script=safe`.
- `-A` OS + version + scripts + traceroute (todo en uno; ruidoso).

## FLAGS DE OUTPUT
- `-oX <file>` Output XML (estructurado, COMPLETO). ✅
- `-oJ <file>` Output JSON. ⚠️ ROTO en la build aarch64 de Kali (7.99) — en HOST (7.991) funciona.
- `-oN <file>` Output normal (texto legible). ✅
- `-oG <file>` Output greppable. ✅
- `-oA <basename>` Los tres formatos principales a la vez.
- `-v/-vv` Aumentar verbosidad.
- `--append-output` Append en vez de sobrescribir.

## FLAGS DE OFUSCACIÓN (solo con autorización explícita del usuario en Fase 0)
- `-D <decoy1,decoy2[,ME],...>` Cloak del scan con decoys. Ej: `-D RND:3`.
- `-S <IP>` Spoof de source address.
- `-f / --mtu <val>` Fragmentar paquetes.
- `-g/--source-port <port>` Puerto de origen (ej. 53, 80).
- `--data-length <N>` Rellenar packets con datos aleatorios.
- `--proxies <url>` Relay a través de proxies HTTP/SOCKS4.
- `--spoof-mac <mac>` Spoofear MAC.

## EJEMPLOS ÚTILES (vars resueltas desde config/stealth.yaml)
```bash
# Step 1 — MODO DOCKER (targets externos): SYN scan
nmap -sS -T{{nmap_timing_template}} --max-rate {{nmap_max_rate}} \
  -p <clienteP> --open -Pn \
  -oX /workspace/evidence/<target>/nmap_ports.xml \
  -oN /workspace/evidence/<target>/nmap_ports.txt \
  -oG /workspace/evidence/<target>/nmap_ports.gnmap \
  <TARGET>

# Step 1 — MODO HOST (LAN local): TCP Connect scan
nmap -sT -T{{nmap_timing_template}} --max-rate {{nmap_max_rate}} \
  -p <clienteP> --open -Pn \
  -oX <WORKSPACE>/evidence/<target>/nmap_ports.xml \
  -oN <WORKSPACE>/evidence/<target>/nmap_ports.txt \
  -oG <WORKSPACE>/evidence/<target>/nmap_ports.gnmap \
  <TARGET>
# luego: python3 scripts/xml_to_nmap_json.py <xml> <json>

# Step 3 — Scan detallado SOLO sobre puertos confirmados (nunca rango completo)
#   (MODO HOST: -sT -sC -sV; MODO DOCKER: -sS -sC -sV) con -oX/-oN + json derivado.
```

## NOTAS PARA EL AGENTE
- SIEMPRE guardar `-oX` (evidencia estructurada completa) y, dado el bug citado,
  el JSON derivado del XML.
- SIEMPRE usar `--open` en Step 1 (reduce ruido de output).
- `-sJ` solo en HOST; en DOCKER usar el workaround.
- En Step 3, `-p` recibe EXACTAMENTE los puertos de `evidence/<target>/open_ports.txt`, NUNCA un rango completo.
- WAF presente → mínimo `-T2` y `--max-rate <= 30`.
- IDS/EDR presentes → `-T1` y `--max-rate <= 10`.
- Tarpits → mantener rate bajo y aumentar timeouts (`--host-timeout`), NO acelerar.
- Hosts descubiertos fuera de `config/scope.json` → registrar en `out_of_scope_findings` del manifest, NO escanearlos.