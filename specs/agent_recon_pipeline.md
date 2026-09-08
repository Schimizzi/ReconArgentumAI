# Spec operativa — Recon Pipeline (Fase 1)

> Instrucción operativa que el **Orchestrator** lee ANTES de ejecutar la Fase 1.
> Complementa: `openspec/changes/add-pentest-recon-pipeline/specs/recon-pipeline/spec.md` (contrato formal),
> `.cline/master_prompt.md` (rol y guardrails) y `config/approved_commands.md` (única fuente de comandos).
> `<WORKSPACE>` = raíz del proyecto. Todos los paths son relativos a `<WORKSPACE>` (ver master_prompt.md §0).

## 0. Precondiciones de entrada

- `config/scope.json` con los targets reales del engagement (plantilla reemplazada).
- `config/stealth.yaml` calibrado en Fase 0 (timeouts/rates/threads, decoys).
- `config/approved_commands.md` con los comandos `APROBADO` (o `SALTADO`) por el usuario para este target.
- Help files consultados: `tools/*_help.md` (flags verificados localmente).

## 0bis. Modos de ejecución (arquitectura híbrida + Agente 1 automático)

| Modo | Binario | Lanzador | Nmap | Binarios |
|---|---|---|---|---|
| **DOCKER** | targets EXTERNOS (Internet) o VM Kali con Docker | `run_docker.sh --auto` (sin LLM) / `run_docker.sh` (Orchestrator) | `-sS` (root; contenedor corre como root) | dentro del contenedor Kali; scripts en `scripts/host/` |
| **HOST** | LAN local (macOS) o VM Kali sin Docker | `run_host.sh` / `bash scripts/host/run_fase1_run3.sh` | **`-sT`** si no root, **`-sS`** si root (autodetectado) | directo en el host; scripts en `scripts/host/` |

> 🤖 **Agente 1 automático SIN LLM (2026-09-07):** ambos modos comparten el **mismo** set
> `scripts/host/` y el **mismo runner maestro** `scripts/host/run_fase1_run3.sh`, que recorre
> `authorized_targets` de `scope.json` y delega cada IP a `run_target.sh`. No hace falta LLM para
> la Fase 1: los scripts deciden status `success/failed/skipped_*`, retry 1x y delays desde
> `config/stealth.yaml`.

- ⚠️ **Docker Desktop (macOS) NO accede la LAN local del host**: ni `-sS` (raw sockets emulados)
  ni `-sT` (NAT/gRPC) propagan bien el tráfico → para escanear `192.168.8.0/24` usar SIEMPRE **MODO HOST**.
- Ambos modos comparten el mismo DAG (10 steps, 9 tools), `config/stealth.yaml`,
  workaround `-oJ` (ver Step 1) y el sub-schema de evidencia (`evidence/<target>/…`, `manifest.json`).
- **Wordlists portables** (2026-09-07): `step7_gobuster.sh` y `preflight_run.sh` resuelven las
  SecLists probando `/opt/SecLists/...` → `/usr/share/seclists/...` → `$HOME/Documents/SecLists/...` → `tools/seclists_common.txt`
  (cache web local del repo). Funciona igual en host macOS, VM Kali y contenedor.
- **Scan type autodetectado** (2026-09-07): `step1_nmap_ports.sh` y `step3_nmap_detailed.sh` usan
  `-sS` cuando `EUID == 0` (root: VM Kali / contenedor) y `-sT` en caso contrario (host macOS sin root).

## 1. DAG lineal — 10 steps, 9 herramientas

| Step | Herramienta | Input | Output en `evidence/<target>/` | Post-proceso |
|---|---|---|---|---|
| 1 | Nmap (port scan) | target (scope.json) | `nmap_ports.xml`, `nmap_ports.json`, `nmap_ports.txt` | extraer abiertos → `open_ports.txt` |
| 2 | HTTPX (probe web) | `open_ports.txt` | `httpx.json` (JSONL completo) | extraer URLs http/https → `web_endpoints.txt` |
| 3 | Nmap (-sC -sV) | `open_ports.txt` (solo abiertos) | `nmap_detailed.json`, `nmap_detailed.xml`, `nmap_detailed.txt` | — |
| 4 | Nuclei | `open_ports.txt` — **SIEMPRE** si hay ≥1 puerto abierto | `nuclei.json` (JSONL) | — |
| 5 | Nikto | `web_endpoints.txt` — **solo si hay web** | `nikto_<port>.json` (o `.html`+`.txt`) | — |
| 6 | WhatWeb | `web_endpoints.txt` — **solo si hay web** | `whatweb.json` (o `.txt`) | — |
| 7 | Gobuster/Dirsearch | **multi-modo** — `dir` (si hay web) + `dns` (si target es dominio) + `tftp` (si UDP 69 abierto) | `gobuster_<port>.txt`, `gobuster_dns.txt`, `gobuster_tftp.txt` | — |
| 8 | SSLyze | **puertos con túnel SSL/TLS** detectados por Nmap (no solo 443/8443) | `sslyze_<port>.json` (o `.txt`) | — |
| 9 | IIS Shortname (8.3) | **solo si hay web** + firma `Microsoft-IIS` en `httpx.json` (`webserver`) | `iis_shortname_evidence.txt/.json`, `iis_scan_urls.txt`, `iis_shortname_commands_outputs.txt` | — |
| 10 | SMB Enum (`step10_smbclient_enum.sh`) | **solo si TCP 139/445 abierto** (`open_ports.txt` o `nmap_detailed.xml`) | `smbclient_shares.txt`, `smbclient_<share>.txt` | — |

Orden SIEMPRE lineal `1→2→3→…→10`, sin paralelismo (R3 del master_prompt).

## 2. Reglas transversales (aplican a TODOS los steps)

1. **Secuencial estricto**: nunca dos herramientas contra el mismo target al mismo tiempo.
2. **Delays de stealth**: entre tools sobre el mismo target → `delay_between_tools_seconds`; entre targets → `delay_between_targets_minutes` (ambos desde `config/stealth.yaml`).
3. **Scope guardrail (R1)**: antes de CADA comando se verifica que el target esté en `config/scope.json` (respetando `excluded_ips[]`). Hosts fuera de scope → SOLO se registran en `out_of_scope_findings` (manifest) / `out_of_scope[]` (reporte). Nunca se les ejecuta un scan.
4. **Variables `{{...}}`**: TODOS los timeouts, rates y threads de los comandos base se resuelven de `config/stealth.yaml`. Prohibido hardcodear valores en el comando. Si Fase 0 calibra un valor nuevo, PRIMERO se actualiza `stealth.yaml` y después se propone el comando.
5. **Evidencia completa e inmutable (R4)**: el output crudo se guarda COMPLETO; el filtrado/resumen SOLO ocurre al ingerir (Agente 3), nunca en disco.
6. **Solo comandos aprobados**: nada se ejecuta si no está en `config/approved_commands.md` como `APROBADO` para ese target.

## 3. Steps (input / comando base / output / post-proceso)

### Step 1 — Nmap port scan (input: target desde scope.json)

```bash
nmap -sS -T{{nmap_timing_template}} --max-rate {{nmap_max_rate}} \
  --open -Pn \
  -oX <WORKSPACE>/evidence/<target>/nmap_ports.xml \
  -oN <WORKSPACE>/evidence/<target>/nmap_ports.txt \
  -oG <WORKSPACE>/evidence/<target>/nmap_ports.gnmap \
  <TARGET>
```

> ⚠️ **Workaround bug `-oJ` (verificado 2026-08-30):** nmap 7.99+dfsg-1kali1
> (arm64) del contenedor tiene el JSON output (`-oJ`) ROTO (no escribe archivo y
> corrompe el parseo de outputs). Por eso el comando usa `-oX/-oN/-oG` y el
> `nmap_ports.json` se **deriva del XML** en el post-proceso con
> `scripts/xml_to_nmap_json.py` (mismo sub-schema `.scan[IP].tcp[port].state`).
> Detalle en `tools/nmap_help.md` y `config/approved_commands.md`.

- Rango/puertos a escanear: lista `clienteP` de `config/stealth.yaml` (cliente actual; reemplaza `--top-ports 1000` aprobado en Fase 0).
- Decoys (`-D {{decoy_ips}}`): solo si el usuario los autorizó.
- **Post-proceso** — extraer puertos abiertos en `IP:PORT` por línea + derivar JSON:

```bash
jq -r '(.scan | keys[]) as $t | .scan[$t].tcp | to_entries[] |
  select(.value.state == "open") | "\($t):\(.key)"' \
  <WORKSPACE>/evidence/<target>/nmap_ports.json \
  > <WORKSPACE>/evidence/<target>/open_ports.txt
```

- **Excepción operativa**: si `open_ports.txt` queda vacío tras un Step 1 exitoso, no hay base de escaneo → el target se registra `incomplete` en el manifest (con nota) y se pasa al siguiente target.

### Step 2 — HTTPX probe web (input: `open_ports.txt`)

> ⚠️ El binario de probe HTTP se resuelve con **prioridad `httpx-toolkit` → `httpx-pd` → `httpx`** (los 3 de ProjectDiscovery).
> En **Kali Linux** (VM y contenedor Docker) el binario PD se llama **`httpx-toolkit`** (Kali renombra los binarios PD que chocan con paquetes Python) — es el PRINCIPAL, y se instala con `sudo apt install httpx-toolkit`.
> En macOS existe `httpx-pd` (binario en `go/bin/httpx-pd`). El `httpx` del PATH (cliente HTTP de Python) NUNCA sirve para probe: la resolución
> lo evita priorizando `httpx-toolkit`/`httpx-pd`, y solo lo acepta como fallback si realmente soporta `-l` (PD real).

```bash
httpx-toolkit -l <WORKSPACE>/evidence/<target>/open_ports.txt \
  -o <WORKSPACE>/evidence/<target>/httpx.json \
  -json \
  -timeout {{httpx_timeout_seconds}} \
  -retries {{httpx_retries}} \
  -t {{httpx_threads}}
```

- Threads `-t {{httpx_threads}}` resuelto desde `stealth.yaml` (Fase 0: `httpx_threads: 5`).
- **Post-proceso** — extraer SOLO URLs con esquema http/https:

```bash
jq -r '.url // empty' <WORKSPACE>/evidence/<target>/httpx.json \
  | grep -E '^https?://' \
  > <WORKSPACE>/evidence/<target>/web_endpoints.txt
```

### Step 3 — Nmap -sC -sV detallado (input: SOLO puertos abiertos)

**Nunca** sobre rango completo: `-p` SIEMPRE con la lista de `open_ports.txt`.

```bash
nmap -sC -sV -p <PUERTOS_COMA_SEPARADOS> \
  -T{{nmap_timing_template}} --max-rate {{nmap_max_rate}} -Pn \
  -oJ <WORKSPACE>/evidence/<target>/nmap_detailed.json \
  -oX <WORKSPACE>/evidence/<target>/nmap_detailed.xml \
  -oN <WORKSPACE>/evidence/<target>/nmap_detailed.txt \
  <TARGET>
```

### Step 4 — Nuclei (input: `open_ports.txt`) — SIEMPRE si hay puertos abiertos

> **Optimización Multiprotocolo (2026-08-31):** Nuclei es un motor **multiprotocolo** (red, SSH,
> DNS, TLS, web, etc.). Se ejecuta SIEMPRE que `open_ports.txt` no esté vacío, apuntando a los
> hosts/puertos abiertos del target, para que sus plantillas de red/SSH/DNS/OT descubran
> vulnerabilidades no-web además de las web. Ya NO depende de `web_endpoints.txt`.

```bash
nuclei -l <WORKSPACE>/evidence/<target>/open_ports.txt \
  -o <WORKSPACE>/evidence/<target>/nuclei.json \
  -jsonl \
  -rl {{nuclei_rate_limit}} \
  -timeout {{nuclei_timeout_seconds}} \
  -bs {{nuclei_bulk_size}} \
  -s critical,high,medium
```

- `open_ports.txt` contiene `IP:PORT` uno por línea → Nuclei aplica plantillas web a los puertos
  HTTP(S) y plantillas de red/SSH/DNS/etc. a los demás (matching por `host:port`).
- Templates: **set default de nuclei** (descarga automática en el 1er run) filtrado por severidad
  con `-s critical,high,medium` (aprobado en Fase 0; reemplaza `-es info` y excluye `unknown`).
- `-bs {{nuclei_bulk_size}}` hosts en paralelo por template, resuelto de `stealth.yaml` (Fase 0: `nuclei_bulk_size: 5`; default nuclei = 25).
- Si `open_ports.txt` está vacío (no hay puertos abiertos) → manifest `skipped_no_ports`.

### Step 5 — Nikto (input: `web_endpoints.txt` → SECUENCIAL, 1 por endpoint)

```bash
nikto -h <URL> -Format json \
  -o <WORKSPACE>/evidence/<target>/nikto_<port>.json \
  -Tuning 123b \
  -maxtime {{nikto_maxtime_seconds}}s \
  -nocheck
```

- NUNCA `-Tuning 6` (DoS).
- `-Format json` **verificado** en Nikto 2.6.1 del contenedor (Paso 2 del proyecto). `-maxtime`
  acepta duraciones (`{{nikto_maxtime_seconds}}s`). `-nocheck` evita el chequeo de updates al arrancar.
- Fallback (solo si `-Format json` fallara): `nikto -h <URL> -o <WORKSPACE>/evidence/<target>/nikto_<port>.html -Tuning 123b -maxtime {{nikto_maxtime_seconds}}s 2>&1 | tee <WORKSPACE>/evidence/<target>/nikto_<port>.txt`. El manifest refleja el formato real.

### Step 6 — WhatWeb (input: `web_endpoints.txt`)

```bash
whatweb -i <WORKSPACE>/evidence/<target>/web_endpoints.txt \
  --log-json=<WORKSPACE>/evidence/<target>/whatweb.json \
  -a 2 \
  --open-timeout {{whatweb_timeout_seconds}} \
  --read-timeout {{whatweb_read_timeout_seconds}} \
  --max-threads {{whatweb_threads}}
```

- **Verificado en WhatWeb 0.6.4 del contenedor (Paso 2):** NO existe `--json-output`;
  el JSON se emite con `--log-json=<file>`. NO existe `--timeout` único: usar
  `--open-timeout` + `--read-timeout` (ambos resueltos de `stealth.yaml`).
- Agresión `-a 2` aprobada en Fase 0 (conservadora). Threads `--max-threads {{whatweb_threads}}`.

### Step 7 — Gobuster/Dirsearch (input: multi-modo, Service-Based Routing)

> **Optimización Multiprotocolo (2026-08-31):** Gobuster ya no es solo `dir`. Se rutea por
> servicio pendiente de descubrir:
> - **`dir`**: si `web_endpoints.txt` NO está vacío → 1 por endpoint web, secuencial.
> - **`dns`**: si el target es un **dominio** (no una IP cruda) → fuerza bruta de subdominios con
>   `gobuster dns`. Si el target es IP, se informa `skipped_no_domain`.
> - **`tftp`**: si el **puerto 69/UDP** está abierto (probe UDP aprobado) → enumeración TFTP con
>   `gobuster tftp`.

Wordlists (path aprobado en Fase 0): `dir`→ Web-Content `common.txt` · `dns`→ DNS
`subdomains-top1million-5000.txt` · `tftp`→ Web-Content `common.txt`.

#### Modo `dir` (Web)
```bash
gobuster dir \
  -u <URL> \
  -w <WORDLIST_WEB_FASE0> \
  -o <WORKSPACE>/evidence/<target>/gobuster_<port>.txt \
  -t {{gobuster_threads}} \
  --timeout {{gobuster_timeout_seconds}}s \
  -s 200,204,301,307,401,403 \
  -x txt,bak,old,zip
```

#### Modo `dns` (dominio)
```bash
gobuster dns \
  -d <DOMINIO> \
  -w <WORDLIST_DNS> \
  -o <WORKSPACE>/evidence/<target>/gobuster_dns.txt \
  -t {{gobuster_threads}} \
  --timeout {{gobuster_timeout_seconds}}s
```

#### Modo `tftp` (puerto 69/UDP abierto)
```bash
gobuster tftp \
  -s <TARGET> \
  -w <WORDLIST_WEB_FASE0> \
  -o <WORKSPACE>/evidence/<target>/gobuster_tftp.txt \
  -t {{gobuster_threads}} \
  --timeout {{gobuster_timeout_seconds}}s
```

- Sin JSON nativo (ninguno de los 3 modos) → `.txt` COMPLETO (registrar en el manifest).
- **Probe UDP 69** (aprobado en la Optimización Multiprotocolo): se resuelve desde
  `config/stealth.yaml` (`nmap_udp_probe_*`), nunca hardcodeado (R5). Evidencia con
  `--open -Pn` y `-oG`.

### Step 8 — SSLyze (input: puertos con túnel SSL/TLS detectados por Nmap)

> **Optimización Multiprotocolo (2026-08-31):** SSLyze ya no depende de `web_endpoints.txt`.
> Se detectan los puertos con cifrado desde la salida del Step 3 (`nmap_detailed.json`/`.xml`):
> servicios con `tunnel="ssl"`, nombres de servicio conocidos con TLS (https, imaps, pop3s,
> smtps, ftps, ldaps, sips, telnets …), y puertos bien conocidos TLS (443, 8443, 465, 636,
> 990, 992, 993, 995, 3389-RDP, 5986-WinRM …) entre los puertos abiertos. Se ejecuta SECUENCIAL
> 1 por puerto TLS.

```bash
sslyze <TARGET>:<TLS_PORT> \
  --json_out <WORKSPACE>/evidence/<target>/sslyze_<port>.json \
  --quiet \
  --certinfo
```

- **Flag de JSON verificado en el host (Paso 2 del proyecto — contenedor Docker): `--json_out`** (SSLyze 6.3.1). No usar `--json_outfile`.
- `--regular` **ya no existe en 6.x**: SSLyze corre por defecto el set estándar de scan commands + `--mozilla_config intermediate`. Cada scan command adicional que interese (p.ej. `--tlsv1 --tlsv1_1 --sslv3 --reneg --heartbleed --robot`) se aprueba en Fase 0.
- **Timeout/stealth:** SSLyze 6.x **no expone flag de timeout en CLI**. La variable `sslyze_connect_timeout` de `config/stealth.yaml` se usa como **umbral del Orchestrator** (tiempo de espera antes de declarar fallo y decisión de conexión lenta), NUNCA se hardcodea un timeout en el comando. Si Fase 0 indica WAF/tarpits/red lenta o el scan devuelve timeouts → añadir **`--slow_connection`** (reduce concurrencia; más fiable en redes lentas) y/o `--https_tunnel` si hay proxy aprobado.
- Fallback si `--json_out` fallara: volcar stdout completo a `sslyze_<port>.txt` (sin `--quiet`).
- Si no hay puertos TLS detectables → manifest `skipped_no_tls`.

### Step 9 — IIS Shortname 8.3 (input: `web_on` + firma IIS en `httpx.json`)

> **Integrado 2026-09-07.** El Step 9 solo se ejecuta si hay endpoints web (**`web_on`**) y el
> `httpx.json` del Step 2 reporta la firma `Microsoft-IIS`/`IIS` en el campo `webserver`. En el
> pipeline **no existe** `gobuster_evidence.txt` todavía (eso lo genera `check_gobuster_urls.sh`
> a mano sobre `CLIENTE/`); por eso el descubrimiento IIS en modo pipeline usa `httpx.json` y
> los directorios de `gobuster_<port>.txt` de `evidence/<target>/`.
>
> Si no hay web **o** el servidor no es IIS → `skipped_no_iis` y NO se envía ningún request de
> tilde enumeration.

```bash
python3 scripts/host/step9_iis_shortname_scan.py --ev-dir <WORKSPACE>/evidence/<target> --target <TARGET>
```

- La firma IIS se toma del campo `webserver` de `httpx.json` (`Microsoft-IIS/8.5`, `Microsoft-IIS/10.0`,
  etc.); servers como `gSOAP/2.8`, `Apache-Coyote/1.1` o `nginx` **no** disparan el Step 9.
- Evidencia en `evidence/<target>/`: `iis_shortname_evidence.txt`/`.json` (consumido por el Agente 6),
  `iis_scan_urls.txt` y `iis_shortname_commands_outputs.txt`.
- `--force` no es necesario aquí (el script conserva evidencia previa salvo que sea SIN_CONEXION total;
  en el pipeline las corridas son frescas sobre el ev-dir del target).
- El `httpx.json` puede no incluir el campo `webserver`, o el server puede omitir el header → en
  ese caso Step 9 queda `skipped_no_iis` (no se infiere IIS sin confirmación).

### Step 10 — SMB Enum `step10_smbclient_enum.sh` (input: puertos 139/445)

> **Service-Based Router (igual que Nuclei):** el Step 10 solo se ejecuta si TCP 139 o 445 está
> abierto, decidido desde `open_ports.txt` (Step 1) y confirmado con `nmap_detailed.xml` (Step 3).
> La enumeración es **solo lectura** (null session `-N`), nunca monta ni escribe en el remoto (R2).

```bash
bash scripts/host/step10_smbclient_enum.sh --ev-dir <WORKSPACE>/evidence/<target> --force --no-ping-check
```

- `--force`: el pipeline regenera evidencia en cada corrida (al contrario del no-clobber manual).
- `--no-ping-check`: el target ya respondió en los Steps 1-3 de la misma corrida (no se duplica
  el gate ICMP).
- Evidencia en `evidence/<target>/`: `smbclient_shares.txt` + `smbclient_<share>.txt` (solo si
  login anónimo o shares accesibles; si no, se elimina — ruido sin hallazgo).
- Si no hay 139/445 → `skipped_no_smb` y no se genera tráfico hacia el target.

## 4. Service-Based Routing (Optimización — 2026-08-31)

> Reemplaza el concepto rígido de "bifurcación no-web". El pipeline decide **por step** según
> los servicios detectados (Service-Based Routing), NO aplana los steps 4-8 ante la ausencia
> de web. Herramientas multiprotocolo (Nuclei, Gobuster, SSLyze) se ejecutan según el input
> que aplique a su protocolo; solo Nikto y WhatWeb son estrictamente web.

Tras el post-proceso del Step 2 y el Step 3:

| Step | Herramienta | Condición de ejecución | Si NO aplica → status |
|---|---|---|---|
| 4 | Nuclei | `open_ports.txt` no vacío (**SIEMPRE** si hay ≥1 puerto abierto) | `skipped_no_ports` |
| 5 | Nikto | `web_endpoints.txt` no vacío | `skipped_no_web` |
| 6 | WhatWeb | `web_endpoints.txt` no vacío **y** binario disponible (PATH o `tools/WhatWeb/`) — auto-detección 2026-09-07 | `skipped` / `skipped_no_web` |
| 7 | Gobuster (dir) | `web_endpoints.txt` no vacío | `skipped_no_web` |
| 7 | Gobuster (dns) | target es un **dominio** (no IP cruda) | `skipped_no_domain` |
| 7 | Gobuster (tftp) | **puerto 69/UDP abierto** (probe UDP aprobado) | `skipped_no_tftp` |
| 8 | SSLyze | ≥1 puerto con túnel SSL/TLS (del Step 3) | `skipped_no_tls` |
| 9 | IIS Shortname | `web_on` (hay web) **y** `httpx.json.webserver` contiene `Microsoft-IIS`/`IIS` | `skipped_no_iis` |
| 10 | SMB Enum | TCP 139 ó 445 abierto (`open_ports.txt` o `nmap_detailed.xml`) | `skipped_no_smb` |

- **El pipeline continúa sano ante cualquier `skipped_*`**: no es un error, no aborta el target;
  los hallazgos de servicios no-web del Step 3 y del Step 4 siguen al Agente 3.
- Ejemplo real (DREAMCO-2026, run#2 pre-optimización): targets `10.150.40.155`/`10.150.40.170`
  tenían 6 puertos abiertos (SMB/RDP/RPC) y **Nuclei se saltaba** por no haber web → con esta
  optimización Nuclei DEBE correr contra `open_ports.txt` y detectar las plantillas no-web.

## 5. Error handling

1. Cualquier herramienta falla → **retry 1x** con el mismo comando (mismos parámetros y paths).
2. Si vuelve a fallar → manifest `failed` con el error y **se continúa** con el step siguiente (no aborta el target).
3. **EXCEPCIÓN Step 1**: dos fallos de Nmap port scan → el target se marca **`incomplete`** (sin base de puertos), se saltea el resto y se pasa al siguiente target.

## 6. Manifest por target — `evidence/<target>/manifest.json`

Esquema exacto (igual a design.md):

```json
{
  "target": "10.156.226.156",
  "target_id": "TGT-001",
  "started_at": "<ISO8601>",
  "completed_at": "<ISO8601>",
  "tools_executed": [
    {"step": 1, "tool": "nmap_ports", "status": "success", "output": ["nmap_ports.json", "nmap_ports.xml"]},
    {"step": 2, "tool": "httpx", "status": "success", "output": ["httpx.json"]},
    {"step": 3, "tool": "nmap_detailed", "status": "success", "output": ["nmap_detailed.json", "nmap_detailed.xml", "nmap_detailed.txt"]},
    {"step": 4, "tool": "nuclei", "status": "skipped_no_ports", "output": []},
    {"step": 5, "tool": "nikto", "status": "skipped_no_web", "output": []},
    {"step": 6, "tool": "whatweb", "status": "skipped_no_web", "output": []},
    {"step": 7, "tool": "gobuster", "status": "skipped_no_web", "output": []},
    {"step": 8, "tool": "sslyze", "status": "skipped_no_tls", "output": []},
    {"step": 9, "tool": "iis_shortname", "status": "skipped_no_iis", "output": []},
    {"step": 10, "tool": "smbclient_enum", "status": "skipped_no_smb", "output": []}
  ],
  "out_of_scope_findings": [],
  "errors": []
}
```

- Estados válidos de `status`: `success` | `failed` | `skipped` (WhatWeb sin binario disponible) | `skipped_no_ports` (Nuclei sin puertos) | `skipped_no_web` (Nikto/WhatWeb/Gobuster-dir sin web) | `skipped_no_domain` | `skipped_no_tftp` | `skipped_no_tls` | `skipped_no_iis` (Step 9 sin web o sin firma Microsoft-IIS) | `skipped_no_smb` (Step 10 sin 139/445 abiertos). `tools_executed` contiene SIEMPRE los 10 steps (10 entradas), inclusive los saltados.
- Se genera al terminar el pipeline del target (o al abandonarlo por `incomplete`).