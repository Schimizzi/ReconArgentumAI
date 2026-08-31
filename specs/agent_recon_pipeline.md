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

## 0bis. Modos de ejecución (arquitectura híbrida)

| Modo | Cuándo | Lanzador | Nmap | Binarios |
|---|---|---|---|---|
| **DOCKER** | targets EXTERNOS (Internet) | `run_docker.sh` → `docker compose run --rm pentest` | `-sS` (raw sockets, requiere caps) | dentro del contenedor Kali; scripts en `scripts/` |
| **HOST** | LAN local (macOS) | `run_host.sh` | **`-sT`** (TCP Connect; no requiere root) | directo en el host; scripts en `scripts/host/` |

- ⚠️ **Docker Desktop (macOS) NO ve la LAN local del host**: ni `-sS` (raw sockets emulados)
  ni `-sT` (NAT/gVisor) propagan bien el tráfico → para escanear `192.168.8.0/24` usar SIEMPRE **MODO HOST**.
- Ambos modos comparten el mismo DAG (8 steps, 7 tools), variables de `config/stealth.yaml`,
  workaround `-oJ` (ver Step 1) y el sub-schema de evidencia (`evidence/<target>/…`, `manifest.json`).
- Modo HOST: en `scripts/host/*.sh` cada step resuelve `{{...}}` de stealth.yaml con los valores
  actuales (documentados en el propio script). La wordlist de Gobuster en HOST se descarga
  (cache en `tools/seclists_common.txt`); en DOCKER usa `/opt/SecLists/.../common.txt`.

## 1. DAG lineal — 8 steps, 7 herramientas

| Step | Herramienta | Input | Output en `evidence/<target>/` | Post-proceso |
|---|---|---|---|---|
| 1 | Nmap (port scan) | target (scope.json) | `nmap_ports.xml`, `nmap_ports.json`, `nmap_ports.txt` | extraer abiertos → `open_ports.txt` |
| 2 | HTTPX (probe web) | `open_ports.txt` | `httpx.json` (JSONL completo) | extraer URLs http/https → `web_endpoints.txt` |
| 3 | Nmap (-sC -sV) | `open_ports.txt` (solo abiertos) | `nmap_detailed.json`, `nmap_detailed.xml`, `nmap_detailed.txt` | — |
| 4 | Nuclei | `web_endpoints.txt` | `nuclei.json` (JSONL) | — |
| 5 | Nikto | `web_endpoints.txt` (secuencial por endpoint) | `nikto_<port>.json` (o `.html`+`.txt`) | — |
| 6 | WhatWeb | `web_endpoints.txt` | `whatweb.json` (o `.txt`) | — |
| 7 | Gobuster/Dirsearch | `web_endpoints.txt` + wordlist Fase 0 | `gobuster_<port>.txt` | — |
| 8 | SSLyze | solo puertos `https://` | `sslyze_<port>.json` (o `.txt`) | — |

Orden SIEMPRE lineal `1→2→3→…→8`, sin paralelismo (R3 del master_prompt).

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

- Rango/puertos a escanear (`--top-ports 1000`): definido y aprobado en Fase 0.
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

> ⚠️ El pipeline corre dentro del contenedor Docker (Paso 2 del proyecto). El binario de
> ProjectDiscovery se invoca como **`httpx-pd`** (symlink `httpx-pd → httpx` verificado; ambos
> funcionan). NUNCA confundir con el cliente HTTP de Python `httpx` (vive en el host, no en el contenedor).

```bash
httpx-pd -l <WORKSPACE>/evidence/<target>/open_ports.txt \
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

### Step 4 — Nuclei (input: `web_endpoints.txt`) — solo si hay web

```bash
nuclei -l <WORKSPACE>/evidence/<target>/web_endpoints.txt \
  -o <WORKSPACE>/evidence/<target>/nuclei.json \
  -jsonl \
  -rl {{nuclei_rate_limit}} \
  -timeout {{nuclei_timeout_seconds}} \
  -bs {{nuclei_bulk_size}} \
  -s critical,high,medium
```

- Templates: **set default de nuclei** (descarga automática en el 1er run) filtrado por severidad
  con `-s critical,high,medium` (aprobado en Fase 0; reemplaza `-es info` y excluye `unknown`).
- `-bs {{nuclei_bulk_size}}` hosts en paralelo por template, resuelto de `stealth.yaml` (Fase 0: `nuclei_bulk_size: 5`; default nuclei = 25).

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

### Step 7 — Gobuster/Dirsearch (input: `web_endpoints.txt` → SECUENCIAL, 1 por endpoint)

Wordlist: path aprobado en Fase 0.

```bash
gobuster dir \
  -u <URL> \
  -w <WORDLIST_FASE0> \
  -o <WORKSPACE>/evidence/<target>/gobuster_<port>.txt \
  -t {{gobuster_threads}} \
  --timeout {{gobuster_timeout_seconds}}s \
  -s 200,204,301,307,401,403 \
  -x txt,bak,old,zip
```

- Sin JSON nativo → `.txt` COMPLETO (registrar en el manifest).

### Step 8 — SSLyze (input: solo puertos `https://` → SECUENCIAL, 1 por puerto)

```bash
sslyze <TARGET>:<HTTPS_PORT> \
  --json_out <WORKSPACE>/evidence/<target>/sslyze_<port>.json \
  --quiet \
  --certinfo
```

- **Flag de JSON verificado en el host (Paso 2 del proyecto — contenedor Docker): `--json_out`** (SSLyze 6.3.1). No usar `--json_outfile`.
- `--regular` **ya no existe en 6.x**: SSLyze corre por defecto el set estándar de scan commands + `--mozilla_config intermediate`. Cada scan command adicional que interese (p.ej. `--tlsv1 --tlsv1_1 --sslv3 --reneg --heartbleed --robot`) se aprueba en Fase 0.
- **Timeout/stealth:** SSLyze 6.x **no expone flag de timeout en CLI**. La variable `sslyze_connect_timeout` de `config/stealth.yaml` se usa como **umbral del Orchestrator** (tiempo de espera antes de declarar fallo y decisión de conexión lenta), NUNCA se hardcodea un timeout en el comando. Si Fase 0 indica WAF/tarpits/red lenta o el scan devuelve timeouts → añadir **`--slow_connection`** (reduce concurrencia; más fiable en redes lentas) y/o `--https_tunnel` si hay proxy aprobado.
- Fallback si `--json_out` fallara: volcar stdout completo a `sslyze_<port>.txt` (sin `--quiet`).

## 4. Bifurcación no-web (OBLIGATORIA)

Tras el post-proceso del Step 2:

- **`web_endpoints.txt` VACÍO** (target sin servicios web) → los Steps **4, 5, 6, 7 y 8** se **OMITEN automáticamente**: cada uno se registra en el manifest con estado **`skipped_no_web`** y `output: []`. El pipeline **continúa sano**: no es un error, no se marca `failed`, no se aborta el target; los hallazgos de servicios no-web del Step 3 siguen normalmente por el flujo hacia el Agente 3.
- **`web_endpoints.txt` con al menos una URL** → se ejecutan los Steps 4-8 normalmente sobre esos endpoints.

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
    {"step": 4, "tool": "nuclei", "status": "skipped_no_web", "output": []},
    {"step": 5, "tool": "nikto", "status": "skipped_no_web", "output": []},
    {"step": 6, "tool": "whatweb", "status": "skipped_no_web", "output": []},
    {"step": 7, "tool": "gobuster", "status": "skipped_no_web", "output": []},
    {"step": 8, "tool": "sslyze", "status": "skipped_no_web", "output": []}
  ],
  "out_of_scope_findings": [],
  "errors": []
}
```

- Estados válidos de `status`: `success` | `failed` | `skipped_no_web`. `tools_executed` contiene SIEMPRE los 8 steps (8 entradas), inclusive los saltados.
- Se genera al terminar el pipeline del target (o al abandonarlo por `incomplete`).