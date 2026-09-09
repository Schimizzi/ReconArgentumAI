# 🛡️ ReconArgentumAI

> **AI-driven Pentesting** — Pipeline automatizado, multi-agente y guiado por IA para el reconnaissance y análisis de infraestructura autorizada.

[![Pipeline](https://img.shields.io/badge/Pipeline-10%20Steps%20·%209%20Tools-6f42c1)]() [![Agentes](https://img.shields.io/badge/Agentes-6-brightgreen)]() [![IA-Agnóstico](https://img.shields.io/badge/IA-Agnóstico-blue)]()

ReconArgentumAI es una **plataforma de pentesting de infraestructura** que orquesta un pipeline de *recon* de 10 pasos sobre 9 herramientas de seguridad, dirigido por un **modelo de IA** (agnóstico del proveedor) a través de Cline / Roo Code. El sistema **no explota nada**: produce evidencia completa en disco, planes de explotación documentados y reportes profesionales, siguiendo guardrails de scope, stealth y ofuscación inquebrantables.

Pensado para **red teams, auditores y equipos de seguridad ofensiva** que quieren *recon* reproducible, trazable y de bajo ruido, tanto contra **Internet** como contra la **LAN local** — desde una misma herramienta.

---

## 🚀 Características Principales

| Característica | Detalle |
|---|---|
| 🧠 **Pipeline multi-agente guiado por IA** | 6 agentes especializados (Orchestrator, Recon, Agente 3 Exploitation Planner, Agente 4 CVE Researcher, Agente 5 Reporter, Agente 6 Consolidador de Hallazgos) coordinados por un master prompt. **Agnóstico del modelo**: funciona con Cline, Roo Code y cualquier LLM capaz de seguir instrucciones. |
| 🧮 **Protección de Contexto** | Los agentes miden cada archivo de evidencia (`wc -l` / `wc -c`) y **filtran dinámicamente con `jq`/`grep`** todo lo que supere **200 líneas o 50 KB** antes de ingerirlo. El crudo queda inmutable en disco. |
| 🔒 **Ofuscación automática de credenciales** | Cualquier *password, token, API key o credencial* descubierta se redacta como `***` en los reportes. La evidencia original no se toca. |
| 🕶️ **Sigilo dinámico (stealth)** | Delay entre herramientas (30s) y entre targets (5 min), rate-limits y timeouts parametrizados desde `config/stealth.yaml`. **Nada hardcodeado**. Adaptación automática ante WAF/tarpits (sube timeouts, baja rates). |
| 🎯 **Ranking inteligente de CVEs** | Top 3-5 CVEs por servicio con orden estricto: **exploit público verificado > impacto crítico (RCE/auth-bypass/SQLi) > CVSS**. Cada CVE con `rank_reason` documentado. |
| 📦 **Doble modo de ejecución** | **Docker** (Kali) para targets en Internet + **Host** (macOS nativo) para la LAN local — con scripts y ayuda por modo. |
| ✅ **Informe dual + individual** | `final_report.md`/`.json` consolidado + `reports/<target_id>_report.md`/`.json` por target, todos con JSON validado y paths absolutos de trazabilidad. |
---

## 🧩 Arquitectura Multi-Agente

El pipeline se ejecuta en **5 fases orchestradas por un Orchestrator lógico** (un solo LLM con roles diferenciados), cada agente con una *spec operativa* propia en `specs/`:

```
Fase 0  Calibración interactiva
Fase 1  Recon secuencial (DAG 10 steps)
Fase 2  Análisis (Agente 3: plan de explotación + Agente 4: CVE research)
Fase 3  Reporte final (Agente 5: MD + JSON)
Fase 4  Consolidación (organize_project.py + Agente 6: resúmenes doc/txt por target)
```

| Fase | Agente | Rol | Salida clave | Modo de ejecución |
|---|---|---|---|---|
| **0** | 🎛️ **Orchestrator** | Calibra las 9 herramientas con el usuario (contexto de defensas, rango de puertos, wordlists) y registra **solo comandos aprobados**. | `config/approved_commands.md` | 🤖 **LLM / Manual** |
| **1** | 🔍 **Recon Agent** | Ejecuta el DAG lineal 1→8 (Nmap → HTTPX → Nmap detallado → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze) con delays de stealth, bifurcación **no-web** y retry 1x. | `evidence/<target>/` + `manifest.json` | 🧰 **Manual (script)** |
| **1** | ⚠️ **Incidentes de run** (*) | Interpretar fallos de herramientas, hosts out-of-scope, VPN/WAF/tarpits, re-scans y decisiones de retry/cutoff. Los scripts no deciden: lo hace el operador. | `logs/` + manifests actualizados | 🤖 **LLM / Manual** |
| **2** | 📋 **Agente 3 — Exploitation Planner** | Correlaciona evidencia por servicio con **protección de contexto** y redacta vectores accionables (pre-condiciones, pasos, PoC, detección, rollback). **Nunca ejecuta exploits.** | `plans/<target_id>_exploitation_plan.md` | 🧠 **Solo LLM** |
| **2** | 🧬 **Agente 4 — CVE Researcher** | Consulta NVD / GitHub Advisories / Exploit-DB (timeout 30s/fuente), filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`. | `cve_research/<target_id>_cves.json` | 🧠 **Solo LLM** |
| **3** | 📝 **Agente 5 — Reporter** | Consolida todo en informe dual + reportes individuales, con **ofuscación de credenciales** y validación JSON estricta. | `reports/final_report.*` + `reports/<target_id>_report.*` | 🧰 **Manual (script)** |
| **4** | 📂 **Agente 6 — Consolidador de Hallazgos** | Independiente de `organize_project.py`: analiza SOLO `CLIENTE/<target>/outputs/` y extrae/reorganiza hallazgos de las herramientas en 2 entregables por target (`.doc` + `.txt`) con **cero invención**, deduplicación y ofuscación. Nueva evidencia copiada a `outputs/` se detecta en la siguiente corrida. | `CLIENTE/<target>/<target_id>_resumen_vulnerabilidades.doc` + `..._resumen_breve.txt` | 🧰 **Manual (script)** |

> ### 🎮 ¿Cuándo interviene el LLM? (modos de ejecución)
>
> - 🧠 **Solo LLM** — el paso **no tiene automatización**: requiere criterio de un agente de IA
>   (o un analista humano siguiendo la spec). No se completa solo con scripts. Los scripts de
>   consulta (ej. `scripts/nvd_*.py`) son **auxiliares**: el entregable final lo arma el agente.
> - 🧰 **Solo manual (script)** — el paso está **automatizado por un script** y **no requiere LLM**:
>   un humano lo lanza con el comando indicado. Los Agentes 5 y 6 están *materializados* en scripts
>   (`scripts/host/make_report.py`, `scripts/make_vuln_report.py`, `scripts/organize_project.py`).
> - 🤖 **LLM / Manual** — puede hacerlo **cualquiera de los dos**: el LLM (modo recomendado por el
>   master prompt) o un humano técnico con criterio; la elección la toma el operador del pipeline.
>
> (*) No es un agente formal: es la interpretación humana/LLM de los incidentes que los scripts
> registran pero no deciden.

> 🔢 **Numeración de agentes:** los roles de análisis y reporte tienen spec operativa propia
> en `specs/` (`agent_3_exploitation_plan.md`, `agent_4_cve_research.md`, `agent_5_reporter.md`,
> `agent_6_consolidador_hallazgos.md`). El **Orchestrator** (Fase 0) y el **Recon Agent**
> (Fase 1) se gobiernan por el master prompt `.cline/master_prompt.md` y no tienen número propio.

### Guardrails inquebrantables (R1-R5)
- **R1 Scope estricto** — nunca se escanea fuera de `config/scope.json`.
- **R2 No-ejecución** — los exploits quedan documentados, jamás ejecutados.
- **R3 Secuencial estricto** — una herramienta a la vez, con delays.
- **R4 Evidencia completa** — outputs íntegros e inmutables en disco.
- **R5 Stealth** — todo rate/timeout/thread sale de `config/stealth.yaml`.
---

## 🔀 Modos de Ejecución

La arquitectura es **híbrida**: dos modos según el objetivo, con el mismo pipeline, la misma evidencia y los mismos reportes.

| | 🐳 **Modo Docker** | 💻 **Modo Host** |
|---|---|---|
| **Cuándo** | Targets en **Internet** (o VM Kali con Docker) | **LAN local** (la red del equipo macOS) |
| **Lanzador** | `./run_docker.sh` | `./run_host.sh` |
| **Binarios** | Contenedor **Kali Linux** (imagen `recon-argento-stepai`) | Herramientas nativas del host (Homebrew / pipx / git clone) |
| **Nmap** | `-sS` (SYN, requiere raw sockets / `NET_RAW`; contenedor corre como root) | `-sT` (TCP Connect, sin permisos root) — autodetectado |
| **Scripts** | `scripts/host/` (mismo set unificado que Host/VM) | `scripts/host/` (en el host) |
| **Wordlist** | `/opt/SecLists/...` → `/usr/share/seclists/...` → fallback `tools/seclists_common.txt` | `/usr/share/seclists/...` → `~/Documents/SecLists/...` → `tools/seclists_common.txt` |

> ⚠️ **Importante:** Docker Desktop (macOS) **no ve la LAN local del host** (ni con `-sS` ni con `-sT`, por el backend de red emulado). Para escanear `192.168.x.x` usa **siempre el Modo Host**.
>
> 🤖 **Sin LLM (solo Agente 1):** ambos modos pueden ejecutar la **Fase 1 completa de forma automática** con el mismo runner `scripts/host/run_fase1_run3.sh` (ver abajo). El LLM solo se necesita para Fase 0 (calibración) y Fases 2-4 (análisis/reportes).

```bash
# Modo Docker — Agente 1 (Fase 1) automático, SIN LLM
./run_docker.sh --auto                 # todos los targets de scope.json
./run_docker.sh --auto-target 1.2.3.4  # solo esa IP

# Modo Docker (session interactiva dentro del contenedor Kali)
docker compose run --rm pentest bash

# Modo Host — Agente 1 (Fase 1) automático, SIN LLM
bash scripts/host/run_fase1_run3.sh    # todos los targets de scope.json
bash scripts/host/run_target.sh 1.2.3.4  # solo esa IP

# Modo Host (verifica tools + conectividad e imprime instrucciones)
./run_host.sh 192.168.8.1
```

> 🔐 **Auditoría manual de credenciales (Hydra)** — opcional y **fuera del pipeline**:
> `bash scripts/hydra_audit.sh --all` recorre todos los targets autorizados × sus
> puertos auditables (21/ftp, 22/ssh, 6379/redis, 1433/mssql, …) con **máximo 25
> intentos por servicio** (solo evidencia), clasifica cada uno como
> `VULNERABLE / NO_VULNERABLE / INCONCLUSO` y deja todo el verbose en
> `logs/hydra.log`. Requiere `hydra` (host: `brew install hydra`; ya va en el Dockerfile).
> Ver [`scripts/hydra_audit.md`](scripts/hydra_audit.md).
---

## ⚙️ Prerrequisitos

- **VS Code** con la extensión **Cline** (o **Roo Code**) — el orquestador de IA.
- **Docker Desktop** (para el Modo Docker) — la imagen Kali se construye con `docker compose build`.
- **Opcional — IA local:** [**LM Studio**](https://lmstudio.ai) sirviendo un modelo (ej. Qwen/Llama/DeepSeek) en `http://localhost:1234`; desde Cline se apunta a la API local y el pipeline funciona **sin conexión a un proveedor cloud**.
- **Host tools (solo Modo Host):**
  ```bash
  brew install nmap nikto gobuster pipx
  pipx install sslyze
  # WhatWeb (no tiene fórmula): git clone + gem
  git clone --depth 1 https://github.com/urbanadventurer/WhatWeb tools/WhatWeb
  gem install addressable -v 2.8.7
  ```
  > Instalación automatizada: `./scripts/install_host_tools.sh`
- **⚠️ HTTPX (probe web, ProjectDiscovery) — el binario se resuelve con prioridad `httpx-toolkit` → `httpx-pd` → `httpx`:**
  - **Kali Linux:** el binario PD se llama **`httpx-toolkit`** (Kali renombra los binarios PD que chocan con paquetes Python). Es el PRINCIPAL.
  - **macOS / contenedor Docker:** el pipeline usa **`httpx-pd`** (en macOS vive en `go/bin/httpx-pd`). El contenedor Docker instala **`httpx-toolkit`** vía apt (mismo paquete de Kali que la VM: `sudo apt install httpx-toolkit`).
  - ⚠️ **No confundir:** el comando `httpx` del PATH (ej. el de Conda/Python `pip install httpx`) es el **cliente HTTP de Python** y **NO sirve** para probe. La resolución prioriza `httpx-toolkit`/`httpx-pd` justamente para evitar caer en él.
  - Verificación: `preflight_run.sh` y `run_host.sh` aceptan `httpx-toolkit` **o** `httpx-pd` (y `httpx` solo si es PD real) y reportan cuál se usa.

---

## 🚀 Guía de Uso Rápido (Quick Start)

### 1) Configurá el alcance

Editá `config/scope.json` con los targets **autorizados** del engagement:

```json
{
  "engagement_id": "PENTEST-2025-001",
  "authorized_targets": [
    {"id": "TGT-001", "ip": "10.10.0.10"},
    {"id": "TGT-002", "ip": "192.168.1.50"}
  ],
  "excluded_ips": ["10.10.0.255"],
  "notes": "Solo hosts con autorización expresa."
}
```

### 2) Levantá el entorno

```bash
# Construir la imagen Docker (solo la primera vez)
docker compose build

# Shell interactivo dentro del entorno Kali (Modo Docker)
docker compose run --rm pentest bash
```

Para el **Modo Host** simplemente verificá las herramientas con `./run_host.sh <gateway>` (imprime el estado y las instrucciones). En ambos modos podés correr el **Agente 1 de forma 100% automática (sin LLM)** — es el mismo runner:

```bash
# (a) Modo Docker (targets de Internet o VM Kali con Docker)
./run_docker.sh --auto                 # Fase 1 completa, todos los targets de scope.json
# (b) Modo Host o VM Kali (LAN local o directo en la VM)
bash scripts/host/preflight_run.sh     # verifica tools + wordlists (opcional pero recomendado)
bash scripts/host/run_fase1_run3.sh    # Fase 1 completa, todos los targets de scope.json
```

Cada target corre el DAG de 10 steps (Nmap → HTTPX → Nmap detallado → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze → IIS → SMB) con delays de stealth, retry 1x y `skipped_*` automático según el servicio detectado. La evidencia queda en `evidence/<target>/` + `manifest.json`.

### 3) (Opcional) Fase 0 interactiva con Cline + Fases 2-4 (análisis/reportes)

Para la **calibración interactiva (Fase 0)** y el **análisis posterior (Fases 2-4)** sí se usa un LLM. Abrí Cline **en la raíz del workspace** y pegá este prompt (o el equivalente en tu idioma):

```text
Leé el archivo .cline/master_prompt.md y asumí el rol de Orchestrator
de este pipeline de pentest. Iniciá la Fase 0 (calibración interactiva)
de las 9 herramientas (Nmap, HTTPX, Nuclei, Nikto, WhatWeb, Gobuster,
SSLyze, IIS Shortname 8.3, SMB Enum) según el scope definido en config/scope.json. Cuando tengas los
comandos aprobados, ejecutá la Fase 1 contra los targets del alcance y
continuá con la Fase 2 (Agente 3: plan de explotación + Agente 4: CVE
research), la Fase 3 (Agente 5: reporte final) y la Fase 4 (consolidación
en CLIENTE/ + Agente 6: resúmenes por target). Respetá SIEMPRE los
guardrails R1-R5.
```

El Orchestrator te guiará: primero **aprobás o modificás** cada comando (Fase 0), y luego el DAG corre **secuencialmente** generando toda la evidencia y los reportes.

> 💡 Si solo te interesa la **evidencia del recon** (Fase 1) sin análisis/reportes, el paso **2)** con el runner automático es todo lo que necesitás — no hace falta ningún LLM.

---

## 📁 Estructura del Proyecto

```
ReconArgentumAI/
├── .cline/
│   └── master_prompt.md          # Rol del Orchestrator + guardrails R1-R5 + formato de respuesta
├── config/
│   ├── scope.json                # ⭐ Alcance autorizado (engagement, targets, excluded_ips)
│   ├── stealth.yaml              # Timeouts, rates, threads y delays (fuente única R5)
│   └── approved_commands.md      # ÚNICA fuente de comandos que Fase 1 puede ejecutar
├── specs/
│   ├── agent_recon_pipeline.md   # Spec operativa Fase 1 (DAG 10 steps, modos, bifurcación no-web)
│   ├── agent_3_exploitation_plan.md  # Spec Agente 3 (protección de contexto, plan documentado)
│   ├── agent_4_cve_research.md   # Spec Agente 4 (ranking CVEs, fuentes, rank_reason)
│   ├── agent_5_reporter.md       # Spec Agente 5 (informe dual + individual, ofuscación)
│   └── agent_6_consolidador_hallazgos.md  # Spec Agente 6 (resúmenes .doc/.txt, cero invención)
├── tools/
│   ├── nmap_help.md … sslyze_help.md  # Help files verificados (flags reales de cada tool)
│   └── WhatWeb/                  # Binario local de WhatWeb (no hay fórmula Homebrew)
├── scripts/
│   ├── organize_project.py       # ⭐ Consolidación final: CLIENTE/<target>/{data,outputs}
│   ├── make_vuln_report.py       # ⭐ Agente 6: resúmenes .doc + .txt por target (solo lee outputs/)
│   ├── cves_md.py                # Convierte cve_research/*.json → *_cves.md (Markdown)
│   ├── step*.sh                  # Steps 1-8 (Modo Docker)
│   └── host/
│       ├── run_fase1_run3.sh     # Runner maestro Fase 1 (scope + delays + logs)
│       ├── run_target.sh         # Orquestador por target (DAG 10 steps + manifest)
│       ├── make_report.py        # ⭐ Agente 5: reporte dual + individuales
│       ├── detect_tls_ports.py   # Detecta puertos TLS para SSLyze
│       ├── step9_iis_shortname_scan.py # ⭐ Step 9: IIS Shortname 8.3 (ev-dir / CLIENTE)
│       ├── step10_smbclient_enum.sh     # ⭐ Step 10: SMB enum null session (ev-dir / CLIENTE)
│       └── step*.sh              # Steps 1-10 (Modo Host, incl. step7_udp_probe.sh)
├── evidence/
│   └── <target>/
│       ├── manifest.json         # Estado por target + outputs + out_of_scope
│       ├── nmap_ports.*           # Evidencia cruda (inmutable, R4)
│       ├── open_ports.txt · web_endpoints.txt
│       └── nuclei.json · nikto_*.json · whatweb.json · gobuster_*.txt …
├── plans/
│   └── <target_id>_exploitation_plan.md   # Planes documentados (nunca ejecutados)
├── cve_research/
│   └── <target_id>_cves.json     # CVEs rankeados con rank_reason
├── reports/
│   ├── final_report.md / .json   # Informe consolidado del engagement
│   └── <target_id>_report.md / .json   # Informes individuales por target
├── logs/
│   └── fase1_run.md              # Bitácora de ejecución del Orchestrator
├── openspec/
│   ├── specs/                    # Main specs consolidadas (sync formal)
│   └── changes/archive/          # Changes completados archivados
├── CLIENTE/                      # ⭐ Consolidación final (gitignored, nombre fijo)
│   └── <target_ip>/
│       ├── data/                 # 2 Markdown: *exploitation_plan.md · *report.md
│       └── outputs/              # 1 evidencia por escaneo (nmap solo .xml)
├── Dockerfile · docker-compose.yml
└── run_docker.sh · run_host.sh   # Lanzadores de entorno
```

---

## 📊 Informes del Engagement — Agente 5 (Reporter, Fase 3)

> Spec operativa completa: `specs/agent_5_reporter.md`.

`scripts/host/make_report.py` es el **Agente 5 (Reporter)**. Al completar las Fases 1-2, lee la
evidencia de **todos los targets** del engagement —`evidence/<target>/manifest.json`, planes en
`plans/` y CVE research en `cve_research/`— y genera el informe consolidado del engagement más
un informe individual por cada target:

```bash
python3 scripts/host/make_report.py
```

| Archivo generado | Contenido |
|---|---|
| `reports/final_report.md` / `.json` | Informe **consolidado del engagement**: portada (engagement, fechas, scope), resumen ejecutivo, alcance y metodología (tools + stealth), una sección por target (servicios, vulnerabilidades, CVEs, plan de explotación, config insegura), matriz de riesgo global y recomendaciones ordenadas. JSON machine-readable validado. |
| `reports/<target_id>_report.md` / `.json` | Informe **individual por target** con las mismas tablas que su sección en el unificado y paths absolutos de su evidencia. |

Reglas del Agente 5:
- **Trazabilidad por paths absolutos**: cada hallazgo referencia su fuente en `evidence/`, `plans/` y `cve_research/` (sección *Anexos* del MD y `evidence_paths{}` / `exploitation_plan_ref` del JSON).
- **Ofuscación `***`** de passwords/tokens/API keys/credenciales en MD y JSON; la evidencia cruda en disco **no se modifica**.
- **JSON validado**: `final_report.json` y los individuales se validan (`python3 -m json.tool` / `jq empty`) antes de considerarse generados; los contadores de `summary` deben coincidir con los `targets[]` reales.
- **Coherencia individual ↔ unificado**: cada `<target_id>_report.json` comparte `target_id`/`ip`/`risk_score`/`cves` con su entrada homónima en `final_report.json`.
- **Targets `incomplete` / `no_web`**: se documentan igualmente, con listas vacías y su `risk_score` correspondiente.
- **Escala de riesgo por CVSS**: 9+ = CRÍTICO, 7+ = ALTO, 4+ = MEDIO, resto = BAJO.

---

## 📦 Consolidación final del engagement

Al terminar los escaneos y el informe del engagement (Fases 1–3 completas), dos pasos de la **Fase 4** ordenan la información por target y generan los entregables para el cliente.

### 1) Ordenar la evidencia en `CLIENTE/` — `organize_project.py`

```bash
python3 scripts/organize_project.py
```

Genera `CLIENTE/` (nombre fijo, y por eso **excluido en `.gitignore`**) con esta estructura:

```
CLIENTE/
├── README.md                      # Índice de targets + totales (servicios, vulns, CVEs)
├── 10.10.10.152/
│   ├── data/                      # 2 documentos en Markdown (para pegar en un lector de .md)
│   │   ├── 10.10.10.152_exploitation_plan.md
│   │   └── 10.10.10.152_report.md
│   ├── outputs/                   # UNA evidencia por escaneo (nombres originales)
│   ├── 10.10.10.152_resumen_vulnerabilidades.doc   # ← generado por el Agente 6
│   └── 10.10.10.152_resumen_breve.txt              # ← generado por el Agente 6
└── 10.156.244.50/ …               # (igual por cada target escaneado)
```

Opciones útiles:

| Opción | Descripción |
|---|---|
| `--project NOMBRE` | Usar otro nombre de directorio en vez de `CLIENTE`. |
| `--target IP` | Consolidar solo ese target (repetible). |
| `--scope` | Procesar únicamente targets registrados en `config/scope.json`. |
| `--dry-run` | Previsualizar la estructura sin crear nada. |
| `--no-clobber` | No sobrescribir archivos existentes en `CLIENTE/`. |

El consolidado no modifica la evidencia cruda (`evidence/`), ni los planes (`plans/`),
ni el CVE research (`cve_research/`): copia conservando los nombres originales, con
**una sola evidencia por escaneo** (nmap solo el `.xml`; quedan fuera `nmap_ports.*`,
`manifest.json`, intermedios, logs y `*_report.json`). El JSON de `cve_research/` se
usa **solo para contar CVEs** en el `README.md` del proyecto: **no** se renderiza
`<target_id>_cves.md`.

### 2) Generar los resúmenes por target — Agente 6 (Consolidador de Hallazgos, Fase 4)

`scripts/make_vuln_report.py` es el **Agente 6 (Consolidador de hallazgos)**, un script
**independiente** que NO modifica `organize_project.py`. Lee **solo** el directorio
`outputs/` de cada target ya consolidado y extrae/reorganiza los hallazgos de las
herramientas (nuclei, nikto, sslyze, nmap, gobuster, evidencia manual)
para generar **dos entregables por target**:

```bash
python3 scripts/make_vuln_report.py
```

| Archivo generado | Contenido |
|---|---|
| `<target_id>_resumen_vulnerabilidades.doc` | Documento compatible con **Word/LibreOffice** (HTML): cabecera con fecha y total, una sección por hallazgo (**`VULN-00X` literal**, título, severidad, descripción extraída de fuente, 📁 Fuente + ↳ Ubicación, espacio en blanco para pegar evidencia) y **tabla resumen** final. El `VULN-00X` no se numera automáticamente: lo asignás a mano al agregar o quitar hallazgos. |
| `<target_id>_resumen_breve.txt` | **Una línea por hallazgo**: `VULN-00X | <título> (Severidad: X) | <archivo fuente> → <ubicación>`. |

Opciones:

| Opción | Descripción |
|---|---|
| `--project NOMBRE` | Directorio destino (default: `CLIENTE`). Debe tener por cada target una carpeta `outputs/`. |
| `--target IP` | Generar solo para ese target (repetible). |
| `--dry-run` | Previsualizar qué archivos de `outputs/` se analizan y qué reportes se generarían (no crea nada). |
| `--no-clobber` | No sobrescribir reportes ya existentes. |

Reglas inquebrantables del Agente 6 (**cero invención**, ver `specs/agent_6_consolidador_hallazgos.md`):
- Solo se extrae lo que está **explícitamente** en los archivos de `outputs/`; PDF/cabeceras sin hallazgos se omiten.
- La **severidad** se registra solo si el archivo fuente la declara (`severity: high`, `CVSS 9.8`, …). Si no → `Severidad: No declarada en fuente`.
- **Deduplicación**: si dos fuentes reportan lo mismo, el hallazgo aparece una vez con la fuente de más detalle y las demás referenciadas en la ubicación.
- **Ofuscación** `***` de credenciales/tokens; los archivos fuente NO se modifican.
- **Detección dinámica**: cualquier archivo nuevo que copies a `outputs/` (p.ej. `evidencia.md` o un nuevo `.json` con hallazgos) se considera automáticamente en la siguiente corrida, sin tocar el script.
- Confirmación de entrega: `✅ <target> analizado. N hallazgos extraídos…` (o `⚠️ … No se generaron reportes` si N = 0).

¿Cómo correr el flujo completo del entregable?

```bash
# 1) Consolidar la evidencia en CLIENTE/ (organiza copias + genera README)
python3 scripts/organize_project.py

# 2) Agente 6: generar los resúmenes .doc y .txt por target (lee outputs/ de CLIENTE/)
python3 scripts/make_vuln_report.py --project CLIENTE
```

---

## ⚠️ Disclaimer Ético

**ReconArgentumAI es una herramienta de seguridad ofensiva diseñada EXCLUSIVAMENTE para uso en infraestructuras donde se cuenta con autorización expresa por escrito.**

- ⚖️ **Usá esta herramienta únicamente** sobre sistemas y redes que sean de tu propiedad, o para los que tengas un contrato/permiso formal de *pentest* (scope firmado).
- 🚫 El pipeline **nunca ejecuta exploits** — solo documenta vectores. Aun así, el *recon* genera tráfico de red y puede ser detectado.
- 📜 **Legalidad** — el escaneo o prueba de seguridad sin autorización puede constituir un delito (Computer Fraud and Abuse Act, Código Penal local, etc.). El autor y los colaboradores **no son responsables** del uso indebido.
- 🤝 **Ética** — la intención es *asegurar* infraestructura, no dañarla. Ante un hallazgo, priorizá la divulgación responsable al propietario del sistema.

> 🔐 **En caso de duda: no escanees.**

---

## 📄 Licencia

Uso académico y profesional con autorización expresa. Ver los archivos de configuración y specs del proyecto para los detalles de operación.