# 🛡️ ReconArgentumAI

> **AI-driven Pentesting** — Pipeline automatizado, multi-agente y guiado por IA para el reconocimiento y análisis de infraestructura autorizada.

ReconArgentumAI es una **plataforma de pentesting de infraestructura** que orquesta un pipeline de *recon* de **12 pasos sobre 11 herramientas** de seguridad, dirigido por un **modelo de IA** (agnóstico del proveedor) a través de Cline / Roo Code o Hermes Agent. El sistema **no explota nada**: produce evidencia completa en disco, planes de explotación documentados y **entregables por target** (`_resumen_vulnerabilidades.doc` + `_resumen_breve.txt`), siguiendo guardrails de scope, stealth y ofuscación inquebrantables.

Pensado para **red teams, auditores y equipos de seguridad ofensiva** que quieren *recon* reproducible, trazable y de bajo ruido, tanto contra **Internet** como contra la **LAN local** — desde una misma herramienta. Opcionalmente, la **Fase 1 (Recon)** puede ejecutarse **sin LLM** de forma totalmente automática (<code>--auto</code>), delegando la orquestación a scripts portables que deciden estados <code>success / failed / skipped_*</code>, retry 1x y delays desde configuración.

---

## 📑 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Arquitectura Multi-Agente](#-arquitectura-multi-agente)
- [Modos de Ejecución](#-modos-de-ejecución)
- [Prerrequisitos](#-prerrequisitos)
- [Guía de Uso Rápido (Quick Start)](#-guía-de-uso-rápido-quick-start)
- [Fase 1: Pipeline de Recon (12 Steps)](#-fase-1-pipeline-de-recon-12-steps)
- [Fase 2: Análisis](#-fase-2-análisis)
- [Fase 4: Consolidación y Entregables](#-fase-4-consolidación-y-entregables)
- [Fase 5: QA Final (Validación Determinista)](#-fase-5-qa-final-validación-determinista)
- [Integración con Hermes Agent](#-integración-con-hermes-agent)
- [Workarounds Conocidos](#-workarounds-conocidos)
- [Troubleshooting](#-troubleshooting)
- [Auditoría Manual (Hydra)](#-auditoría-manual-hydra)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Disclaimer Ético](#-disclaimer-ético)
- [Licencia](#-licencia)

---

## 🚀 Características Principales

Las cinco fases y sus agentes se detallan en [Arquitectura Multi-Agente](#-arquitectura-multi-agente); acá va lo que distingue al proyecto:

| Característica | Detalle |
|---|---|
| 🧮 **Protección de Contexto** | Los agentes miden cada archivo de evidencia (`wc -l` / `wc -c`) y **filtran dinámicamente con `jq`/`grep`** todo lo que supere **200 líneas o 50 KB** antes de ingerirlo. El crudo queda inmutable en disco. |
| 🔒 **Ofuscación automática de credenciales** | Cualquier *password, token, API key o credencial* descubierta se redacta como `***` en los reportes. La evidencia original no se toca. |
| 🕶️ **Sigilo dinámico (stealth)** | Delay entre herramientas (30 s) y entre targets (5 min), rate-limits y timeouts parametrizados desde `config/stealth.yaml`. **Nada hardcodeado**. Adaptación ante WAF/tarpits (sube timeouts, baja rates). |
| 🎯 **Ranking inteligente de CVEs** | Top 3-5 CVEs por servicio con orden estricto: **exploit público verificado > impacto crítico (RCE/auth-bypass/SQLi) > CVSS**. Cada CVE con `rank_reason` documentado. |
| ✅ **QA determinista antes de entregar** | 8 comprobaciones mecánicas **sin LLM** (`scripts/qa_check.py`) validan integridad, consistencia, trazabilidad y ofuscación. Si falla un check crítico, la entrega se bloquea. |
| 📦 **Entregables consolidados por target** | `organize_project.py` ordena la evidencia en `CLIENTE/<target>/` y `make_vuln_report.py` (Agente 6) genera los resúmenes `.doc` + `.txt`, todos con paths absolutos de trazabilidad. |

## 🧩 Arquitectura Multi-Agente

El pipeline se ejecuta en **5 fases**, orchestradas por un **Orchestrator lógico** (un solo LLM con roles diferenciados); cada agente tiene su *spec operativa* en `specs/`:

```
Fase 0  Calibración interactiva
Fase 1  Recon secuencial (DAG 12 steps, 11 herramientas)
Fase 2  Análisis (Agente 3: plan de explotación + Agente 4: CVE research)
Fase 4  Consolidación (organize_project.py + Agente 6: resúmenes doc/txt por target)
Fase 5  QA Final (Agente 7: 8 checks deterministas, validación pre-entrega)
```

> 📌 **Sobre la numeración (Fase 3 / Agente 5):** la numeración conserva los IDs históricos del proyecto. **No existe una Fase 3** ni un Agente 5: la antigua fase de reporter (`make_report.py`) fue retirada del pipeline y su rol lo cubren hoy el **Agente 6** (entregables `.doc`/`.txt` por target) y la **Fase 5** (QA determinista). El Agente 2 fue absorbido por el propio Recon. Los IDs vigentes son **1** (Recon), **3** (Exploitation Planner), **4** (CVE Researcher), **6** (Consolidador de Hallazgos) y **7** (QA Final), más el **Orchestrator** de la Fase 0 — **6 agentes** en total.

| Fase | Agente | Rol | Salida clave | Modo de ejecución |
|---|---|---|---|---|
| **0** | 🎛️ **Orchestrator** | Calibra las herramientas con el usuario (contexto de defensas, puertos, wordlists) y registra solo comandos aprobados. | `config/approved_commands.md` | 🤖 **LLM / Manual** |
| **1** | 🔍 **Agente 1 — Recon Agent** | Ejecuta el DAG lineal de 12 steps (Nmap → HTTPX → Nmap -sC -sV → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze → IIS Shortname → SMB Enum → LDAP Enum → Enum4linux) con delays stealth, service-based routing y retry 1x. | `evidence/<target>/` + `manifest.json` | 🤖 **LLM / Automático sin LLM** (`--auto`) |
| **2** | 🧠 **Agente 3 — Exploitation Planner** | Correlaciona evidencia por servicio con **protección de contexto** y redacta vectores accionables. **Nunca ejecuta exploits.** | `plans/<target_id>_exploitation_plan.md` | 🧠 **Solo LLM** |
| **2** | 🔬 **Agente 4 — CVE Researcher** | Consulta **vulnx** (ProjectDiscovery, fuente única: NVD + Exploit-DB + advisories + CISA KEV), filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`. | `cve_research/<target_id>_cves.json` | 🧠 **Solo LLM** |
| **4** | 📦 **Consolidador físico** | `organize_project.py` copia evidencia a `CLIENTE/<target>/{data,outputs}/` + genera README del proyecto. | `CLIENTE/<target>/{data,outputs}/` + `CLIENTE/README.md` | 🖥️ **Script** |
| **4** | 📝 **Agente 6 — Consolidador de Hallazgos** | Lee solo `CLIENTE/<target>/outputs/`, extrae hallazgos con **cero invención** y genera 2 entregables por target. | `_resumen_vulnerabilidades.doc` + `_resumen_breve.txt` | 🖥️ **Script** (`make_vuln_report.py`) |
| **5** | ✅ **Agente 7 — QA Final** | Ejecuta 10 checks deterministas (integridad, consistencia, trazabilidad, ofuscación, advisory crítico sin reportar) sobre todos los artefactos. **No usa LLM.** | Salida `[PASS]/[FAIL]` por check | 🖥️ **Script** (`qa_check.py`) |

> 💡 **Fase 1 automática (sin LLM):** desde la unificación 2026-09-07, el Agente 1 se ejecuta 100% sin LLM. Los scripts portables (`run_fase1_run3.sh` + `run_target.sh` + `stepN.sh`) recorren `authorized_targets`, ejecutan los 12 steps con delays, deciden estados `success / failed / skipped_*`, implementan retry 1x y generan `manifest.json`.

### Guardrails inquebrantables (R1-R5)
- **R1 Scope estricto** — nunca se escanea fuera de `config/scope.json`.
- **R2 No-ejecución** — los exploits quedan documentados, jamás ejecutados.
- **R3 Secuencial estricto** — una herramienta a la vez, con delays (`delay_between_tools_seconds` y `delay_between_targets_minutes` desde `stealth.yaml`).
- **R4 Evidencia completa** — outputs íntegros e inmutables en disco.
- **R5 Stealth** — todo rate/timeout/thread sale de `config/stealth.yaml`. Nada hardcodeado.

> 🛡️ **Definición canónica:** flujo **Hermes** → [`SOULs/orchestrator/SOUL.md`](SOULs/orchestrator/SOUL.md) § *GUARDRAILS INQUEBRANTABLES (R1-R5)*. Flujo **Cline/Roo Code** → [`.cline/master_prompt.md.template`](.cline/master_prompt.md.template) §2.

---

## 🔀 Modos de Ejecución

El pipeline soporta **tres entornos** que comparten el mismo set de scripts (`scripts/host/`), el mismo runner maestro (`run_fase1_run3.sh`) y la misma estructura de evidencia. Los comandos exactos de cada uno están en la [Guía de Uso Rápido](#-guía-de-uso-rápido-quick-start).

| Aspecto | 🐳 Docker (Kali) | 💻 Host (macOS) | 🖥️ VM Kali |
|---|---|---|---|
| **Para qué** | Targets EXTERNOS (Internet) | LAN local | Targets externos o LAN |
| **Lanzador** | `run_docker.sh` | `run_host.sh` | `bash scripts/host/run_fase1_run3.sh` |
| **Nmap** | `-sS` (root) | `-sT` (sin root) o `-sS` (sudo) — autodetectado | `-sS` (root) |
| **Binario HTTPX** | `httpx-toolkit` | `httpx-pd` → `httpx` (autodetección) | `httpx-toolkit` |
| **WhatWeb** | `apt install whatweb` | `tools/WhatWeb/whatweb` (git clone) | `apt install whatweb` |
| **Wordlists** | `/opt/SecLists/` | `~/Documents/SecLists/` → `tools/seclists_common.txt` | `/opt/SecLists/` o `/usr/share/seclists/` |
| **LAN accesible** | ❌ No (Docker Desktop no ve LAN) | ✅ Sí | ✅ Sí |

> ⚠️ Docker Desktop (macOS) **no ve la LAN local**: ni `-sS` (raw sockets emulados) ni `-sT` (NAT/gRPC) propagan bien el tráfico. Para escanear `192.168.x.x` usá **siempre el Modo Host**.

> 🖥️ `run_host.sh` **no ejecuta el pipeline**: verifica las herramientas y la conectividad, e imprime las instrucciones (y el comando exacto) para lanzarlo. El pipeline se lanza con `run_fase1_run3.sh` (todos los targets) o `run_target.sh <IP>` (uno solo).

## 🧰 Prerrequisitos

| Componente | Docker (Kali) | Host (macOS) | VM Kali |
|---|---|---|---|
| **Contenedor/VM** | Docker Desktop | — | Kali Linux |
| **Orquestador IA** | VS Code + Cline o Roo Code (o Hermes Agent) | ídem | ídem |
| **Nmap · Nuclei · Nikto** | ya incluidos en la imagen | `brew install nmap nikto` + Nuclei por `go install` | `apt install` |
| **Gobuster · jq** | ya incluidos | `brew install gobuster jq` | `apt install` |
| **SSLyze** | ya incluido | `pipx install sslyze` | `pipx install sslyze` |
| **smbclient · ping** | ya incluidos | incluidos en macOS | `apt install smbclient` |
| **ldapsearch** | incluido en macOS (`/usr/bin`) | incluido en macOS | `apt install ldap-utils` |
| **enum4linux-ng** | — | ❌ no aplica (Step 12 solo Linux) | `apt install enum4linux-ng` |
| **HTTPX (probe PD)** | `httpx-toolkit` | `httpx-pd` → `httpx` | `httpx-toolkit` |
| **WhatWeb** | `apt install whatweb` | `git clone` en `tools/WhatWeb` | `apt install whatweb` |
| **SecLists** | `/opt/SecLists` | `~/Documents/SecLists` | `/opt/SecLists` |

- **VS Code** con la extensión **Cline** (o **Roo Code**) — el orquestador de IA. *(Alternativa: Hermes Agent, ver [Integración con Hermes](#-integración-con-hermes-agent).)*
- **Docker Desktop** (solo para el Modo Docker) — la imagen Kali se construye con `docker compose build`.
- **Opcional — IA local:** [**LM Studio**](https://lmstudio.ai) sirviendo un modelo (ej. Qwen/Llama/DeepSeek) en `http://localhost:1234`; desde Cline se apunta a la API local y el pipeline funciona **sin conexión a un proveedor cloud**.
- **Instalación rápida en macOS** (host):

  ```bash
  # Todo en un solo comando
  bash scripts/install_host_tools.sh

  # O manualmente
  brew install nmap nikto gobuster pipx jq
  pipx install sslyze
  git clone --depth 1 https://github.com/urbanadventurer/WhatWeb tools/WhatWeb
  gem install public_suffix -v 4.0.7     # en Ruby 2.6/2.7 debe instalarse primero
  gem install addressable -v 2.8.7       # dependencia de WhatWeb 0.6.4
  ```

  > 💡 Si `gem install addressable` falla con *"public_suffix requires Ruby version >= 3.0"*, instalá primero `public_suffix -v 4.0.7` (compatible con Ruby 2.6/2.7) y reintentá.

- **Wordlists para Gobuster**

  ```bash
  # Opción recomendada (funciona en Docker y VM Kali)
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists

  # Opción macOS
  git clone --depth 1 https://github.com/danielmiessler/SecLists ~/Documents/SecLists
  ```

> ⚠️ **HTTPX** — el binario de probe (ProjectDiscovery) se resuelve con prioridad: **`httpx-toolkit`** (Kali) → **`httpx-pd`** (macOS) → **`httpx`** (solo si es PD real con flag `-l`). NO confundir con el cliente HTTP de Python (`pip install httpx`), que NO sirve para probe.

---

## 🚀 Guía de Uso Rápido (Quick Start)

### 1) Configurá el alcance

Editá `config/scope.json` con los targets **autorizados** del engagement:

```json
{
  "engagement_id": "PENTEST-2026-001",
  "authorized_targets": [
    {"id": "TGT-001", "ip": "10.10.0.10"},
    {"id": "TGT-002", "ip": "192.168.1.50"}
  ],
  "excluded_ips": ["10.10.0.255"],
  "notes": "Solo hosts con autorización expresa."
}
```

### 2) Fase 1 automática (sin LLM) — comandos

```bash
# ── Docker (targets de Internet) ────────────────────────────────────
docker compose build                       # solo la primera vez
./run_docker.sh --auto                     # Fase 1 completa, todos los targets
./run_docker.sh --auto-target 10.10.0.10   # Fase 1 para un solo target
./run_docker.sh --auto --dry-run           # simular (no ejecuta nada)

# ── Host / VM Kali (LAN local o targets accesibles) ─────────────────
bash scripts/host/preflight_run.sh         # verifica tools + wordlists + scope
WORKSPACE=$(pwd) bash scripts/host/run_fase1_run3.sh   # Fase 1 completa
bash scripts/host/run_target.sh 10.10.0.10 # Fase 1 para un solo target
./run_host.sh                              # verifica entorno e imprime instrucciones
```

Cada target ejecuta el DAG de 12 steps con delays de stealth, retry 1x y `skipped_*` automático según servicio detectado. La evidencia queda en `evidence/<target>/` + `manifest.json`. Detalle en [Fase 1](#-fase-1-pipeline-de-recon-12-steps).

### 3) Fase 0 interactiva + Fases 2-5 (con LLM)

Abrí Cline en la raíz del workspace y usá este prompt (o equivalente):

```bash
# Solo la primera vez: el master prompt real es local y se crea desde la plantilla
cp .cline/master_prompt.md.template .cline/master_prompt.md
```

```text
Leé el archivo .cline/master_prompt.md y asumí el rol de Orchestrator
de este pipeline de pentest. Iniciá la Fase 0 (calibración interactiva)
de las herramientas según el scope definido en config/scope.json. Cuando tengas los
comandos aprobados, ejecutá la Fase 1 contra los targets del alcance y
continuá con la Fase 2 (Agente 3: plan de explotación + Agente 4: CVE
research), la Fase 4 (consolidación en CLIENTE/ + Agente 6: resúmenes por
target) y la Fase 5 (QA determinista). Respetá SIEMPRE los
guardrails R1-R5.
```

El Orchestrator te guiará: **aprobás o modificás** cada comando (Fase 0), y luego ejecutás las Fases 1-5 secuencialmente.

> 💡 Si solo te interesa la **evidencia del recon** (Fase 1), el paso **2)** con el runner automático es todo lo que necesitás — sin LLM.
>
> 📄 `.cline/master_prompt.md` es **local** (`.gitignore`): la versión publicada es la plantilla sanitizada `.cline/master_prompt.md.template`, sin IPs ni paths del analista.

## 🔍 Fase 1: Pipeline de Recon (12 Steps)

> Spec operativa: `specs/agent_recon_pipeline.md` · Implementación: `scripts/host/` (`run_fase1_run3.sh` + `run_target.sh` + `step1..step10`)

Es un **DAG lineal** (`1 → 2 → … → 12`) sobre **11 herramientas**, con **service-based routing**: cada paso decide si corresponde ejecutarse según lo detectado por los pasos anteriores. Nunca hay dos herramientas en paralelo contra el mismo target (R3).

| # | Step | Herramienta | Cuándo se ejecuta | Evidencia producida |
|---|---|---|---|---|
| 1 | `nmap_ports` | Nmap | Siempre — el resto depende de esto | `nmap_ports.json` + `open_ports.txt` |
| 2 | `httpx` | HTTPX (PD) | Siempre (detecta servicios web) | `httpx.json` + `web_endpoints.txt` |
| 3 | `nmap_detailed` | Nmap `-sC -sV` | Siempre, sobre los puertos abiertos | `nmap_detailed.xml` / `.json` |
| 4 | `nuclei` | Nuclei | Siempre (multiprotocolo, sobre `open_ports.txt`) | `nuclei.json` |
| 5 | `nikto` | Nikto | Solo si hay web | `nikto_<puerto>.json` |
| 6 | `whatweb` | WhatWeb | Solo si hay web | `whatweb.json` |
| 7 | `gobuster` | Gobuster | `dir` si hay web · `dns` si el target es dominio · `tftp` si UDP/69 | `gobuster_*.txt` |
| 8 | `sslyze` | SSLyze | Solo en los puertos TLS detectados en el Step 3 | `sslyze_<puerto>.json` |
| 9 | `iis_shortname` | IIS Shortname (8.3) | Web **y** firma `Microsoft-IIS` en `httpx.json` | `iis_shortname_*` |
| 10 | `smbclient_enum` | smbclient (null session) | Solo si 139/445 están abiertos | `smbclient_*.txt` |
| 11 | `ldap_enum` | ldapsearch (anónimo; creds opt-in) | Si 389/636/3268/3269 abierto (Linux y macOS) | `ldapsearch.txt` + `ldapsearch_domain.txt` |
| 12 | `enum4linux` | enum4linux-ng (anónimo/solo lectura) | Solo Linux y solo si 139/445 están abiertos | `enum4linux.txt` + `enum4linux.json` |

**Comportamiento del runner:**

- **Retry 1x** por herramienta (`run_retry`) y **lock por target** (`evidence/<target>/.run.lock`) que impide dos corridas concurrentes; un lock de más de 30 min se considera obsoleto y se limpia.
- **Sin puertos abiertos** en el Step 1 → el target queda `"status": "incomplete"`, los steps 2-10 se marcan `skipped_no_ports` y **no se ejecuta nada más** (no se inventan hallazgos).
- Delays de stealth entre herramientas y entre targets, siempre desde `config/stealth.yaml` (R5).

**`manifest.json` — contrato de trazabilidad por target:**

```json
{
  "target": "10.10.0.10",
  "target_id": "TGT-001",
  "started_at": "2026-10-13T19:30:56-03:00",
  "completed_at": "2026-10-13T19:44:43-03:00",
  "tools_executed": [
    {"step": 1, "tool": "nmap_ports", "status": "success",
     "output": ["nmap_ports.json", "open_ports.txt"]},
    {"step": 8, "tool": "sslyze", "status": "skipped_no_tls", "output": []}
  ],
  "out_of_scope_findings": [],
  "errors": []
}
```

`status` es siempre `success`, `failed` o `skipped_*`; `output` enumera los archivos concretos que respaldan cada paso.

---

## 📊 Fase 2: Análisis

### Agente 3 — Exploitation Planner

> Spec: `specs/agent_3_exploitation_plan.md`

Correlaciona servicios, versiones y vulnerabilidades detectadas y produce un **plan de explotación documentado por target**. **Nunca ejecuta exploits**: los comandos quedan solo en el documento. Antes de ingerir cada archivo de evidencia lo mide (`wc -l` / `wc -c`) y, si supera **200 líneas o 50 KB**, lo filtra con `jq`/`grep` (el crudo en disco no se toca).

Salida: `plans/<target_id>_exploitation_plan.md`

### Agente 4 — CVE Research

> Spec: `specs/agent_4_cve_research.md` · Script: `scripts/cve_research_vulnx.py` · Guía: [`scripts/cve_research_vulnx.md`](scripts/cve_research_vulnx.md)

Consulta **vulnx** (ProjectDiscovery) como fuente única: consolida NVD, Exploit-DB, GitHub advisories, vendor bulletins y CISA KEV en una sola API. Filtra **CVSS ≥ 4.0** y rankea Top 3-5 por servicio con orden estricto (exploit público verificado > impacto crítico > CVSS) y `rank_reason` obligatorio por CVE.

Además fusiona **todas** las fuentes de versión de la evidencia (nmap + whatweb + **nikto + httpx + headers de Gobuster**) y aplica una **advisory watchlist local** (`config/advisories/`) para los CVE críticos que vulnx todavía no indexa (hoy: **PHP2Shell** `CVE-2026-109618` / `CVE-2026-109619`), con comparación determinista de versiones y dos guardas anti falso positivo: nunca lista un CVE sobre su propia versión parcheada (watchlist) y **descarta los CVE cuyo fix declarado ya está aplicado en el host** (`filtered_patched_cves[]`, desactivable con `--no-patched-filter`) — esto último elimina el ruido típico de la búsqueda textual de vulnx (consultar `php 8.2.31` devolvía los CVE arreglados *en* 8.2.31).

```bash
python3 scripts/cve_research_vulnx.py \
    --target-id TGT-001 --target-ip 10.10.0.10 \
    --nmap       evidence/10.10.0.10/nmap_detailed.json \
    --whatweb    evidence/10.10.0.10/whatweb.json \
    --nuclei     evidence/10.10.0.10/nuclei.json \
    --evidence-dir evidence/10.10.0.10 \
    --cliente-dir  CLIENTE/10.10.0.10/outputs \
    --advisories config/advisories
```

Salida: `cve_research/<target_id>_cves.json` (incluye `source_omissions` cuando una consulta no responde, `watchlist_matches[]` y `summary.watchlist_cves`). Requiere el binario `vulnx` en el PATH; con `PDCP_API_KEY` se eliminan los rate-limits. Complemento determinista (offline): **`scripts/php2shell_audit.py`** barre toda la evidencia y clasifica cada target contra el advisory (`plans/php2shell_<fecha>.md`). Utilidad auxiliar: `scripts/cves_md.py`.

## 📦 Fase 4: Consolidación y Entregables

### 1) `organize_project.py` — Consolidar evidencia

```bash
python3 scripts/organize_project.py                       # todos los targets
python3 scripts/organize_project.py --target 10.10.0.10   # solo uno
python3 scripts/organize_project.py --scope               # solo targets en scope
python3 scripts/organize_project.py --dry-run             # simular
```

Estructura: `CLIENTE/<target_ip>/{data/ (planes+reportes), outputs/ (evidencia)}` + `README.md`.

Opciones: `--project`, `--target`, `--scope`, `--dry-run`, `--no-clobber`.

### 2) `make_vuln_report.py` — Agente 6 (Consolidador de Hallazgos)

> Spec: `specs/agent_6_consolidador_hallazgos.md` · Guía: [`scripts/make_vuln_report.md`](scripts/make_vuln_report.md)

Lee solo `outputs/` de cada target consolidado. **Cero invención:**

```bash
python3 scripts/make_vuln_report.py --project CLIENTE
```

| Archivo | Contenido |
|---|---|
| `<target_id>_resumen_vulnerabilidades.doc` | Word/LibreOffice (HTML): VULN-00X, título, severidad, fuente, tabla resumen |
| `<target_id>_resumen_breve.txt` | 1 línea/hallazgo: `VULN-00X | título (Severidad) | fuente → ubicación` |

Opciones: `--project`, `--target`, `--dry-run`, `--no-clobber`, `--reset`.

Reglas: solo lo explícito en fuentes, severidad solo si declarada, deduplicación, ofuscación `***`, detección dinámica, acumulación de corridas.

Flujo completo:

```bash
python3 scripts/organize_project.py
python3 scripts/make_vuln_report.py --project CLIENTE
```

---

## ✅ Fase 5: QA Final (Validación Determinista)

**Propósito:** verificación mecánica de todos los artefactos antes de declarar el pipeline completado. Es **100 % determinista**: no usa LLM, solo comprobaciones de sistema de **solo lectura**.

```bash
python3 scripts/qa_check.py     # desde la raíz del proyecto (no acepta argumentos)
```

- **10 checks** (`CK-01` … `CK-10`) sobre alcance (incluye **`target_id` únicos por target**), integridad de outputs, legibilidad de JSON/JSONL, consistencia de CVEs, trazabilidad de los planes, consistencia del reporte, ofuscación de secretos, entregables de la Fase 4 y **advisory crítico sin reportar** (PHP2Shell).
- **Bloqueantes:** `CK-01` (scope/ids), `CK-04` (CVEs), `CK-05` (planes), `CK-07` (secretos) y `CK-10` (advisory crítico) → si fallan, la entrega se detiene. El resto son informativos o permiten continuar con advertencia.
- **Exit code:** `0` (todo PASS) / `1` (al menos un FAIL). Los checks cuyo insumo no existe reportan *"no aplica"* y no fallan.

> 📖 Detalle de cada check, entradas y salidas: [`scripts/qa_check.md`](scripts/qa_check.md). El check `CK-06` valida `reports/final_report.json` **si existe**: ese artefacto es legacy (el generador de reporte final fue retirado con la Fase 3) y su ausencia se considera "no aplica".

## 🤖 Integración con Hermes Agent

ReconArgentumAI puede ejecutarse con **Hermes Agent** (framework de agentes CLI) como motor multi-agente. Los perfiles de comportamiento (SOUL) de los 4 bots del pipeline están versionados en el repo:

```
SOULs/
├── orchestrator/    OrchestratorBot  — coordina las fases 0 → 1 → 2 → 4 → 5
├── recon/           ReconBot         — Fase 1 (escaneo)
├── analyst/         AnalystBot       — F2a (CVEs) + F2b (plan de explotación)
└── reporter/        ReporterBot      — F4 (consolidación) + F5 (QA)
```

### ▶ Instalación (una vez por máquina)

```bash
# Desde la raíz del proyecto clonado
bash scripts/install_souls.sh
```

El script crea **4 perfiles Hermes** (`orchestrator`, `recon`, `analyst`, `reporter`) en `~/.hermes/profiles/` con sus respectivos SOUL.md como system prompt. Detalle: [`SOULs/README.md`](SOULs/README.md).

### 🎛 Orquestación con Hermes

El Orchestrator delega cada fase invocando la CLI de Hermes con el flag `-p <perfil>` (y **no** `--in`, que solo cambia el directorio de trabajo):

```bash
# Ejemplo: delegar Fase 1 al ReconBot
hermes -p recon -z \
  "WORKSPACE=/ruta/local/ReconArgentumAI ... ejecutá run_fase1_run3.sh ..." chat

# El perfil 'recon' ya carga automáticamente el SOUL.md como system prompt
# con la identidad ReconBot y las reglas de ReconArgentumAI.
```

> 📖 Para la secuencia completa de comandos, criterios de éxito y bloqueo, consultá [`RUNBOOK.md`](RUNBOOK.md).

---

## 🧯 Workarounds Conocidos

| Problema | Síntoma | Workaround implementado |
|---|---|---|
| **`-oJ` de Nmap roto en Kali arm64** | `nmap -oJ` no escribe archivo o da error | `step1_nmap_ports.sh` y `step3_nmap_detailed.sh` usan `-oX` (XML) y derivan JSON con `scripts/xml_to_nmap_json.py` |
| **Nikto ignora `-maxtime`** (ESXi, HP embebidos) | Nikto se cuelga >5 min pese a `-maxtime 30s` | `run_target.sh` implementa watchdog: timeout = `nikto_maxtime_seconds × 3`, mata proceso y marca `failed` |
| **Gobuster sin respuesta a dict** | Server no responde → 23.7k timeouts seguidos (horas) | `step7_gobuster.sh` con cutoff `gobuster_max_seconds` (default 180s); mata proceso y marca `failed` |
| **Bash 3.2 (macOS) + `set -u` + array vacío** | `"${ARGS[@]}"` → "unbound variable" | `step8_sslyze.sh` usa `"${ARGS[@]+"${ARGS[@]}"}"` (compatible Bash 3.2/4.x) |
| **httpx.json duplicado por redirects** | HTTPX sigue redirect 80→443, misma URL 2 veces | `step2_httpx.sh` aplica `sort -u` a `web_endpoints.txt` |
| **Certificados TLS autofirmados en Gobuster** | Gobuster `dir` falla en PreRun y cada request se cuelga | `step7_gobuster.sh` agrega `-k` (`--no-tls-validation`) en modo `dir` |
| **Lock por target (R3)** | Dos instancias de `run_target.sh` sobre mismo target | `mkdir` atómico como lock (`$EVID/.run.lock`); 2ª instancia aborta; el lock de +30 min se limpia solo |
| **WhatWeb: `-a` solo acepta 1, 3 o 4** | `-a 2` no existe en v0.6.4 | `step6_whatweb.sh` usa `-a 1` (agresión pasiva) y propaga el exit code real (si falla, el manifest lo registra como `failed`) |
| **`-sT` (Connect) en lugar de `-sS` (SYN)** | En macOS sin root el port scan usa Connect Scan | El tipo de scan se autodetecta por privilegios (`EUID==0` → `-sS`, si no → `-sT`): Docker y VM Kali usan `-sS` |

---

## 🔧 Troubleshooting

### Sanity check: herramientas faltantes

```bash
./run_docker.sh                        # Docker: sanity automático al ejecutar (rebuild 1x si falta algo)
bash scripts/host/preflight_run.sh     # Host: verificación completa de tools + wordlists + scope
```

Si falta algo, la instalación está documentada en [Prerrequisitos](#-prerrequisitos).

### Error: "Imagen sin las tools del Agente 1"

```bash
docker compose build --no-cache
# O simplemente: ./run_docker.sh --auto  (rebuild automático 1x si es necesario)
```

### Error: "R3-FAIL: otro pipeline corriendo sobre X"

Existe un lock activo en `evidence/<target>/.run.lock`.

```bash
ls -la evidence/*/.run.lock 2>/dev/null    # listar locks
rm -rf evidence/*/.run.lock                # limpiar (solo si es seguro)
```

### Target marcado `incomplete`

Ocurre cuando el **Step 1 no encontró ningún puerto abierto** (`open_ports.txt` vacío): el runner marca el target como `incomplete`, salta los steps 2-10 con `skipped_no_ports` y lo documenta en el manifest. **No es un fallo del pipeline.**

Posibles causas:
- El host está apagado, o responde a ARP pero descarta todo el TCP (`filtered` / `host-unreach`).
- Un firewall filtra los 1.000 puertos por defecto del escaneo.

Verificá qué se escaneó y qué estado quedó registrado:

```bash
jq '.tools_executed[] | select(.step==1)' evidence/<IP>/manifest.json
cat evidence/<IP>/nmap_ports.txt       # p. ej. "All 1000 scanned ports ... filtered"
```

> 💡 Por defecto el Step 1 escanea `--top-ports 1000`. Para usar una lista propia de puertos, descomentá `clienteP` en `config/stealth.yaml`; si la variable no existe o está vacía, el script cae automáticamente en `--top-ports 1000`.

### Targets inalcanzables / VPN caída

```bash
for ip in $(jq -r '.authorized_targets[].ip' config/scope.json); do
  ping -c 1 -W 2 "$ip" >/dev/null 2>&1 && echo "OK $ip" || echo "FALLA $ip"
done
```

El pipeline usa `-Pn` y continúa, pero sin conectividad los steps fallarán por timeout.

### Logs de ejecución

```bash
cat evidence/<IP>/_step.log          # Todos los pasos del target
cat evidence/<IP>/_errors.log        # Errores específicos
cat logs/fase1_<IP>.log              # Log del runner maestro
cat logs/hydra.log                   # Log de Hydra (auditoría manual)
```

## 🔐 Auditoría Manual (Hydra)

**Fuera del pipeline.** Bajo demanda del analista.

```bash
bash scripts/hydra_audit.sh --all                              # todos los targets × puertos auditables
bash scripts/hydra_audit.sh 10.10.0.10 ftp                     # target + servicio
bash scripts/hydra_audit.sh 10.10.0.10 ssh -L users.txt -P pass.txt   # wordlists propias
```

- **Scope (R1):** solo targets de `config/scope.json`.
- **Límite:** 25 intentos/servicio (`hydra_max_attempts`).
- **Clasificación:** `VULNERABLE / NO_VULNERABLE / INCONCLUSO`.
- **Log central:** `logs/hydra.log` (acumulativo, nunca se borra).
- **Evidencia:** `evidence/<IP>/hydra_<servicio>_<puerto>.txt` (solo si VULNERABLE).

> ⚠️ Fuerza bruta = tráfico intrusivo. Solo sobre infraestructura autorizada.

> 📖 Guía en lenguaje simple: [`scripts/hydra_audit.md`](scripts/hydra_audit.md).

---

## 📁 Estructura del Proyecto

```
ReconArgentumAI/
├── .cline/
│   ├── master_prompt.md.template     # ⭐ Rol Orchestrator + guardrails R1-R5 (plantilla versionada)
│   └── master_prompt.md              # Copia local (gitignored): cp …template → …md
├── .clinerules/workflows/            # Workflows OpenSpec (opsx-propose / apply / archive / sync…)
├── SOULs/                            # ⭐ Perfiles Hermes de los 4 agentes (SOUL.md + README)
│   ├── orchestrator/ ─ recon/ ─ analyst/ ─ reporter/
├── config/
│   ├── scope.json (no versionado)    # ⭐ Alcance autorizado del engagement
│   ├── scope.json.template           # Plantilla versionada del alcance
│   ├── stealth.yaml                  # Timeouts/rates/delays (fuente única R5)
│   ├── advisories/                   # ⭐ Watchlist local de CVEs críticos recientes (PHP2Shell)
│   └── approved_commands.md          # Comandos aprobados en Fase 0 (no versionado)
├── specs/                            # Specs operativas de cada agente
├── openspec/
│   ├── config.yaml                   # Config OpenSpec
│   ├── specs/                        # 7 capacidades (specs formales sincronizadas)
│   └── changes/                      # Changes activos + archive/
├── tools/
│   ├── *_help.md                     # Help files verificados (9)
│   └── WhatWeb/                      # Binario local WhatWeb
├── scripts/
│   ├── README.md                     # Guía de entrada (lenguaje simple)
│   ├── host/                         # Pipeline Fase 1: steps 1-12, runners, preflight
│   ├── cve_research_vulnx.py         # ⭐ Agente 4 (CVE Research con vulnx + watchlist)
│   ├── php2shell_audit.py            # ⭐ Auditoría offline PHP2Shell (alimenta CK-10)
│   ├── organize_project.py           # ⭐ Fase 4 — consolidación
│   ├── make_vuln_report.py           # ⭐ Agente 6 — entregables por target
│   ├── qa_check.py                   # ⭐ Agente 7 — QA determinista
│   ├── install_souls.sh              # Instala los 4 perfiles Hermes
│   ├── hydra_audit.sh · cleanup_engagement.sh · install_host_tools.sh
│   └── cves_md.py · xml_to_nmap_json.py · check_gobuster_urls.sh …
├── evidence/                         # Evidencia cruda por target (+ manifest.json)
├── plans/                            # Planes de explotación
├── cve_research/                     # CVEs rankeados por target
├── reports/                          # Reportes legacy (el generador fue retirado con la Fase 3)
├── logs/                             # Logs de ejecución
├── CLIENTE/                          # ⭐ Consolidación por target (gitignored)
├── RUNBOOK.md                        # ⭐ Manual operativo del Orchestrator
├── Dockerfile                        # Kali + 11 herramientas + SecLists
├── docker-compose.yml
└── run_docker.sh / run_host.sh       # Lanzadores (Docker / host macOS)
```

> 🔒 `config/scope.json`, `approved_commands.md`, `evidence/`, `plans/`, `cve_research/`, `reports/`, `logs/` y `CLIENTE/` **no se versionan** (contienen datos del engagement). Sí se versionan las plantillas `*.template`.

---

## ⚠ Disclaimer Ético

**ReconArgentumAI es una herramienta de seguridad ofensiva diseñada EXCLUSIVAMENTE para uso en infraestructuras donde se cuenta con autorización expresa por escrito.**

- ⚖️ **Usá esta herramienta únicamente** sobre sistemas y redes que sean de tu propiedad, o para los que tengas un contrato/permiso formal de *pentest* (scope firmado).
- 🚫 El pipeline **nunca ejecuta exploits** — solo documenta vectores. Aun así, el *recon* genera tráfico de red y puede ser detectado.
- 📜 **Legalidad** — el escaneo o prueba de seguridad sin autorización puede constituir un delito (Computer Fraud and Abuse Act, Código Penal local, etc.). El autor y los colaboradores **no son responsables** del uso indebido.
- 🤝 **Ética** — la intención es *asegurar* infraestructura, no dañarla. Ante un hallazgo, priorizá la divulgación responsable al propietario del sistema.

> 🔐 **En caso de duda: no escanees.**

---

## 📄 Licencia

Uso académico y profesional con autorización expresa. Ver los archivos de configuración y specs del proyecto para los detalles de operación.
