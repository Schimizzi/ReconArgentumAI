# 🛡️ ReconArgentumAI

> **AI-driven Pentesting** — Pipeline automatizado, multi-agente y guiado por IA para el reconocimiento y análisis de infraestructura autorizada.

[![Pipeline](https://img.shields.io/badge/Pipeline-10%20Steps%20·%2011%20Tools-6f42c1)]() [![Agentes](https://img.shields.io/badge/Agentes-6-brightgreen)]() [![IA-Agnóstico](https://img.shields.io/badge/IA-Agnóstico-blue)]() [![Kali-Ready](https://img.shields.io/badge/Kali-Ready-00a859)]()

ReconArgentumAI es una **plataforma de pentesting de infraestructura** que orquesta un pipeline de *recon* de 10 pasos sobre 11 herramientas de seguridad, dirigido por un **modelo de IA** (agnóstico del proveedor) a través de Cline / Roo Code. El sistema **no explota nada**: produce evidencia completa en disco, planes de explotación documentados y reportes profesionales, siguiendo guardrails de scope, stealth y ofuscación inquebrantables.

Pensado para **red teams, auditores y equipos de seguridad ofensiva** que quieren *recon* reproducible, trazable y de bajo ruido, tanto contra **Internet** como contra la **LAN local** — desde una misma herramienta. Opcionalmente, la **Fase 1 (Recon)** puede ejecutarse **sin LLM** de forma totalmente automática (<code>--auto</code>), delegando la orquestación a scripts portables que deciden estados <code>success / failed / skipped_*</code>, retry 1x y delays desde configuración.

---

## 📑 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Arquitectura Multi-Agente](#-arquitectura-multi-agente)
- [Prerequisitos](#-prerequisitos)
- [Instalación Rápida](#-instalación-rápida)
- [Modos de Ejecución](#-modos-de-ejecución)
- [Fase 1: Pipeline de Recon (10 Steps)](#-fase-1-pipeline-de-recon-10-steps)
- [Fase 2: Análisis](#-fase-2-análisis)
- [Fase 3: Reporte Final](#-fase-3-reporte-final)
- [Fase 4: Consolidación y Entregables](#-fase-4-consolidación-y-entregables)
- [Auditoría Manual (Hydra)](#-auditoría-manual-hydra)
- [Workarounds Conocidos](#-workarounds-conocidos)
- [Troubleshooting](#-troubleshooting)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Disclaimer Ético](#-disclaimer-ético)
- [Licencia](#-licencia)

---

## 🚀 Características Principales

| Característica | Detalle |
|---|---|
| 🧠 **Pipeline multi-agente guiado por IA** | 6 agentes especializados (Orchestrator, Recon, Exploitation Planner, CVE Researcher, Reporter, Consolidador de Hallazgos) coordinados por un master prompt. **Agnóstico del modelo**: funciona con Cline, Roo Code y cualquier LLM. La Fase 1 puede ejecutarse **sin LLM** en modo automático (`--auto`). |
| 🧮 **Protección de Contexto** | Los agentes miden cada archivo de evidencia (`wc -l` / `wc -c`) y **filtran dinámicamente con `jq`/`grep`** todo lo que supere **200 líneas o 50 KB** antes de ingerirlo. El crudo queda inmutable en disco. |
| 🔒 **Ofuscación automática de credenciales** | Cualquier *password, token, API key o credencial* descubierta se redacta como `***` en los reportes. La evidencia original no se toca. |
| 🕶️ **Sigilo dinámico (stealth)** | Delay entre herramientas (30s) y entre targets (5 min), rate-limits y timeouts parametrizados desde `config/stealth.yaml`. **Nada hardcodeado**. Adaptación automática ante WAF/tarpits (sube timeouts, baja rates). |
| 🎯 **Ranking inteligente de CVEs** | Top 3-5 CVEs por servicio con orden estricto: **exploit público verificado > impacto crítico (RCE/auth-bypass/SQLi) > CVSS**. Cada CVE con `rank_reason` documentado. |
| 📦 **Tres modos de ejecución** | **Docker** (contenedor Kali, para Internet), **Host** (macOS nativo, para LAN local) y **VM Kali** (nativa). Todos comparten el mismo set de scripts portables. |
| 🤖 **Fase 1 automática sin LLM** | El Agente 1 se ejecuta con `run_docker.sh --auto` o `run_host.sh → run_fase1_run3.sh` sin necesidad de un modelo de lenguaje. Estados `success / failed / skipped_*`, retry 1x y delays desde configuración. |
| ✅ **Informe dual + individual** | `final_report.md`/`.json` consolidado + `reports/<target_id>_report.md`/`.json` por target, todos con JSON validado y paths absolutos de trazabilidad. |

---

## 🧩 Arquitectura Multi-Agente

El pipeline se ejecuta en **5 fases orchestradas por un Orchestrator lógico** (un solo LLM con roles diferenciados), cada agente con una *spec operativa* propia en `specs/`:

```
Fase 0  Calibración interactiva
Fase 1  Recon secuencial (DAG 10 steps, 11 tools)
Fase 2  Análisis (Agente 3: plan de explotación + Agente 4: CVE research)
Fase 3  Reporte final (Agente 5: MD + JSON)
Fase 4  Consolidación (organize_project.py + Agente 6: resúmenes doc/txt por target)
```

| Fase | Agente | Rol | Salida clave | Modo de ejecución |
|---|---|---|---|---|
| **0** | 🎛️ **Orchestrator** | Calibra las herramientas con el usuario (contexto de defensas, puertos, wordlists) y registra solo comandos aprobados. | `config/approved_commands.md` | 🤖 **LLM / Manual** |
| **1** | 🔍 **Recon Agent** | Ejecuta el DAG lineal de 10 steps (Nmap → HTTPX → Nmap -sC -sV → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze → IIS Shortname → SMB Enum) con delays stealth, service-based routing y retry 1x. | `evidence/<target>/` + `manifest.json` | 🤖 **LLM / Automático sin LLM** (`--auto`) |
| **2** | 🧠 **Agente 3 — Exploitation Planner** | Correlaciona evidencia por servicio con **protección de contexto** y redacta vectores accionables. **Nunca ejecuta exploits.** | `plans/<target_id>_exploitation_plan.md` | 🧠 **Solo LLM** |
| **2** | 🔬 **Agente 4 — CVE Researcher** | Consulta NVD / Exploit-DB, filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`. | `cve_research/<target_id>_cves.json` | 🧠 **Solo LLM** |
| **3** | 📋 **Agente 5 — Reporter** | Consolida manifests + planes + CVEs en informe dual + reportes individuales. | `reports/final_report.*` + `reports/<target_id>_report.*` | 🖥️ **Script** (`make_report.py`) |
| **4** | 📦 **Consolidador físico** | `organize_project.py` copia evidencia a `CLIENTE/<target>/{data,outputs}/` + genera README del proyecto. | `CLIENTE/<target>/{data,outputs}/` + `CLIENTE/README.md` | 🖥️ **Script** |
| **4** | 📝 **Agente 6 — Consolidador de Hallazgos** | Lee solo `CLIENTE/<target>/outputs/`, extrae hallazgos con **cero invención** y genera 2 entregables por target. | `_resumen_vulnerabilidades.doc` + `_resumen_breve.txt` | 🖥️ **Script** (`make_vuln_report.py`) |

> 💡 **Fase 1 automática (sin LLM):** desde la unificación 2026-09-07, el Agente 1 se ejecuta 100% sin LLM. Los scripts portables (`run_fase1_run3.sh` + `run_target.sh` + `stepN.sh`) recorren `authorized_targets`, ejecutan los 10 steps con delays, deciden estados `success / failed / skipped_*`, implementan retry 1x y generan `manifest.json`.

### Guardrails inquebrantables (R1-R5)
- **R1 Scope estricto** — nunca se escanea fuera de `config/scope.json`.
- **R2 No-ejecución** — los exploits quedan documentados, jamás ejecutados.
- **R3 Secuencial estricto** — una herramienta a la vez, con delays (`delay_between_tools_seconds` y `delay_between_targets_minutes` desde `stealth.yaml`).
- **R4 Evidencia completa** — outputs íntegros e inmutables en disco.
- **R5 Stealth** — todo rate/timeout/thread sale de `config/stealth.yaml`. Nada hardcodeado.

---

## 🔀 Modos de Ejecución

El pipeline soporta **tres entornos** que comparten el mismo set de scripts (`scripts/host/`), el mismo runner maestro (`run_fase1_run3.sh`) y la misma estructura de evidencia.

| Aspecto | 🐳 Docker (Kali) | 💻 Host (macOS) | 🖥️ VM Kali |
|---|---|---|---|
| **Para qué** | Targets EXTERNOS (Internet) | LAN local | Targets externos o LAN |
| **Lanzador** | `run_docker.sh` | `run_host.sh` | `bash scripts/host/run_fase1_run3.sh` |
| **Nmap** | `-sS` (root) | `-sT` (sin root) o `-sS` (sudo) — autodetectado | `-sS` (root) |
| **Binario HTTPX** | `httpx-toolkit` | `httpx-pd` → `httpx` (autodetección) | `httpx-toolkit` |
| **WhatWeb** | `apt install whatweb` | `tools/WhatWeb/whatweb` (git clone) | `apt install whatweb` |
| **Wordlists** | `/opt/SecLists/` | `~/Documents/SecLists/` → `tools/seclists_common.txt` | `/opt/SecLists/` o `/usr/share/seclists/` |
| **LAN accesible** | ❌ No (Docker Desktop no ve LAN) | ✅ Sí | ✅ Sí |

> ⚠️ Docker Desktop (macOS) **no ve la LAN local**: ni `-sS` (raw sockets emulados) ni `-sT` (NAT/gRPC) propagan bien el tráfico. Para escanear `192.168.x.x` usa **siempre el Modo Host**.

### Fase 1 automática sin LLM

```bash
# Docker — todos los targets
./run_docker.sh --auto
# Docker — solo un target
./run_docker.sh --auto-target 10.10.10.1
# Docker — simular (no ejecuta nada)
./run_docker.sh --auto --dry-run

# Host — todos los targets
WORKSPACE=$(pwd) bash scripts/host/run_fase1_run3.sh
# Host — solo un target
bash scripts/host/run_target.sh 10.10.10.1
# Host — verificación previa de tools
bash scripts/host/preflight_run.sh

# Host (LAN) — verifica tools + conectividad e imprime instrucciones
./run_host.sh
```

### Modo con LLM (Orchestrator en Cline / Roo Code)

```bash
# 1. Abrir Cline en el workspace
# 2. Verificar config/scope.json con targets autorizados
# 3. Prompt: "Iniciá la Fase 1 del pipeline en MODO DOCKER" (o MODO HOST)
```

---

## ⚙️ Prerrequisitos

- **VS Code** con la extensión **Cline** (o **Roo Code**) — el orquestador de IA.
- **Docker Desktop** (para el Modo Docker) — la imagen Kali se construye con `docker compose build`.
- **Opcional — IA local:** [**LM Studio**](https://lmstudio.ai) sirviendo un modelo (ej. Qwen/Llama/DeepSeek) en `http://localhost:1234`; desde Cline se apunta a la API local y el pipeline funciona **sin conexión a un proveedor cloud**.
- **Herramientas del sistema:** ver tabla de prerequisitos arriba. Instalación rápida en macOS:

  ```bash
  # Todo en un solo comando
  bash scripts/install_host_tools.sh
  
  # O manualmente
  brew install nmap nikto gobuster pipx jq
  pipx install sslyze
  git clone --depth 1 https://github.com/urbanadventurer/WhatWeb tools/WhatWeb
  gem install addressable -v 2.8.7
  ```

> ⚠️ **HTTPX** — el binario de probe (ProjectDiscovery) se resuelve con prioridad: **`httpx-toolkit`** (Kali) → **`httpx-pd`** (macOS) → **`httpx`** (solo si es PD real con flag `-l`). NO confundir con el cliente HTTP de Python (`pip install httpx`), que NO sirve para probe.

### Wordlists para Gobuster

```bash
# Opción recomendada (funciona en Docker y VM Kali)
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists

# Opción macOS
git clone --depth 1 https://github.com/danielmiessler/SecLists ~/Documents/SecLists
```

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

### 2) Fase 1 automática (sin LLM)

```bash
# Docker — construir imagen (solo la primera vez)
docker compose build

# Docker — Fase 1 completa para todos los targets
./run_docker.sh --auto

# Docker — solo un target específico
./run_docker.sh --auto-target 10.10.0.10

# Host — verificar tools primero
bash scripts/host/preflight_run.sh

# Host — Fase 1 completa para todos los targets
WORKSPACE=$(pwd) bash scripts/host/run_fase1_run3.sh

# Host — solo un target
bash scripts/host/run_target.sh 10.10.0.10
```

Cada target ejecuta el DAG de 10 steps con delays de stealth, retry 1x y `skipped_*` automático según servicio detectado. La evidencia queda en `evidence/<target>/` + `manifest.json`.

### 3) Fase 0 interactiva + Fases 2-4 (con LLM)

Abrí Cline en la raíz del workspace y usá este prompt (o equivalente):

```text
Leé el archivo .cline/master_prompt.md y asumí el rol de Orchestrator
de este pipeline de pentest. Iniciá la Fase 0 (calibración interactiva)
de las herramientas según el scope definido en config/scope.json. Cuando tengas los
comandos aprobados, ejecutá la Fase 1 contra los targets del alcance y
continuá con la Fase 2 (Agente 3: plan de explotación + Agente 4: CVE
research), la Fase 3 (Agente 5: reporte final) y la Fase 4 (consolidación
en CLIENTE/ + Agente 6: resúmenes por target). Respetá SIEMPRE los
guardrails R1-R5.
```

El Orchestrator te guiará: **aprobás o modificás** cada comando (Fase 0), y luego ejecutás
las Fases 1-4 secuencialmente.

> 💡 Si solo te interesa la **evidencia del recon** (Fase 1), el paso **2)** con el runner
> automático es todo lo que necesitás — sin LLM.

---

## 🛠️ Workarounds Conocidos

| Problema | Síntoma | Workaround implementado |
|---|---|---|
| **`-oJ` de Nmap roto en Kali arm64** | `nmap -oJ` no escribe archivo o da error | `step1_nmap_ports.sh` y `step3_nmap_detailed.sh` usan `-oX` (XML) y derivan JSON con `scripts/xml_to_nmap_json.py` |
| **Nikto ignora `-maxtime`** (ESXi, HP embebidos) | Nikto se cuelga >5 min pese a `-maxtime 30s` | `run_target.sh` implementa watchdog: timeout = `nikto_maxtime_seconds × 3`, mata proceso y marca `failed` |
| **Gobuster sin respuesta a dict** | Server no responde → 23.7k timeouts seguidos (horas) | `step7_gobuster.sh` con cutoff `gobuster_max_seconds` (default 180s); mata proceso y marca `failed` |
| **Bash 3.2 (macOS) + `set -u` + array vacío** | `"${ARGS[@]}"` → "unbound variable" | `step8_sslyze.sh` usa `"${ARGS[@]+"${ARGS[@]}"}"` (compatible Bash 3.2/4.x) |
| **httpx.json duplicado por redirects** | HTTPX sigue redirect 80→443, misma URL 2 veces | `step2_httpx.sh` aplica `sort -u` a `web_endpoints.txt` |
| **Certificados TLS autofirmados en Gobuster** | Gobuster `dir` falla en PreRun y cada request se cuelga | `step7_gobuster.sh` agrega `-k` (`--no-tls-validation`) en modo `dir` |
| **Lock por target (R3)** | Dos instancias de `run_target.sh` sobre mismo target | `mkdir` atómico como lock (`$EVID/.run.lock`); 2ª instancia aborta |
| **WhatWeb: `-a` solo acepta 1, 3 o 4** | `-a 2` no existe en v0.6.4 | `step6_whatweb.sh` usa `-a 1` (agresión pasiva) |

---

## 🔧 Troubleshooting

### Sanity check: herramientas faltantes

```bash
# Docker — sanity automático al ejecutar
./run_docker.sh

# Host — verificación completa
bash scripts/host/preflight_run.sh
```

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
cat logs/hydra.log                   # Log de Hydra
```

### Target marcado `incomplete`

Si el Step 1 falla dos veces → target `incomplete`. Posibles causas:
- Host apagado o ruta caída.
- Firewall bloqueando Nmap.
- `clienteP` vacío o incorrecto en `stealth.yaml`.

```bash
jq '.tools_executed[] | select(.step==1)' evidence/<IP>/manifest.json
```

### Port scan usa `-sT` (Connect) y esperaba `-sS` (SYN)

El scan type se autodetecta: `EUID==0` → `-sS`, si no → `-sT`. En macOS sin sudo siempre será `-sT`. En Docker y VM Kali (root) será `-sS`.

---

## 📊 Fase 2: Análisis

### Agente 3 — Exploitation Planner

> Spec: `specs/agent_3_exploitation_plan.md`

Correlaciona servicios, versiones y vulnerabilidades detectadas y produce un **plan de explotación documentado por target**. **Nunca ejecuta exploits**: los comandos quedan solo en el documento.

Salida: `plans/<target_id>_exploitation_plan.md`

### Agente 4 — CVE Research

> Spec: `specs/agent_4_cve_research.md`

Busca CVEs en NVD / Exploit-DB / Packet Storm para los servicios detectados. Filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`.

Salida: `cve_research/<target_id>_cves.json`

Scripts auxiliares: `scripts/nvd_query.py`, `scripts/nvd_cve_detail.py`, `scripts/cves_md.py`.

## 📊 Fase 3: Reporte Final — Agente 5

> Spec: `specs/agent_5_reporter.md`

`scripts/host/make_report.py` lee la evidencia de todos los targets y genera:

```bash
python3 scripts/host/make_report.py
```

| Archivo | Contenido |
|---|---|
| `reports/final_report.md` + `.json` | Informe consolidado: portada, resumen, metodología, sección por target, matriz de riesgo, ofuscación `***` |
| `reports/<target_id>_report.md` + `.json` | Informe individual con paths absolutos |

Reglas: trazabilidad absoluta, ofuscación de credenciales, JSON validado, escala CVSS.

---

## 📦 Fase 4: Consolidación y Entregables

### 1) `organize_project.py` — Consolidar evidencia

```bash
python3 scripts/organize_project.py                                    # todos los targets
python3 scripts/organize_project.py --target 10.10.0.10                # solo uno
python3 scripts/organize_project.py --scope                            # solo targets en scope
python3 scripts/organize_project.py --dry-run                          # simular
```

Estructura: `CLIENTE/<target_ip>/{data/ (planes+reportes), outputs/ (evidencia)}` + `README.md`.

Opciones: `--project`, `--target`, `--scope`, `--dry-run`, `--no-clobber`.

### 2) `make_vuln_report.py` — Agente 6 (Consolidador de Hallazgos)

> Spec: `specs/agent_6_consolidador_hallazgos.md`

Lee solo `outputs/` de cada target consolidado. **Cero invención**:

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

## 🔐 Auditoría Manual — Hydra

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

---

## 📁 Estructura del Proyecto

```
ReconArgentumAI/
├── .cline/
│   └── master_prompt.md              # Rol Orchestrator + guardrails R1-R5
├── .clinerules/workflows/            # Workflows OpenSpec
├── config/
│   ├── scope.json                    # ⭐ Alcance autorizado
│   ├── stealth.yaml                  # Timeouts/rates (fuente única R5)
│   └── approved_commands.md          # Comandos aprobados Fase 0
├── specs/                            # Specs operativas de cada agente
├── openspec/
│   ├── config.yaml                   # Config OpenSpec
│   ├── specs/                        # Specs formales sincronizadas
│   └── changes/                      # Changes activos/archivados
├── tools/
│   ├── *_help.md                     # Help files verificados
│   └── WhatWeb/                      # Binario local WhatWeb
├── scripts/
│   ├── README.md                     # Guía de entrada (lenguaje simple)
│   ├── host/                         # Pipeline Fase 1 (steps 1-10, run_target, etc.)
│   ├── organize_project.py           # ⭐ Consolidación
│   ├── make_vuln_report.py           # ⭐ Agente 6
│   ├── hydra_audit.sh / cleanup_engagement.sh / install_host_tools.sh
│   └── nvd_query.py / cves_md.py / check_gobuster_urls.sh …
├── evidence/                         # Evidencia cruda por target
├── plans/                            # Planes de explotación
├── cve_research/                     # CVEs rankeados
├── reports/                          # Informes finales
├── logs/                             # Logs de ejecución
├── CLIENTE/                          # ⭐ Consolidación (gitignored)
├── Dockerfile                        # Kali + 11 tools + SecLists
├── docker-compose.yml
└── run_docker.sh / run_host.sh       # Lanzadores
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