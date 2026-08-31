# 🛡️ ReconArgentumAI

> **AI-driven Pentesting** — Pipeline automatizado, multi-agente y guiado por IA para el reconnaissance y análisis de infraestructura autorizada.

[![Pipeline](https://img.shields.io/badge/Pipeline-8%20Steps%20·%207%20Tools-6f42c1)]() [![Agentes](https://img.shields.io/badge/Agentes-5-brightgreen)]() [![IA-Agnóstico](https://img.shields.io/badge/IA-Agnóstico-blue)]()

ReconArgentumAI es una **plataforma de pentesting de infraestructura** que orquesta un pipeline de *recon* de 8 pasos sobre 7 herramientas de seguridad, dirigido por un **modelo de IA** (agnóstico del proveedor) a través de Cline / Roo Code. El sistema **no explota nada**: produce evidencia completa en disco, planes de explotación documentados y reportes profesionales, siguiendo guardrails de scope, stealth y ofuscación inquebrantables.

Pensado para **red teams, auditores y equipos de seguridad ofensiva** que quieren *recon* reproducible, trazable y de bajo ruido, tanto contra **Internet** como contra la **LAN local** — desde una misma herramienta.

---

## 🚀 Características Principales

| Característica | Detalle |
|---|---|
| 🧠 **Pipeline multi-agente guiado por IA** | 5 agentes especializados (Orchestrator, Recon, Exploitation Planner, CVE Researcher, Reporter) coordinados por un master prompt. **Agnóstico del modelo**: funciona con Cline, Roo Code y cualquier LLM capaz de seguir instrucciones. |
| 🧮 **Protección de Contexto** | Los agentes miden cada archivo de evidencia (`wc -l` / `wc -c`) y **filtran dinámicamente con `jq`/`grep`** todo lo que supere **200 líneas o 50 KB** antes de ingerirlo. El crudo queda inmutable en disco. |
| 🔒 **Ofuscación automática de credenciales** | Cualquier *password, token, API key o credencial* descubierta se redacta como `***` en los reportes. La evidencia original no se toca. |
| 🕶️ **Sigilo dinámico (stealth)** | Delay entre herramientas (30s) y entre targets (5 min), rate-limits y timeouts parametrizados desde `config/stealth.yaml`. **Nada hardcodeado**. Adaptación automática ante WAF/tarpits (sube timeouts, baja rates). |
| 🎯 **Ranking inteligente de CVEs** | Top 3-5 CVEs por servicio con orden estricto: **exploit público verificado > impacto crítico (RCE/auth-bypass/SQLi) > CVSS**. Cada CVE con `rank_reason` documentado. |
| 📦 **Doble modo de ejecución** | **Docker** (Kali) para targets en Internet + **Host** (macOS nativo) para la LAN local — con scripts y ayuda por modo. |
| ✅ **Informe dual + individual** | `final_report.md`/`.json` consolidado + `reports/<target_id>_report.md`/`.json` por target, todos con JSON validado y paths absolutos de trazabilidad. |
---

## 🧩 Arquitectura Multi-Agente

El pipeline se ejecuta en **4 fases orchestradas por un Orchestrator lógico** (un solo LLM con roles diferenciados), cada agente con una *spec operativa* propia en `specs/`:

```
Fase 0  Calibración interactiva
Fase 1  Recon secuencial (DAG 8 steps)
Fase 2  Análisis (plan de explotación + CVE research)
Fase 3  Reporte final (MD + JSON)
```

| Fase | Agente | Rol | Salida clave |
|---|---|---|---|
| **0** | 🎛️ **Orchestrator** | Calibra las 7 herramientas con el usuario (contexto de defensas, rango de puertos, wordlists) y registra **solo comandos aprobados**. | `config/approved_commands.md` |
| **1** | 🔍 **Recon Agent** | Ejecuta el DAG lineal 1→8 (Nmap → HTTPX → Nmap detallado → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze) con delays de stealth, bifurcación **no-web** y retry 1x. | `evidence/<target>/` + `manifest.json` |
| **2** | 📋 **Exploitation Planner** | Correlaciona evidencia por servicio con **protección de contexto** y redacta vectores accionables (pre-condiciones, pasos, PoC, detección, rollback). **Nunca ejecuta exploits.** | `plans/<target_id>_exploitation_plan.md` |
| **2** | 🧬 **CVE Researcher** | Consulta NVD / GitHub Advisories / Exploit-DB (timeout 30s/fuente), filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`. | `cve_research/<target_id>_cves.json` |
| **3** | 📝 **Reporter** | Consolida todo en informe dual + reportes individuales, con **ofuscación de credenciales** y validación JSON estricta. | `reports/final_report.*` + `reports/<target_id>_report.*` |

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
| **Cuándo** | Targets en **Internet** | **LAN local** (la red del equipo macOS) |
| **Lanzador** | `./run_docker.sh` | `./run_host.sh` |
| **Binarios** | Contenedor **Kali Linux** (imagen `recon-argento-stepai`) | Herramientas nativas del host (Homebrew / pipx / git clone) |
| **Nmap** | `-sS` (SYN, requiere raw sockets / `NET_RAW`) | `-sT` (TCP Connect, sin permisos root) |
| **Scripts** | `scripts/` (dentro del contenedor) | `scripts/host/` (en el host) |
| **Wordlist** | `/opt/SecLists/...` | `tools/seclists_common.txt` (descarga automática) |

> ⚠️ **Importante:** Docker Desktop (macOS) **no ve la LAN local del host** (ni con `-sS` ni con `-sT`, por el backend de red emulado). Para escanear `192.168.x.x` usa **siempre el Modo Host**.

```bash
# Modo Docker (session interactiva dentro del contenedor Kali)
docker compose run --rm pentest bash

# Modo Host (verifica tools + conectividad e imprime instrucciones)
./run_host.sh 192.168.8.1
```
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

Para el **Modo Host** simplemente verificá las herramientas con `./run_host.sh <gateway>` (imprime el estado y las instrucciones).

### 3) Prompt Inicial para Cline

Abrí Cline **en la raíz del workspace** y pegá este prompt (o el equivalente en tu idioma):

```text
Leé el archivo .cline/master_prompt.md y asumí el rol de Orchestrator
de este pipeline de pentest. Iniciá la Fase 0 (calibración interactiva)
de las 7 herramientas (Nmap, HTTPX, Nuclei, Nikto, WhatWeb, Gobuster,
SSLyze) según el scope definido en config/scope.json. Cuando tengas los
comandos aprobados, ejecutá la Fase 1 contra los targets del alcance y
continuá con la Fase 2 (plan de explotación + CVE research) y la Fase 3
(reporte final). Respetá SIEMPRE los guardrails R1-R5.
```

El Orchestrator te guiará: primero **aprobás o modificás** cada comando (Fase 0), y luego el DAG corre **secuencialmente** generando toda la evidencia y los reportes.

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
│   ├── agent_recon_pipeline.md   # Spec operativa Fase 1 (DAG 8 steps, modos, bifurcación no-web)
│   ├── agent_3_exploitation_plan.md  # Spec Agente 3 (protección de contexto, plan documentado)
│   ├── agent_4_cve_research.md   # Spec Agente 4 (ranking CVEs, fuentes, rank_reason)
│   └── agent_5_reporter.md       # Spec Agente 5 (informe dual + individual, ofuscación)
├── tools/
│   ├── nmap_help.md … sslyze_help.md  # Help files verificados (flags reales de cada tool)
│   └── WhatWeb/                  # Binario local de WhatWeb (no hay fórmula Homebrew)
├── scripts/
│   ├── step*.sh                  # Steps 1-8 (Modo Docker)
│   └── host/
│       ├── run_target.sh         # Orquestador por target (DAG completo + manifest)
│       ├── make_manifest.py      # Manifest robusto por target
│       ├── make_report.py        # Reporte dual + individuales (Agente 5)
│       └── step*.sh              # Steps 1-8 (Modo Host)
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
│   └── specs/                    # Main specs consolidadas (sync formal)
├── Dockerfile · docker-compose.yml
└── run_docker.sh · run_host.sh   # Lanzadores de entorno
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