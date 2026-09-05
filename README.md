# 🛡️ ReconArgentumAI

> **AI-driven Pentesting** — Pipeline automatizado, multi-agente y guiado por IA para el reconnaissance y análisis de infraestructura autorizada.

[![Pipeline](https://img.shields.io/badge/Pipeline-8%20Steps%20·%207%20Tools-6f42c1)]() [![Agentes](https://img.shields.io/badge/Agentes-6-brightgreen)]() [![IA-Agnóstico](https://img.shields.io/badge/IA-Agnóstico-blue)]()

ReconArgentumAI es una **plataforma de pentesting de infraestructura** que orquesta un pipeline de *recon* de 8 pasos sobre 7 herramientas de seguridad, dirigido por un **modelo de IA** (agnóstico del proveedor) a través de Cline / Roo Code. El sistema **no explota nada**: produce evidencia completa en disco, planes de explotación documentados y reportes profesionales, siguiendo guardrails de scope, stealth y ofuscación inquebrantables.

Pensado para **red teams, auditores y equipos de seguridad ofensiva** que quieren *recon* reproducible, trazable y de bajo ruido, tanto contra **Internet** como contra la **LAN local** — desde una misma herramienta.

---

## 🚀 Características Principales

| Característica | Detalle |
|---|---|
| 🧠 **Pipeline multi-agente guiado por IA** | 6 agentes especializados (Orchestrator, Recon, Exploitation Planner, CVE Researcher, Reporter, Consolidador de Hallazgos) coordinados por un master prompt. **Agnóstico del modelo**: funciona con Cline, Roo Code y cualquier LLM capaz de seguir instrucciones. |
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
Fase 1  Recon secuencial (DAG 8 steps)
Fase 2  Análisis (plan de explotación + CVE research)
Fase 3  Reporte final (MD + JSON)
Fase 4  Consolidación (organize_project.py + Agente 6: resúmenes doc/txt por target)
```

| Fase | Agente | Rol | Salida clave |
|---|---|---|---|
| **0** | 🎛️ **Orchestrator** | Calibra las 7 herramientas con el usuario (contexto de defensas, rango de puertos, wordlists) y registra **solo comandos aprobados**. | `config/approved_commands.md` |
| **1** | 🔍 **Recon Agent** | Ejecuta el DAG lineal 1→8 (Nmap → HTTPX → Nmap detallado → Nuclei → Nikto → WhatWeb → Gobuster → SSLyze) con delays de stealth, bifurcación **no-web** y retry 1x. | `evidence/<target>/` + `manifest.json` |
| **2** | 📋 **Exploitation Planner** | Correlaciona evidencia por servicio con **protección de contexto** y redacta vectores accionables (pre-condiciones, pasos, PoC, detección, rollback). **Nunca ejecuta exploits.** | `plans/<target_id>_exploitation_plan.md` |
| **2** | 🧬 **CVE Researcher** | Consulta NVD / GitHub Advisories / Exploit-DB (timeout 30s/fuente), filtra CVSS ≥ 4.0 y rankea Top 3-5 por servicio con `rank_reason`. | `cve_research/<target_id>_cves.json` |
| **3** | 📝 **Reporter** | Consolida todo en informe dual + reportes individuales, con **ofuscación de credenciales** y validación JSON estricta. | `reports/final_report.*` + `reports/<target_id>_report.*` |
| **4** | 📂 **Consolidador de Hallazgos** | Independiente de `organize_project.py`: analiza SOLO `CLIENTE/<target>/outputs/` y extrae/reorganiza hallazgos de las herramientas en 2 entregables por target (`.doc` + `.txt`) con **cero invención**, deduplicación y ofuscación. Nueva evidencia copiada a `outputs/` se detecta en la siguiente corrida. | `CLIENTE/<target>/<target_id>_resumen_vulnerabilidades.doc` + `..._resumen_breve.txt` |

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
│   ├── specs/                    # Main specs consolidadas (sync formal)
│   └── changes/archive/          # Changes completados archivados
├── CLIENTE/                      # ⭐ Consolidación final (gitignored, nombre fijo)
│   └── <target_ip>/
│       ├── data/                 # 2 Markdown: *exploitation_plan.md · *report.md
│       └── outputs/              # *cves.md + 1 evidencia por escaneo (nmap solo .xml)
├── Dockerfile · docker-compose.yml
└── run_docker.sh · run_host.sh   # Lanzadores de entorno
```

---

## 📦 Consolidación final del engagement

Al terminar todos los escaneos (Fases 1–3 completas), dos pasos ordenan la información
por target y generan los entregables para el cliente.

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
│   ├── outputs/                   # 10.10.10.152_cves.md (generado) + UNA evidencia por escaneo
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
`manifest.json`, intermedios, logs y `*_report.json`) y **genera** `<target_id>_cves.md`
en `outputs/` ofuscando credenciales con `***`.

### 2) Generar los resúmenes por target — Agente 6 (`make_vuln_report.py`)

`scripts/make_vuln_report.py` es el **Agente 6 (Consolidador de hallazgos)**, un script
**independiente** que NO modifica `organize_project.py`. Lee **solo** el directorio
`outputs/` de cada target ya consolidado y extrae/reorganiza los hallazgos de las
herramientas (nuclei, nikto, sslyze, nmap, gobuster, `*_cves.md`, evidencia manual)
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
# 1) Consolidar la evidencia en CLIENTE/ (organiza copias + genera README y cves.md)
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