# Recon Pipeline Specification — Delta (unify-fase1-sin-llm)

## MODIFIED Requirements

### Requirement: Step 1 — Port scan inicial
El sistema SHALL ejecutar Nmap sobre el target con los parámetros aprobados en Fase 0, guardando `nmap_ports.xml` y `nmap_ports.json` completos en `evidence/<target>/`. El scan type SHALL autodetectarse por privilegios del proceso: **`-sS`** (SYN, raw sockets) cuando el proceso corre como root (`EUID == 0`; VM Kali, contenedor Docker), y **`-sT`** (TCP Connect) en caso contrario (host macOS sin root). Como post-proceso SHALL extraer los puertos abiertos en formato `IP:PORT` (uno por línea) a `evidence/<target>/open_ports.txt`.

#### Scenario: Extracción de puertos abiertos
- **WHEN** el port scan termina con éxito
- **THEN** `open_ports.txt` contiene una línea por cada puerto abierto en formato `IP:PORT`

#### Scenario: Scan type autodetectado (root)
- **WHEN** el proceso corre como root (`EUID == 0`, p.ej. VM Kali o contenedor Docker)
- **THEN** el comando de Nmap del Step 1 usa `-sS` (SYN scan)

#### Scenario: Scan type autodetectado (sin root)
- **WHEN** el proceso no corre como root (p.ej. host macOS sin sudo)
- **THEN** el comando de Nmap del Step 1 usa `-sT` (TCP Connect scan)

#### Scenario: Step 1 falla de forma definitiva
- **WHEN** Nmap Step 1 falla y su retry único también falla
- **THEN** el target se marca como `incomplete` en el manifest y el pipeline pasa al siguiente target

### Requirement: Step 3 — Scan detallado solo de puertos abiertos
El sistema SHALL ejecutar Nmap -sC -sV únicamente sobre los puertos que el Step 1 confirmó abiertos (nunca sobre un rango completo), guardando `nmap_detailed.json`, `nmap_detailed.xml` y `nmap_detailed.txt` completos. El scan type SHALL autodetectarse por privilegios del proceso con el mismo criterio que el Step 1: **`-sS`** con root (`EUID == 0`) y **`-sT`** en caso contrario.

#### Scenario: Restricción de puertos
- **WHEN** el Step 3 se ejecuta
- **THEN** su parámetro de puertos contiene exactamente la lista de `open_ports.txt`, sin rangos adicionales

#### Scenario: Scan type autodetectado (root / sin root)
- **WHEN** el Step 3 se ejecuta con el proceso como root (o sin root)
- **THEN** el comando usa `-sS` (root) o `-sT` (sin root), igual que el Step 1, sin configuración adicional por entorno

## ADDED Requirements

### Requirement: Ejecución automática de Fase 1 sin LLM
El sistema SHALL poder ejecutar el DAG completo de recon (Fase 1, Agente 1) de forma **automática, sin intervención de un LLM**, en ambos modos de ejecución (DOCKER y HOST/VM), usando el **mismo runner maestro** `scripts/host/run_fase1_run3.sh` que recorre los `authorized_targets` de `config/scope.json` en orden secuencial y delega cada target a `run_target.sh` (DAG 10 steps + `manifest.json`). En el Modo DOCKER, el lanzador `run_docker.sh --auto`(o `--auto-target <IP>`) SHALL ejecutar el mismo runner dentro del contenedor sin requerir un Orchestrator/LLM. El sanity previo SHALL verificar que el contenedor contenga las 9 tools del Agente 1 (`nmap`, `httpx-pd`, `nuclei`, `nikto`, `whatweb`, `gobuster`, `sslyze`, `smbclient`, `ping`) más `jq`. si la imagen es vieja, el lanzador SHALL rebuildearla una vez antes de fallar.



#### Scenario: Fase 1 automática en Modo DOCKER
- **WHEN** el operador ejecuta `./run_docker.sh --auto` con `config/scope.json` conteniendo targets autorizados
- **THEN** el Agente 1 corre completo dentro del contenedor para todos los targets sin LLM y deja `evidence/<target>/manifest.json` en el volumen compartido del workspace

#### Scenario: Fase 1 automática en Modo HOST/VM
- **WHEN** el operador ejecuta `bash scripts/host/run_fase1_run3.sh` en el host o en una VM Kali sin Docker
- **THEN** el Agente 1 corre completo contra todos los targets de scope sin LLM con la misma evidencia que en Docker

#### Scenario: Dry-run
- **WHEN** el operador ejecuta `./run_docker.sh --auto --dry-run`(o `bash scripts/host/run_fase1_run3.sh --dry-run`)
- **THEN** se muestra la secuencia planificada sin ejecutar scans ni crear evidencia

### Requirement: Resolución del binario de probe HTTP (httpx-toolkit/httpx-pd/httpx)
El sistema SHALL resolver el binario de HTTPX (probe web, ProjectDiscovery) con **prioridad `httpx-toolkit` → `httpx-pd` → `httpx`**, los tres de ProjectDiscovery. En **Kali Linux** el binario PD se llama **`httpx-toolkit`** (Kali renombra los binarios PD que chocan con paquetes Python) — es el PRINCIPAL. En macOS/contenedor Docker existe `httpx-pd`. La resolución SHALL **nunca** usar el `httpx` cliente HTTP de Python (presente en el PATH vía Conda/pip) como binario de probe: solo SHALL aceptar `httpx` como fallback si realmente soporta la flag `-l` (o sea, es el PD real). `preflight_run.sh` y `run_host.sh` SHALL verificar los nombres (reportando cuál se usa) y `step2_httpx.sh` SHALL ejecutar el binario resuelto.

#### Scenario: Entorno Kali Linux con httpx-toolkit
- **WHEN** el entorno tiene `httpx-toolkit` en el PATH
- **THEN** el preflight y el Step 2 usan `httpx-toolkit` y reportan ese binario

#### Scenario: Entorno macOS/contenedor con httpx-pd
- **WHEN** el entorno tiene `httpx-pd` en el PATH y no `httpx-toolkit`
- **THEN** el preflight y el Step 2 usan `httpx-pd` y reportan ese binario

#### Scenario: httpx del PATH es el cliente Python
- **WHEN** el entorno tiene `httpx` pero es el cliente HTTP de Python (no soporta `-l`)
- **THEN** la resolución NO lo usa y reporta FALTA con un mensaje accionable (instalar el binario PD)

#### Scenario: Ambos ausentes
- **WHEN** el entorno no tiene ni `httpx-toolkit` ni `httpx-pd` ni un `httpx` de PD real
- **THEN** el preflight reporta FALTA con un mensaje accionable y el Step 2 aborta con un error claro antes de escanear

### Requirement: Wordlists portables para Gobuster y preflight
El sistema SHALL resolver las wordlists de Gobuster(y las verificadas por el preflight) probando **en orden**: `/opt/SecLists/...` (dentro del contenedor Kali / VM Kali con SecLists), `$HOME/Documents/SecLists/...` (host macOS) y **solo para la wordlist web**, `tools/seclists_common.txt` (cache local del repo). Los comandos SHALL usar la primera wordlist existente y NO hardcodear un path de host específico en los scripts. Si ninguna wordlist se encuentra, el preflight SHALL reportar la ausencia con un mensaje accionable que indique dónde instalar SecLists.



#### Scenario: Contenedor con /opt/SecLists
- **WHEN** el pipeline corre dentro del contenedor Docker(o una VM Kali con SecLists en `/opt/SecLists`)
- **THEN** `step7_gobuster.sh` usa `/opt/SecLists/Discovery/Web-Content/common.txt` sin configuración adicional

#### Scenario: Host macOS con SecLists en el HOME
- **WHEN** el proceso corre en un host macOS que tiene `~/Documents/SecLists/...`
- **THEN** `step7_gobuster.sh` y el preflight usan `$HOME/Documents/SecLists/...` (misma ubicación que el pipeline original)

#### Scenario: Host sin SecLists con cache del repo
- **WHEN** el host no tiene `/opt/SecLists` ni `~/Documents/SecLists` pero el repo tiene `tools/seclists_common.txt`
- **THEN** la wordlist web se resuelve desde `tools/seclists_common.txt` y el preflight lo reporta con su ubicación real; la wordlist DNS si no existe se reporta como faltante con instrucciones