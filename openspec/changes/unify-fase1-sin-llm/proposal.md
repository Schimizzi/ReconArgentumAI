## Why

La Fase 1 (Agente 1 — Recon) ya está materializada en scripts (`scripts/host/run_fase1_run3.sh` + `run_target.sh` + los 10 `stepN.sh`), pero el **Modo Docker** aún dependía de un LLM para orquestar los pasos manualmente, y los scripts tenían paths hardcodeados del host macOS (wordlists en `~/Documents/SecLists`) y scan type fijo (`-sT`), lo que impedía correr la misma Fase 1 idéntica en Docker, una VM Kali o el host, sin un LLM. Este cambio unifica el Agente 1 para que se ejecute **100% automático sin LLM** en los tres entornos, con la misma evidencia y los mismos manifests.

## What Changes

- **Runner unificado**: ambos modos (DOCKER y HOST/VM) usan el **mismo** set `scripts/host/` y el **mismo runner maestro** `scripts/host/run_fase1_run3.sh` (recorre `authorized_targets` de `scope.json`, delega cada IP a `run_target.sh`, respeta R1/R3).
- **Scan type autodetectado por privilegios**: `step1_nmap_ports.sh` y `step3_nmap_detailed.sh` usan `-sS` cuando el proceso corre como root (`EUID==0`; VM Kali, contenedor Docker) y `-sT` en caso contrario (host macOS sin root). Antes era un modo fijo por entorno.

- **Wordlists portables**: `step7_gobuster.sh` y `preflight_run.sh` resuelven las SecLists probando `/opt/SecLists/...` (contenedor/Kali) → `$HOME/Documents/SecLists/...` (host macOS) → `tools/seclists_common.txt` (cache web del repo, fallback). Antes estaba hardcodeado al path del host.

- **Imagen Docker completada para el Agente 1 completo**: `Dockerfile` agrega `samba-client` (Step 10 SMB Enum) e `iputils-ping` (preflight + ping gate), y el sanity check del build verifica las **9 tools + jq**.
- **Lanzador Docker sin LLM**: `run_docker.sh --auto` (Fase 1 completa, todos los targets) y `run_docker.sh --auto-target <IP>` ejecutan el Agente 1 dentro del contenedor sin LLM; soporta `--dry-run`, sanity check con rebuild automático UNA vez si la imagen es vieja`.`run_docker.sh` sin argumentos sigue mostrando las instrucciones del Orchestrator (LLM / manual).
- **Docs/spec operativa**: `README.md`, `run_host.sh`, `scripts/host/step1_nmap_ports.md` y `specs/agent_recon_pipeline.md` documentan el modo automático y la unificación.

## Capabilities

### New Capabilities

- Ninguna (no se introduce una capability nueva).

### Modified Capabilities

- `recon-pipeline`: cambian los requirements de ejecución del DAG de recon: (1) la Fase 1 (Agente 1) puede ejecutarse **de forma automática sin un LLM** en ambos modos (DOCKER y HOST/VM), con el mismo runner y la misma evidencia;(2) el scan type de Nmap en Steps  1 y  3 se **autodetecta por privilegios** (`-sS` con root, `-sT` sin root) en lugar de estar fijado por modo;(3) las wordlists de Gobuster y del preflight se **resuelven de forma portable** (`/opt/SecLists` → `$HOME/Documents/SecLists` → `tools/seclists_common.txt`) en lugar de un path hardcodeado del host. El modo DOCKER ahora es ejecutable en automático sin depender de un LLM o del Orchestrator para Fase 1.

## Impact

- **Scripts** (modificados): `scripts/host/step1_nmap_ports.sh`, `scripts/host/step3_nmap_detailed.sh` (scan type autodetectado); `scripts/host/step7_gobuster.sh`, `scripts/host/preflight_run.sh` (wordlists portables + verificación de `smbclient`/`ping`).
- **Docker** (modificado): `Dockerfile` (samba-client, iputils-ping, sanity check 9 tools + jq); `run_docker.sh` (flags `--auto` / `--auto-target` / `--dry-run`, sanity con rebuild 1x)..
- **Docs** (modificados): `README.md` (tabla de modos + Quick Start con Agente 1 automático sin LLM;; `run_host.sh` (instrucciones sin LLM;; `scripts/host/step1_nmap_ports.md` (autodetección;; `specs/agent_recon_pipeline.md` (§0bis: unificación, wordlists portables, scan type autodetectado).
- **Specs OpenSpec**: delta en `openspec/specs/recon-pipeline/spec.md` (via este change;; no se toca `pipeline-orchestration` ni `reporting`.
- **Dependencias**: ninguna nueva fuera de la imagen (paquetes apt `samba-client`, `iputils-ping` dentro del contenedor;; las tools del host ya se requerían para el Step 10/preflight)).
- **Compatibilidad**: no rompe contratos existentes: el comportamiento HOST/LAN y el modo LLM del Orchestrator se mantienen; la Fase 1 sigue produciendo la misma evidencia y los mismos manifests.