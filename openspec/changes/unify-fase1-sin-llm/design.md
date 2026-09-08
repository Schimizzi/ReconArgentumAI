## Context

El pipeline de recon (Fase 1) ya está materializado en scripts portables en `scripts/host/` (`run_fase1_run3.sh` + `run_target.sh` + los 10 `stepN.sh`), con evidencia en `evidence/<target>/` + `manifest.json`. Sin embargo: (1) el Modo DOCKER aún dependía de un LLM para orquestar la Fase 1 a mano, porque `run_docker.sh` solo validaba la imagen y delegaba al Orchestrator;(2) los scripts tenían paths hardcodeados del host macOS para las wordlists de SecLists;(3) el scan type de Nmap estaba fijado por modo(`-sT` en HOST, `-sS` en DOCKER), lo que impedía un solo set de scripts en los tres entornos. Este design cubre cómo unificar el Agente 1 para ejecutarse 100% automático sin LLM en Docker, VM Kali y Host. La motivación está en `proposal.md`.

## Goals / Non-Goals

**Goals:**
- Un solo set de scripts (`scripts/host/`) compartido por los 3 entornos (Host macOS, VM Kali, contenedor Docker).
- Escaneo Nmap con scan type autodetectado por privilegios (`-sS` root / `-sT` sin root).
- Wordlists portables (`/opt/SecLists` → `$HOME/Documents/SecLists` → `tools/seclists_common.txt`) sin paths hardcodeados.

- Imagen Docker completa para el Agente 1 (`samba-client`, `iputils-ping`, sanity check 9 tools + jq).
- Lanzador Docker automático sin LLM (`run_docker.sh --auto` / `--auto-target <IP>`), preservando el modo LLM manual como default.



**Non-Goals:**
- No cambiar el rol del Orchestrator (Fase 0) ni el flujo interactivo de aprobación de comandos.

- No cambiar las Fases 2-4 (análisis, reportes, consolidación).
- No cambiar el formato de evidencia ni el esquema de `manifest.json`.
- No duplicar un segundo set de scripts para Docker(se unifica, no se copia).

## Decisions

- **Un solo set `scripts/host/` en lugar de dos sets por modo**: los 3 entornos corren exactamente los mismos steps y el mismo runner maestro. Alternativa considerada: mantener `scripts/` (docker) y `scripts/host/` por separado → descartada por duplicación y drift de comportamiento.

- **Scan type autodetectado por `EUID` en lugar de variable de config**: `step1_nmap_ports.sh` y `step3_nmap_detailed.sh` eligen `-sS` si `id -u == 0` y `-sT` en caso contrario. Alternativa considerada: parametrizar el scan type en `stealth.yaml` → descartada porque el scan type depende de privilegios del proceso, no es un parámetro de ruido calibrable en Fase 0.


- **Wordlists por orden de candidatos en lugar de variable de config**: una función `resolve_wordlist` prueba `/opt/SecLists/...`, `$HOME/Documents/SecLists/...` y, solo para web, `tools/seclists_common.txt`. Alternativa considerada: descargar SecLists siempre → descartada por depender de red y tiempo; documentar un único path → descartada porque los entornos tienen ubicaciones distintas.


- **Flags `--auto` / `--auto-target` en `run_docker.sh` sin romper el modo default**: sin argumentos sigue imprimiendo las instrucciones del Orchestrator (LLM / manual). El sanity verifica las 9 tools + jq y, en modo automático, rebuilda la imagen UNA vez si es vieja (falta `smbclient`/`ping`) antes de fallar. Alternativa considerada: reemplazar el comportamiento default → descartada por compatibilidad hacia atras.


- **Imagen Docker completada vía apt**: `Dockerfile` agrega `samba-client` e `iputils-ping` y el sanity check del build verifica las 9 tools.Continuación: esto garantiza que el Agente 1 completo corra dentro del contenedor sin LLM, igual que en la VM.



- **Diagnóstico del binario de HTTPX por `command -v` (prioridad `httpx-pd` → `httpx`) en lugar de hardcodear `httpx-pd`**: `step2_httpx.sh`, `preflight_run.sh` y `run_host.sh` resuelven el binario de probe con `command -v httpx-pd` como primera opción y `command -v httpx` como segunda (ambos ProjectDiscovery). Alternativa considerada: crear un symlink `httpx-pd` en Kali (1 comando) → descartada porque no queda registrada en el repo y asume que el `httpx` de Kali es el correcto; la resolución en código queda documentada y funciona en macOS y Kali.

## Risks / Trade-offs

- [Imagen Docker mas grande por los paquetes nuevos] → Mitigación: paquetes apt pequeños; documentado en el Dockerfile.


- [Autodetección silenciosa del scan type puede diferir del comando aprobado textualmente en Fase 0] → Mitigación: la autodetección se documenta en la spec y en `specs/agent_recon_pipeline.md`; el resto de los flags del comando siguen siendo los aprobados.


- [La wordlist DNS no tiene fallback al cache del repo (el cache `tools/seclists_common.txt` solo es web)] → Mitigación: el preflight reporta la ausencia con un mensaje accionable indicando dónde instalar SecLists.


- [El runner `run_fase1_run3.sh` hereda el delay entre targets de `stealth.yaml` (default 5 min] → Impacto esperado: corridas largas; no es un riesgo nuevo (el comportamiento ya existía en HOST).

## Migration Plan

1. Los cambios ya están implementados en el working tree(scripts, `Dockerfile`, `run_docker.sh`, `run_host.sh`, docs, spec operativa).
2. Rebuild de la imagen Docker cuando se requiera: `docker compose build`, o `./run_docker.sh --auto` que rebuilda UNA vez automáticamente si falta `smbclient`/`ping`.
3. Rollback: revertir los archivos modificados (`scripts/host/step1_nmap_ports.sh`, `step3_nmap_detailed.sh`, `step7_gobuster.sh`, `preflight_run.sh`, `run_docker.sh`, `run_host.sh`, `Dockerfile`, `README.md`, `scripts/host/step1_nmap_ports.md`, `specs/agent_recon_pipeline.md`) y el change de OpenSpec crefrent.



## Open Questions

Ninguna: no hay preguntas que puedan cambiar las specs, el approach o el desglose de tareas.