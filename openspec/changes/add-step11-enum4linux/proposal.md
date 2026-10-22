## Why

El pipeline de Fase 1 (DAG 12 steps / 11 herramientas) termina en **SMB Enum (Step 10)** con
`smbclient -L -N`, que solo lista recursos compartidos. En targets con firma de Active Directory
(ej. `10.10.10.80`: Kerberos 88, LDAP 389/636/3268/3269, kpasswd 464, SMB 139/445, workgroup
`ACME`) la evidencia muestra que el servidor **acepta sesion anonima SMB**
(`Anonymous login successful` en `smbclient_shares.txt`) pero **sin shares listables**, y no existe
ninguna herramienta en el framework que enumere **usuarios, grupos, politica de passwords o
informacion de dominio**.

Hoy `enum4linux` **no existe en el framework**: no esta instalado, no esta en el `Dockerfile`, no
tiene help en `tools/`, no esta en la calibracion de Fase 0 y no aparece en el DAG del pipeline. Su
uso correcto exige datos que **ya estan en la evidencia del target** (`outputs/ldapsearch.txt` ->
dominio `INTRANET.ACME.EXAMPLE`, `defaultNamingContext DC=intranet,DC=acme,DC=example`, host
`SRV-DC01.intranet.acme.example`; `nmap_detailed` -> workgroup `ACME`), que hoy se pierden al no
haber un paso que los consuma.

Se necesitan un **Step 11 (LDAP Enum, ldapsearch)** y un **Step 12 (Enum4linux)** que integren la enumeracion AD con los mismos guardrails del resto del
pipeline (R1 scope, R2 solo lectura, R3 secuencial, R4 evidencia completa, R5 timeouts desde
`config/stealth.yaml`) y que **no se ejecute en macOS**.

## What Changes

- Nuevo **scripts/host/step11_ldap_enum.sh** (+ `.md`): root DSE anonimo con `ldapsearch` (Linux y macOS), consultas dirigidas por base DN y modo **credencializado opt-in** (usuarios/SPN) con password por archivo temporal 0600 y `<REDACTED>` en la evidencia.
- Nuevo **scripts/host/step12_enum4linux_enum.sh** (+ **scripts/host/step12_enum4linux_enum.md**),
  espejo de `step10_smbclient_enum.sh`: modos manual (`<TARGET> [PROYECTO]`, `--all`), modo pipeline
  (`--ev-dir <DIR>`), `--force`/no-clobber, gate de ping y **gate Service-Based** por TCP 139/445.
  Ejecuta `enum4linux-ng` (fallback `enum4linux`) en **modo pasivo/anonimo** por defecto, con el
  workgroup autodetectado de la evidencia, timeout resuelto de `stealth.yaml`, guard de plataforma
  (Darwin -> `skipped_unsupported_os`, sin trafico) y guardado de `enum4linux.txt` (1a linea =
  comando ejecutado) mas el export `enum4linux.json`/`enum4linux.yaml` (`-oA`).
- Nuevo **tools/enum4linux_help.md** (help verificado, convencion de `tools/smbclient_help.md`).
- **config/stealth.yaml**: nuevas claves `ldapsearch_timeout_seconds` y `enum4linux_timeout_seconds` (regla R5).
- **config/approved_commands.md**: registrar los comandos de los Steps 11 (LDAP: anonimo APROBADO, credencializado SALTADO por defecto) y 12 como `APROBADO` (el archivo no
  existe hoy en `config/`, aunque las specs lo referencian).
- **scripts/host/run_target.sh**: Step 11 (LDAP, gate 389/636/3268/3269) y Step 12 (Enum4linux, reutiliza la deteccion SMB del Step 10), entradas 11 y 12 en
  `manifest.json` (y en el manifest `incomplete`), `OUT11`, logs `Step N/11`.
- **preflight_run.sh**, **Dockerfile**, **run_docker.sh**, **run_host.sh** y
  **scripts/install_host_tools.***: dependencia `enum4linux-ng` y verificacion **OS-aware**
  (`N/A` en macOS; requerida en Linux).
- **scripts/make_vuln_report.py** (Agente 6): `parse_enum4linux()` mas patron en `_elegir_parser()`
  y prioridad en `_prio()`.
- **Documentacion/specs**: `10 steps / 9 herramientas` -> **`12 steps / 11 herramientas`**.

## Capabilities

### New Capabilities

None (los Steps 11 y 12 extienden capacidades existentes).

### Modified Capabilities

- `recon-pipeline`: agrega el Step 11 (LDAP Enum) y renumera Enum4linux a Step 12; ambos al DAG
  secuencial, al Service-Based Routing (LDAP: 389/636/3268/3269; Enum4linux: 139/445 solo Linux) y al
  manifest por target (12 entradas).
- `pipeline-orchestration`: la calibracion interactiva de Fase 0 pasa de 9 a 11 herramientas
  oficiales (se agrega Enum4linux al final del orden).

## Impact

- **Scripts**: nuevo `scripts/host/step12_enum4linux_enum.sh`; `run_target.sh`, `preflight_run.sh`
  y `make_vuln_report.py` modificados.
- **Entornos**: `Dockerfile`, `run_docker.sh`, `run_host.sh`, `scripts/install_host_tools.sh`.
- **Evidencia**: `enum4linux.txt` / `enum4linux.json` / `enum4linux.yaml` en `evidence/<target>/`
  y `CLIENTE/<ip>/outputs/` (los levanta el Agente 6 en la proxima corrida).
- **Dependencia nueva**: `enum4linux-ng` (apt Kali/Debian; requiere stack Samba). En macOS el Step
  11 queda `skipped_unsupported_os` y **no genera trafico**.
- **Riesgo de deteccion**: ALTO en AD auditado (binds anonimos LDAP/SMB, `lookupsids`); el default
  es pasivo y RID cycling es opt-in.
- **Specs/docs**: `specs/agent_recon_pipeline.md`, `openspec/specs/*`, `.cline/master_prompt.md`,
  `SOULs/*`, `README.md`, `RUNBOOK.md`, `scripts/README.md` y fix en `tools/smbclient_help.md`.
