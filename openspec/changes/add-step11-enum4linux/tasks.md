## 1. Artefactos base

- [x] 1.1 Crear `tools/enum4linux_help.md` (help verificado: enum4linux-ng 1.3.10 y enum4linux 0.9.1; tabla de flags, `{{enum4linux_timeout_seconds}}`, `-A` prohibido, política de plataforma y ejemplos)
- [x] 1.2 Agregar `enum4linux_timeout_seconds: 10` a `config/stealth.yaml` (R5; es el `-t` del tool)
- [x] 1.3 Crear `config/approved_commands.md` (no existe en `config/`) registrando el comando del Step 11 como `APROBADO`

## 2. Script Step 11 (`scripts/host/step12_enum4linux_enum.sh`)

- [x] 2.1 Estructura y CLI: `<TARGET> [PROYECTO]`, `--all`, `--ev-dir <DIR>`, `--force`/`--no-clobber`, `--no-ping-check`, `--rid`
- [x] 2.2 Guard de plataforma: `uname -s` = Darwin -> `skipped_unsupported_os` y `exit 0` sin tráfico (antes de resolver modos)
- [x] 2.3 Resolución de binario `enum4linux-ng` -> `enum4linux`; sin binario -> `skipped` sin tráfico
- [x] 2.4 Gate Service-Based 139/445 desde `nmap_detailed.xml` -> `skipped_no_smb` sin tráfico, más gate de ping (`smbclient_ping_timeout_seconds`)
- [x] 2.5 Autodetección de workgroup/dominio desde la evidencia y paso como `-w`
- [x] 2.6 Timeout `-t` resuelto de `config/stealth.yaml` (R5)
- [x] 2.7 Evidencia: `enum4linux.txt` (1a línea = comando ejecutado) + `-oA` (`enum4linux.json`/`.yaml`) y conservación condicional
- [x] 2.8 Crear `scripts/host/step12_enum4linux_enum.md` (guía operativa sin código, tono de `step10_smbclient_enum.md`)

## 3. Orquestador y manifest

- [x] 3.1 `run_target.sh`: Step 11 tras el Step 10 (reutiliza `HAS_SMB`), `STATUS11`, `OUT11`, y NO invoca el script en macOS (`skipped_unsupported_os`)
- [x] 3.2 `run_target.sh`: entrada 11 en el manifest normal y en el manifest `incomplete`; logs `Step N/11`; headers y comentario del lock
- [x] 3.3 `scripts/host/run_target.md` y `scripts/host/run_fase1_run3.sh`/`.md`: contadores y paso 11

## 4. Entornos

- [x] 4.1 `preflight_run.sh`: check OS-aware de `enum4linux-ng`/`enum4linux` (N/A en macOS; requerido en Linux con hint de instalación)
- [x] 4.2 `Dockerfile`: instalar `enum4linux-ng` + sanity check del binario
- [x] 4.3 `run_docker.sh` y `run_host.sh`: chequeos OS-aware, hints de instalación y contadores
- [x] 4.4 `scripts/install_host_tools.sh`/`.md`: nota de macOS (no aplica) y fix de la afirmación obsoleta de `tools/smbclient_help.md`

## 5. Consolidador (Agente 6)

- [x] 5.1 `parse_enum4linux()` en `scripts/make_vuln_report.py` (acepta el JSON de enum4linux-ng y el TXT del perl)
- [x] 5.2 Patrón en `_elegir_parser()` y prioridad en `_prio()`
- [x] 5.3 Verificar reglas duras: cero invención, `No declarada en fuente`, ofuscación `***` y deduplicación

## 6. Documentación y specs

- [x] 6.1 `specs/agent_recon_pipeline.md`: DAG (fila Step 11), bloque del Step 11, tabla Service-Based, manifest/estados y contadores
- [ ] 6.2 `openspec/specs/recon-pipeline/spec.md` y `openspec/specs/pipeline-orchestration/spec.md` (sync al archivar este cambio)
- [x] 6.3 `.cline/master_prompt.md`: Fase 0 con 10 herramientas, Service-Based Routing y tabla de recursos
- [x] 6.4 `SOULs/orchestrator/SOUL.md` y `SOULs/recon/SOUL.md`
- [x] 6.5 `README.md`, `RUNBOOK.md` y `scripts/README.md`

## 7. Validación

- [x] 7.1 macOS (sin tráfico real): `bash -n` de los `.sh`; Step 11 con XML sintético y stub `enum4linux-ng` que escribe un CENTINELA si es invocado -> EXIGIR que el centinela NO exista y que la salida diga `skipped_unsupported_os`
- [x] 7.2 macOS: `python3 scripts/make_vuln_report.py --dry-run --project CLIENTE --target 10.10.10.80` con un `enum4linux.txt`/`.json` sintético en un `outputs/` temporal (luego eliminarlo)
- [x] 7.3 macOS: `bash scripts/host/preflight_run.sh` (debe reportar N/A y no fallar por el Step 11)
- [x] 7.4 VM Debian con VPN (fuera de este host): corrida real de los Steps 11/12 sobre un target autorizado y verificación de `evidence/<target>/manifest.json` con 12 entradas
- [x] 7.5 Confirmar que ningún `skipped_*` aborta el target y que `tools_executed` siempre tiene 11 entradas
- [x] 7.6 Verificar que `skipped_unsupported_os` no rompe `scripts/qa_check.py` ni el manifest

## 8. Step 11 - LDAP Enum (ldapsearch) [agregado 2026-10-21]

- [x] 8.1 Crear `tools/ldapsearch_help.md` (help verificado)
- [x] 8.2 Crear `scripts/host/step11_ldap_enum.sh` (gate 389/636/3268/3269; anónimo default; credencializado opt-in con pwfile 0600 + `<REDACTED>`)
- [x] 8.3 Crear `scripts/host/step11_ldap_enum.md`
- [x] 8.4 `config/stealth.yaml`: `ldapsearch_timeout_seconds`
- [x] 8.5 `config/approved_commands.md`: 11 herramientas + Steps 11/12 (creds SALTADO por defecto)
- [x] 8.6 `run_target.sh`: LDAP = Step 11 y Enum4linux = Step 12 (logs /12, manifests de 12 entradas, `OUT11`/`OUT12`)
- [x] 8.7 Renumerado `step11_enum4linux_enum.*` -> `step12_enum4linux_enum.*` (+ referencias en docs/config/help)
- [x] 8.8 Entornos: `ldap-utils`/`ldapsearch` en Dockerfile, run_docker, preflight, run_host, install_host_tools
- [x] 8.9 Agente 6: `parse_ldapsearch()` (LDIF) + registro en `_elegir_parser`/`_prio` + dedupe `ad_usuarios`
- [x] 8.10 Docs: `specs/agent_recon_pipeline.md`, `.cline/master_prompt.md`, README, RUNBOOK, scripts/README, SOULs, run_target.md, run_fase1*
- [x] 8.11 Validación local en macOS: anónimo, credencializado (sin leak de password), gate sin LDAP, no-clobber y parser LDIF con dedupe

## 9. Validación asistida (agregado 2026-10-21)

- [x] 9.1 Crear `scripts/host/validate_step11_12.sh` (V-01..V-08: deps, evidencia, expectativa del XML, Steps 11/12 incrementales con gate negativo, anti-fuga del password, `--full` con contrato del manifest, `--project` con consolidador+QA, `--dry-run`)
- [x] 9.2 Crear `scripts/host/validate_step11_12.md`
- [x] 9.3 `scripts/qa_check.py`: nuevo **CK-09** (contrato del DAG de 12 steps, herramientas y estados) + invocación en `main()`
- [x] 9.4 `scripts/qa_check.md`: 8 -> 9 checks (fila CK-09 + criterio de bloqueo)
- [x] 9.5 `RUNBOOK.md`: fila CK-09 en la tabla de bloqueo de §5 + nueva §5.1 con el checklist de los Steps 11/12
- [x] 9.6 `scripts/README.md`: fila del validador
- [x] 9.7 Validación local del validador en macOS (stubs + XML sintético): `--dry-run` PASS 5/5, anónimo PASS 5/5, `--creds` PASS 8/8 sin fuga, gates negativos PASS 5/5
- [x] 9.8 Prueba aislada de CK-09 (5 casos: 11 steps, 12 steps, skips válidos, estado inválido, steps invertidos)
- [x] 9.9 Validado en la VM Debian con --full: 11/11 PASS (manifest 12 entradas, steps 11/12 success, -w ACME): en la VM Debian con VPN, `validate_step11_12.sh <IP> --full --project CLIENTE`
- [x] 9.10 Split de V-08: V-08a (Agente 6 aislado con staging/symlinks; NO toca CLIENTE) + V-08b (cadena de produccion opt-in con --target/--no-clobber)
- [x] 9.11 qa_check.py: SCOPE_FILTER_IP (checks por target de una sola IP) + doc en qa_check.md y RUNBOOK 5.1
- [x] 9.12 Fix de dedupe: _E4L_JSON_TIPO (seccion users del JSON -> tipo enum4linux_usuarios) + reglas ad_grupos/ad_shares/ad_policy en _dup_key
- [x] 9.13 Validacion contra evidencia REAL (copia de evidence/10.10.10.80): V-08a 9/9 PASS y dedupe en 1 entrada

## 10. Fix 2026-10-22 — V-08a expectation-aware + nota de sesión nula

> Contexto: el re-run de `10.10.10.204` en la VM Debian dio `RESUMEN 12/14 PASS | 2 FAIL`, ambos en
> **V-08a** (`falta el hallazgo de dominio LDAP` y `no hay hallazgos de enum4linux`). Resultaron
> **falsos positivos del validador**: el target no expone puertos LDAP (`skipped_no_ldap`) y el Step 12
> descarta la evidencia cruda cuando la sesión anónima es rechazada (`success` + `output: []`).
> El DAG sigue con **12 steps** y los estados válidos no cambian.

- [x] 10.1 `validate_step11_12.sh`: V-08a movido a `run_v08a()` y hecho **expectation-aware**
      (LDAP sólo si hay `ldapsearch*.txt`; enum4linux sólo si hay `enum4linux.*` o su nota; dedupe sólo
      con evidencia AD). Sin evidencia AD → `[SKIP]`, no `[FAIL]`.
- [x] 10.2 Flag `--v08a-only`: corre sólo V-08a, **sin tráfico** (no ejecuta V-01..V-08b) — permite
      re-verificar Agente 6 tras tocar `make_vuln_report.py` o los Steps 10/12.
- [x] 10.3 `--full`: **backup automático** de la evidencia previa en `/tmp/backup_<IP>_<timestamp>`
      (+ `--no-backup`). Motivo: los `output` del manifest son **globs**, así que evidencia vieja puede
      "cubrir" un step `failed` y `CK-02` no lo detecta.
- [x] 10.4 Steps 10/12: cuando se descarta la evidencia cruda por sesión nula rechazada, se conserva la
      nota `smbclient_sin_sesion.txt` / `enum4linux_sin_sesion.txt` (comando + motivo literal) y se
      emite `STEP_SMBCLIENT_NOTE sin_sesion` / `STEP_ENUM4LINUX_NOTE sin_sesion`.
- [x] 10.5 `run_target.sh`: `OUT12` ahora incluye `enum4linux_*.txt` (la nota entra al manifest; en el
      Step 10 el glob `smbclient_*.txt` ya la cubría).
- [x] 10.6 `make_vuln_report.py`: `parse_sesion_rechazada` → hallazgo informativo
      *"Sesion SMB anonima rechazada (smbclient|enum4linux)"* con la evidencia literal (severidad "No
      declarada en fuente"); registrado en `_elegir_parser` y `_prio`.
- [x] 10.7 Tests (sin tráfico): `--v08a-only` **positivo** (`10.10.10.80` → 4/4 PASS), **negativo**
      (`10.10.10.204` → 1 PASS + 2 SKIP; antes 2 FAIL) y **sintético con notas** (2/2 PASS; el reporte
      lista los 2 hallazgos de rechazo).
- [x] 10.8 Docs: `validate_step11_12.md` (semántica V-08a + flags + backup), `step10_smbclient_enum.md` y
      `step12_enum4linux_enum.md` (nota del rechazo), `RUNBOOK.md` §5.1 y `scripts/README.md`.
- [x] 10.9 Spec (sync): nuevo requirement **"Nota de sesión SMB anónima rechazada (Steps 10/12)"** en el
      delta de `recon-pipeline` + merge en `openspec/specs/recon-pipeline/spec.md` (DAG y vocabulario de
      estados intactos).

