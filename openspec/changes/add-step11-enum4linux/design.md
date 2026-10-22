## Context

El pipeline de Fase 1 ejecuta un DAG secuencial (10 steps / 9 herramientas) y termina en `SMB Enum`
(Step 10, `smbclient -L -N`), que solo lista shares. En engagements con Active Directory (caso real:
`10.10.10.80`, DC `SRV-DC01` del dominio `intranet.acme.example`, workgroup `ACME`) la evidencia
muestra sesión nula SMB aceptada (`Anonymous login successful`) pero sin shares listables, y el
framework no tiene ninguna herramienta para enumerar usuarios/grupos/política/dominio. Esa
información ya está parcialmente disponible en la evidencia (`outputs/ldapsearch.txt` ->
`defaultNamingContext`, `ldapServiceName`), pero ningún paso la consume.

Restricciones de entorno confirmadas:

- El pipeline real corre en **Linux** (VM Debian/Kali con VPN o el contenedor Docker); los hosts
  macOS se usan para desarrollo y validación estática, **no** para escanear targets reales.
- `enum4linux-ng` es un paquete **apt de Kali/Debian** (depende del stack Samba: `nmblookup`, `net`,
  `rpcclient`, `smbclient`). En macOS no hay paquete oficial.
- Los timeouts/rates del proyecto son SIEMPRE variables de `config/stealth.yaml` (regla R5).

## Goals / Non-Goals

**Goals:**

- Integrar enum4linux como Step 11 del DAG, con gate Service-Based (139/445) y guard de plataforma
  (no se ejecuta en macOS).
- Enumeración **pasiva y anónima** por defecto (sin credenciales), con evidencia cruda completa
  (`enum4linux.txt` + `enum4linux.json`/`.yaml`) trazable y detectable por el Agente 6.
- Guardrails intactos: R1 scope, R2 solo lectura, R3 secuencial con delays, R4 evidencia completa,
  R5 timeouts desde `stealth.yaml`.
- Reutilizar los patrones existentes de `step10_smbclient_enum.sh`: modos manual/`--all`/`--ev-dir`,
  no-clobber/`--force`, gate de ping y evidencia condicional.

**Non-Goals:**

- Ejecutar enum4linux en macOS (decisión del operador: el framework lo corre solo en Linux).
- Credenciales, Kerberoasting/AS-REP reales o RID cycling por defecto (opt-in y aprobados en Fase 0).
- Modificar otros steps del pipeline ni `scripts/organize_project.py`.

## Decisions

| # | Decisión | Elección | Racional |
|---|---|---|---|
| D1 | Herramienta base | `enum4linux-ng` primario; fallback `enum4linux` (perl) con flags reducidos | ng soporta SMB2/3 y exporta JSON (parseable por el Agente 6); el perl solo da texto |
| D2 | Gate de ejecución | Solo si TCP 139 o 445 están abiertos (`open_ports.txt` / `nmap_detailed.xml`); si no -> `skipped_no_smb` sin tráfico | enum4linux-ng aborta si no puede establecer sesión SMB; reutiliza un estado ya existente |
| D3 | Modo por defecto | Pasivo y anónimo: `-As -w <wk> -t <to> -oA` (sin `-u`/`-p`) | Alineado al plan de explotación: enumeración AD pasiva primero, menor ruido |
| D4 | RID cycling / brute force de shares | Opt-in por flag (`--rid`), aprobado en Fase 0 | `-R`/`-s` generan cientos de `lookupsids` (alto ruido, auditado en AD) |
| D5 | Workgroup/dominio | Autodetectado de la evidencia (smb-os-discovery de `nmap_detailed.xml`, fallback `ldapServiceName`/`defaultNamingContext`) y pasado como `-w` | Evita hardcodear el dominio del cliente y aprovecha la evidencia ya recolectada |
| D6 | Timeout | `enum4linux_timeout_seconds` de `config/stealth.yaml` (R5), mapeado a `-t` | Nada hardcodeado |
| D7 | Evidencia | `enum4linux.txt` (1a línea = comando) + `enum4linux.json`/`enum4linux.yaml` (`-oA`) | R4 (crudo completo) + formato estructurado para el Agente 6 |
| D8 | Evidencia condicional | Se conserva solo si hubo sesión establecida y ≥1 sección con datos; si no, se elimina | Patrón del Step 10: nada de ruido sin hallazgo |
| D9 | Binario ausente en Linux | estado `skipped` (sin tráfico) | Reutiliza el estado ya definido para tool no disponible (WhatWeb) |
| D10 | Plataforma | Guard por `uname -s` = Darwin -> `skipped_unsupported_os`, sin invocar la tool (guard doble: orquestador + script) | Decisión del operador; espeja el `case "$(uname -s)"` del Step 10 |
| D11 | `-A` (Aggressive) | Prohibido en el script y en el help | Hace write-checks sobre shares -> viola R2 (solo lectura) |
| D12 | Fase 0 | Se agrega Enum4linux como 10a herramienta de calibración, con help propio | Exige aprobación explícita del comando antes de ejecutarlo |
| D13 | Orquestación | `run_target.sh` decide el estado (reutiliza `HAS_SMB`) y llama al script con `--ev-dir --force --no-ping-check` | Mismo patrón que los Steps 9 y 10 |
| D14 | Contadores documentales | 10 steps / 9 tools -> 11 steps / 10 tools en docs, specs y master prompt | Consistencia y auditabilidad |

## Decisions (agregado 2026-10-21 - Step 11 LDAP antes de Enum4linux)
| # | Decisión | Elección | Racional |
|---|---|---|---|
| D15 | Orden LDAP antes que Enum4linux | Step 11 = LDAP Enum (ldapsearch) y Step 12 = Enum4linux | El plan de explotación del engagement ya ordena así (LDAP anonymous bind primero); el root DSE es la consulta AD más barata y silenciosa |
| D16 | Plataforma del Step 11 | Corre en **Linux y macOS** (ldapsearch es nativo en ambos) | El guard `skipped_unsupported_os` queda **solo** para Enum4linux; permite validar AD desde macOS |
| D17 | Modo credencializado | **Opt-in** (`--ldap-user`/`--ldap-pass`, aprobado en Fase 0). Password por archivo temporal 0600 (`-y`) y `<REDACTED>` en la evidencia | Sin credenciales el LDAP anónimo solo da el root DSE; con password en la línea de comando se filtraría a la evidencia (R4) y al historial |
| D18 | Gates independientes | LDAP 389/636/3268/3269 vs Enum4linux 139/445 (ninguno depende del otro) | Puede haber DC con LDAP y sin SMB (o al revés): cada step decide por su servicio |
| D19 | Renumerado | Enum4linux pasa de Step 11 a Step 12; manifest con **12 entradas** y nuevo estado `skipped_no_ldap` | Mantiene el orden por costo/ruido y el contrato del manifest (`tools_executed` completo) |
| D20 | Consolidador | Nuevo `parse_ldapsearch()` (LDIF) + regla de dedupe `ad_usuarios` | Los usuarios listados por LDAP y por Enum4linux son el mismo hallazgo: una sola entrada |

## Risks / Trade-offs

- [Falsos negativos por sesión anónima] En AD moderno `-U`/`-G` suelen devolver ACCESS_DENIED sin
  credenciales -> el reporte debe decir "no enumerable anónimamente", nunca "no existen usuarios"
  (regla de cero invención del Agente 6).
- [Ruido/detección] Los binds anónimos LDAP/SMB y `lookupsids` son auditables (AD registra
  4625/4768/4769). Mitigación: default pasivo, RID cycling opt-in y ventana autorizada.
- [Dependencia de SMB1/SMB2] El target real falló listando el workgroup por SMB1
  (`NT_STATUS_RESOURCE_NAME_NOT_FOUND`); enum4linux-ng maneja dialectos SMB2/3, pero la parte
  NetBIOS (`-N`) puede fallar. Mitigación: `-As` (sin NetBIOS) con fallback perl.
- [Nuevo estado `skipped_unsupported_os`] Debe figurar en la lista cerrada de estados de las specs y
  no contarse como fallo. Mitigación: sync de docs + verificación en QA.
- [Divergencia macOS/Linux] El manifest difiere por plataforma en el Step 11 (macOS:
  `skipped_unsupported_os`). Es intencional y queda documentado en el help y en las specs.

## Migration Plan

1. Crear `tools/enum4linux_help.md` y agregar `enum4linux_timeout_seconds` a `config/stealth.yaml`.
2. Crear `scripts/host/step12_enum4linux_enum.sh` (+ `.md`) y registrar el comando en `config/approved_commands.md`.
3. Integrar el Step 11 en `scripts/host/run_target.sh` (estado, manifest y logs N/11).
4. Actualizar entornos: `preflight_run.sh`, `Dockerfile`, `run_docker.sh`, `run_host.sh` e `install_host_tools.*`.
5. Agregar `parse_enum4linux()` al Agente 6 (`scripts/make_vuln_report.py`).
6. Sincronizar docs/specs (contadores 11/10 y nuevo estado).
7. Validación: local en macOS (stub + XML sintético, verificando que NO se ejecuta la tool) y corrida real en la VM Debian con VPN.
8. Rollback: eliminar `step11_*`, revertir el Step 11 en `run_target.sh` y la clave de `stealth.yaml`; el resto de los cambios son documentales.

## Anexo 2026-10-22 — Validación de V-08a y evidencia de "sesión nula rechazada"

**Problema observado:** al re-ejecutar Fase 1 de `10.10.10.204` (VM Debian), `validate_step11_12.sh --full`
cerró con `12/14 PASS | 2 FAIL` por dos expectativas fijas de V-08a:
1. exigía *"Informacion de dominio (LDAP)"* aunque el target **no tiene puertos LDAP** (`skipped_no_ldap`);
2. exigía hallazgos de *enum4linux* aunque el Step 12 **descarta la evidencia cruda** cuando la sesión
   anónima es rechazada (`STEP_ENUM4LINUX_DONE` + `output: []`, por diseño del step).

**Decisión:** que el validador derive la expectativa de la **realidad** (manifest + archivos presentes):
sin evidencia AD no hay nada que exigirle al reporte (`[SKIP]` informativo), pero **si hay evidencia y el
reporte no la refleja, sigue siendo `[FAIL]`** (no se pierde potencia). Además, para no perder el hallazgo
de seguridad que antes desaparecía, los Steps 10/12 conservan una **nota** con el rechazo literal y el
Agente 6 la publica como hallazgo informativo. El `--full` ahora respalda la evidencia previa en `/tmp`
porque los `output` del manifest son globs (evidencia vieja puede enmascarar un step `failed` ante `CK-02`).

