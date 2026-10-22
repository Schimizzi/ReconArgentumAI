# Pipeline Orchestration Specification

## Purpose

Define el rol del Orchestrator del pipeline de pentest: los guardrails inquebrantables que
gobiernan todas las fases (scope, no-ejecución de exploits, secuencial estricto, evidencia
completa, stealth) y la calibración interactiva Fase 0 en la que el usuario aprueba cada comando
antes de ejecutarlo. Desde los Steps 11/12 (LDAP Enum y Enum4linux) la calibración cubre **11 herramientas
oficiales**.

## MODIFIED Requirements

### Requirement: Calibración interactiva Fase 0
Antes de ejecutar cualquier scan, el sistema SHALL calibrar con el usuario cada una de las 11
herramientas oficiales (Nmap, HTTPX, Nuclei, Nikto, WhatWeb, Gobuster/Dirsearch, SSLyze, IIS
Shortname 8.3, SMB Enum/smbclient, LDAP Enum/ldapsearch, Enum4linux/enum4linux-ng), en ese orden. Para cada herramienta el
sistema SHALL: preguntar si se usa; si sí, preguntar qué escanear (puertos/rangos), el contexto de
defensas (WAF/IDS/EDR) y los paths de inputs requeridos; leer el help file correspondiente de
`tools/`; presentar el comando propuesto con justificación flag a flag, output esperado y tiempo
estimado; y requerir aprobación explícita (APROBAR / MODIFICAR / SALTAR). IIS Shortname, SMB Enum, LDAP Enum y
Enum4linux se ejecutan por Service-Based Routing en Fase 1 (solo si el target lo amerita: web+IIS o
139/445 abierto, respectivamente). LDAP Enum corre en Linux y macOS; LDAP Enum corre en Linux y macOS; Enum4linux aplica **solo en Linux**: en macOS se registra como
`[SALTADO: no aplica en macOS]`.

#### Scenario: Usuario modifica un comando
- **WHEN** el usuario responde MODIFICAR con cambios sobre el comando propuesto
- **THEN** el sistema actualiza el comando y lo re-presenta para aprobación

#### Scenario: Usuario salta una herramienta
- **WHEN** el usuario responde NO al uso de una herramienta
- **THEN** el sistema la registra en `config/approved_commands.md` como `[SALTADO por usuario]` y continúa con la siguiente

#### Scenario: Aprobación del pipeline completo
- **WHEN** las 11 herramientas fueron calibradas (aprobadas o saltadas)
- **THEN** el sistema presenta la lista completa de comandos aprobados y requiere aprobación explícita del pipeline completo antes de iniciar Fase 1

#### Scenario: Calibración en macOS
- **WHEN** la Fase 0 corre en macOS
- **THEN** Enum4linux se presenta como `[SALTADO: no aplica en macOS]` porque el Step 12 no se ejecuta en ese SO
