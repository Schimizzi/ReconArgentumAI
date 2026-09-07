# Pipeline Orchestration Specification

## Purpose

Define el rol del Orchestrator del pipeline de pentest: los guardrails inquebrantables que gobiernan todas las fases (scope, no-ejecución de exploits, secuencial estricto, evidencia completa, stealth) y la calibración interactiva Fase 0 en la que el usuario aprueba cada comando antes de ejecutarlo.

## Requirements

### Requirement: Restricción estricta de alcance (scope)
El sistema SHALL ejecutar scans únicamente contra los targets autorizados definidos en `config/scope.json`. Todo host descubierto fuera de ese rango SHALL ser registrado como hallazgo `out_of_scope` sin recibir ningún scan adicional.

#### Scenario: Target dentro del alcance
- **WHEN** el pipeline va a ejecutar un comando contra un target
- **THEN** el sistema verifica que el target esté listado en `config/scope.json` antes de ejecutarlo

#### Scenario: Host descubierto fuera del alcance
- **WHEN** un output de scan (ej. Nmap) revela un host que no pertenece a ningún rango autorizado
- **THEN** el sistema lo registra en `manifest.json` bajo `out_of_scope_findings` y NO ejecuta ningún scan sobre ese host

### Requirement: Prohibición de ejecución de exploits
El sistema SHALL NO ejecutar exploits, payloads ofensivos ni acciones destructivas en ninguna fase. La explotación se limita a planes documentados que un humano puede ejecutar fuera del pipeline.

#### Scenario: Plan de explotación generado
- **WHEN** el Agente 3 genera un plan que incluye comandos de explotación
- **THEN** esos comandos quedan únicamente en el documento del plan y no son ejecutados por el sistema

### Requirement: Ejecución secuencial estricta
El sistema SHALL NO ejecutar dos herramientas en paralelo contra el mismo target. Entre cada herramienta completada y la siguiente SHALL aplicarse el delay de stealth definido en `config/stealth.yaml`.

#### Scenario: Transición entre herramientas
- **WHEN** una herramienta termina su ejecución contra un target
- **THEN** el sistema aplica `delay_between_tools_seconds` antes de iniciar la siguiente herramienta

### Requirement: Evidencia completa por target
El sistema SHALL guardar el output COMPLETO de cada herramienta (sin resumir ni filtrar) en `evidence/<target>/`, prefiriendo formato JSON o XML. Si la herramienta no soporta esos formatos, el output completo se guarda en `.txt` y ello se indica en el manifest.

#### Scenario: Herramienta con output JSON/XML nativo
- **WHEN** una herramienta (ej. Nmap, HTTPX, Nuclei) termina con éxito
- **THEN** su output completo se guarda en `evidence/<target>/` en formato JSON y/o XML

#### Scenario: Herramienta sin output estructurado
- **WHEN** una herramienta (ej. Gobuster) no soporta JSON/XML nativo
- **THEN** el output completo se guarda en `.txt` y el manifest lo indica

### Requirement: Calibración interactiva Fase 0
Antes de ejecutar cualquier scan, el sistema SHALL calibrar con el usuario cada una de las 9 herramientas oficiales (Nmap, HTTPX, Nuclei, Nikto, WhatWeb, Gobuster/Dirsearch, SSLyze, IIS Shortname 8.3, SMB Enum/smbclient), en ese orden. Para cada herramienta el sistema SHALL: preguntar si se usa; si sí, preguntar qué escanear (puertos/rangos), el contexto de defensas (WAF/IDS/EDR) y los paths de inputs requeridos; leer el help file correspondiente de `tools/`; presentar el comando propuesto con justificación flag a flag, output esperado y tiempo estimado; y requerir aprobación explícita (APROBAR / MODIFICAR / SALTAR). IIS Shortname y SMB Enum se ejecutan por Service-Based Routing en Fase 1 (solo si el target lo amerita: web+IIS y 139/445 abierto respectivamente).

#### Scenario: Usuario modifica un comando
- **WHEN** el usuario responde MODIFICAR con cambios sobre el comando propuesto
- **THEN** el sistema actualiza el comando y lo re-presenta para aprobación

#### Scenario: Usuario salta una herramienta
- **WHEN** el usuario responde NO al uso de una herramienta
- **THEN** el sistema la registra en `config/approved_commands.md` como `[SALTADO por usuario]` y continúa con la siguiente

#### Scenario: Aprobación del pipeline completo
- **WHEN** las 9 herramientas fueron calibradas (aprobadas o saltadas)
- **THEN** el sistema presenta la lista completa de comandos aprobados y requiere aprobación explícita del pipeline completo antes de iniciar Fase 1

### Requirement: Comandos aprobados como única fuente de ejecución
El sistema SHALL guardar cada comando aprobado en `config/approved_commands.md` y la Fase 1 SHALL ejecutar exclusivamente esos comandos (con sus variables de target resueltas), sin improvisar flags no aprobados.

#### Scenario: Ejecución de Fase 1
- **WHEN** el pipeline ejecuta un step contra un target
- **THEN** el comando ejecutado corresponde exactamente a uno de los comandos aprobados en `config/approved_commands.md`

### Requirement: Ajuste de stealth ante WAF o tarpits
Si el usuario indica presencia de WAF o tarpits durante la Fase 0, el Orchestrator SHALL sugerir reducir los rate-limits y AUMENTAR los timeouts (ej. 15-20s) para evitar falsos negativos causados por el retardo inducido, y reflejar esos valores en `config/stealth.yaml`.

#### Scenario: Usuario reporta tarpits
- **WHEN** el usuario indica en la Fase 0 que hay tarpits o WAF con retardo inducido
- **THEN** el sistema sugiere valores de timeout aumentados (15-20s) y rate-limit reducido, y los aplica en `config/stealth.yaml` antes de proponer comandos
