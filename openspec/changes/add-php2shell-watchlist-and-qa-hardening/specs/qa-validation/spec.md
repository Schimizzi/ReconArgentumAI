# QA Validation Specification

## MODIFIED Requirements

### Requirement: CK-01 — Validez del scope.json

El QA SHALL verificar que `config/scope.json` contenga `engagement_id` válido no vacío, que
`authorized_targets[]` tenga al menos un elemento, y que **cada `target_id` sea único y no vacío**
(el id es la clave de los artefactos por target: `manifest.json`,
`cve_research/<id>_cves.json`, `plans/<id>_exploitation_plan.md`; un id repetido entre dos IPs hace
que esos artefactos se sobreescriban mutuamente y rompe la trazabilidad del engagement).

#### Scenario: scope.json sin targets

- **WHEN** `config/scope.json` tiene `authorized_targets` vacío
- **THEN** el QA emite `[FAIL] CK-01` y el pipeline SHALL detenerse

#### Scenario: scope.json válido

- **WHEN** `config/scope.json` tiene engagement_id y ≥1 target
- **THEN** el QA emite `[PASS] CK-01`

#### Scenario: target_id duplicados

- **WHEN** dos o más entradas de `authorized_targets[]` comparten `id` (ej. cuatro IPs con
  `S-10.10.10.80`)
- **THEN** el QA emite `[FAIL] CK-01` **BLOQUEANTE**, nombrando los ids repetidos, y el pipeline
  SHALL detenerse hasta corregir el scope

#### Scenario: target sin id

- **WHEN** una entrada de `authorized_targets[]` no tiene `id` o está vacío
- **THEN** el QA emite `[FAIL] CK-01` **BLOQUEANTE** indicando la IP afectada

### Requirement: CK-03 — Parseo JSON global

El QA SHALL verificar que todos los archivos JSON de la evidencia, la investigación CVE y los
reportes sean **legibles**, aceptando tres formas válidas: (1) JSON único, (2) **JSONL** (una línea
= un JSON, formato de `httpx.json`/`nuclei.json` de ProjectDiscovery) y (3) **archivo vacío**, que es
evidencia legítima ("el step corrió y no encontró nada"; el estado real está en `manifest.json`). El
QA SHALL fallar **sólo** cuando un archivo contiene JSON ilegible, reportando ruta y error.

#### Scenario: JSON inválido

- **WHEN** un archivo JSON no parsea ni como JSON único ni como JSONL
- **THEN** `[FAIL] CK-03` con ruta y error

#### Scenario: Todos válidos

- **WHEN** todos los archivos parsean (o están vacíos)
- **THEN** `[PASS] CK-03` informando el desglose, ej. `766 archivos OK (631 JSON, 29 JSONL, 106 vacíos)`

#### Scenario: JSONL de ProjectDiscovery

- **WHEN** un `httpx.json`/`nuclei.json` contiene varios objetos JSON, uno por línea
- **THEN** `[PASS] CK-03` (no se reporta "Extra data" como corrupción)

### Requirement: CK-05 — Trazabilidad del plan de explotación (crítico, bloqueante)

El QA SHALL leer cada `plans/*_exploitation_plan.md`, extraer referencias a `evidence/` mediante
regex, y verificar que existan en disco. La extracción SHALL descartar la puntuación de cierre
(backtick, comas, puntos, paréntesis, comillas) para no contar como "ref rota" el delimitador del
propio Markdown.

#### Scenario: Plan con referencias rotas (crítico, bloqueante)

- **WHEN** hay refs a archivos inexistentes
- **THEN** `[FAIL] CK-05` **BLOQUEANTE** → pipeline DETENIDO

#### Scenario: Referencia citada entre backticks (no es ref rota)

- **WHEN** el plan cita `` `evidence/<ip>/php2shell_summary.txt` `` con backticks de cierre
- **THEN** `[PASS] CK-05`: la ref se valida como `evidence/<ip>/php2shell_summary.txt` (el backtick de
  cierre no forma parte de la ruta)

#### Scenario: Plan sin refs o sin planes

- **WHEN** el plan no tiene referencias a `evidence/` o no hay planes generados
- **THEN** `[PASS] CK-05`, dejando constancia en el detalle de que el plan no tiene trazabilidad
  (no bloqueante, según este requirement)

## ADDED Requirements

### Requirement: CK-09 — Contrato del DAG de recon (12 steps)

El QA SHALL (por cada `manifest.json` de un target autorizado) verificar que `tools_executed`
contenga **exactamente los 12 steps** del DAG con la herramienta esperada por step
(Step 11 = `ldap_enum`, Step 12 = `enum4linux`) y que cada `status` pertenezca al vocabulario válido
(`success`, `failed`, `skipped`, `skipped_no_ports`, `skipped_no_web`, `skipped_no_domain`,
`skipped_no_tftp`, `skipped_no_tls`, `skipped_no_iis`, `skipped_no_smb`, `skipped_no_ldap`,
`skipped_unsupported_os`). Los steps 11/12 con `status: success` y `output: []` SHALL registrarse
como aviso (evidencia condicional descartada), no como fallo del contrato.

#### Scenario: Contrato cumplido

- **WHEN** cada manifest listado tiene 12 steps con la herramienta y el estado esperados
- **THEN** `[PASS] CK-09`

#### Scenario: Manifest de un run anterior al DAG de 12 steps

- **WHEN** un manifest tiene 10 u 11 steps (run previo a los Steps 11/12)
- **THEN** `[FAIL] CK-09` y el pipeline requiere re-ejecutar la Fase 1 de ese target

### Requirement: CK-10 — Advisory crítico sin reportar (PHP2Shell)

El QA SHALL, para cada `cve_research/<target_id>_php2shell.json` con `php.status` en
`{affected, eol_sin_parche}`, verificar que **todos** los CVEs del advisory
(`advisory_cves[]`, hoy `CVE-2026-109618` y `CVE-2026-109619`) aparezcan en
`cve_research/<target_id>_cves.json` (el artefacto que consumen el Agente 6 y los entregables). Si
falta alguno ⇒ `[FAIL] CK-10` **BLOQUEANTE**. Los estados `patched` y `no_php_evidence` SHALL pasar;
`unknown_version` SHALL pasar dejando un aviso de que el target requiere fingerprint activo. El
check SHALL poder degradarse a aviso con `QA_PHP2SHELL_BLOCKING=0`.

#### Scenario: Advisory crítico sin reportar

- **WHEN** el target está afectado (`affected` o `eol_sin_parche`) y su `_cves.json` no contiene los
  CVEs del advisory
- **THEN** `[FAIL] CK-10` **BLOQUEANTE** (detalle: target, versión de PHP, estado y CVEs faltantes)

#### Scenario: Advisory reportado

- **WHEN** los CVEs del advisory están presentes en el `_cves.json` del target (los inyecta el Agente 4
  con `--advisories`)
- **THEN** `[PASS] CK-10`

#### Scenario: Versión de PHP no detectada

- **WHEN** el target queda `unknown_version` (ej. Drupal sobre IIS que oculta el banner)
- **THEN** `[PASS] CK-10` con aviso "requiere fingerprint activo" (no se listan CVEs de versiones no
  detectadas)

#### Scenario: Sin auditoría PHP2Shell

- **WHEN** no existe ningún `cve_research/*_php2shell.json`
- **THEN** `[PASS] CK-10` ("no aplica")
