# QA Validation Specification

## Purpose

Define el **Agente 7 (QA Final)**: un script determinista (`scripts/qa_check.py`) que verifica mecánicamente la consistencia, integridad y trazabilidad de todos los artefactos generados por el pipeline antes de declarar el pipeline como completado. Este agente NO usa LLM — ejecuta comprobaciones de sistema (parseo JSON, existencia de archivos, expresiones regulares) y reporta PASS/FAIL por cada check.

## Requirements

### Requirement: Ejecución post-Fase 4

El QA SHALL ejecutarse después de que la Fase 4 (Consolidación) haya completado exitosamente, y antes de que el Orchestrator emita el mensaje de pipeline completado.

#### Scenario: QA después de Fase 4
- **WHEN** la Fase 4 termina con éxito
- **THEN** el ReporterBot ejecuta `python3 scripts/qa_check.py`
- **AND** el Orchestrator espera la respuesta antes de informar al usuario

### Requirement: CK-01 — Validez del scope.json

El QA SHALL verificar que `config/scope.json` contenga `engagement_id` válido no vacío, y que `authorized_targets[]` tenga al menos un elemento.

#### Scenario: scope.json sin targets
- **WHEN** `config/scope.json` tiene `authorized_targets` vacío
- **THEN** el QA emite `[FAIL] CK-01` y el pipeline SHALL detenerse

#### Scenario: scope.json válido
- **WHEN** `config/scope.json` tiene engagement_id y ≥1 target
- **THEN** el QA emite `[PASS] CK-01`

### Requirement: CK-02 — Existencia de outputs físicos

Para cada target autorizado, el QA SHALL abrir `evidence/<IP>/manifest.json`, y para cada tool con `status:success` verificar que cada archivo en `output[]` exista físicamente.

#### Scenario: Output faltante
- **WHEN** un output listado en manifest no existe en disco
- **THEN** el QA emite `[FAIL] CK-02` con el archivo faltante (target parcial, continua)

#### Scenario: Todos OK
- **WHEN** todos los outputs existen
- **THEN** el QA emite `[PASS] CK-02`

### Requirement: CK-03 — Parseo JSON global

El QA SHALL cargar todos los JSONs (`evidence/*/`, `cve_research/`, `reports/`) con `json.load()`. Si alguno falla, FAIL.

#### Scenario: JSON inválido
- **WHEN** un JSON no parsea
- **THEN** `[FAIL] CK-03` con ruta y error

#### Scenario: Todos válidos
- **WHEN** todos parsean
- **THEN** `[PASS] CK-03 N JSONs válidos`

### Requirement: CK-04 — Consistencia de CVEs (crítico, bloqueante)

Para cada `cve_research/<id>_cves.json`, el QA SHALL: (1) verificar que `summary.total_cves` coincida con el conteo real de CVEs en `services_analyzed[].cves[]` + `web_technologies[].cves[]`; (2) verificar que cada CVE tenga `id`, `cvss_score` y `rank_reason`.

#### Scenario: Inconsistencia en CVEs
- **WHEN** `summary.total_cves` difiere del real, o un CVE no tiene campos requeridos
- **THEN** `[FAIL] CK-04` **BLOQUEANTE** → pipeline DETENIDO

#### Scenario: CVEs consistentes
- **WHEN** todos los checks de consistencia pasan
- **THEN** `[PASS] CK-04`

### Requirement: CK-05 — Trazabilidad del plan de explotación

El QA SHALL leer cada `plans/*_exploitation_plan.md`, extraer referencias a `evidence/` mediante regex, y verificar que existan en disco.

#### Scenario: Plan con referencias rotas
- **WHEN** hay refs a archivos inexistentes
### Requirement: CK-07 — Ausencia de secretos en claro (crítico, bloqueante)

El QA SHALL aplicar regex sobre `reports/*.json` y `reports/*.md` para detectar `password=`, `passwd=`, `secret=`, `token=`, `api_key=`, `Bearer `. Si el valor capturado NO contiene `***`, FAIL.

#### Scenario: Secreto sin ofuscar
- **WHEN** un patrón coincide con valor sin `***`
- **THEN** `[FAIL] CK-07` **BLOQUEANTE** — fuga de datos, pipeline DETENIDO

#### Scenario: Todos ofuscados
- **WHEN** ningún valor está en claro
- **THEN** `[PASS] CK-07`

### Requirement: CK-08 — Existencia de deliverables F4

El QA SHALL buscar archivos `*_resumen_vulnerabilidades.doc` y `*_resumen_breve.txt` en subdirectorios de nivel 2 del workspace. Si existen, PASS; si no, PASS con nota.

#### Scenario: Entregables existen
- **WHEN** se encuentran archivos de resumen
- **THEN** `[PASS] CK-08` con conteo

### Requirement: Salida parseable y exit code

El QA SHALL imprimir resultados en formato `[PASS]/[FAIL] CK-0X <detalle>`, terminando con `RESUMEN: X/Y PASS | Y/Z FAIL`. Exit code 0 si todos PASS, 1 si hay FAIL.

#### Scenario: Formato de salida
- **WHEN** el script termina
- **THEN** su salida sigue el formato especificado
- **AND** exit code = 0 (PASS) o 1 (FAIL)

### Requirement: No modificación de archivos

El QA SHALL ser 100% de solo lectura. NO crea, modifica, mueve ni elimina ningún archivo.

#### Scenario: Ejecución sin efectos secundarios
- **WHEN** el script se ejecuta
- **THEN** ningún archivo del workspace cambia
- **THEN** `[FAIL] CK-05` (no bloqueante, canal continua)

#### Scenario: Plan sin refs o sin planes
- **WHEN** no hay referencias o no hay planes
- **THEN** `[PASS] CK-05`

### Requirement: CK-06 — Consistencia del reporte final (crítico, bloqueante)

El QA SHALL verificar que `reports/final_report.json`: `summary.targets_count` == len(targets[]), y targets[].ids coinciden con authorized_targets[].id del scope.

#### Scenario: Inconsistencia
- **WHEN** targets_count no coincide o hay IDs extraños/faltantes
- **THEN** `[FAIL] CK-06` **BLOQUEANTE** → pipeline DETENIDO

#### Scenario: Reporte consistente
- **WHEN** targets_count coincide y target_ids son subconjunto de scope
- **THEN** `[PASS] CK-06`