# Reporting Specification

## Purpose

Define el Agente 5 reporter: consolida la evidencia de todos los targets, los planes de explotación y el CVE research en un informe final dual — Markdown legible por humanos (PDF-ready) y JSON machine-readable válido — con matriz de riesgo global, recomendaciones ordenadas por prioridad y redacción de datos sensibles.

## Requirements

### Requirement: Informe final dual
El Agente 5 SHALL generar dos archivos: `reports/final_report.md` (informe humano, renderizable como PDF) y `reports/final_report.json` (machine-readable), consolidando evidencia, planes de explotación y CVEs de todos los targets del engagement.

#### Scenario: Engagement con múltiples targets
- **WHEN** el pipeline completó 2 targets
- **THEN** ambos informes incluyen una sección por target y un resumen global que cubre los dos

### Requirement: Informes individuales por target
El Agente 5 SHALL generar, además del informe unificado, un reporte individual por cada target del engagement: `reports/<target_id>_report.md` y `reports/<target_id>_report.json`. El reporte individual SHALL contener únicamente la información pertinente a ese target (servicios, vulnerabilidades, CVEs, plan de explotación y configuración), sin secciones globales de otros targets.

#### Scenario: Engagement con múltiples targets
- **WHEN** el engagement tiene N targets analizados
- **THEN** el Agente 5 genera N pares `reports/<target_id>_report.md` + `reports/<target_id>_report.json` (uno por target), y `final_report.md`/`final_report.json` los agrupa a todos

#### Scenario: Target sin hallazgos (incomplete)
- **WHEN** un target es `incomplete` o sin servicios detectados
- **THEN** su reporte individual se genera igualmente, documentando el estado (incomplete/no_web), con listas vacías y el `risk_score` correspondiente

### Requirement: Estructura del informe Markdown individual
`<target_id>_report.md` SHALL contener: encabezado con Engagement ID, target id/IP y fechas; resumen ejecutivo del target (riesgo del target, hallazgos clave); tabla de servicios detectados (puerto/servicio/versión); tabla de vulnerabilidades (ID/severidad/descripción); tabla de CVEs correlacionados (CVE/CVSS/exploit público/patch/rank_reason); resumen del plan de explotación con referencia al archivo completo; hallazgos de configuración insegura; y paths absolutos de evidencia de ese target.

#### Scenario: Target con hallazgos
- **WHEN** el target tiene servicios, vulnerabilidades o CVEs
- **THEN** su `_report.md` individual los lista en las tablas correspondientes, con la credencial redactada y referencia al plan

#### Scenario: Target sin hallazgos
- **WHEN** el target no tiene servicios ni vulnerabilidades
- **THEN** el `_report.md` individual documenta el estado (incomplete/no_web) con listas vacías y score correspondiente

### Requirement: Estructura del informe Markdown
`final_report.md` SHALL contener: Engagement ID, fechas y scope; resumen ejecutivo (hallazgos críticos, riesgo global, top-3 recomendaciones); alcance y metodología (tools usados, parámetros stealth, modo de ejecución); por target: tabla de servicios detectados (puerto/servicio/versión/riesgo), tabla de vulnerabilidades (ID/severidad/descripción/CVE), tabla de CVEs correlacionados (CVE/CVSS/exploit público/patch), resumen del plan de explotación con referencia al archivo completo, y hallazgos de configuración insegura; matriz de riesgo global por target (crítico/alto/medio/bajo/score); recomendaciones de remediación ordenadas por prioridad; y anexos con paths absolutos de evidencia, planes y CVE research.

#### Scenario: Referencia a plan completo
- **WHEN** un target tiene plan de explotación en `plans/`
- **THEN** la sección del target incluye un resumen y el path absoluto al plan completo

### Requirement: Estructura del informe JSON
`final_report.json` SHALL contener: `engagement_id`, timestamps de inicio/fin, `scope[]`, `methodology` (tools, stealth_params, execution_mode), `targets[]` (id, ip, services[], vulnerabilities[], cves[], config_issues[], exploitation_plan_ref, risk_score, out_of_scope_findings[]), `summary` (totales de targets y hallazgos por severidad, CVEs totales y con exploit), `evidence_paths` (target → path absoluto) y `out_of_scope[]`.

#### Scenario: Consistencia del resumen
- **WHEN** el informe JSON se genera
- **THEN** los contadores de `summary` coinciden con los elementos reales de `targets[]`

### Requirement: Estructura del informe JSON individual
`<target_id>_report.json` SHALL contener: `engagement_id`, `target_id`, `ip`, timestamps de inicio/fin del target, `services[]`, `vulnerabilities[]`, `cves[]`, `config_issues[]`, `exploitation_plan_ref`, `risk_score`, `out_of_scope_findings[]` y `evidence_path` (path absoluto de la evidencia de ese target). Los mismos campos SHALL ser un subconjunto coherente de la entrada correspondiente en `targets[]` del `final_report.json`.

#### Scenario: Coherencia individual vs unificado
- **WHEN** el reporte individual se genera
- **THEN** su `target_id`/`ip`/`risk_score`/`cves` coinciden con la entrada homónima en `final_report.json`

### Requirement: Validez del JSON
El Agente 5 SHALL validar que `final_report.json` sea JSON válido antes de considerarlo generado; un archivo inválido no se deja como resultado final.

#### Scenario: JSON inválido detectado
- **WHEN** la validación del JSON falla
- **THEN** el Agente 5 corrige y revalida antes de finalizar la fase

### Requirement: Redacción de datos sensibles
El Agente 5 SHALL redactar con `***` cualquier dato sensible en claro (passwords, tokens, credenciales) que aparezca en la evidencia consolidada.

#### Scenario: Credencial encontrada en evidencia
- **WHEN** un output de recon contiene una credencial en claro
- **THEN** el informe la muestra como `***` y no incluye el valor original

### Requirement: Paths absolutos de evidencia
Ambos informes SHALL incluir los paths absolutos de la evidencia completa (`evidence/`), los planes de explotación (`plans/`) y el CVE research raw (`cve_research/`), para que cualquier hallazgo sea trazable hasta su fuente.

#### Scenario: Trazabilidad de un hallazgo
- **WHEN** un lector del informe quiere verificar un finding
- **THEN** puede localizar el archivo de evidencia original a partir del path incluido en el informe
