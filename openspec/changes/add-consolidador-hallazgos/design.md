## Context

El pipeline produce evidencia por target en `evidence/<ip>/` y una consolidación en `<project>/<ip>/{data,outputs}` vía `scripts/organize_project.py`. Los outputs consolidados ya incluyen `nuclei.json` (JSONL), `nikto_<port>.json` (listas con `vulnerabilities[]`), `sslyze_<port>.json` (checks con `status`/`result`), `gobuster_*.txt` (líneas), `nmap_detailed.xml` (NSE), `httpx.json` (JSONL), `<target_id>_cves.md` (generado) y potencialmente `evidencia.md`. Ver `specs/agent_6_consolidador_hallazgos.md` para el comportamiento pactado; `scripts/organize_project.py` NO se modifica.

## Goals / Non-Goals

**Goals:**
- Script standalone `scripts/make_vuln_report.py` (stdlib) que escanea `outputs/` de cada target y genera `.doc` + `.txt`.
- Cero invención: cada hallazgo rastreable a archivo + ubicación; severidad solo si está declarada.
- Deduplicación entre fuentes, ofuscación `***`, flags `--project/--target/--dry-run/--no-clobber`.
- Análisis dinámico: nuevos archivos en `outputs/` se incluyen al re-ejecutar sin tocar el script.

**Non-Goals:**
- Modificar `scripts/organize_project.py`.
- Analizar `data/`, `evidence/`, `plans/`, `reports/` o `cve_research/`.
- Generar `.docx` nativo (se usa Word-HTML compatible, sin dependencias nuevas).
- Ejecutar escaneos ni generar evidencia nueva.

## Decisions

- **Word-HTML en lugar de python-docx**: `_resumen_vulnerabilidades.doc` se escribe como documento HTML con extensión `.doc`; Word y LibreOffice lo abren. Evita agregar dependencias (`pip install python-docx`) y mantiene el repo en stdlib pura, coherente con el resto de scripts.
- **Registro de parsers + fallback genérico**: una lista ordenada de `(patrón glob, parser)`; el primero que matchea gana. Los archivos no reconocidos pasan por un parser genérico que:
  - `.json`/`.jsonl` → busca objetos con claves `title/name` + `severity` u `description/msg` (y `id/port/template`), conservando un JSON path como ubicación.
  - `.md`/`.txt` → busca líneas con marcadores explícitos (`CVE-`, `Severity/Severidad:`, `VULN-`, `vulnerab*`, `hallazgo`), con número de línea como ubicación.
  - Sin coincidencias → archivo omitido (regla de cero invención).
- **Entidades de hallazgo**: `{id, titulo, severidad (None si no declarada), descripcion, fuente (ruta relativa), ubicacion, puerto, cve, extra_locations[]}`. La deduplicación normaliza por `cve` o título en minúsculas; la fuente ganadora es la de descripción más larga; las demás se agregan a `extra_locations`.
- **Severidad "declarada"**: se aceptan literales de `info.severity` (nuclei), `Severity:`/`CVSS x (Nivel)` en md/txt, `{severity}` de dicts genéricos. Si la fuente no trae ninguna → `None` → en salida se escribe `No declarada en fuente`.
- **Ofuscación**: mismas regex que `scripts/organize_project.py` (`password/passwd/token/api_key/secret/Bearer/Basic` → `***`).
- **Orden de prioridad de fuentes**: `<target_id>_cves.md` (mayor detalle) → `nuclei.json` → `nikto_*.json` → `sslyze_*.json` → `nmap_detailed.*` (solo scripts NSE de vulnerabilidad) → `gobuster_*.txt` → `httpx.json` (no genera hallazgos por sí mismo; se omite salvo parser genérico con marcadores) → resto.

## Risks / Trade-offs

- [Parsers dependen del formato exacto de las tools] → Conversiones defensivas (dict/listas tolerantes, `errors="ignore"`, líneas corruptas se omiten) y fallback genérico.
- [`.doc` HTML puede abrirse con aviso en Word] → Se incluye metadata mínima y se documenta que LibreOffice/Word lo aceptan; el `.txt` queda siempre como respaldo portable.
- [Dedupe por título normalizado puede fusionar hallazgos distintos con texto idéntico] → Se exige además puerto igual cuando exista; se mantiene `extra_locations` para trazabilidad.
- [`--dry-run` no valida contenido] → Solo previsualiza estructura; el contenido se valida en la corrida real.

## Migration Plan

1. Agregar `scripts/make_vuln_report.py` (no afecta scripts existentes).
2. Agregar `specs/agent_6_consolidador_hallazgos.md` y referenciarla desde `.cline/master_prompt.md` (Fase 4) y el README.
3. Uso: `python3 scripts/organize_project.py` → `python3 scripts/make_vuln_report.py` para producir los reportes por target.
4. Rollback: eliminar los 2 archivos nuevos; nada existente se modifica.