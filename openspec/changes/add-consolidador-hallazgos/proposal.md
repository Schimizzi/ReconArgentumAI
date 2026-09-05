## Why

Tras consolidar la evidencia con `scripts/organize_project.py` (directorio `CLIENTE/`), no existe un entregable que extraiga y reordene los hallazgos de las herramientas (nuclei, nikto, sslyze, gobuster, nmap, cves.md) en reportes formales listos para pegar evidencia y compartir con el cliente. Se necesita un **Agente 6 (Consolidador de hallazgos)** independiente que genere, por cada target consolidado, un `_resumen_vulnerabilidades.doc` y un `_resumen_breve.txt` con **cero invención** (solo extrae lo que está explícitamente en los archivos fuente).

## What Changes

- Nuevo script independiente **`scripts/make_vuln_report.py`** (stdlib pura, Word-HTML compatible con Word/LibreOffice, sin dependencias nuevas) que:
  - Lee **solo** el directorio `outputs/` de cada target consolidado bajo `<project>/<ip>/`.
  - Escanea dinámicamente los archivos presentes en cada corrida (registro de parsers por patrón + fallback genérico), de modo que **evidencia nueva agregada a `outputs/` se incorpora automáticamente al próximo reporte**.
  - Genera dos archivos por target en la raíz del target: `<target_id>_resumen_vulnerabilidades.doc` y `<target_id>_resumen_breve.txt`.
  - Aplica las reglas del prompt del consolidador: cero invención, severidad solo si está declarada en fuente (`No declarada en fuente` en caso contrario), deduplicación con fuente con más detalle, ofuscación de credenciales con `***`, y confirmación final `✅/⚠️`.
- Nueva spec operativa **`specs/agent_6_consolidador_hallazgos.md`** (Agente 6, Fase 4) con el pipeline de archivos, orden de prioridad y reglas duras.
- **`README.md`**: documento cómo se llama a `scripts/organize_project.py` y luego al agente para generar los dos reportes por target, más un apunte del análisis dinámico de `outputs/`.
- **`.cline/master_prompt.md`**: se agrega la Fase 4 (Consolidación) y la referencia a la spec del Agente 6 en la tabla de recursos.
- **NO se modifica** `scripts/organize_project.py`: el agente es completamente independiente y orquestable por separado.

## Capabilities

### New Capabilities

- `consolidador-hallazgos`: Agente 6 que analiza exclusivamente `outputs/` de cada target consolidado y genera `_resumen_vulnerabilidades.doc` + `_resumen_breve.txt` con cero invención, deduplicación, ofuscación y análisis dinámico de nuevos archivos de evidencia.

### Modified Capabilities

- `reporting`: extiende la cadena de reporte con una etapa posterior a `organize_project.py` que produce los resúmenes formales por target (esta etapa corre de forma independiente sobre el consolidado).

## Impact

- **Scripts**: se agrega `scripts/make_vuln_report.py` (no toca `organize_project.py`).
- **Specs**: se agrega `specs/agent_6_consolidador_hallazgos.md`; se referencia desde `.cline/master_prompt.md` (Fase 4).
- **Docs**: `README.md` documenta el flujo de dos llamadas (organize → agente) y la tabla de opciones del agente.
- **Dependencias**: ninguna nueva (stdlib pura).
- **Salida en disco**: nuevos archivos por target en `<project>/<ip>/` (`{target_id}_resumen_vulnerabilidades.doc`, `{target_id}_resumen_breve.txt`).