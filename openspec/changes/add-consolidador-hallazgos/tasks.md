## 1. Specs y documentación

- [x] 1.1 Crear `specs/agent_6_consolidador_hallazgos.md` (spec operativa del Agente 6) alineada a `openspec/changes/add-consolidador-hallazgos/specs/consolidador-hallazgos/spec.md`
- [x] 1.2 Actualizar `.cline/master_prompt.md`: agregar Fase 4 (Consolidación — Agente 6) y la referencia en la tabla de recursos
- [x] 1.3 Actualizar `README.md`: arquitectura de agentes (5 → 6), estructura del proyecto e instrucciones de las dos llamadas (organize + agente)

## 2. Script standalone `scripts/make_vuln_report.py`

- [x] 2.1 Implementar CLI (`--project`, `--target`, `--dry-run`, `--no-clobber`) y resolución de targets (subcarpetas de `<project>/` con `outputs/`)
- [x] 2.2 Implementar helpers de ofuscación (`***`) y utilidades JSON/JSONL defensivas
- [x] 2.3 Implementar parsers específicos: `<target_id>_cves.md`, `nuclei.json`, `nikto_*.json`, `sslyze_*.json`, `nmap_detailed.*`, `gobuster_*.txt`, `httpx.json`
- [x] 2.4 Implementar parser genérico de respaldo para archivos no reconocidos (json/jsonl con title/severity/description; md/txt con marcadores)
- [x] 2.5 Implementar deduplicación entre fuentes (más detalle textual como fuente principal + `extra_locations`)
- [x] 2.6 Implementar generador `.doc` Word-HTML (cabecera, sección por VULN con espacio de evidencia, tabla resumen)
- [x] 2.7 Implementar generador `.txt` (una línea por hallazgo: `VULN-00X | título (Severidad: X) | fuente → ubicación`)
- [x] 2.8 Implementar mensajes de confirmación `✅/⚠️` por target

## 3. Validación

- [x] 3.1 Correr `python3 scripts/make_vuln_report.py --dry-run --project CLIENTE` contra un target real y revisar estructura planificada
- [x] 3.2 Correr el script (sin dry-run) contra un target real y verificar `.doc` + `.txt` generados
- [x] 3.3 Verificar deduplicación (mismo CVE reportado por nuclei y cves.md → una sola entrada con referencia secundaria)
- [x] 3.4 Agregar un archivo de prueba con hallazgos a un `outputs/` temporal, re-ejecutar y confirmar inclusión dinámica; luego eliminarlo
- [x] 3.5 Verificar `--no-clobber` y comportamiento con N = 0 (aviso `⚠️` sin archivos)