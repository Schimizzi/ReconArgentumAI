# `qa_check.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **validador determinista del pipeline** (QA Final). Después de que todos los escaneos, análisis, reportes y consolidación terminaron, este script **verifica mecánicamente** que los 10 requisitos fundamentales del proyecto se cumplan:

- Que los archivos de evidencia estén completos y no corruptos.
- Que los CVEs investigados sean consistentes (sin errores de suma/estructura).
- Que los planes de explotación referencien archivos que realmente existen en disco.
- Que los reportes finales coincidan con el alcance autorizado.
- Que no haya contraseñas, tokens ni secretos en claro en los reportes.
- Que los entregables de la Fase 4 estén generados.

**No alucina, no interpreta, no opina.** Solo ejecuta comprobaciones de sistema (lectura de archivos, parseo de JSON, análisis de texto) y reporta `[PASS]` o `[FAIL]` para cada una.

## ⏱️ ¿Cuándo se usa?

En la **Fase 5 (QA Final)**, justo después de la Fase 4 (Consolidación) y antes de declarar el pipeline como completado. Es la última puerta de control antes de entregar los resultados al usuario.

## ▶️ Cómo se usa

```bash
# Ejecución normal (desde la raíz del proyecto)
python3 scripts/qa_check.py

# Sin argumentos adicionales: lee config/scope.json, evidence/, cve_research/, reports/, plans/

# Filtrar a UN target: solo se evaluan los checks POR TARGET (CK-02/CK-09) de esa IP
SCOPE_FILTER_IP=10.10.10.80 python3 scripts/qa_check.py
```

El script no requiere argumentos. Escanea automáticamente los directorios del proyecto.

## 📥 Entrada / 📤 Salida

- **Entrada:** `config/scope.json`, `evidence/*/manifest.json`, `cve_research/*_cves.json`, `reports/final_report.json`, `reports/*.json`/`.md`, `plans/*_exploitation_plan.md`, entregables F4.
- **Salida:** en consola, líneas con `[PASS]` o `[FAIL]` por cada check, más un resumen final con `X/Y PASS | Y/Z FAIL`.
- **Exit code:** `0` si todos pasaron, `1` si hay al menos un `[FAIL]`.

## ✅ Los 10 checks (CK-01 a CK-10)

| Check | Qué verifica | ¿Bloqueante? |
|---|---|---|
| CK-01 | `scope.json` es válido: al menos un target + `engagement_id`, y **`target_id` únicos y no vacíos** (un id repetido entre targets pisa manifiestos e informes por target) | **🔴 Crítico** — sin eso el pipeline no tiene alcance confiable |
| CK-02 | Por cada target autorizado, los outputs listados en `manifest.json` existen en disco | Parcial — si un target tiene outputs faltantes, se salta |
| CK-03 | Los JSON de evidencia, CVEs y reportes son **legibles**: JSON único, **JSONL** (httpx/nuclei de ProjectDiscovery) o **vacío** (= corrió y no encontró nada, no es corrupción) | Sí |
| CK-04 | En cada `*_cves.json`: `summary.total_cves` coincide con los CVEs listados, y cada CVE tiene `id`, `cvss_score` y `rank_reason` | **🔴 Crítico** — inconsistencia = reporte inválido |
| CK-05 | Cada `*_exploitation_plan.md`: si cita referencias `evidence/...`, todas existen en disco. **Sin refs ⇒ PASS** (no bloqueante, según spec de QA). La extracción ignora la puntuación de cierre (`backtick`, comas, puntos) | **🔴 Crítico** — plan inválido si hay refs rotas |
| CK-06 | `reports/final_report.json` tiene los mismos target_ids que `scope.json` y `summary.targets_count` es correcto (si existe) | Informativo — si no hay reporte, PASS automático |
| CK-07 | Ningún reporte contiene `password=`, `token=`, `secret=`, `api_key=` o `Bearer ` con valor en claro (todo ofuscado con `***`) | Informativo — si no hay reportes, PASS automático |
| CK-08 | Existen archivos `*_resumen_vulnerabilidades.doc` y `*_resumen_breve.txt` de la Fase 4 | Advertencia — puede no aplicar si no se corrió F4 |
| CK-09 | Cada `manifest.json` tiene los **12 steps** del DAG con las herramientas esperadas (Step 11 = `ldap_enum`, Step 12 = `enum4linux`) y estados del vocabulario válido (incluye `skipped_no_ldap` y `skipped_unsupported_os`) | Sí para el contrato (steps/herramientas/estados); informativo si un step 11/12 queda `success` con `output: []` (evidencia condicional descartada) |
| CK-10 | **PHP2Shell (CVE-2026-109618/109619):** por cada `cve_research/<ip>_php2shell.json` con estado `affected` o `eol_sin_parche`, los CVEs del advisory existen en su `_cves.json`. Ese archivo se busca como `<target_id>_cves.json` y, si no existe, como `<ip>_cves.json` (el Agente 4 nombra con el id con que se lo invoca, normalmente la IP) | **🔴 Crítico** — un advisory RCE activo sin reportar bloquea la entrega. Desactivable con `QA_PHP2SHELL_BLOCKING=0` (pasa a aviso) |

## ⚠️ Notas

- **No modifica ningún archivo.** La variable de entorno `SCOPE_FILTER_IP=<IP>` limita los checks por target (CK-02/CK-09) a esa IP. Es 100% de solo lectura.
- **No requiere conexión externa.** Funciona completamente offline.
- **No depende de ningún LLM.** Es Python puro + expresiones regulares.
- Los checks CK-04, CK-05, CK-07 y CK-10 (advisory crítico sin reportar) son **bloqueantes**: si fallan, el pipeline debe detenerse. Los demás (CK-06, CK-08) son informativos o permiten continuar con advertencia.
- **CK-10 se alimenta de `php2shell_audit.py`** (`scripts/php2shell_audit.md`): si todavía no se corrió la auditoría, CK-10 pasa como "no aplica". Si un target tiene PHP sin versión detectada (`unknown_version`), CK-10 **no falla** pero deja el aviso "requiere fingerprint activo".
- **CK-03 acepta JSONL y archivos vacíos:** httpx y nuclei de ProjectDiscovery escriben **un JSON por línea**, y un archivo vacío es evidencia legítima ("el step corrió y no encontró nada"). El check sólo falla ante JSON **ilegible** (y muestra el conteo: `766 archivos OK (631 JSON, 29 JSONL, 106 vacíos)`).
- **CK-01 valida además que los `target_id` sean únicos:** un id duplicado entre dos IPs hace que `cve_research/<id>_cves.json` y el `manifest.json` se sobreescriban mutuamente. Mismo guard en `scripts/host/preflight_run.sh` (fase 1) para fallar antes de escanear.

