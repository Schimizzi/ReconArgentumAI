# `qa_check.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **validador determinista del pipeline** (QA Final). Después de que todos los escaneos, análisis, reportes y consolidación terminaron, este script **verifica mecánicamente** que los 8 requisitos fundamentales del proyecto se cumplan:

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
```

El script no requiere argumentos. Escanea automáticamente los directorios del proyecto.

## 📥 Entrada / 📤 Salida

- **Entrada:** `config/scope.json`, `evidence/*/manifest.json`, `cve_research/*_cves.json`, `reports/final_report.json`, `reports/*.json`/`.md`, `plans/*_exploitation_plan.md`, entregables F4.
- **Salida:** en consola, líneas con `[PASS]` o `[FAIL]` por cada check, más un resumen final con `X/Y PASS | Y/Z FAIL`.
- **Exit code:** `0` si todos pasaron, `1` si hay al menos un `[FAIL]`.

## ✅ Los 8 checks (CK-01 a CK-08)

| Check | Qué verifica | ¿Bloqueante? |
|---|---|---|
| CK-01 | `scope.json` es válido y tiene al menos un target + engagement_id | Sí (sin targets no hay pipeline) |
| CK-02 | Por cada target autorizado, los outputs listados en `manifest.json` existen en disco | Parcial — si un target tiene outputs faltantes, se salta |
| CK-03 | Todos los JSON de evidencia, CVEs y reportes parsean correctamente | Sí |
| CK-04 | En cada `*_cves.json`: `summary.total_cves` coincide con los CVEs listados, y cada CVE tiene `id`, `cvss_score` y `rank_reason` | **🔴 Crítico** — inconsistencia = reporte inválido |
| CK-05 | Cada `*_exploitation_plan.md` contiene referencias a archivos `evidence/...` que existen | **🔴 Crítico** — plan inválido si refs rotas |
| CK-06 | `reports/final_report.json` tiene los mismos target_ids que `scope.json` y `summary.targets_count` es correcto (si existe) | Informativo — si no hay reporte, PASS automático |
| CK-07 | Ningún reporte contiene `password=`, `token=`, `secret=`, `api_key=` o `Bearer ` con valor en claro (todo ofuscado con `***`) | Informativo — si no hay reportes, PASS automático |
| CK-08 | Existen archivos `*_resumen_vulnerabilidades.doc` y `*_resumen_breve.txt` de la Fase 4 | Advertencia — puede no aplicar si no se corrió F4 |

## ⚠️ Notas

- **No modifica ningún archivo.** Es 100% de solo lectura.
- **No requiere conexión externa.** Funciona completamente offline.
- **No depende de ningún LLM.** Es Python puro + expresiones regulares.
- Los checks CK-04, CK-05 y CK-07 son **bloqueantes**: si fallan, el pipeline debe detenerse. Los demás (CK-06, CK-08) son informativos o permiten continuar con advertencia.