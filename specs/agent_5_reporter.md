# Spec operativa — Agente 5: Reporter (Fase 3)

> Instrucción operativa que el **Agente 5** lee ANTES de generar el informe final.
> Complementa: `openspec/changes/add-pentest-recon-pipeline/specs/reporting/spec.md` (contrato formal).
> `<WORKSPACE>` = raíz del proyecto. Todos los paths son relativos a `<WORKSPACE>`.

## 0. Entradas


## 1bis. Informes individuales por target (OBLIGATORIO: uno por target analizado)

- `reports/<target_id>_report.md` — informe humano centrado en UN target.
- `reports/<target_id>_report.json` — machine-readable centrado en UN target.

Cada informe individual SHALL:
1. Cubrir **únicamente** la información de su target (sin secciones globales de otros targets).
2. Incluir las mismas tablas que la sección por target del informe unificado: servicios, vulnerabilidades (ofuscadas), CVEs correlacionados, plan de explotación (resumen + path absoluto) y configuración insegura.
3. Documentar explícitamente si el target es `incomplete`/`no_web` (listas vacías + `risk_score` correspondiente).
4. Ser **coherente** con su entrada homónima en `final_report.json` (mismos `target_id`/`ip`/`risk_score`/`cves`).
5. Ofuscar datos sensibles con `***` igual que el informe unificado (misma regla del §5).
6. Validarse el JSON individual con `python3 -m json.tool` / `jq empty` antes de considerarse generado.

- `config/scope.json` (engagement_id, scope autorizado).
- `evidence/<target>/manifest.json` por cada target.
- `plans/<target_id>_exploitation_plan.md` (si existe).
- `cve_research/<target_id>_cves.json` (si existe).

**Outputs:** `reports/final_report.md` + `reports/final_report.json` (informe unificado) **+** `reports/<target_id>_report.md` + `reports/<target_id>_report.json` (informe individual por cada target analizado).

## 1. Informe dual (OBLIGATORIO: siempre los dos archivos)

- `reports/final_report.md` — informe humano, renderizable como PDF.
- `reports/final_report.json` — machine-readable.

Ambos consolidan la evidencia, los planes de explotación y los CVEs de TODOS los targets del engagement. La sección "Anexos" del MD y el campo `evidence_paths` del JSON incluyen paths **ABSOLUTOS** para trazabilidad completa.

## 2. Estructura de `final_report.md` (en este orden)

1. **Portada / encabezado**: Engagement ID, fechas inicio-fin, scope autorizado.
2. **Resumen ejecutivo**: hallazgos críticos, riesgo global, top-3 recomendaciones.
3. **Alcance y metodología**: tools utilizados (de los manifests), parámetros stealth (de `config/stealth.yaml`), modo de ejecución (secuencial; bifurcación no-web aplicada y en qué targets).
4. **Por target** (una sección por cada target):
   - Tabla de servicios detectados (puerto | servicio | versión | riesgo).
   - Tabla de vulnerabilidades (ID | severidad | descripción | CVE).
   - Tabla de CVEs correlacionados (CVE | CVSS | exploit público | patch disponible).
   - Resumen del plan de explotación + path ABSOLUTO al archivo completo en `plans/`.
   - Hallazgos de configuración insegura.
5. **Matriz de riesgo global por target** (crítico/alto/medio/bajo/score).
6. **Recomendaciones de remediación ordenadas por prioridad**.
7. **Anexos**: paths absolutos de evidencia (`evidence/<target>/`), planes (`plans/`), CVE research (`cve_research/`).

## 3. Esquema de `final_report.json`

```json
{
  "engagement_id": "PENTEST-2025-001",
  "started_at": "<ISO8601>",
  "completed_at": "<ISO8601>",
  "scope": [{"id": "TGT-001", "ip": "10.156.226.156"}],
  "methodology": {
    "tools": ["nmap", "httpx", "nuclei", "nikto", "whatweb", "gobuster", "sslyze"],
    "stealth_params": {"nmap_timing_template": "T2", "nmap_max_rate": 30},
    "execution_mode": "sequential"
  },
  "targets": [
    {
      "id": "TGT-001",
      "ip": "10.156.226.156",
      "services": [],
      "vulnerabilities": [],
      "cves": [],
      "config_issues": [],
      "exploitation_plan_ref": "<abs>/plans/TGT-001_exploitation_plan.md",
      "risk_score": 7.5,
      "out_of_scope_findings": []
    }
  ],
  "summary": {
    "targets_count": 1,
    "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0},
    "total_cves": 5,
    "cves_with_exploit": 3
  },
  "evidence_paths": {"TGT-001": "<abs>/evidence/TGT-001"},
  "out_of_scope": []
}
```

- Los contadores de `summary` DEBEN coincidir con los elementos reales de `targets[]` (verificar consistencia ANTES de escribir el archivo).

## 4. Validación JSON previa (OBLIGATORIA)

Antes de considerar el informe final generado: validar `reports/final_report.json` con un parser (`python3 -m json.tool` o `jq empty`). Si la validación falla → **corregir y revalidar**; un JSON inválido NUNCA es el resultado final de la fase.

## 5. Ofuscación de datos sensibles (regla inquebrantable)

- Cualquier **password, token, credencial, secret o key** que aparezca en claro en la evidencia consolidada y deba reflejarse en el informe → se reemplaza por **`***`**. **Nunca** se incluye el valor original en el informe.
- Aplica por igual al MD y al JSON.
- La evidencia cruda en disco NO se modifica: la redacción con `***` ocurre solo en la copia consolidada del informe.

## 6. Trazabilidad por paths absolutos

Todo hallazgo del informe debe ser trazable hasta su fuente:
- MD → sección "Anexos" + secciones por target.
- JSON → `evidence_paths{}`, `exploitation_plan_ref` y paths de CVE research.