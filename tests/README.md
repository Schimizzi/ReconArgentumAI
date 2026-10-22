# tests/ — Pruebas de regresión (deterministas, sin tráfico)

> Pruebas locales que **no** escanean red ni dependen de un LLM. Se ejecutan a mano antes/después de
> tocar el pipeline. Complementan (no reemplazan) a `scripts/qa_check.py` (Fase 5).

| Test | Qué valida | Requiere |
|---|---|---|
| `test_agente4_field_evidence.py` | Regresión del **Agente 4** (`cve_research_vulnx.py`): la versión de campo (`php2shell_*`) prevalece sobre la del escaneo, `implied_by` (Drupal/DokuWiki→PHP), guardas del advisory (affected/patched/unknown_version) y no-invención de PHP | Evidencia local (`evidence/10.10.12.127`, `evidence/10.10.10.203`), `config/advisories/` |

## Cómo correr

```bash
# Test aislado (standalone, sin pytest):
python3 tests/test_agente4_field_evidence.py

# Si hay evidencia local, espera: RESULT: 16 PASS | 0 FAIL (exit 0).
# En un clon sin evidencia (gitignored) hace SKIP con exit 0.
```

## Notas

- Los tests usan paths **relativos al repo** (`WS = <repo>/`), no absolutos.
- No forman parte del pipeline de producción; son red de seguridad de mantenimiento.
- Agregar nuevos tests aquí, un archivo por área (Agente 3, Agente 4, Steps 11/12, etc.).
