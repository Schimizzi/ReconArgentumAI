# `cves_md.py` — Qué hace (guía sin saber de código)

> 🖐️ **USO MANUAL — FUERA DEL PIPELINE AUTOMATIZADO (2026-10-22).** Este script **no** es invocado por
> ningún step ni agente del pipeline (0 imports / 0 llamadas a `build_cves_md`). Se conserva como utilidad
> **opcional a demanda**. El flujo actual arma los entregables con `organize_project.py`.

## 🧩 ¿Qué es?

Es una **utilidad de conversión opcional**: convierte la investigación de vulnerabilidades (CVE),
que queda en un archivo técnico (JSON), a un documento **Markdown** (`<objetivo>_cves.md`)
con tablas y secciones que se entienden mejor.

**Nota:** en el flujo actual el script **no forma parte del pipeline**. `organize_project.py` **no**
lo invoca (lee el JSON de `cve_research/` solo para contar CVEs en el `README.md`, pero no renderiza
el Markdown). `build_cves_md()` queda disponible como API para generarlo manualmente si se desea.

## ⏱️ ¿Cuándo se usa?

**A mano / a demanda.** No lo llama ninguno de los scripts del pipeline actual. Si algún día se
quiere volver a generar `<objetivo>_cves.md` a partir del JSON, se usa esta utilidad (p. ej.
importando `build_cves_md(target_id, cve_data)`).

## 📥 Entrada / 📤 Salida

- **Entrada:** el JSON de investigación CVE de un objetivo (`cve_research/<target>_cves.json`).
- **Salida:** texto Markdown para el archivo `<target>_cves.md`, con:
  - Resumen (total de CVEs, críticos, altos, con exploit público…).
  - Tabla de CVEs por servicio y por tecnología web.
  - Detalle de cada CVE (descripción, versiones afectadas, versión parcheada, PoCs, enlaces).

## ⚠️ Notas

- Este **no modifica el JSON original**: solo genera el documento legible a partir de él.
- Ofusca (oculta con `***`) datos sensibles y escapa caracteres especiales antes de escribirlos.