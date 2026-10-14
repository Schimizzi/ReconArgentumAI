# `cve_research_vulnx.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el script del **Agente 4 (CVE Research)** de la Fase 2. Su trabajo es, para cada **servicio**
detectado por Nmap (con su versión) y cada **tecnología web** detectada por WhatWeb, buscar las
**vulnerabilidades conocidas (CVE)** que los afectan y quedarse solo con las más relevantes.

Ya **no** consulta cada fuente por separado (NVD, Exploit-DB, avisos de fabricante, GitHub…): usa
**una sola herramienta**, `vulnx` de ProjectDiscovery, que reúne todas esas fuentes en una única
consulta. Reemplaza a los antiguos `nvd_query.py` y `nvd_cve_detail.py`, **eliminados** del
proyecto en la migración a `vulnx` (recuperables desde el historial de git si hicieran falta).

## ⏱️ ¿Cuándo se usa?

En la **Fase 2 (Análisis)**, cuando ya existe la evidencia de un objetivo escaneado
(`nmap_detailed.json` y, si hay web, `whatweb.json` + `nuclei.json`). Se ejecuta **una vez por
objetivo** y deja el resultado listo para que lo consuman el Agente 6 (entregables `.doc`/`.txt`
por target) y la Fase 5 (QA determinista, check CK-04). Necesita **internet** (consulta la nube de ProjectDiscovery).

## ▶️ Cómo se usa

```bash
python3 scripts/cve_research_vulnx.py \
    --target-id TGT-001 \
    --target-ip 10.0.0.1 \
    --nmap evidence/10.0.0.1/nmap_detailed.json \
    --whatweb evidence/10.0.0.1/whatweb.json \
    --nuclei evidence/10.0.0.1/nuclei.json \
    [--output cve_research/TGT-001_cves.json] \
    [--dry-run]
```

| Opción | ¿Obligatoria? | Qué hace |
|---|---|---|
| `--target-id` | Sí | ID del objetivo (ej. `TGT-001`) |
| `--target-ip` | Sí | IP del objetivo |
| `--nmap` | Sí | Path a `nmap_detailed.json` (de donde saca servicios + versiones) |
| `--whatweb` | No | Path a `whatweb.json` (tecnologías web) |
| `--nuclei` | No | Path a `nuclei.json` (para marcar lo que Nuclei ya encontró) |
| `--output` | No | Path de salida (por defecto `cve_research/<target_id>_cves.json`) |
| `--dry-run` | No | Muestra el resumen y **no** escribe el JSON |

Antes de usarlo, `vulnx` tiene que estar instalado (una sola vez):

```bash
go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest

# Opcional: elimina los límites de velocidad de la API
export PDCP_API_KEY="<tu-api-key>"   # se obtiene en https://cloud.projectdiscovery.io
```

## 📥 Entrada / 📤 Salida

- **Entradas:**
  - `evidence/<target>/nmap_detailed.json` → servicios y versiones.
  - `evidence/<target>/whatweb.json` → tecnologías web (opcional).
  - `evidence/<target>/nuclei.json` → CVEs ya detectados por Nuclei (opcional).
- **Salida:** `cve_research/<target_id>_cves.json` — el mismo formato que ya consumen
  `scripts/organize_project.py` (Fase 4 — consolidación) y `scripts/qa_check.py`
  (Fase 5 — chequeo determinista CK-04, validación de CVEs):
  - `services_analyzed` → CVEs por servicio (con su `port`).
  - `web_technologies` → CVEs por tecnología web.
  - `source_omissions` → servicios que quedaron sin datos.
  - `summary` → totales por severidad, con exploit público y con parche disponible.

## 🧷 Reglas internas (cómo decide qué CVEs mostrar)

Sirve saberlo aunque no programes, porque explica el contenido del JSON:

- **Solo CVEs con CVSS ≥ 4.0** (se descartan los informativos o menores).
- Como máximo **Top 5** por servicio; si hay menos de 3, muestra los que haya.
- Orden estricto: **(1)** tiene exploit público verificado (`is_poc`) → **(2)** impacto crítico de
  acceso (RCE, SQLi, bypass de autenticación…) → **(3)** puntaje CVSS más alto como desempate.
- Cada CVE lleva un **`rank_reason`** obligatorio que explica por qué entró al top.
- Si Nuclei ya había encontrado ese CVE, se marca `already_found_by_nuclei: true` (evita repetirlo
  en el informe).

## ⚠️ Notas

- **Timeout de 30 segundos por consulta**: si `vulnx` no responde, ese servicio se omite (queda
  registrado en `source_omissions`) y la búsqueda sigue con el resto.
- **Nunca inventa CVEs**: todo registro proviene de `vulnx search` + `vulnx id`. Sin fuente, no se
  lista.
- Si `vulnx` no está en el PATH, el script corta con un error claro indicando cómo instalarlo (no
  hay vuelta atrás automática a la API NVD directa).
- Al final **valida la consistencia**: el `summary` debe coincidir con los CVEs listados y todos
  los CVEs deben tener `rank_reason`.
- La API de ProjectDiscovery funciona sin credenciales, pero sujeta a límites de velocidad; con
  `PDCP_API_KEY` desaparecen.
- Spec operativa relacionada: `specs/agent_4_cve_research.md` (Agente 4).
