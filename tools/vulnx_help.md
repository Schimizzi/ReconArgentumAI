# VULNX - Reference Help
> FUENTE: README oficial de ProjectDiscovery vulnx
> (https://github.com/projectdiscovery/vulnx) — consultado 2026-10-19.
> NOTA 2026-10-19: comandos VERIFICADOS localmente con **vulnx v2.0.2**
> (`vulnx --help`, `vulnx search --help`, `vulnx id --help`). La CLI real tiene
> flags de filtro dedicados que el README no lista (ver sección "v2.0.2 — FLAGS VERIFICADOS").
> Nota: en el pipeline NO es una de las 9 tools de recon de Fase 1. Se usa como
> motor del **Agente 4 (CVE Research)** (`scripts/cve_research_vulnx.py`, Fase 2)
> para buscar CVEs por producto+versión (NVD + Exploit-DB + CISA KEV + GitHub
> advisories en una sola API). Requiere internet y no es stealth (consulta la nube).

## QUE ES
CLI moderno de ProjectDiscovery para explorar datos de vulnerabilidades con
búsqueda, filtrado y análisis avanzado. Unifica múltiples fuentes (NVD, Exploit-DB,
CISA KEV, vendor bulletins, GitHub advisories) en una sola consulta.

## INSTALACION (una sola vez)
```bash
go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
# verificar
vulnx --help
```

## COMANDOS PRINCIPALES
| Comando | Para qué | Ejemplo |
|---|---|---|
| `search` | Buscar CVEs con filtros avanzados | `vulnx search "apache && severity:high"` |
| `id` | Detalle de un CVE específico | `vulnx id CVE-2021-44228` |
| `filters` | Listar campos/filtros de búsqueda disponibles | `vulnx filters` |
| `analyze` | Agregar/agrupar datos por campo | `vulnx analyze -f severity` |
| `auth` | Configurar API key (ProjectDiscovery Cloud) | `vulnx auth` |
| `version` / `update` | Versión / actualizar | `vulnx version` |
| `healthcheck` | Probar conectividad | `vulnx healthcheck` |

## AUTENTICACION (rate limits)
- Sin API key TODOS los comandos funcionan, pero sujetos a **rate limits**.
- `vulnx auth` → creás/ingresás la key gratis en https://cloud.projectdiscovery.io
- Modo no interactivo (CI/CD/scripts):
  ```bash
  vulnx auth --api-key "$PDCP_API_KEY"
  vulnx auth --test && echo "Auth OK" || echo "Auth failed"
  export PDCP_API_KEY="tu-key"      # alternativa: variable de entorno
  ```
- Si aparece `Rate limit exceeded! API key required for higher limits.` → falta la key.

## v2.0.2 — FLAGS VERIFICADOS LOCALMENTE (importantes)
La CLI real de v2.0.2 trae flags de filtro dedicados (no solo la syntax de query):

**Globales (van antes o después del subcomando):**
- `-j, --json`        : output JSON crudo (para piping, desactiva YAML)
- `-o, --output file` : escribir a archivo JSON (**error si el archivo ya existe**)
- `--silent`          : sin banner ni output no esencial
- `--timeout 30s/1m`  : timeout HTTP de cada request (default 30s)
- `--proxy http://host:8080` : proxy HTTP
- `-d, --debug` / `--verbose` : debug / verbose
- `--no-color` / `--disable-update-check` : sin colores / sin chequear updates
- `--update`          : actualizar vulnx

**`vulnx search` — flags de filtro verificados (además de --json/--limit/--fields/--offset):**
- `-s, --severity <crit,high,medium,low>`  : filtrar por severidad (separada por comas)
- `--cvss-score <'7.5'|'>8.0'|'<=6.0'>`    : rango CVSS con operadores <> <= >=
- `--epss-score <'0.5'|'>0.8'|'<=0.3'>`    : rango EPSS
- `--kev true|false`      : solo CISA Known Exploited Vulnerabilities
- `--poc true|false`      : solo con exploit público (Proof of Concept)
- `--remote-exploit true|false` : solo remotamente explotables
- `-p, --product <a,b>`   : filtrar por producto (separado por comas)
- `--hackerone true|false`: solo reportados en HackerOne
- `--detailed`            : info detallada (similar al subcomando `id`)
- `-n, --limit <n>`       : nº de resultados (default 10; 0 = default servidor)
- `--offset <n>`          : paginación
- `--fields <c1,c2,...>`  : campos a incluir
- `--highlight` / `--facet-size <n>` / `--range-facets` / `--term-facets <a=n,b=n>`

**Comandos extra de v2.0.2 no citados en el README:** `mcp` (server MCP para
tools de ProjectDiscovery) y `completion` (compilación de autocompletado).

## FLAGS DE 'vulnx search'
Flags principales (comando usado por el Agente 4):
- `--json`                    : salida JSON (machine-readable; la consume el pipeline)
- `--output <file>`           : guardar a archivo (`.json`/`.csv` según extensión)
- `--silent`                  : sin banner/informativos (ideal para scripts)
- `--limit <n>`               : máximo de resultados (default bajo; ej. `--limit 50`)
- `--offset <n>`              : paginación
- `--fields <c1,c2,...>`      : solo esos campos (menos payload, ej. `cve_id,severity`)
- `--term-facets / --range-facets` : agregaciones/faceting (avanzado, análisis)
- `--sort-desc <campo>`       : ordenar descendente (ej. `cvss_score`, `epss_score`, `cve_created_at`)

## FLAGS DE 'vulnx id'
- `--json`                          : salida JSON (objeto si es 1 ID, array si varios)
- `--output <file>`                 : guardar a archivo
- `--file <ids.txt>`                : leer IDs de un archivo (1 por línea)
- Input múltiple: `vulnx id CVE-A,CVE-B,CVE-C`
- Auto-detección por stdin: `echo "CVE-2024-1234" | vulnx`

## FLAGS GLOBALES (van antes del subcomando)
- `vulnx --json search "apache"`               : JSON output
- `vulnx --silent search "apache"`             : sin banner
- `vulnx --timeout 60s search "apache"`        : timeout custom
- `vulnx --proxy http://localhost:8080 search` : a través de proxy
- `vulnx --debug search "apache"`              : modo debug
- `vulnx --disable-update-check search ...`    : sin chequear updates

## SINTAXIS DE BUSQUEDA
Operadores lógicos y comparadores sobre campos:
- `&&` (Y), `||` (O), `:` (filtro campo:valor), `>` `<` `>=` `<=` (comparación numérica)
- Cadenas con espacios y operadores especiales se entrecomillan: `"severity:critical && is_remote:true"`
- Negación se logra con `!=` o excluyendo (ver `vulnx search help` / `vulnx filters`).

Campos útiles vistos en el README/USAGE:
- `severity` (critical/high/medium/low), `cvss_score`, `epss_score`
- `cve_id`, `cve_created_at`, `age_in_days`
- `is_poc` (exploit público), `is_kev` (CISA Known Exploited), `is_remote`, `is_template`
- `affected_products.vendor`, `affected_products.product`
- `description`, `tags`

## EJEMPLOS UTILES
```bash
# Búsqueda por producto+versión (lo que hace el Agente 4 por servicio)
vulnx search "apache 2.4.7" --json --limit 20 --silent

# Detalle de un CVE puntual
vulnx id CVE-2021-44228 --json

# Solo CVEs con exploit público y CVSS alto
vulnx search "cvss_score:>8.0 && is_poc:true" --json --limit 20

# Conocidos como explotados (CISA KEV)
vulnx search "is_kev:true" --json --limit 20

# Búsqueda acotada a un rango de CVSS
vulnx search "cvss_score:>8.0" --sort-desc cvss_score --limit 20
```

## NOTAS PIPELINE (Agente 4)
- El script `scripts/cve_research_vulnx.py` usa `vulnx search <producto> <version>`
  y `vulnx id <CVE>` con: `--json`, timeout 30s, 3 reintentos, 4s de delay entre
  reintentos (rate-limit sin API key), `SEARCH_LIMIT=20`, `TOP_N_MAX=5`, `CVSS_MIN=4.0`.
- En la práctica el script NO pasa flags de formato: parsea la salida JSON directamente
  y consulta con query construida de producto+versión.
- Si `vulnx` no está en el PATH, `cve_research_vulnx.py` corta con error claro
  indicando cómo instalarlo.
- Salida del Agente 4: `cve_research/<target_id>_cves.json`
  (consumido por `organize_project.py` y `qa_check.py` — check CK-04).