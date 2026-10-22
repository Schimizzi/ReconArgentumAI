# Spec operativa — Agente 4: Investigación de CVEs (Fase 2)

> Instrucción operativa que el **Agente 4** lee antes de investigar CVEs.
> Complementa: `openspec/changes/integrate-vulnx-cve-research/specs/cve-research/spec.md` (contrato formal).
> `<WORKSPACE>` = raíz del proyecto. Todos los paths son relativos a `<WORKSPACE>`.

## 0. Entradas

- `evidence/<target>/nmap_detailed.json` → servicios + versiones.
- `evidence/<target>/whatweb.*` → tecnologías web (con versión si la reporta).
- `evidence/<target>/nuclei.json` → cross-reference (`already_found_by_nuclei`).
- `config/scope.json` → `engagement_id`, `target_id`.
- `config/advisories/*.json` → **advisory watchlist local** (§1.1). Obligatoria.

### 0.1 Fuentes de versión (todas se consumen)

WhatWeb no siempre reporta la versión de lo que corre detrás. Para no perder
tecnologías, el script fusiona estas fuentes antes de consultar vulnx:

| Fuente | Qué aporta | Ejemplo real |
|---|---|---|
| `nmap_detailed.json` | servicios + versión (`product`/`version`/`extrainfo`) | `Apache httpd 2.4.37`, `extrainfo: ... PHP/5.4.16` |
| `whatweb.json` | plugins de tecnología con versión | `PHP: 8.2.33` |
| `nikto_<port>.json` | banner `x-powered-by` (`000287`) y "outdated" (`600625`) | `Retrieved x-powered-by header: PHP/8.2.31` |
| `httpx.json` | `tech: ["Django:4.2", "PHP:8.2.33", …]` | `PHP:8.2.33` |
| `CLIENTE/<ip>/outputs/gobuster_commands_outputs.txt` | headers `X-Powered-By` / `Server` capturados por los checks de Gobuster | `Server: Apache/2.4.6 … PHP/5.4.16` |
| `php2shell_passive.txt` / `php2shell_fingerprint.txt` / `php2shell_hostcheck*.txt` | **verificación de campo/de host** (cabeceras y línea canónica `PHP-Version:`) — la fuente **más autoritativa** de versión de PHP | `php2shell_passive.txt#6` → `PHP/8.2.33` |

- Cada tecnología agregada desde evidencia lleva el campo **`source`**
  (ej. `"nikto_80.json#20"`) para poder citarla.
- Si la misma tecnología aparece con **dos versiones distintas**, se usa la de la **verificación de
  campo** (`php2shell_*`) y la vieja queda registrada en **`superseded`** (ej. Nikto del 06-oct decía
  `8.2.31`, el campo confirmó `8.2.33` → se analiza 8.2.33 y `superseded: ["8.2.31"]`). Sin esto,
  Agente 4 evaluaba el advisory y el filtro de parcheados contra una versión obsoleta.
- Tecnología **sin versión** (ej. `PHP` a secas en Drupal/IIS): **no se descarta en silencio**.
  Si el nombre del producto matchea un advisory activo, la entrada queda con
  `"needs_fingerprint": true` y se registra en `source_omissions[]` como
  `sin_version | advisory <id>`. Resolverlo es tarea del fingerprint activo
  (`scripts/host/php2shell_check.sh`).

**Output:** `cve_research/<target_id>_cves.json`.

## 1. Fuente de consulta (PRIMARIA y ÚNICA)

Para cada servicio+versión y cada tecnología web, consultar **exclusivamente**:

1. **vulnx search** (motor ProjectDiscovery Cloud API) — por producto + versión.
2. **vulnx id** — para obtener detalle completo de cada CVE (cvss_score, PoCs, referencias).

**Ya no se consultan fuentes externas directas (NVD API, GitHub Security Advisories, vendor bulletins, Exploit-DB) como calls separadas.** vulnx consolida NVD, GitHub, Exploit-DB, vendor advisories, CISA KEV y más en una sola API.

Reglas:
- **Timeout por consulta: 30 segundos (máximo)**. Es un parámetro de la fase de investigación (no de `stealth.yaml`, que rige solo los comandos de recon) y este documento es su única fuente.
- Fuente sin respuesta dentro de 30s → **se omite** y la búsqueda continúa con las restantes; la omisión se registra en `source_omissions[]` del output.
- **Filtro por versión detectada**: solo se investigan servicios/tecnologías con **versión exacta**; los que no la tienen se omiten y se registran con `reason: "sin_version"` en `source_omissions[]`.
- **Filtro de relevancia de producto (anti falso positivo)**: se descarta todo CVE cuyo `affected_products` no coincida con el servicio/producto consultado (matcher amplio de vulnx). Desactivable con `--no-relevance-filter`. Ver `tools/vulnx_help.md`.
- **Filtro de versión parcheada (anti falso positivo de la búsqueda textual)**: se descarta todo CVE cuya **versión de fix declarada** (`remediation`/`description`) sea igual o menor a la versión detectada dentro de la misma rama major.minor (el host ya trae el arreglo). Trazable en `filtered_patched_cves[]`; conservador con versiones con sufijo (`1.0.2k`) y con textos de otros productos. Desactivable con `--no-patched-filter`.
- **`vulnx search` con exit code 0 y stdout vacío ⇒ 0 resultados** (`no_data_available`), nunca `query_failed`.
- Ninguna fuente devuelve datos para un servicio → el output registra `"cves": []` con la nota `no_data_available`.
- Si `vulnx` no está disponible en PATH, se aborta con error (no hay fallback automático a NVD directa).

## 1.1 Advisory watchlist local (OBLIGATORIA)

`config/advisories/*.json` contiene los advisories **críticos y recientes** que vulnx
puede no tener todavía (o cuyas consultas fallan por rate limit). Hoy contiene
`php2shell-2026-10-21.json` (CVE-2026-109618 / CVE-2026-109619, PHP 5.4–8.5 RCE).

Reglas:

- El script carga los advisories **activos** (`"active": true`) con `--advisories`
  (default `config/advisories/`; desactivable sólo con `--no-watchlist`).
- Si el **producto detectado** matchea los `product_aliases` del advisory y hay versión:
  - versión **< parcheada** (o rama EOL) → **se listan TODOS los CVEs del advisory** con
    `rank_reason: "advisory_watchlist_critica"` y `source: "advisory_watchlist"`.
  - versión **= parcheada** → **NO se listan** (guarda anti falso positivo; queda
    `watchlist.status = "patched"`). Esto evita el error observado con
    CVE-2026-17543 sobre PHP 8.2.33 (versión parcheada).
  - **sin versión** → `needs_fingerprint: true` (no se inventan CVEs de versiones).
- El output agrega `watchlist_matches[]` y `summary.watchlist_cves` para trazabilidad.
- La consistencia la verifica **CK-10** en la Fase 5: target afectado ⇒ el CVE del
  advisory debe estar en `cve_research/<target_id>_cves.json`.

> Para advisories EOL (ej. PHP 5.4.16 → `eol_sin_parche`), `patched_version` se
> documenta como *"sin release upstream (EOL): backport de vendor o de fuente"* y se
> recomienda verificar el backport del vendor antes de afirmar explotabilidad.

## 2. Autenticación API Key (opcional)

vulnx funciona sin API key pero sujeto a rate limits. Para eliminarlos:

```bash
vulnx auth  # configura la API key desde https://cloud.projectdiscovery.io
```

O mediante variable de entorno:

```bash
export PDCP_API_KEY="<tu-api-key>"
```

## 3. Filtro por severidad mínima

- Solo CVEs con **CVSS ≥ 4.0**. Se descartan hallazgos informativos o de menor score.

## 4. Top 3-5 por servicio con ranking estricto

Cada lista de CVEs válidos (CVSS ≥ 4.0) se limita a **Top 5**; si hay menos de 3, se incluyen los que haya. El ordenamiento es ESTRICTO y en este orden exacto:

1. **Exploit público verificado** (PoC verificado → `is_poc: true` en vulnx).
2. **Impacto crítico de acceso** (RCE, auth bypass, deserialización, SQLi, o clase equivalente según `vulnerability_impact` de vulnx).
3. **Score CVSS** descendente como desempate.

> Ejemplo: un CVE 7.5 con RCE explotable públicamente se ordena ANTES que un 9.2 teórico sin exploit.

Cada CVE del output DEBE incluir el campo **`rank_reason`** documentando por qué entró al top:
- `exploit_publico_verificado` → entró por la regla 1.
- `impacto_critico_<clase>` (ej. `impacto_critico_rce`) → entró por la regla 2.
- `cvss_desempate` → entró por la regla 3 (o por desempate de CVSS).

## 5. Cross-reference con Nuclei

Cruzamos la lista con `evidence/<target>/nuclei.json`: si Nuclei ya encontró una vulnerabilidad cuyo CVE está en la lista → marcar ese CVE como **`already_found_by_nuclei: true`**. El CVE se mantiene UNA sola vez (sin duplicados) para que no se repita en los resúmenes por target.

## 6. Output JSON — `cve_research/<target_id>_cves.json`

```json
{
  "target": "10.156.226.156",
  "target_id": "TGT-001",
  "research_timestamp": "<ISO8601>",
  "services_analyzed": [
    {
      "service": "ssh",
      "version": "OpenSSH 8.2p1",
      "port": 22,
      "cves": [
        {
          "id": "CVE-2024-6387",
          "cvss_score": 8.1,
          "severity": "HIGH",
          "description": "...",
          "affected_versions": "< 9.6p1",
          "patched_version": "9.6p1+",
          "exploit_available": true,
          "exploit_db_id": "51972",
          "github_poc": ["https://github.com/..."],
          "nvd_url": "...",
          "vendor_advisory": "...",
          "already_found_by_nuclei": false,
          "rank_reason": "exploit_publico_verificado"
        }
      ]
    }
  ],
  "web_technologies": [
    {"technology": "wordpress", "version": "6.5", "cves": []}
  ],
  "source_omissions": [
    {"service": "ssh", "source": "vulnx", "reason": "no_data_available"}
  ],
  "summary": {
    "total_cves": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0,
    "with_public_exploit": 3,
    "patched_available": 4
  }
}
```

- `summary` DEBE ser consistente con los CVEs listados.
- `version: null` + nota en `source_omissions` cuando Nmap no detectó versión precisa (solo CVEs genéricos del servicio).

## 7. Script de ejecución

Usar **`scripts/cve_research_vulnx.py`**:

```bash
python3 scripts/cve_research_vulnx.py \
    --target-id TGT-001 \
    --target-ip 10.0.0.1 \
    --nmap evidence/10.0.0.1/nmap_detailed.json \
    --whatweb evidence/10.0.0.1/whatweb.json \
    --nuclei evidence/10.0.0.1/nuclei.json \
    --evidence-dir evidence/10.0.0.1 \
    --cliente-dir CLIENTE/10.0.0.1/outputs \
    --advisories config/advisories
```

| Flag nuevo | Para qué |
|---|---|
| `--evidence-dir` | versiones web adicionales desde Nikto/HTTPX/Nmap (default: carpeta del `--nmap`) |
| `--cliente-dir` | headers guardados por los checks de Gobuster (`X-Powered-By`, `Server`) |
| `--advisories` | dir/archivo de advisories locales (default `config/advisories/`) |
| `--no-watchlist` | desactiva la watchlist (sólo vulnx) → **no usar en producción** |
| `--no-patched-filter` | desactiva el descarte de CVEs cuyo fix declarado ya está aplicado |

Requiere `vulnx` en PATH (instalado via `go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest`).

## 8. Prohibiciones / reglas duras

- **NUNCA inventar CVEs**: todo registro proviene de `vulnx search` + `vulnx id`. Excepción única: los CVEs de un **advisory local activo** (`config/advisories/`, §1.1), que se listan citando `advisory_id` y `source: "advisory_watchlist"`.
- **NUNCA listar un CVE sobre su propia versión parcheada** (guarda `watchlist.status = patched`). Si la versión detectada es igual o mayor a la parcheada, el CVE no entra al output.
- **`rank_reason` es obligatorio** para cada CVE del top; un CVE sin `rank_reason` invalida el output.
- Sin versión precisa detectada por Nmap → solo CVEs genéricos del servicio, marcados en el output (no asociar CVEs de versiones específicas).
- **Scripts NVD antiguos eliminados**: `scripts/nvd_query.py` y `scripts/nvd_cve_detail.py` fueron removidos del repo (el Agente 4 usa **solo** `vulnx`). Si alguna vez se necesitara consultar la NVD directa, quedan recuperables desde el historial git (`git show 10fbd1c:scripts/nvd_query.py`).