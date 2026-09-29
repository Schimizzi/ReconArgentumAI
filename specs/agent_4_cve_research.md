# Spec operativa — Agente 4: Investigación de CVEs (Fase 2)

> Instrucción operativa que el **Agente 4** lee antes de investigar CVEs.
> Complementa: `openspec/changes/integrate-vulnx-cve-research/specs/cve-research/spec.md` (contrato formal).
> `<WORKSPACE>` = raíz del proyecto. Todos los paths son relativos a `<WORKSPACE>`.

## 0. Entradas

- `evidence/<target>/nmap_detailed.json` → servicios + versiones.
- `evidence/<target>/whatweb.*` → tecnologías web (con versión si la reporta).
- `evidence/<target>/nuclei.json` → cross-reference (`already_found_by_nuclei`).
- `config/scope.json` → `engagement_id`, `target_id`.

**Output:** `cve_research/<target_id>_cves.json`.

## 1. Fuente de consulta (PRIMARIA y ÚNICA)

Para cada servicio+versión y cada tecnología web, consultar **exclusivamente**:

1. **vulnx search** (motor ProjectDiscovery Cloud API) — por producto + versión.
2. **vulnx id** — para obtener detalle completo de cada CVE (cvss_score, PoCs, referencias).

**Ya no se consultan fuentes externas directas (NVD API, GitHub Security Advisories, vendor bulletins, Exploit-DB) como calls separadas.** vulnx consolida NVD, GitHub, Exploit-DB, vendor advisories, CISA KEV y más en una sola API.

Reglas:
- **Timeout por consulta: 30 segundos (máximo)**. Es un parámetro de la fase de investigación (no de `stealth.yaml`, que rige solo los comandos de recon) y este documento es su única fuente.
- Fuente sin respuesta dentro de 30s → **se omite** y la búsqueda continúa con las restantes; la omisión se registra en `source_omissions[]` del output.
- Ninguna fuente devuelve datos para un servicio → el output registra `"cves": []` con la nota `no_data_available`.
- Si `vulnx` no está disponible en PATH, se aborta con error (no hay fallback automático a NVD directa).

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

Cruzamos la lista con `evidence/<target>/nuclei.json`: si Nuclei ya encontró una vulnerabilidad cuyo CVE está en la lista → marcar ese CVE como **`already_found_by_nuclei: true`**. El CVE se mantiene UNA sola vez (sin duplicados) y el Agente 5 lo sabe para no repetirlo en el informe.

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
    --nuclei evidence/10.0.0.1/nuclei.json
```

Requiere `vulnx` en PATH (instalado via `go install github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest`).

## 8. Prohibiciones / reglas duras

- **NUNCA inventar CVEs**: todo registro proviene de `vulnx search` + `vulnx id`. Sin fuente → no se lista.
- **`rank_reason` es obligatorio** para cada CVE del top; un CVE sin `rank_reason` invalida el output.
- Sin versión precisa detectada por Nmap → solo CVEs genéricos del servicio, marcados en el output (no asociar CVEs de versiones específicas).
- **Scripts DEPRECATED** (no usar en pipeline): `scripts/nvd_query.py`, `scripts/nvd_cve_detail.py`. Conservados para rollback.