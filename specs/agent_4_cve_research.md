# Spec operativa — Agente 4: Investigación de CVEs (Fase 2)

> Instrucción operativa que el **Agente 4** lee antes de investigar CVEs.
> Complementa: `openspec/changes/add-pentest-recon-pipeline/specs/cve-research/spec.md` (contrato formal).
> `<WORKSPACE>` = raíz del proyecto. Todos los paths son relativos a `<WORKSPACE>`.

## 0. Entradas

- `evidence/<target>/nmap_detailed.json` → servicios + versiones.
- `evidence/<target>/whatweb.*` → tecnologías web (con versión si la reporta).
- `evidence/<target>/nuclei.json` → cross-reference (`already_found_by_nuclei`).
- `config/scope.json` → `engagement_id`, `target_id`.

**Output:** `cve_research/<target_id>_cves.json`.

## 1. Fuentes de consulta

Para cada servicio+versión y cada tecnología web, consultar en este orden:
1. **NVD API** — por CPE/keyword de producto + versión.
2. **GitHub Security Advisories** — si el ecosistema aplica (libs JS/Python/Go, etc.).
3. **Vendor bulletins / vendor advisory** — del vendor del producto.
4. **Exploit-DB** (searchsploit o web) — para verificar PoC público.

Reglas:

- **Timeout por consulta: 30 segundos (máximo)**. Es un parámetro de la fase de investigación (no de `stealth.yaml`, que rige solo los comandos de recon) y este documento es su única fuente.
- Fuente sin respuesta dentro de 30s → **se omite** y la búsqueda continúa con las restantes; la omisión se registra en `source_omissions[]` del output.
- Ninguna fuente devuelve datos para un servicio → el output registra `"cves": []` con la nota `no_data_available`.

## 2. Filtro por severidad mínima

- Solo CVEs con **CVSS ≥ 4.0**. Se descartan hallazgos informativos o de menor score.

## 3. Top 3-5 por servicio con ranking estricto

Cada lista de CVEs válidos (CVSS ≥ 4.0) se limita a **Top 5**; si hay menos de 3, se incluyen los que haya. El ordenamiento es ESTRICTO y en este orden exacto:

1. **Exploit público verificado** (PoC verificado en GitHub o Exploit-DB) → `exploit_available: true`.
2. **Impacto crítico de acceso** (RCE, auth bypass, deserialización, SQLi, o clase equivalente).
3. **Score CVSS** descendente como desempate.

> Ejemplo: un CVE 7.5 con RCE explotable públicamente se ordena ANTES que un 9.2 teórico sin exploit.

Cada CVE del output DEBE incluir el campo **`rank_reason`** documentando por qué entró al top:
- `exploit_publico_verificado` → entró por la regla 1.
- `impacto_critico_<clase>` (ej. `impacto_critico_rce`) → entró por la regla 2.
- `cvss_desempate` → entró por la regla 3 (o por desempate de CVSS).

## 4. Cross-reference con Nuclei

Cruzar la lista con `evidence/<target>/nuclei.json`: si Nuclei ya encontró una vulnerabilidad cuyo CVE está en la lista → marcar ese CVE como **`already_found_by_nuclei: true`**. El CVE se mantiene UNA sola vez (sin duplicados) y el Agente 5 lo sabe para no repetirlo en el informe.

## 5. Output JSON — `cve_research/<target_id>_cves.json`

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
    {"service": "ssh", "source": "NVD", "reason": "timeout_30s"}
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

## 6. Prohibiciones / reglas duras

- **NUNCA inventar CVEs**: todo registro proviene de una fuente consultada (NVD/GitHub/vendor/Exploit-DB). Sin fuente → no se lista.
- **`rank_reason` es obligatorio** para cada CVE del top; un CVE sin `rank_reason` invalida el output.
- Sin versión precisa detectada por Nmap → solo CVEs genéricos del servicio, marcados en el output (no asociar CVEs de versiones específicas).