## Contexto

`vulnx` es la fuente única del Agente 4 y funciona bien para CVEs ya indexados, pero tiene dos
límites que este change resuelve **sin romper ese contrato**:

1. **Cobertura temporal:** un CVE publicado el 21-10 no está (o responde vacío) el 22-10. Además, la
   consulta puede fallar por rate limit (`source_omissions[].reason = query_failed`).
2. **Cobertura de versiones:** sólo se le pasan las versiones de `nmap_detailed.json` y
   `whatweb.json`, dejando afuera versiones que **sí** están en la evidencia (Nikto, httpx, headers
   capturados por los checks de Gobuster).

## Decisiones

### D1. Advisory watchlist **local** en JSON, no hardcodeada en el script

`config/advisories/*.json` con esquema estable (`branches.{rama}.patched`, `eol_max_exclusive`,
`cves[]`, `product_aliases`). Ventajas: el operador puede agregar el advisory de la semana sin tocar
código, se versiona como contenido de ingeniería, y el mismo archivo lo consumen el Agente 4, el
auditor offline y (vía `advisory_cves`) el CK-10.

*Alternativa descartada:* tabla de CVEs dentro de `cve_research_vulnx.py` (requiere release de código
por cada advisory y dificulta el test offline).

### D2. Comparación de versiones **determinista** en Python, con guard de versión parcheada

`_parse_version_tuple()` + `_advisory_status()`: `affected` (rama < parche), `patched` (= parche),
`eol_sin_parche` (< 8.2.0), `unknown_version`. Si la versión detectada **es igual** a la parcheada, el
CVE **no se lista** — así se evita el falso positivo ya observado con `CVE-2026-17543` sobre PHP
8.2.33 (que es justamente su versión parcheada).

### D3. El auditor offline es la **red de seguridad** y no depende de red

`scripts/php2shell_audit.py` no consulta APIs: barre `evidence/<ip>/` + `CLIENTE/<ip>/outputs/`,
clasifica y **cita archivo + línea** (regla anti-alucinación del Agente 3/4). Es el insumo del CK-10,
por lo que el gate funciona incluso si `vulnx` está caído.

### D4. La verificación de campo queda **fuera del DAG**

Meterla como Step 13 obligaría a cambiar `run_target.sh`, `EXPECTED_STEPS` de CK-09, la spec del
pipeline y todos los manifests históricos. Se resolvió como script manual (`php2shell_check.sh`)
documentado en `config/approved_commands.md`, con modos separados por nivel de intrusión
(`--passive` aprobado; `--fingerprint` y `--detect` opt-in por target).

### D5. `CK-01` valida ids únicos (además de targets + engagement_id)

El id del target es parte de la **clave de los artefactos** (`manifest.json`, `cve_research/<id>_cves.json`,
`plans/<id>_exploitation_plan.md`). Un id repetido corrompe la trazabilidad, así que se valida en dos
puntos: Fase 1 (`preflight_run.sh`, antes de escanear) y Fase 5 (`CK-01`).

### D6. `CK-03` acepta JSONL y vacíos; sólo falla JSON ilegible

Los outputs de ProjectDiscovery (httpx/nuclei) son **JSONL**; un archivo vacío es evidencia legítima
("el step corrió y no encontró nada", el estado real está en el manifest). El check pasa a informar el
desglose (`631 JSON, 29 JSONL, 106 vacíos`) en lugar de fallar. *Se actualiza el spec de QA, que decía
literalmente "cargar todos los JSONs con `json.load()`".*

### D7. `CK-05` se alinea al spec (sin refs ⇒ PASS)

El spec ya decía "plan sin refs a `evidence/` ⇒ PASS"; el código hacía lo contrario. Se corrigió el
código (no el spec) y el detalle de la línea PASS deja constancia de que el plan no tiene
trazabilidad, para que sea visible sin ser bloqueante.

### D8. El filtro de versión parcheada se apoya en el texto del CVE (y es conservador)

`vulnx` es un buscador **de texto**: `search "php 8.2.31"` devuelve los documentos que *mencionan*
8.2.31 — típicamente los CVE **arreglados en** 8.2.31 (8 falsos positivos medidos en
`10.10.12.127`) y, en `10.10.13.103`, CVE-2026-17543/7260 cuyo fix es exactamente 8.2.33.

Decisión: extraer la **versión de fix declarada** de `remediation`/`description` (patrones
`upgrade/update … X`, `X or later`, `before X`, `< X`), descartar el CVE si esa versión es igual o
menor a la detectada **en la misma rama major.minor**, y ser **conservador**:
- se ignoran versiones con sufijo de letra (`1.0.2k`, `9.6p1`) para no confundir `1.0.2`;
- se exige que el texto mencione el producto consultado (evita cruces de numeración);
- los números que el propio texto marca como *afectados* (`X and earlier`, `affected versions X`)
  nunca se consideran fix;
- los descartes se listan en `filtered_patched_cves[]` (auditables) y el filtro se puede apagar con
  `--no-patched-filter`.

*Alternativa descartada:* confiar sólo en `affected_products[].version` de vulnx — en este engagement
viene vacío o como rangos no parseables, y el campo `remediation` es el que trae la versión de fix.

### D9. `rc=0` sin stdout = "0 resultados"

`vulnx search` devuelve **stdout vacío con exit code 0** cuando la consulta no tiene resultados. El
script lo interpretaba como fallo (`stdout no es JSON` → `query_failed` + aviso de rate limit), lo
que contaminaba `source_omissions[]` y ocultaba la causa real. Ahora se mapea a lista vacía
(`no_data_available`) y, si stdout trae avisos junto al JSON, se recupera el objeto embebido.

| Riesgo | Mitigación |
|---|---|
| Marcar como afectado un host con **backport** del vendor (RHEL/Ubuntu) | El auditor marca `distro_backport_posible` cuando la evidencia menciona la distro y el reporte indica verificar `rpm -q --changelog php \| grep -i CVE-2026-1096` |
| Falso positivo por `PHP` sin versión | Estado `unknown_version` (nunca se listan CVEs de versiones no detectadas) + aviso "requiere fingerprint" en CK-10 |
| Ruido de CVEs en el top 5 por servicio | Los CVEs del advisory se agregan **después** del ranking de vulnx y con `rank_reason` propio, sin desplazar a los del top |
| `--detect` invasivo | Requiere `--authorized`, no envía payloads de shell y sólo observa señales (multipart OOM + PHPSESSID largo) |
| Watchlist desactualizada | `config/advisories/` versionado + `active: true|false` por advisory; `specs/agent_4_cve_research.md` §1.1 y `config/approved_commands.md` documentan el flujo |

## Verificación

- `python3 -m py_compile` de los scripts Python y `bash -n` de los shell.
- `php2shell_audit.py --self-test` (15 versiones) y `php2shell_check.sh --self-test` (13 versiones):
  **OK**.
- Prueba unitaria del Agente 4 (inyección de watchlist, guard `patched`, loader de evidencia desde
  Nikto/httpx/Gobberto): **OK**.
- Prueba unitaria de QA (`_json_file_status` con vacío/JSONL/JSON/corrupto y `ck01_scope` con ids
  duplicados/sin id/únicos): **OK**.
- Barrido real: `php2shell_audit.py --all` → 3 afectados + 6 sin versión de 79; `qa_check.py` →
  104/106 PASS (quedan `CK-09` de `10.10.10.204` — manifest viejo de 10 steps: requiere re-run de
  Fase 1 — y `CK-10`, que pasa al re-ejecutar Fase 2a con `--advisories`).
- End-to-end del check de campo contra un servidor local de prueba (`X-Powered-By: PHP/8.2.31`):
  detecta `affected`, SAPI `mod_php`, exit code 2.
