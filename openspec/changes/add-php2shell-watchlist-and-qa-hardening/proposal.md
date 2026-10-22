## Why

El engagement de octubre 2026 (79 targets) expuso tres problemas concretos:

1. **Vulnerabilidad crítica invisible.** El 21-10-2026 PHP publicó el fix de **PHP2Shell**
   (`CVE-2026-109618` / `CVE-2026-109619`, RCE no autenticado por HTTP en PHP 5.4–8.5, CVSS 4.0 9.2,
   con explotación observada in-the-wild). El Agente 4 consulta **una sola fuente** (`vulnx`) y
   **sólo** dos entradas de versión (`nmap_detailed.json` + `whatweb.json`), así que:
   - `10.10.12.127` (PHP **8.2.31**, detectado **sólo** por Nikto `000287`) quedó sin tecnología PHP
     en `cve_research/10.10.12.127_cves.json`;
   - los targets con `PHP` sin versión (Drupal 7 sobre IIS) se descartaban **en silencio**;
   - un CVE tan reciente no aparece en `vulnx` (o su consulta falla por rate limit).
2. **`target_id` duplicados en `scope.json`.** 4 IPs compartían `S-10.10.10.80` y 5 compartían
   `S-10.10.10.195`; el id se propaga al `manifest.json` y al nombre de los artefactos por target, por
   lo que los informes **se pisaban entre sí**.
3. **Falsos positivos en QA.** `CK-03` marcaba `[FAIL]` cualquier `httpx.json` (JSONL de
   ProjectDiscovery: un JSON por línea) y cualquier evidencia **vacía** (p. ej. `nuclei.json` de 0
   bytes = "corrió y no encontró nada"); `CK-05` devolvía `[FAIL]` para planes **sin** refs a
   `evidence/`, contradiciendo el escenario ya escrito en su propio spec.

## What Changes

- **Advisory watchlist local** (`config/advisories/*.json`, versionada): CVEs críticos recientes con
  `branches` + versión parcheada, ramas EOL, SAPI afectados, mitigaciones y señales de detección.
  Primer advisory: `php2shell-2026-10-21.json`.
- **Agente 4** (`scripts/cve_research_vulnx.py`): consume **todas** las fuentes de versión de la
  evidencia (nmap, whatweb, **nikto, httpx, headers de Gobuster**), marca `needs_fingerprint` cuando
  hay tecnología sin versión que matchea un advisory, e **inyecta los CVEs del advisory** con
  `rank_reason: "advisory_watchlist_critica"` y guarda anti falso positivo (nunca lista un CVE sobre
  su propia versión parcheada). Flags nuevos: `--advisories`, `--no-watchlist`, `--evidence-dir`,
  `--cliente-dir`.
- **Nuevo auditor offline** `scripts/php2shell_audit.py` (+ `.md`): barre la evidencia ya generada,
  clasifica cada target contra el advisory (`affected` / `eol_sin_parche` / `patched` /
  `unknown_version`), cita **archivo + línea** de cada hallazgo, e informa el SAPI probable y si hay
  indicio de paquete de distro (posible backport). Salidas: `cve_research/<id>_php2shell.json`,
  `plans/php2shell_<fecha>.md`; **exit 2** si hay afectados.
- **Verificación de campo** `scripts/host/php2shell_check.sh` (+ `.md`): **fuera del DAG** (se corre a
  mano desde la VM con VPN, por target); modos `--passive` (aprobado), `--fingerprint`,
  `--detect --authorized` y `--host-check`; escribe `evidence/<target>/php2shell_*`.
- **QA (`scripts/qa_check.py`)**: `CK-01` exige `target_id` únicos y no vacíos; `CK-03` acepta JSONL y
  vacíos (sólo falla JSON ilegible); `CK-05` se alinea al spec (sin refs ⇒ PASS); **`CK-10` nuevo y
  bloqueante**: target PHP afectado ⇒ los CVE del advisory deben estar en su `cve_research`.
- **Guard de Fase 1** (`scripts/host/preflight_run.sh`): falla si `scope.json` tiene ids duplicados o
  vacíos, antes de escanear.
- **Config**: `config/stealth.yaml` agrega `php2shell_timeout_seconds` / `php2shell_max_paths`;
  `config/advisories/` se versiona (`.gitignore`); `config/approved_commands.md` registra la
  auditoría y el modo pasivo.

## Capabilities

### Modified Capabilities

- `cve-research`: nuevas fuentes de versión desde evidencia cruda + advisory watchlist local
  obligatoria con comparación determinista de versiones.
- `qa-validation`: `CK-01` (ids únicos), `CK-03` (JSONL/vacíos), `CK-05` (alineado al spec),
  `CK-09` (contrato del DAG, drift preexistente) y `CK-10` (advisory crítico sin reportar).
- `recon-pipeline`: la verificación de campo PHP2Shell es explícitamente **fuera del DAG** (se
  mantienen los 12 steps y el contrato del manifest).

## Impact

- **Código:** `scripts/cve_research_vulnx.py`, `scripts/qa_check.py`, `scripts/host/preflight_run.sh`,
  + nuevos `scripts/php2shell_audit.py`, `scripts/host/php2shell_check.sh`.
- **Datos del engagement:** `config/scope.json` (ids corregidos), `evidence/10.10.10.{81,85,195,203}/
  manifest.json` (`target_id` alineado), `evidence/10.10.10.80/manifest.json` (entrada stale
  `ldapsearch_old.txt` eliminada).
- **Resultado del barrido:** 3 targets afectados (`10.10.12.127` PHP 8.2.31, `10.10.13.102` PHP 5.4.16
  EOL con mod_php, `10.10.13.103` PHP 8.2.33) y 6 "PHP sin versión" (Drupal 7 sobre IIS 8.5).
- **Sin cambios** en el contrato de los 12 steps ni en el formato de `cve_research/<id>_cves.json`
  (sólo se agregan `watchlist_matches[]` y `summary.watchlist_cves`).
- **Requiere verificación en campo** (VM con VPN) para confirmar SAPI y backports de distro antes de
  afirmar explotabilidad.
