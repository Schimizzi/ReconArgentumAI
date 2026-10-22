## 1. Advisory watchlist local

- [x] 1.1 Crear `config/advisories/php2shell-2026-10-21.json` (CVE-2026-109618/109619, CVSS 9.2,
      `branches` con parches 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, `eol_max_exclusive`, SAPI, mitigaciones,
      señales y fuentes CERT-EU/NCSC-NL/Wiz/watchTowr).
- [x] 1.2 Versionar `config/advisories/` en `.gitignore` (excepción después de `/config/*`).
- [x] 1.3 Documentar el flujo en `specs/agent_4_cve_research.md` §0.1 y §1.1 y en `RUNBOOK.md`.

## 2. Agente 4 — fuentes de versión y watchlist

- [x] 2.1 `_load_evidence_web_versions()`: versiones desde Nikto (`000287`/`600625`), httpx (`tech`),
      `extrainfo` de Nmap y headers de los checks de Gobuster (`CLIENTE/<ip>/outputs`).
- [x] 2.2 Fusionar con las tecnologías de WhatWeb sin duplicar y agregar campo `source`.
- [x] 2.3 `needs_fingerprint: true` para tecnología sin versión que matchea un advisory activo
      (antes se descartaba en silencio).
- [x] 2.4 `_load_advisories()`, `_advisory_status()`, `_advisory_matches()`, `_build_advisory_entry()`,
      `_apply_advisories()` con `rank_reason = "advisory_watchlist_critica"` y `source = "advisory_watchlist"`.
- [x] 2.5 Guard anti falso positivo: versión detectada == versión parcheada ⇒ no se listan CVEs.
- [x] 2.6 Output: `watchlist_matches[]` + `summary.watchlist_cves`; flags `--advisories`,
      `--no-watchlist`, `--evidence-dir`, `--cliente-dir`.
- [x] 2.7 Test unitario de `_advisory_status` (8.2.31/8.2.33 affected, 8.2.35 patched, 5.4.16 EOL,
      sin versión unknown) y de la inyección de la watchlist: OK.
- [x] 2.8 Filtro de versión parcheada (`--no-patched-filter`): descarta CVEs cuyo fix declarado
      (`remediation`/`description`) es ≤ la versión detectada en la misma rama; trazable en
      `filtered_patched_cves[]`; conservador con sufijos (`1.0.2k`) y textos de otro producto.
- [x] 2.9 Fix de `_run_vulnx`: `rc=0` sin stdout ⇒ lista vacía (0 resultados), no `query_failed`;
      recuperación del JSON embebido si stdout trae avisos.
- [x] 2.10 Excluir pseudo-plugins de WhatWeb (`PoweredBy`, `X-Powered-By`, `X-AspNet-Version`) del
      CVE research y quitar `x-powered-by` de `product_aliases` del advisory (evita ruido y falsos
      matches de la watchlist).
- [x] 2.11 Tests: 17/17 casos del clasificador (incluye versiones con letra, cross-product y frases
      "affected versions X") + auditoría manual de los 14 descartes reales en los 3 targets.

## 3. Auditor offline PHP2Shell

- [x] 3.1 `scripts/php2shell_audit.py`: barrido de 11 globs de evidencia, 8 patrones de versión PHP,
      huellas de CMS PHP, `PHPSESSID`, distro y SAPI probable.
- [x] 3.2 Clasificación `affected` / `eol_sin_parche` / `patched` / `unknown_version` / `no_php_evidence`.
- [x] 3.3 Salidas: `cve_research/<id>_php2shell.json`, `plans/php2shell_<fecha>.md`, exit 2 si hay
      afectados; `--self-test`, `--all`, `--no-write`.
- [x] 3.4 Fix de ids de scope duplicados (usa la IP si el id del scope está repetido) para no pisar JSONs.
- [x] 3.5 `scripts/php2shell_audit.md` (guía sin código) + alta en `scripts/README.md`, `README.md`, `RUNBOOK.md`.

## 4. Verificación de campo (VM con VPN)

- [x] 4.1 `scripts/host/php2shell_check.sh` con modos `--passive`, `--fingerprint`, `--detect` (exige
      `--authorized`), `--host-check`, `--self-test`; timeouts desde `config/stealth.yaml`.
- [x] 4.2 Salidas `evidence/<target>/php2shell_{passive,fingerprint,detect,hostcheck}.txt`,
      `php2shell_result.json`, `php2shell_summary.txt`; exit 2 si afectado.
- [x] 4.3 `scripts/host/php2shell_check.md` + registro en `config/approved_commands.md`
      (`--passive` aprobado; `--fingerprint`/`--detect` opt-in por target).
- [x] 4.4 `config/stealth.yaml`: `php2shell_timeout_seconds`, `php2shell_max_paths` (R5).

## 5. QA — fixes y gate nuevo

- [x] 5.1 `CK-01`: exigir `target_id` únicos y no vacíos (bloqueante).
- [x] 5.2 `CK-03`: aceptar JSONL y archivos vacíos; sólo fallar JSON ilegible; informar el desglose.
- [x] 5.3 `CK-05`: alinear al spec (plan sin refs ⇒ PASS, con constancia en el detalle).
- [x] 5.4 `CK-10` (nuevo, bloqueante): target PHP afectado ⇒ CVE del advisory presente en
      `cve_research/<id>_cves.json`; desactivable con `QA_PHP2SHELL_BLOCKING=0`; `unknown_version` ⇒ aviso.
- [x] 5.5 Guard de Fase 1 en `preflight_run.sh`: ids duplicados o sin id ⇒ `fail=1` antes de escanear.
- [x] 5.6 Docs: `scripts/qa_check.md` (CK-01/03/05/10 + notas), `README.md`, `RUNBOOK.md`
      (criterios de bloqueo y tabla de errores).
- [x] 5.7 Tests unitarios de `_json_file_status` (vacío/JSONL/JSON/JSONL con líneas en blanco/corrupto)
      y de `ck01_scope` (duplicado/sin id/único): OK.

## 6. Sanear datos del engagement

- [x] 6.1 `config/scope.json`: ids únicos `S-<ip>` para los 10 targets + nota de la corrección.
- [x] 6.2 `evidence/10.10.10.{81,85,195,203}/manifest.json`: `target_id` alineado (sólo ese campo).
- [x] 6.3 `evidence/10.10.10.80/manifest.json`: quitar la entrada stale `ldapsearch_old.txt` (no existe
      en disco) para que CK-02 refleje la realidad.

## 7. Validación final

- [x] 7.1 `py_compile` ×3 y `bash -n` ×2: OK.
- [x] 7.2 `php2shell_audit.py --all` → 3 afectados / 6 sin versión / 79 auditados.
- [x] 7.3 `qa_check.py` → 104/106 PASS; quedan `CK-09` (10.10.10.204, manifest viejo) y `CK-10`
      (gate hasta re-ejecutar Fase 2a con `--advisories`).
- [ ] 7.4 Correr en la VM: `php2shell_check.sh --passive` (y `--fingerprint` en los 6 Drupal/IIS),
      re-auditar y re-ejecutar Fase 2a con `--advisories` para cerrar CK-10.
      → **[x] HECHO 2026-10-22**: F1 (3 afectados, `--passive`/`--detect`) + F2 (6 Drupal/IIS,
      `--passive,fingerprint`) desde la VM Debian; re-auditado y Fase 2a corrida con `--advisories`
      para los 3 afectados (CK-10 verde). Cierre: `plans/php2shell_2026-10-22_cierre.md`.
- [ ] 7.5 `openspec validate --specs` y `openspec archive add-php2shell-watchlist-and-qa-hardening`
      (el CLI `openspec` no está instalado en el entorno actual).

## 8. Integración con la verificación de campo (2026-10-22)

> El run de F1 en la VM Debian mostró que, sin esto, el resultado del check de campo **no entraba** al
> informe ni a `CK-10` (el auditor no leía `php2shell_*`), y que con los `target_id` únicos el auditor
> habría escrito `S-<ip>_php2shell.json` mientras `cve_research/` está nombrado por IP.

- [x] 8.1 `php2shell_audit.py`: `CANDIDATE_GLOBS` incluye `php2shell_passive.txt`,
      `php2shell_fingerprint.txt` y `php2shell_detect.txt` (los patrones de header ya extraían la versión).
- [x] 8.2 `_load_field_check()` lee `php2shell_result.json`; su **versión manda** (primera en
      `versions_detected`), su SAPI se reporta como “confirmado en campo” y el JSON agrega el bloque
      `field_check` (`checked_at`, `modes`, `next_steps`).
- [x] 8.3 Nombres: el JSON de auditoría se escribe como `<ip>_php2shell.json` (el id canónico queda en
      `target_id`, dentro del JSON). Limpiados los 2 duplicados `S-*` de la corrida previa.
- [x] 8.4 `qa_check.py` (CK-10): resuelve el `_cves.json` como `<target_id>_cves.json` y, si no existe,
      como `<ip>_cves.json` (evita el FAIL espurio cuando el target in-scope es `affected`).
- [x] 8.5 Tests: auditor con campo (10/10 asserts: versión de campo, EOL vs affected, SAPI de campo,
      `field_check`, hallazgo `field-check`, header de campo consumido) + CK-10 con `target_id`
      canónico (resuelve por IP) **y** caso negativo sin `_cves.json` (sigue fallando).
- [x] 8.6 Docs: `scripts/php2shell_audit.md` (entrada/salida) y `scripts/qa_check.md` (fila CK-10).

## 9. Fix del falso positivo 5.3.0 en los Drupal/IIS (2026-10-22)

> F2 devolvió **PHP 5.3.0** idéntico para los 6 hosts. Causa: el check extraía versiones también del
> **cuerpo** de las respuestas y `/INSTALL.txt` de Drupal dice *“PHP 5.3.0 or higher”*; ese cuerpo no se
> persiste, así que el dato era **no verificable**.

- [x] 9.1 `php2shell_check.sh`: `collect_versions()` extrae **solo de headers** (`Server:`, `X-Powered-By:`)
      + guard de frases de requisitos; se dejó de llamar con el cuerpo (`$TMPD/b`).
- [x] 9.2 `php2shell_audit.py`: guard `_field_version_verifiable()` — la versión del check de campo se usa
      **solo si aparece en un header** de la evidencia cruda; si no, `field_check.verified=false`, se
      descarta (target → `unknown_version`) y se agrega la nota explicativa.
- [x] 9.3 `--fingerprint` persiste `Drupal-Version: <ver>` (línea verificable) y el auditor lo muestra como
      huella `Drupal 7.xx (CMS EOL: requiere migración)` en `app_hints`/`signals`.
- [x] 9.4 Tests: guard (campo verificado vs no verificable) + hint de Drupal + regresión de los tests
      previos (campo, CK-10 fallback). QA **106/106**.

## 10. Cierre del alcance + verificación local en host Windows/IIS (2026-10-22)

- [x] 10.1 `config/scope.json`: nuevo array **`field_check_ips`** (7 hosts habilitados SOLO para
      verificación de campo fuera del DAG: 3 afectados + 4 Drupal/IIS sin versión). No toca
      `authorized_targets` → `CK-01`/`CK-02`/`CK-09` siguen evaluando los 10 del run (QA 106/106).
- [x] 10.2 `scripts/host/php2shell_hostcheck_win.ps1` (nuevo, PowerShell **read-only**): versión desde
      binario (`FileVersion`), registro y handler mappings de IIS; emite `PHP-Version:` / `PHP-SAPI:`.
      La carpeta del handler se reporta como **rama** (`PHP-Branch-Hint`), sin inventar el patch.
- [x] 10.3 `scripts/host/php2shell_hostcheck_win.md` (nuevo): guía de confirmación por nivel de acceso
      (Drupal `admin/reports/status` → host → SMB `C$`/`applicationHost.config` → WinRM 5985 → IT).
- [x] 10.4 `php2shell_audit.py`: `php2shell_hostcheck*.txt` en `CANDIDATE_GLOBS`, patrón canónico
      `^PHP-Version:` (finding `host-check-php-version`) y `PHP-SAPI:` (SAPI “confirmado en el host”).
      `php2shell_check.sh --host-check` emite las mismas líneas canónicas.
- [x] 10.5 Tests: host-check Windows **5/5** + regresión (campo, guard, CK-10) + QA **106/106** con el
      scope nuevo. *(El `pwsh` no está disponible en macOS: el `.ps1` no se pudo parsear acá — se escribió
      con construcciones PS 2.0+ y se validó la integración con la salida que produce.)*
