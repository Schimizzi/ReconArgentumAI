# Recon Pipeline Specification

## ADDED Requirements

### Requirement: Verificación de campo PHP2Shell (fuera del DAG)

El sistema SHALL proveer una verificación **fuera del DAG** para advisories críticos de software web
(`scripts/host/php2shell_check.sh`), de ejecución manual por el operador **desde la VM con VPN** y
por target. El DAG SHALL permanecer en **12 steps** y el contrato del manifest NO SHALL alterarse por
esta verificación. El script SHALL soportar cuatro modos: `--passive` (por defecto; `curl -sS/-I`
sobre rutas estándar, sólo lectura, aprobado), `--fingerprint` (intenta revelar la versión de PHP
donde el banner está oculto, ej. Drupal/IIS; requiere aprobación por target), `--detect` (prueba NO
destructiva del path OOM: un request multipart con `session.upload_progress` y una cookie `PHPSESSID`
larga/percent-encoded; **exige** `--authorized` y NO envía payloads de shell ni escribe archivos) y
`--host-check` (corre en el servidor: `php -v`, `session.upload_progress`, backports del vendor en
`rpm -q --changelog php` / `dpkg`). Los timeouts SHALL resolverse de `config/stealth.yaml`
(`php2shell_timeout_seconds`, `php2shell_max_paths`). La evidencia SHALL quedar en
`evidence/<target>/php2shell_passive.txt`, `php2shell_fingerprint.txt`, `php2shell_detect.txt`,
`php2shell_hostcheck.txt`, `php2shell_result.json` y `php2shell_summary.txt`.

#### Scenario: Verificación pasiva aprobada

- **WHEN** el operador ejecuta `php2shell_check.sh --target <IP> --passive`
- **THEN** el script hace GETs de sólo lectura a rutas estándar (y al easter egg de PHP), guarda los
  headers (`Server`, `X-Powered-By`, `Set-Cookie`) en `php2shell_passive.txt` y clasifica la versión
  contra la tabla del advisory

#### Scenario: Versión afectada detectada

- **WHEN** la respuesta incluye `X-Powered-By: PHP/8.2.31`
- **THEN** `php2shell_result.json` registra `status: "affected"`, el SAPI probable y el script sale
  con exit code `2`

#### Scenario: Ejecución de detección sin autorización

- **WHEN** se invoca `--detect` sin `--authorized`
- **THEN** el modo se SALTA con un mensaje explícito y NO se envía ningún request multipart

#### Scenario: Host que oculta la versión

- **WHEN** el target corre Drupal sobre IIS y el modo `--fingerprint` no logra exponer la versión
- **THEN** el resultado queda `unknown_version` con el siguiente paso documentado (no se asume versión
  ni se listan CVEs)

#### Scenario: Chequeo dentro del servidor

- **WHEN** el operador ejecuta `--host-check` en el propio servidor PHP
- **THEN** se guarda `php2shell_hostcheck.txt` con la versión, la configuración de sesión/memoria, el
  SAPI y el resultado de `rpm -q --changelog php | grep -i CVE-2026-10961[89]`
