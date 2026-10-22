# `php2shell_check.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es la **verificación en campo de PHP2Shell** (`CVE-2026-109618` / `CVE-2026-109619`): se ejecuta
**desde la VM que se conecta por VPN** y comprueba, contra el servidor real, **qué versión de PHP
responde y en qué SAPI**, más las señales de explotación del advisory.

Complementa a `scripts/php2shell_audit.py` (que trabaja **offline** sobre la evidencia ya guardada):
el audit dice "por la evidencia, este target usa PHP X"; este script dice "confirmado en campo".

> ⚠️ **No es un step del DAG de recon** (`run_target.sh` sigue teniendo 12 steps). Se corre a mano
> por target y escribe en `evidence/<target>/php2shell_*`.

## ⏱️ ¿Cuándo se usa?

- Después de correr `php2shell_audit.py --all`, sobre:
  - los targets **afectados** (`affected` / `eol_sin_parche`), y
  - los marcados **“PHP sin versión”** (`unknown_version`: Drupal/IIS que ocultan el banner).
- Y `--host-check` **dentro del servidor** (si tenés acceso) para ver backports del vendor.

## ▶️ Cómo se usa

```bash
# 1) Pasivo (solo lectura, APROBADO) — sin tocar la red del cliente desde la Mac:
bash scripts/host/php2shell_check.sh --target 10.10.12.127 --target-id 10.10.12.127 --passive

# 2) Con fingerprint (hosts que ocultan la versión: Drupal/IIS) — requiere OK por target:
bash scripts/host/php2shell_check.sh --target 10.10.10.204 --modes passive,fingerprint

# 3) Detección no destructiva del path OOM — requiere autorización explícita:
bash scripts/host/php2shell_check.sh --target 10.10.13.102 --detect --authorized

# 4) Dentro del servidor PHP (backports y config):
bash scripts/host/php2shell_check.sh --host-check

# 5) Chequeo offline de la tabla de clasificación:
bash scripts/host/php2shell_check.sh --self-test
```

| Opción | ¿Obligatoria? | Qué hace |
|---|---|---|
| `--target` | Sí (salvo `--self-test`/`--host-check`) | IP del servidor a verificar |
| `--target-id` | No | Solo etiqueta/ID (default: la IP) |
| `--ev-dir` | No | Dir de evidencia (default `evidence/<target>`) |
| `--ports` | No | Puertos web (default `80,443`; ejemplo `--ports 80,443,8080`) |
| `--passive` | No | Modo por defecto (solo lectura) |
| `--fingerprint` | No | Suma `passive,fingerprint` |
| `--detect` | No | Suma `passive,detect` (exige `--authorized`) |
| `--authorized` | Para `--detect` | Declara autorización explícita por target |
| `--host-check` | No | Chequeo local en el servidor (rpm/dpkg/php -i) |
| `--self-test` | No | Valida la clasificación sin tráfico |

## 📥 Entrada / 📤 Salida

- **Entrada:** `config/stealth.yaml` (`php2shell_timeout_seconds`, `php2shell_max_paths`) y el target.
- **Salida (todo en `evidence/<target>/`):**

| Archivo | Contenido |
|---|---|
| `php2shell_passive.txt` | Headers crudos por URL (`Server`, `X-Powered-By`, `Set-Cookie`, `PHPSESSID`) |
| `php2shell_fingerprint.txt` | Resultado del fingerprint (Drupal/versión, easter eggs PHP) |
| `php2shell_detect.txt` | Resultado del probe multipart + señales (fatal de memoria, 500s) |
| `php2shell_hostcheck.txt` | `php -v`, `session.upload_progress`, backport `CVE-2026-10961[89]`, paquetes. **Con `--host-check` va a `logs/php2shell_hostcheck/`** (corre dentro del servidor: no es evidencia de un target y no debe contaminar `evidence/`) |
| `php2shell_result.json` | JSON con versión, estado, SAPI y próximo paso |
| `php2shell_summary.txt` | Resumen legible para pegar en el plan/reporte |

- **Exit code:** `0` (sin afectados / versión no visible) · `2` (versión **afectada** o **EOL**) · `1` (error de uso).

## 🧷 Cómo clasifica

Igual que el advisory y que `php2shell_audit.py`: parcheado desde **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**;
`5.x`, `7.x`, `8.0`, `8.1` → **EOL sin release upstream**. El SAPI se infiere de los headers
(`Server: … PHP/` ⇒ **mod_php**; solo `X-Powered-By` ⇒ probable **FPM/proxy**).

## ⚠️ Notas de seguridad y alcance

- **`--passive`** solo hace `GET` a rutas estándar (`/`, `/index.php`, `/phpinfo.php`, `/install.php`,
  `/cron.php`) y al easter egg de PHP. **No** envía payloads.
- **`--detect`** manda **un** multipart con `session.upload_progress` y **una** cookie `PHPSESSID`
  larga/percent-encoded: son las señales públicas del advisory. **Nunca** ejecuta comandos, ni sube
  archivos, ni intenta shell.
- **R5 (sigilo):** timeouts, puertos y cantidad de rutas salen de `config/stealth.yaml`; hay `sleep 1`
  entre requests.
- **Nunca corre sobre targets fuera del scope firmado.** `--detect` exige `--authorized`.
- **Extracción de versión (fix 2026-10-22):** SOLO desde líneas de **header** (`Server:`, `X-Powered-By:`).
  Antes también miraba el **cuerpo** de las respuestas, lo que produjo un falso positivo en los Drupal/IIS:
  `/INSTALL.txt` dice *“PHP 5.3.0 or higher”* (requisito del CMS) y el check reportó **5.3.0** como si fuera
  la versión instalada. Peor: ese cuerpo **no se persiste**, así que el dato no era auditable — los headers
  sí están en el archivo de evidencia. Hay además un guard que ignora frases de requisitos
  (`requir…`, `or higher`, `minimum`, `at least`).
- **`--fingerprint`** persiste una línea **verificable** `Drupal-Version: <ver>` (fuente `CHANGELOG.txt`)
  además del comentario: así el informe puede citar la versión del CMS (Drupal 7 = EOL → PHP 5.x–7.x) sin
  depender de un cuerpo que no quedó guardado.
- **Si la versión de PHP no es visible remotamente** (típico en IIS: `X-Powered-By` oculto), la
  confirmación es **local en el host**: `--host-check` en Linux (emite `PHP-Version:` / `PHP-SAPI:`) o
  `php2shell_hostcheck_win.ps1` en Windows/IIS — ver
  [`php2shell_hostcheck_win.md`](php2shell_hostcheck_win.md) (incluye la vía sin infraestructura:
  `admin/reports/status` de Drupal).
- Después de correrlo, volvé a ejecutar `python3 scripts/php2shell_audit.py --target-ip <IP>` para
  incorporar la evidencia nueva y que **CK-10** quede consistente.
