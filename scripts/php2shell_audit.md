# `php2shell_audit.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **auditor determinista de PHP2Shell** (los dos RCE críticos de PHP de esta semana:
`CVE-2026-109618` y `CVE-2026-109619`, CVSS 9.2). Recorre la **evidencia que ya está en disco**
(Nikto, HTTPX, WhatWeb, Nmap y los headers que guardó Gobuster) y responde una sola pregunta por
target: **¿qué versión de PHP corre y está parcheada o no?**

No escanea nada, no hace requests y no toca la evidencia: **sólo lee archivos** y los clasifica
contra el advisory local `config/advisories/php2shell-2026-10-21.json`.

## ⏱️ ¿Cuándo se usa?

En la **Fase 2 (Análisis)**, antes de generar el plan de explotación del Agente 3 y como
complemento del CVE Research (Agente 4). También sirve para **re-auditar** todos los targets de una
corrida anterior cuando sale un advisory nuevo (Fase 2 de un run posterior).

> Es la red de seguridad que evita el hueco detectado en el run de octubre 2026: el Agente 4 sólo
> miraba `nmap_detailed.json` + `whatweb.json`, así que el PHP de `10.10.12.127` (que **sólo**
> aparecía en Nikto) nunca llegaba al informe.

## ▶️ Cómo se usa

```bash
# Un target (escribe cve_research/<target_id>_php2shell.json)
python3 scripts/php2shell_audit.py --target-id 10.10.12.127 --target-ip 10.10.12.127

# Todos los targets de evidence/ (escribe un JSON por target + reporte global en plans/)
python3 scripts/php2shell_audit.py --all

# Sin escribir nada (sólo consola)
python3 scripts/php2shell_audit.py --target-ip 10.10.13.102 --no-write

# Chequeo offline de la tabla de clasificación (no lee evidencia)
python3 scripts/php2shell_audit.py --self-test
```

| Opción | ¿Obligatoria? | Qué hace |
|---|---|---|
| `--target-ip` | Sí (salvo `--all`) | IP del target a auditar |
| `--target-id` | No | ID del target (si falta, lo toma de `config/scope.json`) |
| `--evidence-dir` | No | Dir de evidencia (default `evidence/<ip>`) |
| `--cliente-dir` | No | Dir consolidado (default `CLIENTE/<ip>/outputs`) |
| `--advisories` | No | Dir/archivo de advisories (default `config/advisories/`) |
| `--out` / `--report` | No | Rutas de salida del JSON / del reporte global |
| `--all` | No | Audita los 79 targets de `evidence/` y escribe el reporte global |
| `--no-write` | No | Modo consola: no escribe archivos |
| `--self-test` | No | Valida la clasificación de versiones sin tocar evidencia |

## 📥 Entrada / 📤 Salida

- **Entrada:** la evidencia de `evidence/<ip>/` y `CLIENTE/<ip>/outputs/`
  (`nikto_*.json`, `httpx.json`, `whatweb.json`, `nmap_detailed.*`, `gobuster_*`) + el advisory de
  `config/advisories/` + la **evidencia de campo** del check (`php2shell_passive.txt`,
  `php2shell_fingerprint.txt`, `php2shell_detect.txt` y `php2shell_result.json`).
  Cuando existe `php2shell_result.json`, **manda sobre la evidencia vieja** — pero sólo si su versión es
  **verificable**: el auditor exige que esa versión aparezca en una **línea de header** de la evidencia
  cruda (`php2shell_passive.txt`/`fingerprint.txt`/`detect.txt`, ignorando los comentarios `#`).
  Si no aparece (p. ej. el check la sacó de un cuerpo que no se persiste, como el *“PHP 5.3.0 or higher”*
  de `/INSTALL.txt` de Drupal), queda `field_check.verified = false`, **se descarta** para clasificar, el
  target queda `unknown_version` y se agrega la nota explicativa. Cuando sí se verifica, la versión de
  campo pasa a ser la principal, su SAPI se reporta como “confirmado en campo” y el JSON agrega el bloque
  `field_check` (`checked_at`, `modes`, `next_steps`). Si difiere de un run previo, el JSON lista **ambas**
  en `versions_detected` y agrega la nota “Versiones de PHP distintas…”.
  La versión de **Drupal** que persiste `--fingerprint` (`Drupal-Version: 7.xx`) se muestra como huella
  (`Drupal 7.xx (CMS EOL: requiere migración)`) en `app_hints`/`signals`, no como versión de PHP.
- **Salida:**
  - `cve_research/<ip>_php2shell.json` — el nombre usa la **IP** (convención de `cve_research/`; el id
    canónico `S-<ip>`, si existe, queda dentro del JSON en `target_id`). `CK-10` resuelve el
    `_cves.json` probando **primero** `<target_id>_cves.json` y, si no existe, `<ip>_cves.json`.
  - `plans/php2shell_<fecha>.md` — reporte global con 4 bloques: afectados, PHP sin versión,
    parcheados y sin evidencia de PHP.
- **Exit code:** `0` (nada afectado) · `2` (hay afectados: usable como *gate*) · `1` (error de uso).

## 🧷 Cómo clasifica (tabla PHP2Shell)

| Rama | Parcheada desde |
|---|---|
| 8.2.x | **8.2.35** |
| 8.3.x | **8.3.36** |
| 8.4.x | **8.4.27** |
| 8.5.x | **8.5.12** |
| 5.x / 7.x / 8.0 / 8.1 | **EOL**: sin release upstream con el fix (sólo backport de vendor o de fuente) |

Estados posibles: `affected` · `eol_sin_parche` · `patched` · `unknown_version` (hay PHP pero no se
pudo leer la versión) · `no_php_evidence`.

## ⚠️ Notas

- **Cada hallazgo cita `archivo` + `línea`** (ej. `evidence/10.10.12.127/nikto_80.json L20`) para
  cumplir la regla anti-alucinación.
- **Detecta el SAPI probable:** si el header `Server` incluye `PHP/` → **mod_php** (riesgo máximo
  según el advisory); si sólo hay `X-Powered-By` → probable PHP-FPM / proxy.
- **Backports de distro:** si la evidencia muestra marcas de paquete (ubuntu/el7/el8…), el JSON
  marca `distro_backport_posible: true` → **verificar en campo** con
  `rpm -q --changelog php | grep -i CVE-2026-1096` antes de concluir que está sin parchear.
- **IIS/Drupal:** cuando el banner PHP está oculto, la huella del CMS (rutas por defecto de Drupal,
  `doku.php`, `wp-login.php`, phpMyAdmin, Joomla) alcanza para marcar `unknown_version` →
  “hay PHP, falta la versión” (lo resuelve el script de campo `scripts/host/php2shell_check.sh`).
- Este script **no reemplaza** al Agente 4: lo complementa. El Agente 4 sigue consultando `vulnx`
  para el resto de los CVEs.
