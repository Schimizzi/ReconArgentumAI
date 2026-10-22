#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_audit.py — Auditoría determinista de PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

Barre la EVIDENCIA YA GENERADA (nikto, httpx, whatweb, nmap, headers de Gobuster) y
clasifica cada target contra el advisory local `config/advisories/php2shell-*.json`.

100% offline y 100% de solo lectura: NO hace requests de red y NO modifica la
evidencia. Cada hallazgo cita archivo + línea (regla anti-alucinación del Agente 3/4).

Uso:
  python3 scripts/php2shell_audit.py --target-id 10.10.12.127 --target-ip 10.10.12.127
  python3 scripts/php2shell_audit.py --all
  python3 scripts/php2shell_audit.py --self-test

Salidas:
  cve_research/<target_id>_php2shell.json   (una por target auditado)
  plans/php2shell_<YYYY-MM-DD>.md           (reporte global, se escribe con --all)

Exit codes: 0 = sin afectados | 2 = hay afectados (afectado o EOL) | 1 = error de uso
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADVISORIES_DEFAULT = os.path.join(WS, "config", "advisories")
EVIDENCE_DIR = os.path.join(WS, "evidence")
CLIENTE_DIR = os.path.join(WS, "CLIENTE")
SCOPE_PATH = os.path.join(WS, "config", "scope.json")

MAX_LINES_PER_FILE = 300000      # tope de líneas por archivo (evita crudos gigantes)
MAX_FILE_BYTES = 80 * 1024 * 1024

STATUS_AFFECTED = "affected"
STATUS_EOL = "eol_sin_parche"
STATUS_PATCHED = "patched"
STATUS_UNKNOWN = "unknown_version"
STATUS_NO_PHP = "no_php_evidence"

# ---------------------------------------------------------------------------
# Advisories locales + clasificación de versiones
# ---------------------------------------------------------------------------


def _rel(path: str) -> str:
    try:
        return os.path.relpath(path, WS)
    except ValueError:
        return path


def parse_version(text):
    """(major, minor, patch) de un string de versión; None si no hay versión."""
    if text is None:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text))
    if not m:
        return None
    parts = [m.group(1), m.group(2), m.group(3)]
    return tuple(int(p) if p is not None else 0 for p in parts)


def load_advisories(path=None):
    """Carga los advisories activos desde un directorio o archivo JSON."""
    src = path or ADVISORIES_DEFAULT
    files = []
    if os.path.isdir(src):
        files = sorted(glob.glob(os.path.join(src, "*.json")))
    elif os.path.isfile(src):
        files = [src]
    advisories = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                adv = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"  ⚠️  advisory ilegible {fp}: {e}", file=sys.stderr)
            continue
        if adv.get("active", True):
            adv["_source_file"] = _rel(fp)
            advisories.append(adv)
    return advisories


def classify_php(version, adv):
    """Clasifica una versión de PHP contra el advisory.

    Devuelve dict: status, patched_version, branch, detail.
    """
    v = parse_version(version)
    if v is None:
        return {"status": STATUS_UNKNOWN, "patched_version": None, "branch": None,
                "detail": "versión de PHP no detectada — requiere fingerprint activo"}
    branch = f"{v[0]}.{v[1]}"
    branches = adv.get("branches") or {}
    if branch in branches:
        patched = (branches[branch] or {}).get("patched")
        pv = parse_version(patched)
        if pv and v < pv:
            return {"status": STATUS_AFFECTED,
                    "patched_version": patched, "branch": branch,
                    "detail": f"rama {branch} < {patched} (sin parche upstream)"}
        return {"status": STATUS_PATCHED, "patched_version": patched,
                "branch": branch,
                "detail": f"versión >= {patched} (parcheada upstream)"}
    eol_max = parse_version(adv.get("eol_max_exclusive"))
    if eol_max and v < eol_max:
        return {"status": STATUS_EOL, "patched_version": None, "branch": branch,
                "detail": adv.get("eol_note") or
                          f"rama {branch} EOL: sin release upstream con el fix"}
    return {"status": "not_affected_branch", "patched_version": None,
            "branch": branch,
            "detail": f"rama {branch} fuera del rango del advisory"}


def _distro_backport_hint(texts):
    """True si el texto evidencia paquete de distro (backport posible sin cambiar versión)."""
    blob = " ".join(texts).lower()
    return any(tag in blob for tag in ("ubuntu", "el7", "el8", "el9", "fedora",
                                       "debian", "suse", "rhsa", "cloudlinux"))

# ---------------------------------------------------------------------------
# Extracción de versiones desde la evidencia cruda
# ---------------------------------------------------------------------------

# (regex, tipo de hallazgo) — se aplican línea por línea y citan archivo + línea.
SCAN_PATTERNS = [
    (re.compile(r'"msg"\s*:\s*"Retrieved x-powered-by header:\s*PHP[/ ]?v?(\d+\.\d+(?:\.\d+)?)', re.I),
     "nikto-x-powered-by"),
    (re.compile(r'"msg"\s*:\s*"PHP/(\d+\.\d+(?:\.\d+)?)\s+appears to be outdated', re.I),
     "nikto-banner-outdated"),
    (re.compile(r'"tech"\s*:\s*\[[^\]]*"PHP:(\d+\.\d+(?:\.\d+)?)"', re.I), "httpx-tech"),
    (re.compile(r'"PHP"\s*:\s*\{\s*"version"\s*:\s*\[\s*"(\d+\.\d+(?:\.\d+)?)"', re.I),
     "whatweb-php-plugin"),
    (re.compile(r'"extrainfo"\s*:\s*"[^"]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I), "nmap-extrainfo"),
    (re.compile(r'http-server-header:[^\n]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I),
     "nmap-http-server-header"),
    (re.compile(r'x-powered-by\s*:\s*PHP[/ ]?v?(\d+\.\d+(?:\.\d+)?)', re.I),
     "header-x-powered-by"),
    (re.compile(r'server\s*:[^\n]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I), "header-server-php"),
    # Línea canónica de la verificación LOCAL en el host (Windows/IIS o Linux):
    # `PHP-Version: 7.4.33`. Es el único camino aceptado para versiones "locales"
    # (nunca se infiere la versión del cuerpo de una página).
    (re.compile(r'^php-version:\s*v?(\d+\.\d+(?:\.\d+)?)', re.I), "host-check-php-version"),
]

# PHP detectado pero SIN versión (ej. Drupal sobre IIS: httpx reporta tech "PHP")
PHP_NO_VERSION = re.compile(r'"tech"\s*:\s*\[[^\]]*"PHP"\s*[,\]]', re.I)
SERVER_HAS_PHP = re.compile(r'^server\s*:[^\n]*PHP[/ ]', re.I | re.M)
PHPSESSID_RE = re.compile(r'PHPSESSID', re.I)
# Versión de Drupal persistida por `--fingerprint` (línea verificable, no comentario)
DRUPAL_VER_RE = re.compile(r'^drupal[ -]?version:\s*([\d.]+)', re.I)
# SAPI declarado por la verificación local en el host (`PHP-SAPI: fastcgi/php-fpm (IIS)`)
PHP_SAPI_RE = re.compile(r'^php-sapi:\s*(.+?)\s*$', re.I)
# Drupal confirmado por el header X-Generator (WhatWeb lo deja en whatweb.json; el
# check de campo lo captura desde 2026-10-22). Solo la rama mayor (7/8/9...).
DRUPAL_GEN_PATTERNS = [
    re.compile(r'"X-Generator"\s*:\s*\{\s*"string"\s*:\s*\[\s*"Drupal\s*(\d+)', re.I),
    re.compile(r'^x-generator:\s*Drupal\s*(\d+)', re.I),
]

# Marcas de distro en la evidencia (RHEL/Ubuntu backportean el fix SIN cambiar la
# versión upstream, ej. 8.3.6-0ubuntu0.24.04.x) → obliga a verificar el changelog.
DISTRO_RE = re.compile(r'\b(red\s*hat|rhel|centos|ubuntu|debian|suse|cloudlinux|'
                       r'almalinux|rocky|fedora)\b|\bel[789]\b|\brhsa\b', re.I)

# Huellas de aplicaciones PHP (cuando el banner X-Powered-By está oculto, ej. IIS):
# un solo match alcanza para afirmar "hay PHP pero no sé la versión".
# OJO: patrones ESPECÍFICOS. `cron.php` solo no alcanza (existe en cualquier app PHP y
# además es una de las rutas que sondea el propio php2shell_check → falso "Drupal").
PHP_APP_SIGNALS = [
    (re.compile(r'INSTALL\.(mysql|pgsql|sqlite)\.txt', re.I),
     "rutas por defecto de Drupal (CMS PHP)"),
    (re.compile(r'doku\.php|lib/exe/taskrunner\.php', re.I), "DokuWiki (app PHP)"),
    (re.compile(r'wp-login\.php|wp-includes/|wp-content/', re.I), "WordPress (app PHP)"),
    (re.compile(r'phpmyadmin|/pma/', re.I), "phpMyAdmin (app PHP)"),
    (re.compile(r'/components/com_[a-z]+', re.I), "Joomla (CMS PHP)"),
]

CANDIDATE_GLOBS = [
    "nikto_*.json", "httpx.json", "whatweb.json", "nmap_detailed.json",
    "nmap_detailed.txt", "nmap_detailed.xml", "gobuster_evidence.txt",
    "gobuster_evidence.json", "gobuster_commands_outputs.txt", "gobuster_*.txt",
    # Verificación de campo (scripts/host/php2shell_check.sh): headers crudos por URL.
    # Sin esto, el resultado del check de campo NO entraba al informe ni a CK-10.
    "php2shell_passive.txt", "php2shell_fingerprint.txt", "php2shell_detect.txt",
    # Verificación LOCAL en el host (bash --host-check o el PS1 de Windows/IIS)
    "php2shell_hostcheck*.txt",
]


def _candidate_files(dirs):
    """Archivos de evidencia a barrer (deduplicados, en orden)."""
    files = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for pat in CANDIDATE_GLOBS:
            files.extend(sorted(glob.glob(os.path.join(d, pat))))
    seen, out = set(), []
    for fp in files:
        if fp not in seen:
            seen.add(fp)
            out.append(fp)
    return out


def _scan_file(path):
    """Devuelve (findings, flags) para un archivo de evidencia.

    findings: [{"version","source_file","line","evidence","kind"}]
    flags: php_no_version / server_php / phpsessid / texts
    """
    findings = []
    flags = {"php_no_version": False, "server_php": False, "phpsessid": False,
             "distro": False, "app_hints": [], "texts": []}
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return findings, flags
        with open(path, "r", errors="ignore") as fh:
            for i, line in enumerate(fh, 1):
                if i > MAX_LINES_PER_FILE:
                    break
                if PHP_NO_VERSION.search(line):
                    flags["php_no_version"] = True
                if SERVER_HAS_PHP.search(line):
                    flags["server_php"] = True
                if PHPSESSID_RE.search(line):
                    flags["phpsessid"] = True
                if not flags["distro"] and DISTRO_RE.search(line):
                    flags["distro"] = True
                    flags["texts"].append(line.strip()[:200])
                for pat, label in PHP_APP_SIGNALS:
                    # Las líneas de log del propio check (# ..., ## GET ...) NO son
                    # evidencia: son los sondeos que hicimos nosotros.
                    if not line.lstrip().startswith("#") and label not in flags["app_hints"] \
                            and pat.search(line):
                        flags["app_hints"].append(label)
                drupal_m = DRUPAL_VER_RE.match(line.strip())
                if drupal_m and not flags.get("drupal_version"):
                    flags["drupal_version"] = drupal_m.group(1)
                sapi_m = PHP_SAPI_RE.match(line.strip())
                if sapi_m and not flags.get("host_sapi"):
                    flags["host_sapi"] = sapi_m.group(1)
                if not flags.get("drupal_generator"):
                    for dgen in DRUPAL_GEN_PATTERNS:
                        gm = dgen.search(line.strip())
                        if gm:
                            flags["drupal_generator"] = gm.group(1)
                            break
                for pat, kind in SCAN_PATTERNS:
                    m = pat.search(line)
                    if m:
                        findings.append({"version": m.group(1),
                                         "source_file": _rel(path),
                                         "line": i,
                                         "evidence": line.strip()[:200],
                                         "kind": kind})
                        break
    except (IOError, OSError):
        return findings, flags
    flags["texts"] = flags["texts"] + [f["evidence"] for f in findings]
    return findings, flags

# ---------------------------------------------------------------------------
# Auditoría de un target
# ---------------------------------------------------------------------------


def _scope_ids():
    """Mapa {ip: target_id} seguro desde config/scope.json.

    OJO: `config/scope.json` puede traer ids duplicados o cruzados entre IPs
    (verificado en el run de octubre 2026: cuatro IPs con id `S-10.10.10.80` y
    `10.10.10.204` con el id de `10.10.10.195`). Como el JSON de salida se nombra
    `<target_id>_php2shell.json`, un id compartido hace que los targets se pisen.
    Regla: se usa el id del scope SOLO si es único; si está repetido → la IP.
    """
    try:
        with open(SCOPE_PATH, "r", encoding="utf-8") as f:
            scope = json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}
    raw, usados = {}, {}
    for tg in scope.get("authorized_targets", []) or []:
        ip, tid = tg.get("ip"), tg.get("id")
        if ip and tid:
            raw[ip] = tid
    for tid in raw.values():
        usados[tid] = usados.get(tid, 0) + 1
    return {ip: (tid if usados[tid] == 1 else ip) for ip, tid in raw.items()}


def _load_field_check(ev_dir):
    """Lee `evidence/<ip>/php2shell_result.json` (salida del check de campo).

    Devuelve None si no existe. Es la fuente MÁS autoritativa (el check vio los
    headers en vivo, no la evidencia de un run previo).
    """
    fp = os.path.join(ev_dir, "php2shell_result.json")
    if not os.path.isfile(fp):
        return None
    try:
        with open(fp, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
    php = data.get("php") or {}
    return {
        "checked_at": data.get("checked_at"),
        "modes": data.get("modes"),
        "version": (php.get("version") or "").strip() or None,
        "versions_detected": php.get("versions_detected") or "",
        "status": php.get("status"),
        "sapi_hint": php.get("sapi_hint"),
        "next_steps": data.get("next_steps"),
        "source_file": _rel(fp),
    }


def _field_version_verifiable(ev_dir, version):
    """¿La versión declarada por el check de campo aparece en la evidencia cruda?

    Guard anti-deriva (fix 2026-10-22): el check de campo puede haber extraído la
    versión de un **cuerpo** de respuesta que no se persiste (p.ej. `/INSTALL.txt`
    de Drupal dice "PHP 5.3.0 or higher" → reportó 5.3.0 y 5.2.4 como si fueran la
    versión instalada). Si la versión no está en una línea de header de la evidencia,
    el dato NO es auditable y se descarta.
    """
    if not version:
        return False
    pat = re.compile(r'PHP[/ ]?v?' + re.escape(version) + r'(?![\d.])', re.I)
    for name in ("php2shell_passive.txt", "php2shell_fingerprint.txt", "php2shell_detect.txt"):
        fp = os.path.join(ev_dir, name)
        if not os.path.isfile(fp):
            continue
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.lstrip().startswith("#"):
                        continue        # los sondeos que hicimos nosotros no son evidencia
                    if pat.search(line):
                        return True
        except IOError:
            continue
    return False


def audit_target(target_ip, adv, evidence_dir=None, cliente_dir=None, target_id=None):
    """Audita un target y devuelve el dict de resultado (no escribe nada)."""
    ev = evidence_dir or os.path.join(EVIDENCE_DIR, target_ip)
    cl = cliente_dir if cliente_dir is not None else os.path.join(
        CLIENTE_DIR, target_ip, "outputs")
    tid = target_id or _scope_ids().get(target_ip) or target_ip

    findings, flags_all, scanned = [], {}, []
    for fp in _candidate_files([ev, cl]):
        scanned.append(_rel(fp))
        f, fl = _scan_file(fp)
        for k, v in fl.items():
            if k in ("texts", "app_hints"):
                flags_all.setdefault(k, []).extend(v)
            elif k == "drupal_version":
                flags_all[k] = flags_all.get(k) or v      # string, no booleano
            elif k == "drupal_generator":
                flags_all[k] = flags_all.get(k) or v      # string (rama mayor)
            elif k == "host_sapi":
                flags_all[k] = flags_all.get(k) or v      # string (SAPI local)
            elif v:
                flags_all[k] = True
        findings.extend(f)
    flags_all["app_hints"] = sorted(set(flags_all.get("app_hints", [])))
    # La versión de Drupal (persistida por --fingerprint) se muestra junto a las huellas:
    # Drupal 7 = CMS EOL → PHP 5.x-7.x (afectado por diseño en PHP2Shell).
    if flags_all.get("drupal_version"):
        flags_all["app_hints"] = sorted(set(flags_all["app_hints"])
                                        | {"Drupal %s (CMS EOL: requiere migración)"
                                           % flags_all["drupal_version"]})
    elif flags_all.get("drupal_generator"):
        flags_all["app_hints"] = sorted(set(flags_all["app_hints"])
                                        | {"Drupal %s confirmado por X-Generator (CMS EOL)"
                                           % flags_all["drupal_generator"]})

    # Verificación de campo (más autoritativa que la evidencia de un run previo)…
    # …pero SOLO si su versión es verificable en la evidencia cruda (headers).
    field = _load_field_check(ev)
    if field and field.get("version") and not _field_version_verifiable(ev, field["version"]):
        field["verified"] = False
        field["unverified_version"] = field["version"]
        field["version"] = None
    elif field and field.get("version"):
        field["verified"] = True
    if field and field.get("version"):
        findings.append({
            "version": field["version"],
            "source_file": field["source_file"],
            "line": 0,
            "evidence": ("verificación de campo: version=%s status=%s sapi=%s"
                         % (field["version"], field.get("status"), field.get("sapi_hint"))),
            "kind": "field-check",
        })

    # Versiones únicas (ordenadas) y su frecuencia
    versions = []
    for f in findings:
        if f["version"] not in versions:
            versions.append(f["version"])
    if field and field.get("version") and field["version"] in versions:
        versions.remove(field["version"])
        versions.insert(0, field["version"])   # la de campo primero
    findings.sort(key=lambda x: (x["version"], x["source_file"], x["line"]))

    if versions:
        primary = versions[0]
        cls = classify_php(primary, adv)
        notes = []
        if len(versions) > 1:
            notes.append("Versiones de PHP distintas en la evidencia: " +
                         ", ".join(versions))
        host_sapi = (flags_all.get("host_sapi") or "").strip()
        field_sapi = (field or {}).get("sapi_hint") or ""
        if host_sapi and host_sapi.lower() != "desconocido":
            sapi = "confirmado en el host -> " + host_sapi
        elif field_sapi and field_sapi != "desconocido":
            sapi = "confirmado en campo -> " + field_sapi
        elif flags_all.get("server_php"):
            sapi = "mod_php (el header Server incluye PHP/ → módulo Apache)"
        elif any(f["kind"] in ("header-x-powered-by", "nikto-x-powered-by",
                               "httpx-tech", "whatweb-php-plugin") for f in findings):
            sapi = "php-fpm / proxy probable (sólo X-Powered-By o fingerprint de tech)"
        else:
            sapi = "desconocido"
    else:
        primary, cls = None, None
        sapi = "desconocido"
        notes = []
        if flags_all.get("php_no_version") or flags_all.get("app_hints") \
                or (field and field.get("verified") is False):
            cls = classify_php(None, adv)
            motivo = []
            if flags_all.get("php_no_version"):
                motivo.append("fingerprint 'tech: PHP' sin versión")
            if flags_all.get("app_hints"):
                motivo.append("app PHP detectada: " + "; ".join(flags_all["app_hints"]))
            if field and field.get("verified") is False:
                motivo.append("el check de campo declaró %s, descartada por no verificable"
                              % field.get("unverified_version"))
            cls["detail"] = ("PHP presente pero SIN versión en la evidencia ("
                             + ", ".join(motivo) + ") → requiere fingerprint activo")
        else:
            cls = {"status": STATUS_NO_PHP, "patched_version": None, "branch": None,
                   "detail": "sin evidencia de PHP en la evidencia actual"}

    signals = []
    if flags_all.get("phpsessid"):
        signals.append("PHPSESSID presente (app PHP con sesiones)")
    if flags_all.get("php_no_version"):
        signals.append("fingerprint PHP sin versión (tech: PHP)")
    signals.extend(flags_all.get("app_hints", []))

    distro_hint = bool(flags_all.get("distro")) or _distro_backport_hint(
        flags_all.get("texts", []) + list(scanned))
    if field and field.get("verified") is False:
        notes.append("El check de campo declaró PHP %s, pero esa versión NO aparece en la "
                     "evidencia cruda (headers) → descartada por no verificable."
                     % field.get("unverified_version"))
    if distro_hint and cls["status"] in (STATUS_AFFECTED, STATUS_EOL):
        notes.append("Indicio de paquete de distro: verificar backport "
                     "(rpm -q --changelog php | grep -i CVE-2026-1096) antes de "
                     "confirmar explotabilidad.")

    return {
        "target": target_ip,
        "target_id": tid,
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "advisory_id": adv.get("advisory_id"),
        "advisory_cves": [c.get("id") for c in adv.get("cves", [])],
        "advisory_score": adv.get("cvss_score"),
        "field_check": field,
        "php": {
            "versions_detected": versions,
            "version": primary,
            "status": cls["status"],
            "branch": cls["branch"],
            "patched_version": cls["patched_version"],
            "detail": cls["detail"],
            "sapi_hint": sapi,
            "distro_backport_posible": bool(distro_hint),
            "app_hints": flags_all.get("app_hints", []),
            "signals": signals,
        },
        "findings": findings,
        "sources_scanned": scanned,
        "notes": notes,
    }

# ---------------------------------------------------------------------------
# Reporte global (markdown)
# ---------------------------------------------------------------------------


def _report_markdown(results, adv, path):
    """Escribe el reporte global en markdown y devuelve el path."""
    affected = [r for r in results
                if r["php"]["status"] in (STATUS_AFFECTED, STATUS_EOL)]
    unknown = [r for r in results if r["php"]["status"] == STATUS_UNKNOWN]
    patched = [r for r in results if r["php"]["status"] == STATUS_PATCHED]
    clean = [r for r in results if r["php"]["status"] == STATUS_NO_PHP]

    def table(rows):
        out = ["| Target | PHP | Estado | Rama | Parche | SAPI (probable) | Evidencia |",
               "|---|---|---|---|---|---|---|"]
        for r in rows:
            php = r["php"]
            # Cita la fuente de la versión PRINCIPAL (si vino del check de campo, esa)
            ev = "—"
            for f in r["findings"]:
                if f["version"] == php["version"]:
                    ev = (f"{f['source_file']} L{f['line']}" if f["line"] else f["source_file"])
                    break
            if ev == "—" and r["findings"]:
                ev = f"{r['findings'][0]['source_file']} L{r['findings'][0]['line']}"
            if ev == "—" and php.get("app_hints"):
                ev = "; ".join(php["app_hints"])
            out.append("| `{}` | {} | {} | {} | {} | {} | {} |".format(
                r["target"], php["version"] or "?", php["status"],
                php["branch"] or "—", php["patched_version"] or "—",
                php["sapi_hint"], ev))
        return out

    md = [
        f"# Auditoría PHP2Shell — {adv.get('advisory_id')}",
        "",
        f"**Generado:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Advisory:** {adv.get('title')} (CVSS {adv.get('cvss_score')} "
        f"{adv.get('severity')})  ",
        f"**CVEs:** {', '.join(c.get('id') for c in adv.get('cves', []))}  ",
        "**Fuentes:** " + "; ".join(adv.get("sources", [])),
        "",
        f"- Targets auditados: **{len(results)}**",
        f"- Afectados (versión vulnerable o EOL): **{len(affected)}**",
        f"- PHP sin versión (requiere fingerprint): **{len(unknown)}**",
        f"- Parcheados: **{len(patched)}**",
        f"- Sin evidencia de PHP: **{len(clean)}**",
        "",
    ]
    if affected:
        md += ["## 🔴 Afectados", "", *table(affected), ""]
        for r in affected:
            md.append(f"- `{r['target']}`: {r['php']['detail']}"
                      + ("  \n  → " + " ".join(r["notes"]) if r["notes"] else ""))
            if r["php"]["signals"]:
                md.append(f"  - Señales: {', '.join(r['php']['signals'])}")
        md.append("")
    if unknown:
        md += ["## 🟡 PHP detectado sin versión (verificar en campo)", "",
               *table(unknown), ""]
    if patched:
        md += ["## 🟢 Parcheados", "", *table(patched), ""]
    md += ["## ⚪ Sin evidencia de PHP", "",
           ", ".join(f"`{r['target']}`" for r in clean) or "—", "",
           "> Ausencia de evidencia ≠ ausencia de PHP: los targets listados arriba",
           "> no exponen banner PHP en la evidencia actual.", ""]

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    return path


# ---------------------------------------------------------------------------
# Self-test (offline)
# ---------------------------------------------------------------------------

SELF_TEST_CASES = [
    ("5.4.16", STATUS_EOL), ("7.4.33", STATUS_EOL), ("8.0.30", STATUS_EOL),
    ("8.1.29", STATUS_EOL), ("8.2.31", STATUS_AFFECTED),
    ("8.2.34", STATUS_AFFECTED), ("8.2.35", STATUS_PATCHED),
    ("8.3.35", STATUS_AFFECTED), ("8.3.36", STATUS_PATCHED),
    ("8.4.26", STATUS_AFFECTED), ("8.4.27", STATUS_PATCHED),
    ("8.5.11", STATUS_AFFECTED), ("8.5.12", STATUS_PATCHED),
    ("8.2.33", STATUS_AFFECTED), ("8.5.1", STATUS_AFFECTED),
]


def self_test():
    adv = load_advisories()
    if not adv:
        print("❌ No se cargó ningún advisory de config/advisories/")
        return 1
    advisory = adv[0]
    print(f"\n🧪 Self-test de clasificación PHP2Shell ({advisory.get('advisory_id')})")
    fails = 0
    for version, expected in SELF_TEST_CASES:
        got = classify_php(version, advisory)["status"]
        ok = got == expected
        fails += 0 if ok else 1
        print(f"  {'✅' if ok else '❌'} PHP {version:<8} → {got:<16} (esperado {expected})")
    if parse_version(None) is not None:
        fails += 1
        print("  ❌ parse_version(None) debe ser None")
    if parse_version("sin-version") is not None:
        fails += 1
        print("  ❌ parse_version('sin-version') debe ser None")
    print(f"\n  Resultado: {'OK' if fails == 0 else str(fails) + ' FALLOS'}\n")
    return 0 if fails == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_result(r):
    php = r["php"]
    icon = {"affected": "🔴", "eol_sin_parche": "🔴", "patched": "🟢",
            "unknown_version": "🟡", "no_php_evidence": "⚪",
            "not_affected_branch": "⚪"}.get(php["status"], "❔")
    vers = php["version"] or ("SIN VERSIÓN" if php["status"] == STATUS_UNKNOWN
                              else "sin evidencia")
    print(f"  {icon} {r['target']} → PHP {vers} [{php['status']}]")

    for f in r["findings"]:
        print(f"      · {f['source_file']} L{f['line']}: {f['evidence'][:110]}")
    print(f"      SAPI: {php['sapi_hint']}")
    if php["distro_backport_posible"]:
        print("      ⚠️  indicio de paquete de distro → verificar backport del vendor")
    for n in r["notes"]:
        print(f"      ℹ️  {n}")


def main():
    parser = argparse.ArgumentParser(
        description="Auditoría determinista PHP2Shell (offline, read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-ip", help="IP del target (requerido salvo --all/--self-test)")
    parser.add_argument("--target-id", help="ID del target (default: config/scope.json o la IP)")
    parser.add_argument("--evidence-dir", help="Dir de evidencia (default evidence/<ip>)")
    parser.add_argument("--cliente-dir", help="Dir CLIENTE/<ip>/outputs (default automático)")
    parser.add_argument("--advisories", help=f"Dir/archivo de advisories (default {ADVISORIES_DEFAULT})")
    parser.add_argument("--out", help="JSON de salida (default cve_research/<ip>_php2shell.json)")
    parser.add_argument("--report", help="Reporte markdown global (default plans/php2shell_<fecha>.md)")
    parser.add_argument("--all", action="store_true", help="Auditar todos los targets de evidence/")
    parser.add_argument("--no-write", action="store_true", help="No escribir JSON ni reporte")
    parser.add_argument("--self-test", action="store_true", help="Test offline de clasificación")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    advisories = load_advisories(args.advisories)
    if not advisories:
        print("❌ No hay advisories activos en config/advisories/", file=sys.stderr)
        return 1
    adv = advisories[0]

    if args.all:
        targets = sorted(d for d in os.listdir(EVIDENCE_DIR)
                         if os.path.isdir(os.path.join(EVIDENCE_DIR, d))
                         and not d.startswith("_"))   # auxiliares locales (ej. _hostcheck)
    elif args.target_ip:
        targets = [args.target_ip]
    else:
        parser.error("indicá --target-ip o --all (o --self-test)")

    print(f"\n🔎 Auditoría PHP2Shell — advisory {adv.get('advisory_id')} "
          f"({len(targets)} target(s))")
    results = []
    for ip in targets:
        r = audit_target(ip, adv, evidence_dir=args.evidence_dir,
                         cliente_dir=args.cliente_dir, target_id=args.target_id)
        results.append(r)
        if not args.all:
            _print_result(r)

    affected = [r for r in results
                if r["php"]["status"] in (STATUS_AFFECTED, STATUS_EOL)]
    unknown = [r for r in results if r["php"]["status"] == STATUS_UNKNOWN]

    if not args.no_write:
        if args.all:
            # un JSON por target (y nada cuando no hay evidencia de PHP: evita ruido)
            for r in results:
                if r["php"]["status"] == STATUS_NO_PHP:
                    continue
                # Nombre por IP: es la convención de cve_research/ (los *_cves.json del
                # Agente 4 se nombran con el id con que se lo invoca, típicamente la IP).
                # El id canónico (S-<ip>) queda DENTRO del JSON, en target_id.
                out = os.path.join(WS, "cve_research",
                                   f"{r['target']}_php2shell.json")
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(r, f, ensure_ascii=False, indent=2)
            report = args.report or os.path.join(
                WS, "plans", f"php2shell_{datetime.now(timezone.utc).date()}.md")
            _report_markdown(results, adv, report)
            print(f"\n  ✅ Reporte global → {_rel(report)}")
        else:
            out = args.out or os.path.join(
                WS, "cve_research", f"{results[0]['target']}_php2shell.json")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                json.dump(results[0], f, ensure_ascii=False, indent=2)
            print(f"\n  ✅ Output → {_rel(out)}")

    print(f"\n  📊 Afectados: {len(affected)} | PHP sin versión: {len(unknown)} | "
          f"Total auditados: {len(results)}")
    if affected:
        print("  🔴 " + ", ".join(f"{r['target']} (PHP {r['php']['version']})"
                                 for r in affected))
    print()
    return 2 if affected else 0


if __name__ == "__main__":
    sys.exit(main())
