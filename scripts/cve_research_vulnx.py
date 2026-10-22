#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_research_vulnx.py — Agente 4 (CVE Research) usando vulnx como motor principal.

Reemplaza a los antiguos nvd_query.py y nvd_cve_detail.py (eliminados del repo en
la migración a vulnx; recuperables desde el historial git si hicieran falta).
Usa el CLI `vulnx` de ProjectDiscovery para buscar CVEs por producto+versión
y obtener detalles completos de cada CVE.

Contrato de salida (IDÉNTICO al anterior):
  cve_research/<target_id>_cves.json

Uso:
  python3 scripts/cve_research_vulnx.py \\
      --target-id TGT-001 --target-ip 10.0.0.1 \\
      --nmap evidence/10.0.0.1/nmap_detailed.json \\
      --whatweb evidence/10.0.0.1/whatweb.json \\
      --nuclei evidence/10.0.0.1/nuclei.json \\
      [--output cve_research/TGT-001_cves.json]

Requiere:
  - vulnx CLI en PATH (github.com/projectdiscovery/vulnx/v2/cmd/vulnx)
  - Variable de entorno PDCP_API_KEY (opcional, elimina rate limits)
  - Python 3.8+
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
VULNX_BIN = "vulnx"
VULNX_TIMEOUT = 30
VULNX_ATTEMPTS = 3          # reintentos por consulta (sin API key vulnx puede rate-limitar)
VULNX_RETRY_DELAY = 4       # segundos de espera entre reintentos
SEARCH_LIMIT = 20
TOP_N_MAX = 5
CVSS_MIN = 4.0

# Filtro de relevancia CVE->servicio activado por defecto (ver _cve_is_relevant).
# Desactivable con --no-relevance-filter.
RELEVANCE_FILTER = True

# Filtro de versión parcheada activado por defecto (ver _is_covered_by_declared_fix).
# Desactivable con --no-patched-filter.
PATCHED_FILTER = True

# Patrones de "versión de fix" declarada por el CVE.
# Ejemplos reales de la evidencia: "Upgrade to PHP 8.2.33, 8.3.33, 8.4.24, 8.5.9 or later",
# "Update to PHP 5.4.16 RC1 or later", "Update to Apache HTTP Server 2.4.39 or later",
# "PHP 8.2.* < 8.2.33", "OpenSSH before 9.6".
FIX_LIST_PATTERN = re.compile(
    r'(?:upgrade|update|patched|fixed|resolved|mitigated)\b[^.\n]{0,45}?'
    r'((?:\d+\.\d+(?:\.\d+)?(?![\dA-Za-z])(?!\.\d)(?:\s*,\s*)?)+)', re.I)
FIX_OR_LATER_PATTERN = re.compile(
    r'(\d+\.\d+(?:\.\d+)?(?![\dA-Za-z])(?!\.\d))[^\d\n]{0,14}?\bor\s+(?:later|newer|higher|above)', re.I)
FIX_BEFORE_PATTERN = re.compile(
    r'(?:before|prior to)\s+(\d+\.\d+(?:\.\d+)?(?![\dA-Za-z])(?!\.\d))', re.I)
FIX_LT_PATTERN = re.compile(r'<\s*(\d+\.\d+(?:\.\d+)?(?![\dA-Za-z])(?!\.\d))', re.I)

# Frases donde el número es la versión AFECTADA (nunca un fix):
_AFFECTED_AFTER = re.compile(r'(\d+\.\d+(?:\.\d+)?)\s*(?:and|or)\s+(?:earlier|before|prior)', re.I)
_AFFECTED_PREFIX = re.compile(r'(?:affected|vulnerable|affects|impacted|impacta)\b[^.\n]{0,25}$', re.I)

IMPACTO_CRITICO_KEYWORDS = {
    "remote_code_execution", "privilege_escalation",
    "broken_authentication", "broken_access_control",
    "insecure_deserialization", "sql_injection",
    "command_injection", "buffer_overflow",
    "use_after_free", "out_of_bounds_rw",
}

SEVERITY_MAP = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW")]

# ---------------------------------------------------------------------------
# Advisory watchlist local (config/advisories/*.json)
# ---------------------------------------------------------------------------
# CVEs críticos recién publicados que `vulnx` puede no tener todavía (o cuyas
# consultas fallan por rate limit). Se inyectan en el output con comparación
# determinista de versiones, sin depender de la API. Ejemplo vigente: PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619, PHP < 8.2.35/8.3.36/8.4.27/8.5.12).
ADVISORIES_DEFAULT = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "config", "advisories"))
WATCHLIST_RANK_REASON = "advisory_watchlist_critica"

# Plugins de WhatWeb que NO son tecnologías (metadata/pseudo-plugins del fingerprint).
# Buscarlos en vulnx genera FALSOS POSITIVOS (ej. "Country" → CVEs de un plugin de
# WooCommerce, "IP"/"Title"/"Script" → ruido). Se excluyen del CVE research.
WHATWEB_NON_TECH_PLUGINS = {
    "ip", "country", "title", "htmltitle", "script", "html5", "redirectlocation",
    "uncommonheaders", "httpserver", "cookies", "headers", "email", "frame",
    "object", "passwordfield", "comment",
    # Headers genéricos de fingerprint: NO son una tecnología consultable. Si aportan
    # PHP, el loader de evidencia ya lo mapea a la tecnología "PHP"
    # (evita además que un `PoweredBy: Red Hat` matchee la watchlist de PHP).
    "poweredby", "x-powered-by", "x-aspnet-version",
}

# ---------------------------------------------------------------------------
# Filtro de relevancia CVE -> servicio (anti falso positivo)
# ---------------------------------------------------------------------------
# vulnx devuelve por matcher amplio CVEs de productos que NO corren en el host
# (ej. consultar "msrpc" o "Microsoft IIS httpd" y recibir CVEs de Juniper,
# ownCloud, SharePoint, mJobtime, Acronis...). Este filtro descarta un CVE si
# NINGÚN token de su producto afectado (affected_products[].product/vendor)
# coincide con algún token de la consulta (nombre de servicio + producto/versión).

_TOKEN_STOPWORDS = {
    "http", "https", "httpd", "server", "service", "services", "engine", "db",
    "the", "and", "for", "with", "ssl", "tls", "edition", "version", "common",
    "agent", "extension", "nagios", "linux", "unix", "unknown", "none",
}

# Vendors "mono-producto": su nombre de vendor ES el nombre del producto
# (ej. Apache→http_server, Grafana→grafana). Para estos se permite match por
# vendor. Los vendors genéricos (microsoft, oracle, cisco...) NO se permiten por
# vendor para evitar que "microsoft" haga match entre IIS, DirectX y SharePoint.
_PRODUCT_LIKE_VENDORS = {
    "apache", "grafana", "owncloud", "tomcat", "postgresql", "postgres",
    "openssh", "openbsd", "nginx", "wordpress", "drupal", "zabbix", "gitlab",
    "jenkins", "moodle", "atlassian", "jira", "confluence", "sonicwall",
    "ivanti", "mjobtime", "anteeowms", "acronis", "graphapi",
}

# Alias de nombres de producto (abreviatura Nmap -> nombre vulnx y viceversa)
_TOKEN_ALIASES = {
    "iis": {"internet_information_services"},
    "internet_information_services": {"iis"},
    "coyote": {"tomcat"},
    "microsoft-ds": {"windows_server", "smb"},
    "netbios-ssn": {"windows_server", "smb"},
    "msrpc": {"windows_server"},
    "kerberos": {"windows_server"},
    "ldap": {"windows_server", "active_directory"},
    "ms-wbt-server": {"windows_server", "remote_desktop"},
    "terminal": {"windows_server", "remote_desktop"},
    "wsman": {"windows_server"},
    "httpapi": {"windows_server"},
}


def _tokenize(text: str) -> set:
    """Divide un texto en tokens alfanuméricos >= 3 chars, sin stopwords."""
    if not text:
        return set()
    toks = {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3}
    return {t for t in toks if t not in _TOKEN_STOPWORDS}


def _expand_aliases(tokens: set) -> set:
    """Agrega alias conocidos a un conjunto de tokens."""
    out = set(tokens)
    for t in list(tokens):
        out |= _TOKEN_ALIASES.get(t, set())
    return out


def _token_match(a: str, b: str) -> bool:
    """Match exacto, o por substring solo si AMBOS tokens son largos (>=5).

    Evita falsos match por tokens cortos/genéricos (ej. "api" dentro de "httpapi").
    """
    if not a or not b:
        return False
    if a == b:
        return True
    return len(a) >= 5 and len(b) >= 5 and (a in b or b in a)


# Productos conocidos que NO tienen relación con infraestructura típica: si
# aparecen en la descripción de un CVE sin `affected_products`, se descarta.
_NOISE_KEYWORDS = {
    "owncloud", "graph_api", "graphapi", "sharepoint", "mjobtime", "anteeowms",
    "anteeo", "acronis", "cyber_infrastructure", "rosariosis", "rosario",
    "ivanti", "mobileiron", "sma100", "solarwinds", "serv-u", "serv_u",
}


def _cve_is_relevant(detail: dict, query_tokens: set) -> bool:
    """True si el CVE parece aplicarse al producto consultado.

    Reglas:
    - Match por PRODUCTO afectado (token o string completo) -> relevante.
    - Match por VENDOR solo si el vendor es "mono-producto" (allowlist).
    - Sin `affected_products`: se usa la descripción contra _NOISE_KEYWORDS.
    """
    affected = detail.get("affected_products") or []
    q_exp = _expand_aliases(query_tokens)
    if affected:
        for a in affected:
            prod = (a.get("product") or "").lower()
            vend = (a.get("vendor") or "").lower()
            # 1) match por PRODUCTO
            cand = _expand_aliases(_tokenize(prod))
            if prod:
                cand.add(prod.replace(" ", "_"))
            cand = _expand_aliases(cand)
            for ct in cand:
                for qt in q_exp:
                    if _token_match(ct, qt):
                        return True
            # 2) match por VENDOR solo si es mono-producto
            if vend in _PRODUCT_LIKE_VENDORS:
                for ct in _expand_aliases(_tokenize(vend)):
                    for qt in q_exp:
                        if _token_match(ct, qt):
                            return True
        return False
    # Sin affected_products: usar descripción (safety-net anti ruido)
    desc = (detail.get("description") or "").lower()
    if desc:
        for kw in _NOISE_KEYWORDS:
            if kw in desc:
                # el ruido aparece en la descripción: descartar salvo que la
                # consulta apunte explícitamente a ese producto
                if not any(_token_match(kw, qt) for qt in q_exp):
                    return False
    return True


def _severity_label(score: float | None) -> str:
    if score is None:
        return "N/A"
    for thr, label in SEVERITY_MAP:
        if score >= thr:
            return label
    return "LOW"


# ---------------------------------------------------------------------------
# Helpers de shell
# ---------------------------------------------------------------------------

def _run_vulnx(args: list[str], timeout: int = VULNX_TIMEOUT,
               attempts: int = VULNX_ATTEMPTS) -> dict | list | None:
    """Ejecuta vulnx y devuelve el JSON parseado.

    Reintenta `attempts` veces: sin PDCP_API_KEY la API de ProjectDiscovery puede
    responder vacío/error de forma intermitente y antes esto producía un output con
    0 CVEs sin ninguna señal de fallo. Nota: vulnx imprime banner + [INF] en STDERR,
    así que stdout sigue siendo JSON limpio.
    """
    cmd = [VULNX_BIN] + args
    last_err = "sin respuesta"
    for attempt in range(1, attempts + 1):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            last_err = f"timeout >{timeout}s"
        except FileNotFoundError:
            print("  \u26a0\ufe0f  vulnx no encontrado en PATH. Instalar: go install "
                  "github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest", file=sys.stderr)
            return None
        except Exception as e:
            last_err = str(e)
        else:
            if proc.returncode == 0:
                out = (proc.stdout or "").strip()
                # rc=0 SIN stdout = la consulta respondió y no hay resultados
                # (comportamiento normal de vulnx): NO es un fallo de consulta.
                if not out:
                    return []
                try:
                    return json.loads(out)
                except json.JSONDecodeError:
                    # vulnx puede imprimir avisos junto al JSON: rescatar el objeto.
                    start, end = out.find("{"), out.rfind("}")
                    if start != -1 and end > start:
                        try:
                            return json.loads(out[start:end + 1])
                        except json.JSONDecodeError:
                            pass
                    last_err = "stdout no es JSON"
            else:
                err_lines = [ln for ln in (proc.stderr or "").splitlines() if ln.strip()]
                last_err = err_lines[-1] if err_lines else f"rc={proc.returncode}"
        if attempt < attempts:
            time.sleep(VULNX_RETRY_DELAY)
    print(f"  \u26a0\ufe0f  vulnx sin datos tras {attempts} intentos ({last_err}). "
          f"Posible rate limit \u2192 export\u00e1 PDCP_API_KEY.", file=sys.stderr)
    return None


def _search_vulns(product: str, version: str | None = None) -> list[dict] | None:
    """Devuelve la lista de resultados, o None si la consulta FALLÓ (≠ lista vacía).

    `vulnx search` con rc=0 y sin stdout significa "0 resultados" → `_run_vulnx`
    devuelve `[]` (lista) y acá se propaga como lista vacía, NO como fallo.
    """
    query = product
    if version and version not in ("unknown", "", "none"):
        query = f"{product} {version}"
    data = _run_vulnx(["search", query, "--json", "--limit", str(SEARCH_LIMIT)])
    if data is None:
        return None
    if isinstance(data, list):
        return data
    return data.get("results") or []


def _get_cve_details(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    data = _run_vulnx(["id"] + cve_ids + ["--json"])
    if data is None:
        return {}
    if isinstance(data, list):
        return {item["cve_id"]: item for item in data if item.get("cve_id")}
    return {}


# ---------------------------------------------------------------------------
# Advisory watchlist — carga, match y comparación de versiones
# ---------------------------------------------------------------------------


def _parse_version_tuple(text):
    """(major, minor, patch) de un string de versión; None si no hay versión."""
    if not text:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text))
    if not m:
        return None
    return tuple(int(g) if g is not None else 0 for g in m.groups())


def _declared_fix_versions(detail: dict) -> set:
    """Versiones que el CVE declara como fix (remediation + description).

    Conservador: sólo toma números que aparecen en contextos de fix
    ("upgrade/update/patched to ...", "X or later", "before X", "< X") y descarta
    los que el propio texto marca como versión afectada ("X and earlier",
    "affected versions X").
    """
    rem = str(detail.get("remediation") or "")
    desc = str(detail.get("description") or "")
    fixes = set()

    def _add(text):
        v = _parse_version_tuple(text)
        if v:
            fixes.add(v)

    for m in FIX_LIST_PATTERN.finditer(rem):
        prefix = rem[max(0, m.start(1) - 30):m.start(1)]
        if _AFFECTED_PREFIX.search(prefix):
            continue
        for tok in re.findall(r'\d+\.\d+(?:\.\d+)?', m.group(1)):
            _add(tok)
    for m in FIX_OR_LATER_PATTERN.finditer(rem):
        _add(m.group(1))
    for text in (rem, desc):
        for m in FIX_BEFORE_PATTERN.finditer(text):
            _add(m.group(1))
        for m in FIX_LT_PATTERN.finditer(text):
            _add(m.group(1))
        for m in _AFFECTED_AFTER.finditer(text):
            fixes.discard(_parse_version_tuple(m.group(1)))
    return fixes


def _is_covered_by_declared_fix(version: str, detail: dict,
                                query_tokens: set | None = None) -> bool:
    """True si la versión detectada YA incluye el fix declarado por el CVE.

    Anti falso positivo del propio `vulnx` (el buscador es de texto: consultar
    "php 8.2.31" devuelve los CVE *arreglados* en 8.2.31). Sólo se compara dentro
    de la MISMA rama major.minor y, si se pasan `query_tokens`, sólo se acepta si
    el texto del CVE menciona el mismo producto (evita cruces como "Spark 2.4.6"
    sobre un "Apache 2.4.6").
    """
    v = _parse_version_tuple(version)
    if v is None:
        return False
    if query_tokens:
        blob = " ".join(str(detail.get(k) or "") for k in ("remediation", "description"))
        text_tokens = _tokenize(blob)
        if not any(_token_match(qt, tt) for qt in query_tokens for tt in text_tokens):
            return False
    for fix in _declared_fix_versions(detail):
        if fix[0] == v[0] and fix[1] == v[1] and v >= fix:
            return True
    return False


def _load_advisories(path: str | None) -> list[dict]:
    """Carga los advisories locales activos desde un dir o un archivo JSON."""
    src = path or ADVISORIES_DEFAULT
    files = []
    if os.path.isdir(src):
        files = [os.path.join(src, n) for n in sorted(os.listdir(src))
                 if n.endswith(".json")]
    elif os.path.isfile(src):
        files = [src]
    advisories = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                adv = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"  \u26a0\ufe0f  advisory ilegible {fp}: {e}", file=sys.stderr)
            continue
        if adv.get("active", True):
            advisories.append(adv)
    return advisories


def _advisory_status(adv: dict, version: str) -> tuple[str, str | None]:
    """(status, patched) para la versión detectada.

    status: affected | patched | eol_sin_parche | not_affected | unknown_version
    """
    v = _parse_version_tuple(version)
    if v is None:
        return "unknown_version", None
    key = f"{v[0]}.{v[1]}"
    branches = adv.get("branches") or {}
    if key in branches:
        patched = (branches[key] or {}).get("patched")
        pv = _parse_version_tuple(patched)
        if pv and v < pv:
            return "affected", patched
        if pv:
            return "patched", patched
    eol_max = _parse_version_tuple(adv.get("eol_max_exclusive"))
    if eol_max and v < eol_max:
        return "eol_sin_parche", None
    return "not_affected", None


def _advisory_matches(adv: dict, name: str, version: str = "") -> bool:
    """True si el advisory aplica al producto detectado (tokens + alias)."""
    aliases = adv.get("product_aliases") or [adv.get("product") or ""]
    q = _expand_aliases(_tokenize(name)) | _expand_aliases(_tokenize(version))
    for alias in aliases:
        if not alias:
            continue
        for ct in _expand_aliases(_tokenize(alias)):
            for qt in q:
                if _token_match(ct, qt):
                    return True
    return False


def _advisory_implied(adv: dict, name: str) -> bool:
    """True si la tecnología IMPLICA el producto del advisory (ej. Drupal ⇒ PHP).

    Se usa para marcar `needs_fingerprint` en apps PHP cuya versión de PHP no se ve
    (Drupal/IIS): el advisory aplica al PHP que corre por debajo.
    """
    for implied in adv.get("implied_by") or []:
        if not implied:
            continue
        for ct in _expand_aliases(_tokenize(implied)):
            for qt in _expand_aliases(_tokenize(name)):
                if _token_match(ct, qt):
                    return True
    return False


def _build_advisory_entry(adv: dict, cve: dict, version: str, status: str,
                          patched: str | None, already_found: bool) -> dict:
    refs = cve.get("references") or []
    nvd_url = next((u for u in refs if "nvd.nist.gov" in u),
                   f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}")
    vendor = next((u for u in refs if "nvd.nist.gov" not in u), "")
    return {
        "id": cve.get("id"),
        "cvss_score": cve.get("cvss_score"),
        "severity": cve.get("severity") or _severity_label(cve.get("cvss_score")),
        "description": (cve.get("mechanism") or "")[:500],
        "affected_versions": f"{adv.get('product', 'php')} {version} (estado: {status})"[:300],
        "patched_version": (patched or
                            "sin release upstream (EOL): backport de vendor o de fuente")[:300],
        "exploit_available": bool(cve.get("exploit_available")),
        "exploit_db_id": None,
        "github_poc": [u for u in refs if "github.com" in u],
        "nvd_url": nvd_url,
        "vendor_advisory": vendor,
        "already_found_by_nuclei": already_found,
        "source": "advisory_watchlist",
        "advisory_id": adv.get("advisory_id"),
        "in_the_wild": bool(cve.get("in_the_wild")),
        "rank_reason": WATCHLIST_RANK_REASON,
    }


def _apply_advisories(advisories: list[dict], services_analyzed: list[dict],
                      web_analyzed: list[dict], nuclei_cves: set[str]) -> list[dict]:
    """Inyecta los CVEs del advisory en los servicios/tecnologías que matchean.

    Guarda anti falso positivo: si la versión detectada ES la parcheada, NO se
    listan CVEs (sólo se deja constancia en `watchlist.status = patched`).
    """
    matches = []
    for group, is_web in ((services_analyzed, False), (web_analyzed, True)):
        for entry in group:
            name = entry.get("technology") if is_web else entry.get("service")
            version = entry.get("version") or ""
            for adv in advisories:
                implied = False
                if not _advisory_matches(adv, name or "", version):
                    # App PHP sin versión visible (Drupal/IIS): el advisory aplica al PHP
                    # que corre por debajo → se marca para fingerprint, sin listar CVEs.
                    if not version and _advisory_implied(adv, name or ""):
                        implied = True
                    else:
                        continue
                status, patched = (("unknown_version", None) if implied
                                   else _advisory_status(adv, version))
                info = {"entry": name, "kind": "web" if is_web else "service",
                        "version": version, "advisory_id": adv.get("advisory_id"),
                        "status": status, "patched_version": patched, "cves": []}
                if implied:
                    entry["needs_fingerprint"] = True
                    info["detail"] = ("tecnología PHP implícita por la app (%s) y versión de PHP "
                                      "no detectada" % (name or "?"))
                elif status in ("affected", "eol_sin_parche"):
                    existing = {c.get("id") for c in entry.get("cves", [])}
                    for cve in adv.get("cves", []):
                        if cve.get("id") in existing:
                            continue
                        entry.setdefault("cves", []).append(_build_advisory_entry(
                            adv, cve, version, status, patched,
                            (cve.get("id") or "").upper() in nuclei_cves))
                        info["cves"].append(cve.get("id"))
                elif status == "unknown_version":
                    entry["needs_fingerprint"] = True
                    info["detail"] = "producto del advisory sin versión detectada"
                entry["watchlist"] = {"advisory_id": adv.get("advisory_id"),
                                      "status": status, "patched_version": patched}
                matches.append(info)
    return matches


# ---------------------------------------------------------------------------
# Versiones web adicionales desde la evidencia cruda (Nikto/HTTPX/Gobuster/Nmap)
# ---------------------------------------------------------------------------
# WhatWeb no siempre reporta PHP; Nikto (000287/600625), HTTPX (`tech`), el
# `extrainfo` de Nmap y los headers guardados por los checks de Gobuster sí.
# Sin esto, un PHP detectado únicamente por Nikto queda invisible para el Agente 4.

_EVID_PHP_PATTERNS = [
    (re.compile(r'"msg"\s*:\s*"Retrieved x-powered-by header:\s*PHP[/ ]?v?(\d+\.\d+(?:\.\d+)?)', re.I),
     "nikto-x-powered-by"),
    (re.compile(r'"msg"\s*:\s*"PHP/(\d+\.\d+(?:\.\d+)?)\s+appears to be outdated', re.I),
     "nikto-banner-outdated"),
    (re.compile(r'"tech"\s*:\s*\[[^\]]*"PHP:(\d+\.\d+(?:\.\d+)?)"', re.I), "httpx-tech"),
    (re.compile(r'"PHP"\s*:\s*\{\s*"version"\s*:\s*\[\s*"(\d+\.\d+(?:\.\d+)?)"', re.I),
     "whatweb-php"),
    (re.compile(r'"extrainfo"\s*:\s*"[^"]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I), "nmap-extrainfo"),
    (re.compile(r'http-server-header:[^\n]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I),
     "nmap-http-server-header"),
    (re.compile(r'x-powered-by\s*:\s*PHP[/ ]?v?(\d+\.\d+(?:\.\d+)?)', re.I),
     "header-x-powered-by"),
    (re.compile(r'server\s*:[^\n]*PHP/(\d+\.\d+(?:\.\d+)?)', re.I), "header-server-php"),
    # Línea canónica de la verificación LOCAL en el host (`PHP-Version: 7.4.33`)
    (re.compile(r'^php-version:\s*v?(\d+\.\d+(?:\.\d+)?)', re.I), "host-check-php-version"),
]

_EVID_GENERIC_TECH_PATTERNS = [
    (re.compile(r'"tech"\s*:\s*\[[^\]]*"([A-Za-z][\w\.\-]{1,25}):(\d+\.\d+(?:\.\d+)?)"', re.I),
     "httpx-tech"),
    (re.compile(r'x-powered-by\s*:\s*([A-Za-z][\w\.\-]{1,25})/(\d+\.\d+(?:\.\d+)?)', re.I),
     "header-x-powered-by"),
]

_EVID_FILES = ["nikto_*.json", "httpx.json", "nmap_detailed.txt", "nmap_detailed.json",
               "gobuster_commands_outputs.txt", "gobuster_evidence.txt",
               # Verificación de campo/de host (php2shell_check.sh / PS1 de Windows):
               # son la fuente MÁS autoritativa de versión. Sin esto, Agente 4 usaba la
               # versión vieja de Nikto (ej. 8.2.31) aunque el campo confirmara 8.2.33.
               "php2shell_passive.txt", "php2shell_fingerprint.txt", "php2shell_detect.txt",
               "php2shell_hostcheck*.txt"]

# Archivos de la verificación de campo (tienen prioridad sobre el resto)
_EVID_FIELD_PREFIX = "php2shell_"


def _load_evidence_web_versions(evidence_dir: str | None,
                                extra_dirs: list[str] | None = None) -> list[dict]:
    """Tecnologías+versión detectadas en la evidencia cruda.

    Devuelve [{"technology","version","source"}] deduplicado por (tech, versión).
    """
    dirs = [d for d in ([evidence_dir] + list(extra_dirs or []))
            if d and os.path.isdir(d)]
    if not dirs:
        return []
    found = []
    for d in dirs:
        for pat in _EVID_FILES:
            for fp in sorted(glob.glob(os.path.join(d, pat))):
                try:
                    with open(fp, "r", errors="ignore") as fh:
                        for i, line in enumerate(fh, 1):
                            hit = False
                            for rx, _kind in _EVID_PHP_PATTERNS:
                                m = rx.search(line)
                                if m:
                                    found.append({"technology": "PHP",
                                                  "version": m.group(1),
                                                  "source": f"{os.path.basename(fp)}#{i}"})
                                    hit = True
                                    break
                            if hit:
                                continue
                            for rx, _kind in _EVID_GENERIC_TECH_PATTERNS:
                                m = rx.search(line)
                                if m:
                                    found.append({"technology": m.group(1),
                                                  "version": m.group(2),
                                                  "source": f"{os.path.basename(fp)}#{i}"})
                                    break
                except (IOError, OSError):
                    continue
    seen, out, idx = set(), [], {}
    for f in found:
        key = (f["technology"].lower(), f["version"])
        if key in seen:
            # Misma tecnología+versión vista desde otra fuente: se prefiere la de la
            # verificación de campo (mejor procedencia).
            pos = idx[key]
            if str(f.get("source", "")).startswith(_EVID_FIELD_PREFIX) and \
                    not str(out[pos].get("source", "")).startswith(_EVID_FIELD_PREFIX):
                out[pos] = f
            continue
        seen.add(key)
        idx[key] = len(out)
        out.append(f)

    # Prioridad: si una tecnología tiene versión proveniente de la verificación de campo
    # (`php2shell_*`), se descartan las versiones viejas de la misma tecnología y se deja
    # constancia en `superseded` (trazabilidad de la discrepancia).
    field_techs = {f["technology"].lower() for f in out
                   if str(f.get("source", "")).startswith(_EVID_FIELD_PREFIX)}
    if field_techs:
        superseded = {}
        final = []
        for f in out:
            tech = f["technology"].lower()
            if tech in field_techs and not str(f.get("source", "")).startswith(_EVID_FIELD_PREFIX):
                superseded.setdefault(tech, []).append(f["version"])
                continue
            final.append(f)
        for f in final:
            sup = superseded.get(f["technology"].lower())
            if sup:
                f["superseded"] = sorted(set(sup))
        out = final
    return out
# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------

def _has_critical_impact(impacts: list[str]) -> bool:
    if not impacts:
        return False
    norm = [(i or "").lower().replace(" ", "_") for i in impacts]
    return any(kw in n for kw in IMPACTO_CRITICO_KEYWORDS for n in norm)


def _rank_cves(cves: list[dict]) -> list[dict]:
    def sort_key(c: dict) -> tuple:
        poc = 0 if c.get("is_poc") else 1
        crit = 0 if _has_critical_impact(c.get("vulnerability_impact") or []) else 1
        cvss = -(c.get("cvss_score") or 0.0)
        return (poc, crit, cvss)
    return sorted(cves, key=sort_key)


def _determine_rank_reason(cve: dict, rank_position: int) -> str:
    if cve.get("is_poc"):
        return "exploit_publico_verificado"
    if _has_critical_impact(cve.get("vulnerability_impact") or []):
        impacts = cve.get("vulnerability_impact", [])
        tag = "_".join(impacts[0].lower().split()) if impacts else "critico"
        return f"impacto_critico_{tag}"
    return "cvss_desempate"


# ---------------------------------------------------------------------------
# Cross-reference con Nuclei
# ---------------------------------------------------------------------------

def _load_nuclei_cves(nuclei_path: str | None) -> set[str]:
    if not nuclei_path or not os.path.exists(nuclei_path):
        return set()
    cves = set()
    try:
        with open(nuclei_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = obj.get("info") or {}
                classification = info.get("classification") or {}
                cve_id = classification.get("cve_id") or ""
                if cve_id:
                    cves.add(cve_id.upper())
                for cid in classification.get("cve_ids", []):
                    cves.add(cid.upper())
                name = info.get("name") or ""
                if name.upper().startswith("CVE-"):
                    cves.add(name.upper().split()[0])
    except Exception:
        pass
    return cves


# ---------------------------------------------------------------------------
# Construccion del output
# ---------------------------------------------------------------------------

def _build_cve_entry(vulnx_detail: dict, already_found: bool) -> dict:
    cve_id = vulnx_detail.get("cve_id", "")
    cvss_score = vulnx_detail.get("cvss_score")
    description = vulnx_detail.get("description") or ""
    remediation = vulnx_detail.get("remediation") or ""

    affected = vulnx_detail.get("affected_products") or []
    affected_versions = "; ".join(
        a.get("product", "") for a in affected if a.get("product")
    )[:300]

    pocs = vulnx_detail.get("pocs") or []
    github_pocs = []
    exploit_db_id = None
    for poc in pocs:
        url = poc.get("url", "")
        if "github.com" in url:
            github_pocs.append(url)
        elif "exploit-db.com" in url:
            m = re.search(r'/exploits/(\d+)', url)
            if m:
                exploit_db_id = m.group(1)

    nvd_url = ""
    vendor_advisory = ""
    citations = vulnx_detail.get("citations") or []
    for cit in citations:
        url = cit.get("url", "")
        if "nvd.nist.gov" in url:
            nvd_url = url
        elif url and not vendor_advisory:
            vendor_advisory = url
    if not nvd_url:
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return {
        "id": cve_id,
        "cvss_score": cvss_score,
        "severity": _severity_label(cvss_score),
        "description": description[:500] if description else "",
        "affected_versions": affected_versions,
        "patched_version": remediation[:300] if remediation else "",
        "exploit_available": bool(vulnx_detail.get("is_poc")),
        "exploit_db_id": exploit_db_id,
        "github_poc": github_pocs,
        "nvd_url": nvd_url,
        "vendor_advisory": vendor_advisory,
        "already_found_by_nuclei": already_found,
        "rank_reason": "",
    }
# ---------------------------------------------------------------------------
# Carga de evidencia
# ---------------------------------------------------------------------------

def _load_nmap_services(nmap_path: str) -> list[dict]:
    if not nmap_path or not os.path.exists(nmap_path):
        print("  \u26a0\ufe0f  nmap_detailed.json no encontrado", file=sys.stderr)
        return []
    try:
        with open(nmap_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  \u26a0\ufe0f  Error leyendo {nmap_path}: {e}", file=sys.stderr)
        return []
    services = []
    for host_data in (data.get("scan") or {}).values():
        for port_str, port_info in (host_data.get("tcp") or {}).items():
            svc = port_info.get("service", {}) or {}
            name = svc.get("name", "")
            if not name or name == "unknown":
                continue
            product = svc.get("product", "") or ""
            version = svc.get("version", "") or ""
            full_version = f"{product} {version}".strip() if product else version
            services.append({
                "name": name, "product": product,
                "version": full_version,
                "port": int(port_str) if port_str.isdigit() else 0,
            })
    return services


def _load_whatweb(whatweb_path: str | None) -> list[dict]:
    if not whatweb_path or not os.path.exists(whatweb_path):
        return []
    try:
        with open(whatweb_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return []
    technologies = []
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins") if isinstance(data, list) else entry
        if isinstance(plugins, dict):
            for tech_name, tech_info in plugins.items():
                if tech_name.lower() in WHATWEB_NON_TECH_PLUGINS:
                    continue  # metadata de WhatWeb, no una tecnología
                version = ""
                if isinstance(tech_info, dict):
                    vl = tech_info.get("version") or []
                    if vl:
                        version = vl[0] if isinstance(vl, list) else str(vl)
                technologies.append({"technology": tech_name, "version": version})
    seen = set()
    uniq = []
    for t in technologies:
        key = f'{t["technology"]}|{t["version"]}'
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq
# ---------------------------------------------------------------------------
# Investigacion por servicio
# ---------------------------------------------------------------------------

def _investigate_service(name: str, version: str, port: int,
                          nuclei_cves: set[str],
                          is_web: bool = False) -> tuple[dict, bool]:
    """Devuelve (resultado, query_failed); query_failed=True si vulnx no respondió."""
    base = {"technology": name, "version": version or None, "cves": []} if is_web \
           else {"service": name, "version": version or None, "port": port, "cves": []}

    results = _search_vulns(name, version)
    if results is None:              # fallo de consulta (timeout / rate limit)
        return base, True
    if not results:
        return base, False

    valid = [r for r in results
             if isinstance(r.get("cvss_score"), (int, float)) and r["cvss_score"] >= CVSS_MIN]
    if not valid:
        return base, False

    cve_ids = [r["cve_id"] for r in valid if r.get("cve_id")]
    details = _get_cve_details(cve_ids)

    # Tokens de la consulta: nombre de servicio + producto/versión detectada
    query_tokens = _tokenize(name) | _tokenize(version)

    entries = []
    filtered_out = 0
    dropped_patched = []
    for r in valid:
        cve_id = r.get("cve_id", "")
        detail = details.get(cve_id, r)
        # Anti falso positivo: descartar CVEs de productos ajenos (matcher amplio)
        if RELEVANCE_FILTER and not _cve_is_relevant(detail if detail.get("affected_products") else r, query_tokens):
            filtered_out += 1
            continue
        # Anti falso positivo del propio vulnx: el CVE declara un fix que el host YA tiene.
        if PATCHED_FILTER and _is_covered_by_declared_fix(version, detail, query_tokens):
            dropped_patched.append(cve_id)
            continue
        already = cve_id.upper() in nuclei_cves
        entries.append(_build_cve_entry(detail, already))

    if filtered_out:
        print(f"[{filtered_out} descartados por relevancia] ", end="")
    if dropped_patched:
        print(f"[{len(dropped_patched)} descartados por versión parcheada] ", end="")

    ranked = _rank_cves(entries)
    for i, cve in enumerate(ranked):
        cve["rank_reason"] = _determine_rank_reason(cve, i)
    top_cves = ranked[:TOP_N_MAX]

    if is_web:
        out = {"technology": name, "version": version or None, "cves": top_cves}
    else:
        out = {"service": name, "version": version or None, "port": port, "cves": top_cves}
    if dropped_patched:
        out["filtered_patched_cves"] = dropped_patched
    return out, False


def _collect_omissions(services_analyzed: list[dict],
                        web_analyzed: list[dict],
                        failed_services: list[str] | None = None,
                        failed_web: list[str] | None = None,
                        omitted_services: list[str] | None = None,
                        omitted_web: list[str] | None = None) -> list[dict]:
    """Registra por qué un servicio quedó sin CVEs.

    reason=query_failed    → vulnx no respondió (rate limit/timeout) → revisar
    reason=no_data_available → vulnx respondió sin CVEs para ese producto
    reason=sin_version     → Nmap no detectó version exacta → omitido intencionalmente
    """
    failed_services = failed_services or []
    failed_web = failed_web or []
    omitted_services = omitted_services or []
    omitted_web = omitted_web or []
    omissions = []
    for s in services_analyzed:
        if not s.get("cves"):
            name = s.get("service", "?")
            if s.get("error") == "sin_version":
                omissions.append({
                    "service": name,
                    "source": "vulnx",
                    "reason": "sin_version",
                    "detail": "Nmap no detectó version exacta — omitido por filtro de precisión",
                })
            else:
                omissions.append({
                    "service": name,
                    "source": "vulnx",
                    "reason": "query_failed" if name in failed_services else "no_data_available",
                })
    for w in web_analyzed:
        if not w.get("cves"):
            key = f"web/{w.get('technology', '?')}"
            if w.get("error") == "sin_version":
                omissions.append({
                    "service": key,
                    "source": "vulnx",
                    "reason": "sin_version",
                    "detail": "WhatWeb no detectó version exacta — omitido por filtro de precisión",
                })
            else:
                omissions.append({
                    "service": key,
                    "source": "vulnx",
                    "reason": "query_failed" if key in failed_web else "no_data_available",
                })
    return omissions


# ---------------------------------------------------------------------------
# Procesamiento principal
# ---------------------------------------------------------------------------

def process_target(target_id: str, target_ip: str,
                   nmap_path: str, whatweb_path: str | None,
                   nuclei_path: str | None,
                   output_path: str | None = None,
                   dry_run: bool = False,
                   advisories_path: str | None = None,
                   evidence_dir: str | None = None,
                   extra_evidence_dirs: list[str] | None = None) -> dict:
    services = _load_nmap_services(nmap_path)
    web_technologies = _load_whatweb(whatweb_path)
    nuclei_cves = _load_nuclei_cves(nuclei_path)
    advisories = _load_advisories(advisories_path) if advisories_path is not False else []

    # D1: versiones web que WhatWeb no reporta (Nikto, HTTPX, headers de Gobuster, Nmap).
    for ev in _load_evidence_web_versions(evidence_dir, extra_evidence_dirs):
        if not any(w["technology"].lower() == ev["technology"].lower()
                   and (w.get("version") or "") == ev["version"]
                   for w in web_technologies):
            web_technologies.append(ev)

    if advisories:
        print("  \U0001f6e1\ufe0f  Advisories activos: "
              + ", ".join(a.get("advisory_id", "?") for a in advisories))

    services_analyzed = []
    failed_services = []
    omitted_services = []
    for svc in services:
        # Saltar servicios sin versión: Nmap no pudo determinar la versión exacta,
        # por lo que vulnx buscaría solo por nombre de servicio/producto y devolvería
        # CVEs de todas las versiones (muchos FALSOS POSITIVOS, ej. "msrpc" → CVEs de
        # routers Juniper en un Windows Server).
        has_version = svc.get("version", "") or ""
        if has_version.lower() in ("", "unknown", "none"):
            svc_name = svc.get("product", "") or svc.get("name", "?")
            print(f"  \U0001f50d {svc['name']} (port {svc['port']})... [omitido: sin version detectada]", flush=True)
            svc_stub = {
                "port": svc["port"], "protocol": svc.get("protocol", "tcp"),
                "name": svc.get("name", "?"), "product": svc.get("product", ""),
                "version": "", "cves": [], "ranked": False,
                "source_service": f"{svc.get('name','')} (no version → omitido)",
                "error": "sin_version",
            }
            if svc.get("product","") and not svc.get("version",""):
                omitted_services.append(f"{svc.get('product')} (port {svc['port']} — sin version)")
            services_analyzed.append(svc_stub)
            continue
        print(f"  \U0001f50d {svc['name']} (port {svc['port']}, v{svc['version']})...",
              end=" ", flush=True)
        r, failed = _investigate_service(svc["name"], svc["version"], svc["port"], nuclei_cves)
        services_analyzed.append(r)
        if failed:
            failed_services.append(r.get("service", svc["name"]))
        print(f"{'ERROR de consulta' if failed else str(len(r.get('cves', []))) + ' CVEs'}")

    web_analyzed = []
    failed_web = []
    omitted_web = []
    for wt in web_technologies:
        has_version = wt.get("version", "") or ""
        if has_version.lower() in ("", "unknown", "none"):
            adv_hit = [a.get("advisory_id") for a in advisories
                       if _advisory_matches(a, wt["technology"], "")
                       or _advisory_implied(a, wt["technology"])]
            nota = (f" \u26a0\ufe0f  advisory {adv_hit[0]} aplica al producto → "
                    f"requiere fingerprint de versión" if adv_hit else "")
            print(f"  \U0001f310 web/{wt['technology']}... [omitido: sin version detectada]{nota}",
                  flush=True)
            wt_stub = {
                "technology": wt["technology"], "version": wt.get("version", ""),
                "cves": [], "ranked": False,
                "error": "sin_version",
                "needs_fingerprint": bool(adv_hit),
            }
            if wt.get("source"):
                wt_stub["source"] = wt["source"]
            if not wt.get("version", ""):
                omitted_web.append(f"web/{wt['technology']} (sin version)"
                                   + (f" | advisory {adv_hit[0]}" if adv_hit else ""))
            web_analyzed.append(wt_stub)
            continue
        print(f"  \U0001f310 web/{wt['technology']} (v{wt['version']})...",
              end=" ", flush=True)
        r, failed = _investigate_service(wt["technology"], wt["version"], 0,
                                          nuclei_cves, is_web=True)
        if wt.get("source"):
            r["source"] = wt["source"]
        web_analyzed.append(r)
        if failed:
            failed_web.append(f"web/{r.get('technology', wt['technology'])}")
        print(f"{'ERROR de consulta' if failed else str(len(r.get('cves', []))) + ' CVEs'}")
    if failed_services or failed_web:
        print(f"  \u26a0\ufe0f  {len(failed_services) + len(failed_web)} consulta(s) fallaron "
              f"(ver source_omissions[].reason=query_failed)", file=sys.stderr)
    if omitted_services or omitted_web:
        print(f"  \U0001f4a1 Sin version: {len(omitted_services)} servicio(s) + "
              f"{len(omitted_web)} web(s) omitidos (sin version exacta)",
              file=sys.stderr)

    # D3: advisory watchlist local (CVEs recién publicados / no indexados en vulnx).
    watchlist_matches = _apply_advisories(advisories, services_analyzed, web_analyzed,
                                          nuclei_cves) if advisories else []
    for m in watchlist_matches:
        extra = f" (+{len(m['cves'])} CVEs)" if m["cves"] else ""
        print(f"  \U0001f6e1\ufe0f  watchlist {m['advisory_id']}: {m['entry']} "
              f"v{m['version'] or '?'} → {m['status']}{extra}")

    all_cves = []
    for s in services_analyzed:
        all_cves.extend(s["cves"])
    for w in web_analyzed:
        all_cves.extend(w["cves"])

    def sev_count(label):
        return sum(1 for c in all_cves if c.get("severity") == label)

    result = {
        "target": target_ip,
        "target_id": target_id,
        "research_timestamp": datetime.now(timezone.utc).isoformat(),
        "services_analyzed": services_analyzed,
        "web_technologies": web_analyzed,
        "watchlist_matches": watchlist_matches,
        "source_omissions": _collect_omissions(services_analyzed, web_analyzed,
                                                failed_services, failed_web,
                                                omitted_services, omitted_web),
        "summary": {
            "total_cves": len(all_cves),
            "critical": sev_count("CRITICAL"),
            "high": sev_count("HIGH"),
            "medium": sev_count("MEDIUM"),
            "low": sev_count("LOW"),
            "with_public_exploit": sum(1 for c in all_cves if c.get("exploit_available")),
            "patched_available": sum(1 for c in all_cves if c.get("patched_version")),
            "watchlist_cves": sum(1 for c in all_cves
                                  if c.get("source") == "advisory_watchlist"),
        },
    }

    if dry_run:
        print("\n  \U0001f4ac DRY RUN \u2014 JSON no escrito (solo se muestra el resumen).")
    else:
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"\n  \u2705 Output \u2192 {output_path}")
        else:
            default_path = os.path.normpath(os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..",
                "cve_research", f"{target_id}_cves.json"))
            os.makedirs(os.path.dirname(default_path), exist_ok=True)
            with open(default_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"\n  \u2705 Output \u2192 {default_path}")

    return result
# ---------------------------------------------------------------------------
# CLI / Entry point
# ---------------------------------------------------------------------------

def _validate_output(result: dict):
    s = result["summary"]
    all_cves = []
    for svc in result.get("services_analyzed", []):
        all_cves.extend(svc.get("cves", []))
    for wt in result.get("web_technologies", []):
        all_cves.extend(wt.get("cves", []))
    assert len(all_cves) == s["total_cves"], \
        f"Inconsistencia: {len(all_cves)} CVEs listados vs {s['total_cves']} en summary"
    assert all(c.get("rank_reason") for c in all_cves), \
        "Todos los CVEs deben tener rank_reason"
    print(f"\n  \u2705 Validacion de consistencia OK")
    print(f"  \U0001f4ca Resumen: {s['total_cves']} CVEs | "
          f"{s['critical']}C {s['high']}H {s['medium']}M {s['low']}L | "
          f"{s['with_public_exploit']} exploit | {s['patched_available']} patch")


def main():
    parser = argparse.ArgumentParser(
        description="Agente 4 \u2014 CVE Research usando vulnx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target-id", required=True, help="ID del target (ej. TGT-001)")
    parser.add_argument("--target-ip", required=True, help="IP del target")
    parser.add_argument("--nmap", required=True, help="Path a nmap_detailed.json")
    parser.add_argument("--whatweb", help="Path a whatweb.json (opcional)")
    parser.add_argument("--nuclei", help="Path a nuclei.json (opcional cross-ref)")
    parser.add_argument("--output",
                        help="Path de salida (default: cve_research/<target_id>_cves.json)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo imprime lo que haria, no escribe output")
    parser.add_argument("--no-relevance-filter", action="store_true",
                        help="Desactivar el filtro anti falso positivo (CVE por relevancia de producto)")
    parser.add_argument("--no-patched-filter", action="store_true",
                        help="Desactivar el filtro de versión parcheada (no descartar CVEs cuyo fix ya está aplicado)")
    parser.add_argument("--advisories",
                        help=f"Dir/archivo de advisories locales (default: {ADVISORIES_DEFAULT})")
    parser.add_argument("--no-watchlist", action="store_true",
                        help="Desactivar la advisory watchlist local (solo vulnx)")
    parser.add_argument("--evidence-dir",
                        help="Dir de evidencia cruda para versiones web adicionales "
                             "(default: carpeta del --nmap)")
    parser.add_argument("--cliente-dir",
                        help="Dir CLIENTE/<ip>/outputs (headers de los checks de Gobuster)")
    args = parser.parse_args()

    # Flag global del filtro de relevancia
    globals()["RELEVANCE_FILTER"] = not args.no_relevance_filter
    # Flag global del filtro de versión parcheada
    globals()["PATCHED_FILTER"] = not args.no_patched_filter

    evidencias = args.evidence_dir or (os.path.dirname(args.nmap) if args.nmap else None)
    extra_evid = [args.cliente_dir] if args.cliente_dir else []
    advisories_path = False if args.no_watchlist else (args.advisories or ADVISORIES_DEFAULT)

    print(f"\n\U0001f52c CVE Research \u2014 {args.target_ip} ({args.target_id})")
    print(f"   Motor: vulnx v2")
    print(f"   Nmap:  {args.nmap}")
    print(f"   WhatWeb: {args.whatweb or '(no disponible)'}")
    print(f"   Nuclei: {args.nuclei or '(no disponible)'}")
    print(f"   Evidencia extra: {evidencias or '(no disponible)'}")
    print(f"   Advisories: {advisories_path if advisories_path else '(desactivado)'}")
    print()

    result = process_target(
        target_id=args.target_id,
        target_ip=args.target_ip,
        nmap_path=args.nmap,
        whatweb_path=args.whatweb,
        nuclei_path=args.nuclei,
        output_path=args.output,
        dry_run=args.dry_run,
        advisories_path=advisories_path,
        evidence_dir=evidencias,
        extra_evidence_dirs=extra_evid,
    )

    if args.dry_run:
        s = result["summary"]
        print(f"\n  \U0001f4ca Resumen dry-run: {s['total_cves']} CVEs | "
              f"Criticas: {s['critical']} | Altas: {s['high']} | "
              f"Medias: {s['medium']} | Bajas: {s['low']} | "
              f"Con exploit publico: {s['with_public_exploit']} | "
              f"Parche disp.: {s['patched_available']}")
        return

    _validate_output(result)


if __name__ == "__main__":
    main()