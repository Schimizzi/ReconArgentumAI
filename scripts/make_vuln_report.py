#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_vuln_report.py — Agente 6 (Consolidador de hallazgos, Fase 4).

Consolida SOLO el directorio <PROYECTO>/<TARGET>/outputs/ de cada target ya
consolidado por scripts/organize_project.py y genera, en la raiz del target
(el directorio que contiene data/ y outputs/):

  <target_id>_resumen_vulnerabilidades.doc  (Word/LibreOffice, HTML compatible)
  <target_id>_resumen_breve.txt             (una linea por hallazgo)

Todas las vulnerabilidades usan el ID literal "VULN-00X" (sin numeracion
automatica): el analista asigna el numero final a mano en el reporte al
agregar o quitar hallazgos.

Reglas de cero invencion (ver specs/agent_6_consolidador_hallazgos.md):
  - Solo se extrae lo que esta EXPLICITAMENTE reportado en los archivos fuente.
  - Severidad solo si el archivo la declara; si no → "No declarada en fuente".
  - Deduplicacion entre fuentes (la de mas detalle textual gana).
  - Ofuscacion de credenciales con *** (no modifica los archivos fuente).
  - Configuracion insegura TEXTUAL en scripts NSE de nmap (ej.
    `smb2-security-mode` en hostscript con "Message signing enabled but not
    required") se extrae como hallazgo con severidad "No declarada en fuente"
    (la fuente no la declara). Estados de scan de SSLyze != COMPLETED y
    entradas de ESTADO TECNICO de Nikto (id FAIL, "Unable to connect") se
    OMITEN: son limitaciones del escaner, no hallazgos.
  - Deteccion dinamica: cualquier archivo nuevo en outputs/ (con hallazgos
    reconocibles, ya sea por parser conocido o fallback generico) se incluye
    en el siguiente reporte sin tocar este script.

Uso:
  python3 scripts/make_vuln_report.py [--project NOMBRE] [--target IP]...
                                      [--dry-run] [--no-clobber]

- Sin args: procesa TODOS los targets con carpeta en <project>/ (default CLIENTE).
- --project: nombre del directorio consolidado (default: CLIENTE).
- --target IP: procesa solo ese target (repetible).
- --dry-run: imprime la estructura prevista, no crea ni sobrescribe nada.
- --no-clobber: no sobrescribe reportes ya existentes.

No modifica scripts/organize_project.py (agente 100% independiente).
"""
import argparse
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Checks de SSLyze (6.x) cuyos keys salen literal de scan_result.
_SSLYZE_CHECKS = [
    ("ssl_2_0_cipher_suites", "SSLv2 cipher suites"),
    ("ssl_3_0_cipher_suites", "SSLv3 cipher suites"),
    ("tls_1_0_cipher_suites", "TLS 1.0 cipher suites"),
    ("tls_1_1_cipher_suites", "TLS 1.1 cipher suites"),
    ("tls_1_2_cipher_suites", "TLS 1.2 cipher suites"),
    ("tls_1_3_cipher_suites", "TLS 1.3 cipher suites"),
    ("tls_compression", "TLS compression"),
    ("tls_1_3_early_data", "TLS 1.3 early data"),
    ("openssl_ccs_injection", "OpenSSL CCS injection"),
    ("tls_fallback_scsv", "TLS_FALLBACK_SCSV"),
    ("heartbleed", "Heartbleed"),
    ("robot", "ROBOT attack"),
    ("session_renegotiation", "Session renegotiation"),
    ("session_resumption", "Session resumption"),
    ("elliptic_curves", "Elliptic curves"),
    ("http_headers", "HTTP headers"),
    ("tls_extended_master_secret", "Extended Master Secret"),
]

# Scripts NSE de configuracion cuyo output TEXTUAL expone una condicion
# insegura explicita (frase literal en la fuente). El script en si NO es una
# vulnerabilidad declarada, pero la condicion si esta escrita en la evidencia:
# se extrae como hallazgo con severidad "No declarada en fuente".
# Claves en minuscula; patrones tambien en minuscula (match case-insensitive).
_NSE_CONFIG = {
    "smb2-security-mode": ["message signing enabled but not required"],
    "smb-security-mode": ["message signing disabled"],
}

# Clasificacion de ids de Nikto 2.1.6 usada SOLO para etiquetar/organizar el
# reporte (nunca agrega severidad ni inventa vulnerabilidades).
_NIKTO_TIPO = {
    "000287": "fingerprinting",   # headers revelados (x-powered-by, allow-origin, x-aspnet-version)
    "750537": "fingerprinting",   # Default IIS server content
    "500645": "fingerprinting",   # identifies this app/server as: ...
    "999990": "fingerprinting",   # OPTIONS: Allowed HTTP Methods
    "999985": "fingerprinting",   # OPTIONS: Public HTTP Methods
    "013587": "hardening",        # suggested security header missing
    "000998": "indicador",        # configuration information may be available
    "001732": "indicador",        # This might be interesting (directorio presente)
    "002112": "indicador",        # Ahh...log information (directorio presente)
    "999993": "indicador",        # hostname vs certificado
    "400000": "potencial",        # DELETE allowed
    "400001": "potencial",        # PUT allowed
}
# Mensajes de ESTADO TECNICO de Nikto (no hallazgos): indican que la tool no
# pudo completar la peticion (timeout/sin conexion), no una debilidad.
_NIKTO_ERROR_MSG = re.compile(
    r"unable to connect|failed to connect|connection timed out|could not connect"
    r"|connection refused|timed out while", re.I)
# Mensajes "ruido" de Nikto que NO son hallazgos:
#  - "* may be outdated" (600376/601012): mensaje hardcodeado de la DB contra la
#    version del propio build de Nikto, sin verificacion remota real de parches.
#  - "junk HTTP methods which may cause false positives" (999967): auto-aviso
#    del propio plugin (dice "may cause false positives").
#  - "IP address found in the <cookie> cookie": bug del plugin de cookies que
#    reporta la IP del propio scanner (::ffff:10), no una cookie maliciosa.
_NIKTO_IGNORE_MSG = re.compile(
    r"may be outdated|appears to be outdated|is outdated"
    r"|junk http methods"
    r"|ip address found in the .*cookie", re.I)


def warn(msg):
    """Aviso por consola (no rompe el procesamiento)."""
    print(f"  ⚠️ {msg}")


def ofuscar(t):
    """Redacta credenciales/tokens/keys con *** (solo los reportes; los
    archivos fuente de outputs/ NO se modifican)."""
    if not isinstance(t, str):
        return t
    t = re.sub(r"(password\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(passwd\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(default password is\s+)(\w+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(\btoken\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(api[_-]?key\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(secret\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(Basic\s+)[A-Za-z0-9+/=]+", r"\1***", t, flags=re.I)
    t = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", t, flags=re.I)
    return t


def load_json(path):
    """Carga un JSON (None si falta o falla, sin romper el flujo)."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None


def load_jsonl(path):
    """Carga JSONL: una linea = un objeto JSON. Lineas corruptas se ignoran."""
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _corta(texto, max_chars=400):
    """Trunca texto a max_chars conservando saltos de linea basicos."""
    t = ofuscar(str(texto or ""))
    t = re.sub(r"\r\n?", "\n", t)
    t = re.sub(r"[ \t]+", " ", t)
    if len(t) > max_chars:
        t = t[:max_chars].rstrip() + "…"
    return t


# ---------------------------------------------------------------------------
# Parsers especificos de evidencia (formato real de cada tool del pipeline)
# Cada parser devuelve una lista de dicts:
#   {titulo, severidad (None si no declarada), descripcion, fuente, ubicacion,
#    puerto (str|None), cve (str|None)}
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
_SEV_LITERAL_RE = re.compile(
    r"(?:severity|severidad)\s*[:=]\s*([^\s,;){|}]+)", re.I
)
_CVSS_SEV_RE = re.compile(
    r"CVSS(?:\s*[:=])?\s*([\d.]+(?:\s*\(([^)]+)\))?)", re.I
)


def _severidad_de_texto(texto):
    """Severidad explícitamente escrita en un texto (o None)."""
    m = _SEV_LITERAL_RE.search(str(texto or ""))
    if m:
        return m.group(1).strip() or None
    m = _CVSS_SEV_RE.search(str(texto or ""))
    if m:
        if m.group(2):
            return m.group(2).strip()
        return m.group(1).strip()
    return None


def parse_cves_md(path, rel):
    """outputs/<target_id>_cves.md → CVEs con severidad, descripcion y fuente."""
    if not os.path.exists(path):
        return []
    lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    findings = []
    seccion = "general"
    cves = []  # renglones de tabla: (cve, cvss, severidad, linea)
    cve_desc = {}  # cve -> [(descripcion, linea), ...]
    for i, raw in enumerate(lines, start=1):
        linea = raw.strip()
        if linea.startswith("###"):
            seccion = re.sub(r"^#+\s*", "", linea)
        m = _CVE_RE.search(linea)
        if linea.startswith("|") and m and "|" in linea:
            trozos = [p.strip() for p in linea.strip("|").split("|")]
            if len(trozos) >= 3 and trozos[2] not in ("Severidad", "CVSS"):
                sev = trozos[2] if trozos[2] and trozos[2] != "-" else None
                cves.append((m.group(0), trozos[1] if len(trozos) > 1 else "", sev, i))
        if linea.startswith("**") and m:
            cve_actual = m.group(0)
            cve_desc.setdefault(cve_actual, []).append(("", i))
            continue
        if (linea.startswith("**Descripcion:") or linea.startswith("**Description:")
                or linea.startswith("**Descripción:")):
            contenido = re.sub(r"^\*\*Descrip(cion|tion|ción):\s*\*?\*?\s*", "", linea)
            for cve_busc, lista in cve_desc.items():
                if lista and lista[-1][0] == "":
                    lista[-1] = (contenido, i)
                    break
    for (cve, cvss, sev, n_linea) in cves:
        desc_list = cve_desc.get(cve)
        desc = ""
        if desc_list:
            # Ultima descripcion no vacia (las lineas con *Referencias* etc.
            # pueden haber agregado entradas vacias al mismo CVE).
            for d, _ln in reversed(desc_list):
                if d:
                    desc = _corta(d, 400)
                    break
        severidad = sev or None
        if not severidad and cvss:
            m2 = re.search(r"\(([^)]+)\)", cvss)
            if m2:
                severidad = m2.group(1).strip()
        if not severidad:
            for d, _ln in (cve_desc.get(cve) or []):
                s = _severidad_de_texto(d)
                if s:
                    severidad = s
                    break
        findings.append({
            "titulo": cve,
            "severidad": severidad,
            "descripcion": desc or "Sin descripción en fuente.",
            "fuente": rel,
            "ubicacion": f"sección {seccion!r} (línea {n_linea})",
            "puerto": None,
            "cve": cve,
        })
    return findings


def parse_nuclei(path, rel):
    """outputs/nuclei.json (JSONL) → detecciones con severity declarada."""
    findings = []
    for idx, item in enumerate(load_jsonl(path)):
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        name = info.get("name") or item.get("template-id") or item.get("template") or ""
        template = item.get("template-id") or item.get("template") or ""
        sev = info.get("severity") or ""
        desc = info.get("description") or info.get("impact") or ""
        matched = item.get("matched-at") or item.get("matched_at") or ""
        classif = info.get("classification") or {}
        cve = None
        if isinstance(classif, dict):
            cvelist = classif.get("cve-id") or []
            if isinstance(cvelist, list):
                cve = next((str(c) for c in cvelist if str(c).upper().startswith("CVE-")), None)
            elif isinstance(cvelist, str):
                cve = cvelist
        if not name and not cve:
            continue
        ubicacion = f"$.{idx}.info.name (template: {template}"
        if matched:
            ubicacion += f"; matched-at: {matched}"
        ubicacion += ")"
        findings.append({
            "titulo": _corta(name, 200),
            "severidad": sev or None,
            "descripcion": _corta(desc, 400) if desc else "Sin descripción en fuente.",
            "fuente": rel,
            "ubicacion": ubicacion,
            "puerto": str(item.get("port") or "") or None,
            "cve": cve,
        })
    return findings


def _linea_plana(texto):
    """Condensa un texto a una sola linea (para el .txt)."""
    t = ofuscar(str(texto or ""))
    t = re.sub(r"\s+", " ", t).strip()
    return t


def parse_nikto(path, rel):
    """outputs/nikto_<port>.json → hallazgos de Nikto (severidad NO declarada).

    Se descartan las entradas de ESTADO TECNICO / RUIDO del escaner:
    id 'FAIL', "Unable to connect", "* may be outdated", "junk HTTP methods" y
    "IP address found in the ... cookie" (bug del plugin). Las cookies creadas
    sin flag httponly se CONSOLIDAN en un UNICO hallazgo por archivo. Cada
    hallazgo se etiqueta con la clasificacion interna de id (ver _NIKTO_TIPO)."""
    data = load_json(path)
    findings = []
    if not isinstance(data, list):
        return findings
    for e_idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            continue
        puerto = str(entry.get("port") or "")
        cookies = []
        for v_idx, v in enumerate(entry.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                continue
            msg = v.get("msg") or ""
            if not msg:
                continue
            vid = str(v.get("id") or "")
            if (vid in ("FAIL", "") or _NIKTO_ERROR_MSG.search(msg)
                    or _NIKTO_IGNORE_MSG.search(msg)):
                continue
            url = v.get("url") or ""
            ubicacion = f"$.{e_idx}.vulnerabilities[{v_idx}].msg"
            if url:
                ubicacion += f" (url: {url})"
            # cookies httponly: consolidar en UN hallazgo por archivo
            if "created without the httponly flag" in msg.lower():
                cookies.append((ubicacion, _corta(msg, 200)))
                continue
            findings.append({
                "titulo": _corta(msg, 200),
                "severidad": None,
                "descripcion": _corta(msg + (" — " + url if url else ""), 400),
                "fuente": rel,
                "ubicacion": ubicacion,
                "puerto": puerto,
                "cve": None,
                "tipo": _NIKTO_TIPO.get(vid) or "potencial",
            })
        if cookies:
            n_c = len(cookies)
            detalle = "; ".join(c for _, c in cookies[:8])
            if n_c > 8:
                detalle += f"; ... y {n_c - 8} cookies más"
            findings.append({
                "titulo": f"Cookies creadas sin flag HttpOnly ({n_c})",
                "severidad": None,
                "descripcion": _corta(detalle, 500),
                "fuente": rel,
                "ubicacion": cookies[0][0],
                "puerto": puerto,
                "cve": None,
                "tipo": "potencial",
            })
    return findings


def parse_sslyze(path, rel):
    """outputs/sslyze_<port>.json → checks COMPLETED con resultado (anomalias TLS).

    Un scan_status != COMPLETED (ej. ERROR_NO_CONNECTIVITY) es una limitacion
    del escaner (no pudo negociar TLS) y NO un hallazgo: se omite (regla 1.6)."""
    data = load_json(path)
    findings = []
    if not isinstance(data, dict):
        return findings
    scans = data.get("server_scan_results") or []
    if isinstance(scans, dict):
        scans = [scans]
    for s_idx, scan in enumerate(scans):
        if not isinstance(scan, dict):
            continue
        puerto = ""
        loc = scan.get("server_location") or {}
        if isinstance(loc, dict):
            puerto = str(loc.get("port") or "")
        sr = scan.get("scan_result") or {}
        if not isinstance(sr, dict):
            continue
        for key, label in _SSLYZE_CHECKS:
            chk = sr.get(key) or {}
            if not isinstance(chk, dict):
                continue
            if chk.get("status") != "COMPLETED":
                continue
            res = chk.get("result")
            if res is None:
                continue
            try:
                payload = json.dumps(res, ensure_ascii=False, indent=1)
            except Exception:
                payload = str(res)
            if not payload or payload == "null":
                continue
            findings.append({
                "titulo": label,
                "severidad": None,
                "descripcion": _corta(payload, 500),
                "fuente": rel,
                "ubicacion": f"$.server_scan_results[{s_idx}].scan_result.{key}",
                "puerto": puerto or None,
                "cve": None,
            })
    return findings


def _hallazgo_nse(rel, sid, output, ubicacion, puerto=None):
    """Crea un hallazgo desde un script NSE (vuln explicita o config insegura
    textual del output). Devuelve None si no es ninguno de los dos casos."""
    if not sid or not (output or "").strip():
        return None
    out_low = (output or "").lower()
    es_vuln = ("vuln" in sid.lower()
               or "exploit" in sid.lower()
               or "heartbleed" in sid.lower()
               or "vulners" in sid.lower()
               or "VULNERABLE" in output
               or "vulnerable" in out_low)
    es_config = any(p in out_low for p in _NSE_CONFIG.get(sid.lower(), ()))
    if not (es_vuln or es_config):
        return None
    return {
        "titulo": sid,
        "severidad": _severidad_de_texto(output) if es_vuln else None,
        "descripcion": _corta(output, 400),
        "fuente": rel,
        "ubicacion": ubicacion,
        "puerto": puerto,
        "cve": None,
    }


def parse_nmap(path, rel):
    """outputs/nmap_detailed.xml → scripts NSE de vulnerabilidad (puerto) +
    scripts de hostscript con configuracion insegura textual (ej. smb2-security-mode).
    Servicios abiertos sin script NSE relevante NO son hallazgos."""
    if not os.path.exists(path):
        return []
    findings = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return findings
    for host in root.findall("host"):
        ports = host.findall("./ports/port") or []
        for port in ports:
            portid = str(port.get("portid") or "")
            for script in port.findall("script"):
                sid = script.get("id") or ""
                output = (script.get("output") or "").strip()
                h = _hallazgo_nse(
                    rel, sid, output,
                    f"//host/ports/port[@portid={portid}]/script[@id={sid}]",
                    portid)
                if h:
                    findings.append(h)
        # hostscript: scripts NSE sin puerto asociado (config insegura textual)
        for script in host.findall("hostscript/script"):
            sid = script.get("id") or ""
            output = (script.get("output") or "").strip()
            h = _hallazgo_nse(
                rel, sid, output,
                f"//host/hostscript/script[@id={sid}]")
            if h:
                findings.append(h)
    return findings


def parse_gobuster(path, rel):
    """outputs/gobuster_<port>.txt → UN hallazgo consolidado por archivo con las
    rutas descubiertas (lineas literales). Las rutas son superficie de ataque
    (informacion), no vulnerabilidades: NO se fabrica una VULN por linea."""
    if not os.path.exists(path):
        return []
    findings = []
    base = os.path.basename(path)
    m = re.search(r"gobuster_(\d+)\.txt$", base)
    puerto = m.group(1) if m else ""
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except Exception:
        return findings
    rutas = []
    for i, raw in enumerate(lines, start=1):
        linea = raw.strip()
        if not linea:
            continue
        # gobuster txt real: "/admin (Status: 301) [Size: 0] [--> /admin/]"
        if not (linea.startswith("/") or "(Status:" in linea):
            continue
        if linea.startswith(("Gobuster", "=================================",
                             "Starting ", "Finished ", "Time:", "Threads:")):
            continue
        rutas.append((i, linea))
    if not rutas:
        return findings
    max_mostrar = 20
    piezas = [f"L{i}: {l}" for i, l in rutas[:max_mostrar]]
    if len(rutas) > max_mostrar:
        piezas.append(f"... y {len(rutas) - max_mostrar} rutas más")
    desc = "; ".join(piezas)
    p_from, p_to = rutas[0][0], rutas[-1][0]
    findings.append({
        "titulo": f"Rutas descubiertas en {base} ({len(rutas)})",
        "severidad": None,
        "descripcion": _corta(desc, 1500),
        "fuente": rel,
        "ubicacion": f"líneas {p_from}-{p_to}",
        "puerto": puerto or None,
        "cve": None,
        "tipo": "directorios",
    })
    return findings


def parse_httpx(path, rel):
    """outputs/httpx.json (JSONL) → no declara hallazgos por si mismo.

    Por regla de cero invencion: httpx solo informa respuestas HTTP/headers.
    Si un JSONL de httpx incluyera un objeto con campos explicitos de hallazgo
    (title/severity/description), el parser generico de respaldo lo capturaria;
    este parser devuelve [] porque no hay formato de hallazgo estandar."""
    return []


# --- Parser generico de respaldo (deteccion dinamica de evidencia nueva) ---

_MARCADORES_TEXTO = re.compile(
    r"CVE-\d{4}-\d+|Severity\s*:|Severidad\s*:|CVSS\s*[:=]|"
    r"VULN-\d+|vulnerab|hallazgo|finding|deteccion|detección", re.I)


def _walk_json(obj, path, out):
    """Recorre un objeto JSON buscando dicts con claves tipo hallazgo."""
    if isinstance(obj, dict):
        llaves = set(obj.keys())
        if ("title" in llaves or "name" in llaves or "msg" in llaves) and (
                "severity" in llaves or "description" in llaves
                or "desc" in llaves or "template" in llaves or "vulnerability" in llaves):
            out.append((obj, path))
            return
        for k, v in obj.items():
            _walk_json(v, f"{path}.{k}", out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_json(v, f"{path}[{i}]", out)


def parse_generico(path, rel):
    """Fallback: JSON/JSONL con title+severity/description, o texto con marcadores."""
    ext = os.path.splitext(path)[1].lower()
    findings = []
    if ext in (".json", ".jsonl"):
        data = load_json(path)
        items = []
        if isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
            for i, v in enumerate(data):
                items.append((v, f"$[{i}]"))
        elif data is not None:
            _walk_json(data, "$", items)
        if not items:
            # quizas es jsonl suelto (no parseado como json unico)
            for idx, item in enumerate(load_jsonl(path)):
                _walk_json(item, f"$[{idx}]", items)
        for obj, jpath in items:
            if not isinstance(obj, dict):
                continue
            titulo = obj.get("title") or obj.get("name") or obj.get("template") or ""
            if not titulo:
                continue
            sev = obj.get("severity") or ""
            desc = obj.get("description") or obj.get("desc") or obj.get("msg") or ""
            cve = None
            for k, v in obj.items():
                if isinstance(v, str) and _CVE_RE.search(v):
                    cve = _CVE_RE.search(v).group(0)
                    break
            if not titulo:
                continue
            findings.append({
                "titulo": _corta(titulo, 200),
                "severidad": sev or None,
                "descripcion": _corta(desc, 400) if desc else "Sin descripción en fuente.",
                "fuente": rel,
                "ubicacion": jpath,
                "puerto": str(obj.get("port") or "") or None,
                "cve": cve,
            })
    elif ext in (".md", ".txt"):
        try:
            lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except Exception:
            return findings
        for i, raw in enumerate(lines, start=1):
            linea = raw.strip()
            if not linea:
                continue
            es_encabezado = linea.startswith(("#", "*", ">", "|", "---")) or linea.startswith("```")
            es_lista = linea.startswith("- ")
            if es_encabezado and not (es_lista and _MARCADORES_TEXTO.search(linea)):
                continue
            if not _MARCADORES_TEXTO.search(linea):
                continue
            if es_lista:
                linea = re.sub(r"^-\s+", "", linea)
            if len(linea) > 500:
                linea = linea[:500]
            findings.append({
                "titulo": _corta(linea, 200),
                "severidad": _severidad_de_texto(linea),
                "descripcion": _corta(linea, 400),
                "fuente": rel,
                "ubicacion": f"línea {i}",
                "puerto": None,
                "cve": None,
            })
    return findings
# ---------------------------------------------------------------------------
# Registro de parsers + deduplicacion + resolucion de target_id
# ---------------------------------------------------------------------------

def get_target_id(project_dir, ip):
    """target_id: desde el nombre del <tid>_cves.md en outputs/ (si existe),
    fallback manifest.json de evidence/, fallback IP pura."""
    out_dir = os.path.join(project_dir, ip, "outputs")
    if os.path.isdir(out_dir):
        for f in sorted(os.listdir(out_dir)):
            if f.endswith("_cves.md") and not f.startswith("."):
                return f[: -len("_cves.md")]
    man = load_json(os.path.join(WS, "evidence", ip, "manifest.json"))
    if isinstance(man, dict) and man.get("target_id"):
        return str(man["target_id"])
    return ip


def _dup_key(find):
    """Clave de deduplicacion: CVE; o reglas semanticas; o titulo+puerto.

    - 'Suggested security header missing': un hallazgo por header (varios puertos).
    - fingerprinting (000287/750537/500645): mismo mensaje en varios puertos web →
      uno solo.
    - 'OPTIONS: ...' : colapsar 'Allowed' y 'Public' con el mismo set de metodos
      en el mismo puerto.
    - SMB signing: nuclei 'SMB Signing Not Required' y nmap 'smb2-security-mode'
      representan el mismo hallazgo -> uno solo."""
    if find.get("cve"):
        return ("cve", str(find["cve"]).lower())
    titulo = (find.get("titulo") or "")
    tl = titulo.lower()
    if tl in ("smb signing not required", "smb2-security-mode"):
        return ("smb_signing",)
    if tl.startswith("options:"):
        metodos = ",".join(sorted(re.findall(
            r"\b(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|PATCH|CONNECT)\b",
            titulo.upper())))
        return ("options", metodos, str(find.get("puerto") or ""))
    if find.get("tipo") == "fingerprinting":
        key = re.sub(r"[^a-z0-9]+", " ", tl).strip()
        return ("nikto_fingerprint", key)
    if find.get("tipo") == "potencial" and tl.startswith("cookies creadas sin flag httponly"):
        key = re.sub(r"[^a-z0-9]+", " ", tl).strip()
        return ("nikto_cookies", key)
    if tl.startswith("suggested security header missing"):
        key = re.sub(r"[^a-z0-9]+", " ", tl).strip()
        return ("nikto_hardening", key)
    tit = re.sub(r"[^a-z0-9]+", " ", tl).strip()
    return ("titulo", tit, str(find.get("puerto") or ""))


def deduplicar(findings):
    """Misma deteccion en varias fuentes → una sola entrada, con la fuente de
    mas detalle textual como principal y el resto anotado en extra_locations."""
    grupos = {}
    for f in findings:
        key = _dup_key(f)
        if key not in grupos:
            grupos[key] = []
        grupos[key].append(f)
    out = []
    for key, lista in grupos.items():
        if len(lista) == 1:
            out.append(lista[0])
            continue
        lista.sort(key=lambda x: (1 if x.get("severidad") else 0,
                                  len(x.get("descripcion") or "")), reverse=True)
        principal = dict(lista[0])
        extras = []
        for otro in lista[1:]:
            extras.append(f"(también en {otro['fuente']} → {otro['ubicacion']})")
        if extras:
            principal["ubicacion"] = principal["ubicacion"] + " " + " ".join(extras)
        principal["extra_locations"] = extras
        out.append(principal)
    out.sort(key=lambda x: (x.get("cve") or x.get("titulo") or "").lower())
    return out


def _elegir_parser(name):
    """Devuelve (parser, es_especifico) segun el patron del nombre de archivo."""
    if name.endswith("_cves.md"):
        return parse_cves_md, True
    if name == "nuclei.json":
        return parse_nuclei, True
    if re.match(r"nikto_.+\.json$", name):
        return parse_nikto, True
    if re.match(r"sslyze_.+\.json$", name):
        return parse_sslyze, True
    if re.match(r"nmap_detailed\..+$", name):
        return parse_nmap, True
    if name == "httpx.json":
        return parse_httpx, True
    if re.match(r"gobuster_.+\.txt$", name):
        return parse_gobuster, True
    return parse_generico, False


def analizar_outputs(out_dir, rel_base="outputs"):
    """Escanea TODO el directorio outputs/ y devuelve los hallazgos (antes de
    deduplicar). Detecta dinamicamente archivos nuevos."""
    findings = []
    if not os.path.isdir(out_dir):
        return findings
    # orden de prioridad: cves.md, nuclei, nikto, sslyze, nmap, httpx, gobuster, resto
    def _prio(name):
        if name.endswith("_cves.md"):
            return 0, name
        if name == "nuclei.json":
            return 1, name
        if re.match(r"nikto_.+\.json$", name):
            return 2, name
        if re.match(r"sslyze_.+\.json$", name):
            return 3, name
        if re.match(r"nmap_detailed\..+$", name):
            return 4, name
        if name == "httpx.json":
            return 5, name
        if re.match(r"gobuster_.+\.txt$", name):
            return 6, name
        return 7, name
    for name in sorted(os.listdir(out_dir), key=_prio):
        path = os.path.join(out_dir, name)
        if os.path.isdir(path) or name.startswith("."):
            continue
        parser, _ = _elegir_parser(name)
        try:
            findings.extend(parser(path, f"{rel_base}/{name}"))
        except Exception as e:
            warn(f"parser {name} falla: {e}")
    return findings
# ---------------------------------------------------------------------------
# Generadores de reportes (.doc Word-HTML + .txt de una linea por hallazgo)
# ---------------------------------------------------------------------------

def _severidad_texto(find):
    """Severidad para mostrar: literal de fuente o 'No declarada en fuente'."""
    return find.get("severidad") or "No declarada en fuente"


def _render_doc(target_label, fecha, findings):
    """Reporte .doc como HTML compatible con Word/LibreOffice."""
    n = len(findings)
    declaradas = sum(1 for f in findings if f.get("severidad"))
    L = []
    L.append("""<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="utf-8">
<title>REPORTE DE VULNERABILIDADES – {{TARGET}}</title>
<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View>
</w:WordDocument></xml><![endif]-->
<style>
body {font-family: Calibri, Arial, sans-serif; font-size: 11pt; margin: 2cm;}
h1 {color: #1a1a2e;}
h2 {color: #1a1a2e; border-bottom: 1px solid #999; padding-bottom: 2px;}
.fuente {font-family: Consolas, monospace; font-size: 9pt; color: #444;}
.lugar {font-family: Consolas, monospace; font-size: 9pt; color: #444;}
.evidencia {background: #f4f4f4; border: 1px dashed #999; padding: 8px; color: #888;}
table {border-collapse: collapse; width: 100%;}
th, td {border: 1px solid #888; padding: 4px 6px; font-size: 9pt; text-align: left;}
th {background: #eee;}
.severidad {font-weight: bold;}
</style>
</head>
<body>
""".replace("{{TARGET}}", html.escape(str(target_label))))
    L.append(f"<h1>REPORTE DE VULNERABILIDADES – {html.escape(str(target_label))}</h1>")
    L.append(f"<p><b>Fecha de generación:</b> {html.escape(fecha)}</p>")
    L.append(f"<p><b>Total de hallazgos extraídos:</b> {n}</p>")
    L.append(f"<p><b>Severidades declaradas en fuente:</b> {declaradas} de {n}</p>")
    for find in findings:
        titulo = html.escape(ofuscar(str(find.get("titulo") or "")))
        sev = html.escape(_severidad_texto(find))
        desc = html.escape(ofuscar(str(find.get("descripcion") or ""))).replace("\n", "<br>")
        fuente = html.escape(ofuscar(str(find.get("fuente") or "")))
        ubic = html.escape(ofuscar(str(find.get("ubicacion") or "")))
        L.append('<hr>')
        L.append(f"<h2>{html.escape(find['id'])} – {titulo}</h2>")
        L.append(f'<p><b>Severidad:</b> <span class="severidad">{sev}</span></p>')
        tipo = find.get("tipo")
        if tipo:
            L.append(f'<p><b>Tipo (clasificación de la fuente):</b> {html.escape(ofuscar(str(tipo)))}</p>')
        L.append(f"<p><b>Descripción (extraída de fuente):</b><br>{desc}</p>")
        L.append(f'<p>📁 <b>Fuente:</b> <span class="fuente">{fuente}</span><br>'
                 f'&nbsp;&nbsp;&nbsp;↳ <b>Ubicación:</b> <span class="lugar">{ubic}</span></p>')
        L.append('<p class="evidencia">[ESPACIO EN BLANCO PARA EVIDENCIA – pegar captura aquí]</p>')
    L.append('<hr>')
    L.append('<h2>TABLA RESUMEN</h2>')
    L.append("<table><tr><th>ID</th><th>Título (literal)</th><th>Severidad</th>"
              "<th>Fuente</th><th>Ubicación</th></tr>")
    for find in findings:
        L.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(str(find["id"])),
            html.escape(ofuscar(str(find.get("titulo") or ""))),
            html.escape(_severidad_texto(find)),
            html.escape(ofuscar(str(find.get("fuente") or ""))),
            html.escape(ofuscar(str(find.get("ubicacion") or ""))),
        ))
    L.append("</table>")
    L.append("</body></html>")
    return "\n".join(L)


def _render_txt(findings):
    """Reporte .txt: estrictamente UNA linea por hallazgo."""
    out = []
    for find in findings:
        titulo = _linea_plana(find.get("titulo")).replace("|", " ")
        sev = _linea_plana(_severidad_texto(find))
        fuente = _linea_plana(find.get("fuente"))
        ubic = _linea_plana(find.get("ubicacion")).replace("|", " ")
        out.append(f"{find['id']} | {titulo} (Severidad: {sev}) | {fuente} → {ubic}")
    return "\n".join(out) + ("\n" if out else "")
# ---------------------------------------------------------------------------
# Procesamiento por target + entrada principal
# ---------------------------------------------------------------------------

def descubrir_targets(project_dir, only_targets):
    """Subdirectorios de <project_dir>/ con carpeta outputs/."""
    if not os.path.isdir(project_dir):
        print(f"❌ No existe {project_dir}/ — corri primero scripts/organize_project.py.")
        sys.exit(1)
    todos = sorted(
        d for d in os.listdir(project_dir)
        if os.path.isdir(os.path.join(project_dir, d)) and not d.startswith(".")
    )
    if only_targets:
        res = []
        for ip in only_targets:
            if os.path.isdir(os.path.join(project_dir, ip, "outputs")):
                res.append(ip)
            else:
                warn(f"target {ip} no tiene outputs/ en {project_dir}/ — omitido")
        return res
    return todos


def procesar_target(project_dir, ip, dry_run, no_clobber):
    """Analiza outputs/ de un target y genera los 2 reportes."""
    out_dir = os.path.join(project_dir, ip, "outputs")
    if not os.path.isdir(out_dir):
        warn(f"sin outputs/ para {ip}; se omite")
        return None
    target_id = get_target_id(project_dir, ip)
    target_label = target_id if target_id else ip
    if dry_run:
        print(f"\n► Target {ip}  (target_id: {target_id})")
        for name in sorted(os.listdir(out_dir)):
            path = os.path.join(out_dir, name)
            if not os.path.isfile(path) or name.startswith("."):
                continue
            print(f"    analizar outputs/{name}")
        doc = os.path.join(project_dir, ip, f"{target_id}_resumen_vulnerabilidades.doc")
        txt = os.path.join(project_dir, ip, f"{target_id}_resumen_breve.txt")
        print(f"    generar {os.path.relpath(doc, WS)}")
        print(f"    generar {os.path.relpath(txt, WS)}")
        return {"ip": ip, "target_label": target_label, "findings": []}

    findings = analizar_outputs(out_dir)
    findings = deduplicar(findings)
    # ID literal para todas las vulnerabilidades: el analista las numerará a mano
    # (puede agregar o quitar entradas sin renumerar el resto).
    for f in findings:
        f["id"] = "VULN-00X"

    n = len(findings)
    declaradas = sum(1 for f in findings if f.get("severidad"))
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    doc_path = os.path.join(project_dir, ip, f"{target_id}_resumen_vulnerabilidades.doc")
    txt_path = os.path.join(project_dir, ip, f"{target_id}_resumen_breve.txt")

    if n == 0:
        print(f"⚠️ {target_label}: No se encontraron hallazgos explícitos en ninguno de los "
              "archivos fuente. No se generaron reportes.")
        if not dry_run:
            for ruta in (doc_path, txt_path):
                if os.path.exists(ruta):
                    try:
                        os.remove(ruta)
                        print(f"  🧹 {os.path.relpath(ruta, WS)}: reporte obsoleto "
                              "eliminado (sin hallazgos actuales).")
                    except Exception as e:
                        warn(f"no se pudo eliminar {os.path.relpath(ruta, WS)}: {e}")
        return {"ip": ip, "target_label": target_label, "findings": []}

    errores = 0
    for ruta, contenido in ((doc_path, _render_doc(target_label, fecha, findings)),
                            (txt_path, _render_txt(findings))):
        if no_clobber and os.path.exists(ruta):
            warn(f"[no-clobber] ya existe: {os.path.relpath(ruta, WS)}")
            continue
        try:
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(contenido)
        except Exception as e:
            warn(f"error escribiendo {os.path.relpath(ruta, WS)}: {e}")
            errores += 1

    print(f"✅ {target_label} analizado. {n} hallazgos extraídos de los archivos fuente.")
    print(f"Severidades declaradas en fuente: {declaradas} de {n}.")
    print("Archivos generados:")
    print(f"- {os.path.relpath(doc_path, WS)}")
    print(f"- {os.path.relpath(txt_path, WS)}")
    if errores:
        warn(f"{errores} archivo(s) no se pudieron escribir")
    return {"ip": ip, "target_label": target_label, "findings": findings}


def main():
    parser = argparse.ArgumentParser(
        description="Agente 6 — Consolidador de hallazgos. Lee SOLO outputs/ de "
                    "cada target consolidado y genera _resumen_vulnerabilidades.doc "
                    "+ _resumen_breve.txt con cero invencion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--project", default="CLIENTE",
                        help="Directorio destino del consolidado (default: CLIENTE).")
    parser.add_argument("--target", action="append", metavar="IP",
                        help="Procesar solo ese target IP (repetible).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo previsualizar la estructura; no crea nada.")
    parser.add_argument("--no-clobber", action="store_true",
                        help="No sobrescribir reportes ya existentes.")
    args = parser.parse_args()

    project_dir = os.path.join(WS, args.project)
    if not os.path.isdir(project_dir):
        print(f"❌ No existe {os.path.relpath(project_dir, WS)}/ — "
              "corri primero scripts/organize_project.py.")
        sys.exit(1)
    targets = descubrir_targets(project_dir, args.target)
    if not targets:
        print("❌ No hay targets con outputs/ para procesar.")
        sys.exit(1)
    print(f"Proyecto: {os.path.relpath(project_dir, WS)}/ — {len(targets)} target(s)"
          + ("  (dry-run: no se crea nada)" if args.dry_run else ""))
    resultados = []
    for ip in targets:
        resultados.append(procesar_target(project_dir, ip, args.dry_run, args.no_clobber))
    return 0


if __name__ == "__main__":
    main()