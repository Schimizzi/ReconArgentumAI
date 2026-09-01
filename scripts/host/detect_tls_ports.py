#!/usr/bin/env python3
"""Detecta puertos con túnel SSL/TLS desde la evidencia de Nmap (Step 3).

OPTIMIZACIÓN MULTIPROTOCOLO 2026-08-31 — Step 8 (SSLyze) ya no depende de
web_endpoints.txt. Este helper lee nmap_detailed.json (o fallback al XML) y emite
una línea por puerto con SSL/TLS:

  <PORT> <SERVICE_NAME> <tunnel|starttls_proto>

Reglas de detección (en orden):
  1. tunnel=="ssl"     → TLS directo (https, imaps, smtps, ldaps, sips, ftps, etc.)
  2. servicio en lista TLS_NAME  → TLS directo por nombre (ssl/http, https, imaps, ...)
  3. puerto en lista TLS_PORT    → TLS directo por puerto conocido (443, 8443, 465, 636,
                                   990, 992, 993, 995, 5061, 5986, 990, 6514, 8883? — no, 8883 MQTTS)
  4. puerto 3389 (RDP)  → STARTTLS rdp (SSLyze --starttls rdp)
  5. servicio conocido con STARTTLS (smtp, imap, pop3, ftp, ldap) → --starttls <proto>

Uso: detect_tls_ports.py <EVID_DIR> [--with-starttls]
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

# Servicios cuyo nombre ya indica TLS directo
TLS_NAME = {"https", "ssl/http", "imaps", "pop3s", "smtps", "ldaps", "sips",
            "ftps", "telnets", "nntps", "mss", "smtps", "https-alt", "ssl/https",
            "kpasswd5", "wss", "wss (TLS)"}
# Puertos bien conocidos TLS directo (cuando el servicio no lo aclara)
TLS_PORT = {443, 444, 465, 563, 585, 614, 636, 853, 989, 990, 992, 993, 994,
            995, 2049, 2484, 3128, 3269, 3799, 5061, 5062, 5671, 5986, 6514,
            8443, 9443, 9899, 9907, 9943, 9944, 10000, 10443, 12000}
# Servicio → protocolo STARTTLS de SSLyze
STARTTLS_MAP = {"smtp": "smtp", "imap": "imap", "pop3": "pop3", "ftp": "ftp",
                "ldap": "ldap", "postgres": "postgres", "mysql": "mysql",
                "xmpp": "xmpp", "rdp": "rdp"}


def load_json(path):
    with open(path) as f:
        return json.load(f)


def from_json(ev_dir):
    out = []
    data = load_json(os.path.join(ev_dir, "nmap_detailed.json"))
    for host in data.get("scan", {}).values():
        for port, rec in (host.get("tcp") or {}).items():
            if rec.get("state") != "open":
                continue
            svc = rec.get("service") or {}
            name = (svc.get("name") or "").lower()
            tunnel = (svc.get("tunnel") or "").lower()
            product = (svc.get("product") or "").lower()
            port_n = int(port)
            yield (port_n, name, tunnel, product)


def from_xml(ev_dir):
    root = ET.parse(os.path.join(ev_dir, "nmap_detailed.xml")).getroot()
    for host in root.findall("host"):
        for p in host.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            name = (svc.get("name") or "").lower() if svc is not None else ""
            tunnel = (svc.get("tunnel") or "").lower() if svc is not None else ""
            product = (svc.get("product") or "").lower() if svc is not None else ""
            yield (int(p.get("portid")), name, tunnel, product)


def main():
    ev_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    with_starttls = "--with-starttls" in sys.argv
    if os.path.exists(os.path.join(ev_dir, "nmap_detailed.json")):
        ports_iter = from_json(ev_dir)
    elif os.path.exists(os.path.join(ev_dir, "nmap_detailed.xml")):
        ports_iter = from_xml(ev_dir)
    else:
        print("", end="")
        return

    results = []
    for port_n, name, tunnel, product in ports_iter:
        starttls = ""
        proto = ""
        if tunnel == "ssl":
            proto = "tls"
        elif name in TLS_NAME:
            proto = "tls"
        elif port_n in TLS_PORT:
            proto = "tls"
        elif name == "ms-wbt-server" or (port_n == 3389 and proto == ""):
            proto = "starttls"; starttls = "rdp"
        elif name in STARTTLS_MAP:
            proto = "starttls"; starttls = STARTTLS_MAP[name]
        if proto:
            if proto == "tls":
                results.append((port_n, name, "tls", ""))
            elif with_starttls:
                results.append((port_n, name, "starttls", starttls))
    # dedupe, orden numérico
    seen = set()
    for r in sorted(results):
        key = (r[0], r[3])
        if key in seen:
            continue
        seen.add(key)
        print(f"{r[0]} {r[1]} {r[2]} {r[3]}")


if __name__ == "__main__":
    main()