#!/usr/bin/env python3
"""Convierte nmap_ports.xml -> nmap_ports.json (workaround -oJ roto).

MOTIVO: en el contenedor Kali (Paso 2 del proyecto), nmap 7.99+dfsg-1kali1
(arm64/aarch64) tiene el flag -oJ (JSON output) ROTO: no escribe archivo y
corrompe el parsing de outputs (bug de paquete Kali rolling, verificado
2026-08-30). -oX/-oN/-oG funcionan correctamente.

Este script genera un json derivado del XML con el sub-schema que consume el
pipeline: .scan[<IP>].tcp[<port>].state (string "open") + .service.{name,
product,version,extrainfo} y .scaninfo. Uso:
  xml_to_nmap_json.py <nmap_ports.xml> <nmap_ports.json>
"""
import json
import sys
import xml.etree.ElementTree as ET


def parse(path_xml: str, path_json: str) -> None:
    root = ET.parse(path_xml).getroot()
    out: dict = {"nmap": {}, "scan": {}}

    # scaninfo
    scaninfo = {}
    for si in root.findall("scaninfo"):
        scaninfo[si.get("protocol", "tcp")] = {
            "type": si.get("type"),
            "method": si.get("method"),
            "services": si.get("services"),
        }
    out["nmap"]["scaninfo"] = scaninfo

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        rec = {"hostnames": [], "addresses": {}, "status": {}, "tcp": {}}

        for a in host.findall("address"):
            rec["addresses"][a.get("addrtype")] = a.get("addr")
        for hn in host.findall("hostnames/hostname"):
            rec["hostnames"].append({"name": hn.get("name") or "", "type": hn.get("type") or ""})

        status = host.find("status")
        if status is not None:
            rec["status"] = {"state": status.get("state"), "reason": status.get("reason")}

        for port in host.findall("ports/port"):
            pid = port.get("portid")
            st = port.find("state")
            svc = port.find("service")
            entry: dict = {}
            if st is not None:
                entry["state"] = st.get("state")  # string: "open" | "closed" | "filtered"
            entry["service"] = {
                "name": svc.get("name") if svc is not None and svc.get("name") else "",
                "product": svc.get("product") if svc is not None and svc.get("product") else "",
                "version": svc.get("version") if svc is not None and svc.get("version") else "",
                "extrainfo": svc.get("extrainfo") if svc is not None and svc.get("extrainfo") else "",
                # OPTIMIZACIÓN MULTIPROTOCOLO 2026-08-31: preservar el atributo tunnel del XML
                # de Nmap ("ssl" cuando el servicio negocia TLS, ej. https, imaps, 993, 990, etc.)
                "tunnel": svc.get("tunnel") if svc is not None and svc.get("tunnel") else "",
            }
            rec["tcp"][pid] = entry

        out["scan"][ip] = rec

    with open(path_json, "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    parse(sys.argv[1], sys.argv[2])