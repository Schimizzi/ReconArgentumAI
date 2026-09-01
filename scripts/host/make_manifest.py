#!/usr/bin/env python3
"""Genera/regenera manifest.json por target con outputs reales en disco.

Uso: make_manifest.py <TARGET> [started_at] [completed_at]
Lee config/scope.json (target_id, excluded) y evidencia/<target>/ para listar
los outputs reales de cada step. Estados: success/failed/skipped/skipped_no_*\n se
conservan si existe un manifest previo; caso contrario se infieren por step
según la lógica Service-Based Routing (Optimización Multiprotocolo 2026-08-31).
"""
import json
import os
import sys
from datetime import datetime

WS = os.environ.get("WORKSPACE", os.getcwd())

# Service-Based Routing: qué status por step cuando no hay outputs.
SKIP_BY_STEP = {
    1: "skipped_no_ports",   # Nmap sin puertos (target incomplete)
    2: "skipped_no_ports",   # HTTPX sin puertos base
    3: "skipped_no_ports",   # detallado sin puertos base
    4: "skipped_no_ports",   # Nuclei siempre, si no hay puertos
    5: "skipped_no_web",     # Nikto solo web
    6: "skipped",            # WhatWeb SALTADO por usuario
    7: "skipped_no_web",     # Gobuster sin web/dominio/udp69
    8: "skipped_no_tls",     # SSLyze sin puertos TLS
}


def infer(step: int, tool_outputs: list) -> str:
    if tool_outputs:
        return "success"
    return SKIP_BY_STEP.get(step, "skipped_no_web")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Uso: make_manifest.py <TARGET> [started_at] [completed_at]")
    target = sys.argv[1]
    ev = os.path.join(WS, "evidence", target)

    # scope
    try:
        scope = json.load(open(os.path.join(WS, "config", "scope.json")))
    except Exception:
        scope = {"authorized_targets": [], "excluded_ips": []}
    tid = next((t["id"] for t in scope.get("authorized_targets", []) if t["ip"] == target), target)
    excluded = target in scope.get("excluded_ips", [])

    now = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    started = sys.argv[2] if len(sys.argv) > 2 else now
    completed = sys.argv[3] if len(sys.argv) > 3 else now

    prev = {}
    mpath = os.path.join(ev, "manifest.json")
    if os.path.exists(mpath):
        try:
            prev = json.load(open(mpath))
        except Exception:
            prev = {}

    def files(*pats):
        out = []
        for p in pats:
            out.extend(sorted(f for f in os.listdir(ev) if __import__("fnmatch").fnmatch(f, p)))
        return out

    steps = [
        (1, "nmap_ports", files("nmap_ports.*", "open_ports.txt")),
        (2, "httpx", files("httpx.json", "web_endpoints.txt")),
        (3, "nmap_detailed", files("nmap_detailed.*")),
        (4, "nuclei", files("nuclei.json")),
        (5, "nikto", files("nikto_*.json")),
        (6, "whatweb", files("whatweb.json")),
        (7, "gobuster", files("gobuster_*.txt", "udp_69.gnmap")),
        (8, "sslyze", files("sslyze_*.json")),
    ]
    # WhatWeb fue SALTADO por usuario en Fase 0 (DREAMCO-2026, 2026-08-31): no se ejecuta.
    SKIPPED_TOOLS = {6: "skipped"}

    tools = []
    for step, tool, outs in steps:
        if step in SKIPPED_TOOLS:
            tools.append({"step": step, "tool": tool, "status": SKIPPED_TOOLS[step], "output": []})
            continue
        status = ""
        for e in prev.get("tools_executed", []):
            if e.get("step") == step:
                status = e.get("status", "")
                break
        if not status:
            status = infer(step, outs)
        tools.append({"step": step, "tool": tool, "status": status, "output": outs})

    # errores: desde _errors.log si existe (FIX 2026-08-31: antes quedaba siempre []).
    errs = []
    elog = os.path.join(ev, "_errors.log")
    if os.path.exists(elog):
        with open(elog, "r", errors="ignore") as f:
            errs = [l.strip() for l in f.read().splitlines() if l.strip()]

    manifest = {
        "target": target,
        "target_id": tid,
        "started_at": started,
        "completed_at": completed,
        "tools_executed": tools,
        "out_of_scope_findings": [],
        "errors": errs,
    }
    if excluded:
        manifest["out_of_scope_findings"].append({"ip": target, "reason": "in excluded_ips"})
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"manifest OK: {mpath}")


if __name__ == "__main__":
    main()