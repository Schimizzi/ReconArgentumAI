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

IMPACTO_CRITICO_KEYWORDS = {
    "remote_code_execution", "privilege_escalation",
    "broken_authentication", "broken_access_control",
    "insecure_deserialization", "sql_injection",
    "command_injection", "buffer_overflow",
    "use_after_free", "out_of_bounds_rw",
}

SEVERITY_MAP = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW")]

# Plugins de WhatWeb que NO son tecnologías (metadata/pseudo-plugins del fingerprint).
# Buscarlos en vulnx genera FALSOS POSITIVOS (ej. "Country" → CVEs de un plugin de
# WooCommerce, "IP"/"Title"/"Script" → ruido). Se excluyen del CVE research.
WHATWEB_NON_TECH_PLUGINS = {
    "ip", "country", "title", "htmltitle", "script", "html5", "redirectlocation",
    "uncommonheaders", "httpserver", "cookies", "headers", "email", "frame",
    "object", "passwordfield", "comment",
}


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
                try:
                    return json.loads(proc.stdout)
                except json.JSONDecodeError:
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
    """Devuelve la lista de resultados, o None si la consulta FALLÓ (≠ lista vacía)."""
    query = product
    if version and version not in ("unknown", "", "none"):
        query = f"{product} {version}"
    data = _run_vulnx(["search", query, "--json", "--limit", str(SEARCH_LIMIT)])
    if data is None:
        return None
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

    entries = []
    for r in valid:
        cve_id = r.get("cve_id", "")
        detail = details.get(cve_id, r)
        already = cve_id.upper() in nuclei_cves
        entries.append(_build_cve_entry(detail, already))

    ranked = _rank_cves(entries)
    for i, cve in enumerate(ranked):
        cve["rank_reason"] = _determine_rank_reason(cve, i)
    top_cves = ranked[:TOP_N_MAX]

    if is_web:
        return {"technology": name, "version": version or None, "cves": top_cves}, False
    return {"service": name, "version": version or None, "port": port, "cves": top_cves}, False


def _collect_omissions(services_analyzed: list[dict],
                        web_analyzed: list[dict],
                        failed_services: list[str] | None = None,
                        failed_web: list[str] | None = None) -> list[dict]:
    """Registra por qué un servicio quedó sin CVEs.

    reason=query_failed   → vulnx no respondió (rate limit/timeout) → revisar
    reason=no_data_available → vulnx respondió sin CVEs para ese producto
    """
    failed_services = failed_services or []
    failed_web = failed_web or []
    omissions = []
    for s in services_analyzed:
        if not s.get("cves"):
            name = s.get("service", "?")
            omissions.append({
                "service": name,
                "source": "vulnx",
                "reason": "query_failed" if name in failed_services else "no_data_available",
            })
    for w in web_analyzed:
        if not w.get("cves"):
            key = f"web/{w.get('technology', '?')}"
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
                   output_path: str | None = None) -> dict:
    services = _load_nmap_services(nmap_path)
    web_technologies = _load_whatweb(whatweb_path)
    nuclei_cves = _load_nuclei_cves(nuclei_path)

    services_analyzed = []
    failed_services = []
    for svc in services:
        print(f"  \U0001f50d {svc['name']} (port {svc['port']}, v{svc['version']})...",
              end=" ", flush=True)
        r, failed = _investigate_service(svc["name"], svc["version"], svc["port"], nuclei_cves)
        services_analyzed.append(r)
        if failed:
            failed_services.append(r.get("service", svc["name"]))
        print(f"{'ERROR de consulta' if failed else str(len(r.get('cves', []))) + ' CVEs'}")

    web_analyzed = []
    failed_web = []
    for wt in web_technologies:
        print(f"  \U0001f310 web/{wt['technology']} (v{wt['version']})...",
              end=" ", flush=True)
        r, failed = _investigate_service(wt["technology"], wt["version"], 0,
                                          nuclei_cves, is_web=True)
        web_analyzed.append(r)
        if failed:
            failed_web.append(f"web/{r.get('technology', wt['technology'])}")
        print(f"{'ERROR de consulta' if failed else str(len(r.get('cves', []))) + ' CVEs'}")
    if failed_services or failed_web:
        print(f"  \u26a0\ufe0f  {len(failed_services) + len(failed_web)} consulta(s) fallaron "
              f"(ver source_omissions[].reason=query_failed)", file=sys.stderr)

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
        "source_omissions": _collect_omissions(services_analyzed, web_analyzed,
                                                failed_services, failed_web),
        "summary": {
            "total_cves": len(all_cves),
            "critical": sev_count("CRITICAL"),
            "high": sev_count("HIGH"),
            "medium": sev_count("MEDIUM"),
            "low": sev_count("LOW"),
            "with_public_exploit": sum(1 for c in all_cves if c.get("exploit_available")),
            "patched_available": sum(1 for c in all_cves if c.get("patched_version")),
        },
    }

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
    args = parser.parse_args()

    print(f"\n\U0001f52c CVE Research \u2014 {args.target_ip} ({args.target_id})")
    print(f"   Motor: vulnx v2")
    print(f"   Nmap:  {args.nmap}")
    print(f"   WhatWeb: {args.whatweb or '(no disponible)'}")
    print(f"   Nuclei: {args.nuclei or '(no disponible)'}")
    print()

    result = process_target(
        target_id=args.target_id,
        target_ip=args.target_ip,
        nmap_path=args.nmap,
        whatweb_path=args.whatweb,
        nuclei_path=args.nuclei,
        output_path=args.output,
    )

    if args.dry_run:
        print("\n  \U0001f4cb DRY RUN \u2014 JSON no escrito. Resumen:")
        s = result["summary"]
        print(f"     Total CVEs: {s['total_cves']}")
        print(f"     Criticas: {s['critical']} | Altas: {s['high']} | "
              f"Medias: {s['medium']} | Bajas: {s['low']}")
        print(f"     Con exploit publico: {s['with_public_exploit']} | "
              f"Parche disp.: {s['patched_available']}")
        return

    _validate_output(result)


if __name__ == "__main__":
    main()