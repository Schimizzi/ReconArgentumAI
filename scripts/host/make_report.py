#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agente 5 (Reporter) — Genera final_report + informes individuales por target."""
import json
import os
import re
from datetime import datetime

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ofuscar(t):
    """Redacta datos sensibles con *** (solo copia del informe)."""
    if not isinstance(t, str):
        return t
    t = re.sub(r'(password\s*[=:]\s*)([^\s,;]+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(passwd\s*[=:]\s*)([^\s,;]+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(default password is\s+)(\w+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(token\s*[=:]\s*)([^\s,;]+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(api[_-]?key\s*[=:]\s*)([^\s,;]+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(secret\s*[=:]\s*)([^\s,;]+)', r'\1***', t, flags=re.I)
    t = re.sub(r'(Basic\s+)[A-Za-z0-9+/=]+', r'\1***', t, flags=re.I)
    t = re.sub(r'(Bearer\s+)[A-Za-z0-9._~+/=-]+', r'\1***', t, flags=re.I)
    return t


def riesgo(score):
    if score >= 9:
        return "CRITICO"
    if score >= 7:
        return "ALTO"
    if score >= 4:
        return "MEDIO"
    return "BAJO"


def leer_stealth():
    out = {}
    with open(os.path.join(WS, "config", "stealth.yaml")) as f:
        for line in f:
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    return out


def scope_excluded():
    try:
        s = json.load(open(os.path.join(WS, "config", "scope.json")))
        return s.get("excluded_ips", [])
    except Exception:
        return []


def build_target(tg):
    tid, ip = tg["id"], tg["ip"]
    evdir = os.path.join(WS, "evidence", ip)
    entry = {"id": tid, "ip": ip, "services": [], "vulnerabilities": [],
             "cves": [], "config_issues": [], "exploitation_plan_ref": None,
             "risk_score": 0.0, "out_of_scope_findings": []}
    mpath = os.path.join(evdir, "manifest.json")
    manifest = {}
    if os.path.exists(mpath):
        manifest = json.load(open(mpath))

    plan = os.path.join(WS, "plans", f"{tid}_exploitation_plan.md")
    if os.path.exists(plan):
        entry["exploitation_plan_ref"] = os.path.abspath(plan)

    rpath = os.path.join(WS, "cve_research", f"{tid}_cves.json")
    if os.path.exists(rpath):
        try:
            res = json.load(open(rpath))
            for s in res.get("services_analyzed", []):
                for c in s.get("cves", []):
                    c["service"] = s["service"]
                    entry["cves"].append(c)
            for wt in res.get("web_technologies", []):
                for c in wt.get("cves", []):
                    c["service"] = f"web/{wt['technology']}"
                    entry["cves"].append(c)
        except Exception:
            pass

    npd = os.path.join(evdir, "nmap_detailed.json")
    if os.path.exists(npd):
        try:
            det = json.load(open(npd))
            for h in det.get("scan", {}).values():
                for port, pinfo in h.get("tcp", {}).items():
                    svc = pinfo.get("service", {})
                    entry["services"].append({
                        "port": port,
                        "service": svc.get("name") or "",
                        "version": (svc.get("product") or "") + " " + (svc.get("version") or ""),
                    })
        except Exception:
            pass

    nuc = os.path.join(evdir, "nuclei.json")
    if os.path.exists(nuc):
        try:
            with open(nuc) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    fl = json.loads(line)
                    entry["vulnerabilities"].append({
                        "source": "nuclei",
                        "severity": fl.get("info", {}).get("severity", ""),
                        "name": ofuscar(fl.get("info", {}).get("name", "")),
                        "description": ofuscar(fl.get("info", {}).get("description", "")),
                        "matched_at": fl.get("matched_at", ""),
                    })
        except Exception:
            pass

    nik = os.path.join(evdir, "nikto_80.json")
    if os.path.exists(nik):
        try:
            nk = json.load(open(nik))[0]
            for v in nk.get("vulnerabilities", []):
                entry["vulnerabilities"].append({
                    "source": "nikto", "severity": "info",
                    "name": v.get("id", ""),
                    "description": ofuscar(v.get("msg", "")),
                    "url": v.get("url", ""),
                })
        except Exception:
            pass

    for c in entry["vulnerabilities"]:
        if c["source"] == "nikto" and ("missing" in c["description"].lower() or "header" in c["description"].lower()):
            entry["config_issues"].append(c["description"])
    if not entry["services"] and os.path.exists(evdir):
        entry["config_issues"] = entry["config_issues"] or ["target incomplete: sin puertos abiertos en top-1000"]

    entry["out_of_scope_findings"] = manifest.get("out_of_scope_findings", [])

    score = 0.0
    for v in entry["vulnerabilities"]:
        sev = v["severity"].lower()
        score = max(score, {"critical": 9.0, "high": 7.5, "medium": 5.0, "info": 1.0}.get(sev, 2.0))
    for c in entry["cves"]:
        if c.get("cvss_score"):
            score = max(score, float(c["cvss_score"]))
    entry["risk_score"] = min(10.0, round(score, 1))
    return entry


def main():
    scope = json.load(open(os.path.join(WS, "config", "scope.json")))
    engagement = scope["engagement_id"]
    targets_scope = scope["authorized_targets"]

    starts, ends = [], []
    for t in targets_scope:
        m = os.path.join(WS, "evidence", t["ip"], "manifest.json")
        if os.path.exists(m):
            d = json.load(open(m))
            if d.get("started_at"):
                starts.append(d["started_at"])
            if d.get("completed_at"):
                ends.append(d["completed_at"])
    started_at = min(starts) if starts else datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    completed_at = max(ends) if ends else started_at

    targets = [build_target(t) for t in targets_scope]

    vulns = [v for t in targets for v in t["vulnerabilities"]]
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        k = v["severity"].lower()
        if k in sev_count:
            sev_count[k] += 1
    cves_all = [c for t in targets for c in t["cves"]]
    with_exploit = sum(1 for c in cves_all if c.get("exploit_available"))

    return {
        "engagement_id": engagement,
        "started_at": started_at,
        "completed_at": completed_at,
        "scope": [{"id": t["id"], "ip": t["ip"]} for t in targets_scope],
        "methodology": {
            "tools": ["nmap", "httpx", "nuclei", "nikto", "whatweb", "gobuster", "sslyze"],
            "stealth_params": leer_stealth(),
            "execution_mode": "sequential",
        },
        "targets": targets,
        "summary": {
            "targets_count": len(targets),
            "findings_by_severity": sev_count,
            "total_cves": len(cves_all),
            "cves_with_exploit": with_exploit,
        },
        "evidence_paths": {t["id"]: os.path.abspath(os.path.join(WS, "evidence", t["ip"])) for t in targets_scope},
        "out_of_scope": scope_excluded(),
    }
def generar_md(report):
    L = []
    L.append("# Informe de Pentest — Recon Pipeline\n")
    L.append(f"**Engagement:** `{report['engagement_id']}`  ")
    L.append(f"**Período:** {report['started_at']} → {report['completed_at']}  ")
    L.append("**Alcance:** " + ", ".join(f"`{t['id']}` {t['ip']}" for t in report['scope']) + "\n")
    L.append("## 1. Resumen ejecutivo\n")
    L.append("El reconocimiento identificó infraestructura de red doméstica/LAN (192.168.8.0/24). "
             "**TGT-006 (192.168.8.233)** es un gateway/router con **AdGuard Home** expuesto (riesgo ALTO), "
             "OpenSSH 9.6p1 con CVE-2024-6387 si no parchado, resolver Unbound con riesgo KeyTrap, y panel de "
             "instalación web expuesto. TGT-005 (.201) es el host local sin servicios expuestos.\n")
    L.append("**Riesgo global:** ALTO.\n")
    L.append("**Recomendaciones top-3:**\n")
    L.append("1. Endurecer AdGuard Home: rotar credenciales admin, deshabilitar wizard de instalación, limitar acceso a la LAN.")
    L.append("2. Actualizar OpenSSH (9.8p1 o backport USN-6859-1) si la build 3ubuntu13.18 no incluye el fix de CVE-2024-6387.")
    L.append("3. Actualizar Unbound >= 1.19.1 y AdGuard Home >= 0.107.75.\n")
    L.append("## 2. Alcance y metodología\n")
    L.append("Herramientas: `" + ", ".join(report['methodology']['tools']) + "`.  ")
    L.append("Modo: secuencial (DAG 8 steps). Bifurcación no-web aplicada en TGT-005 (incomplete).\n")
    L.append("Parámetros stealth: `" + json.dumps(report['methodology']['stealth_params']) + "`\n")
    L.append("## 3. Por target\n")
    for t in report['targets']:
        L.append(f"### {t['id']} — {t['ip']} (riesgo {riesgo(t['risk_score'])} · score {t['risk_score']})\n")
        if t['services']:
            L.append("| Puerto | Servicio | Versión |\n|---|---|---|")
            for s in t['services']:
                L.append(f"| {s['port']} | {s['service']} | {s['version']} |")
            L.append("")
        if t['vulnerabilities']:
            L.append("**Vulnerabilidades (ofuscadas):**")
            L.append("| Severidad | Hallazgo | Fuente |\n|---|---|---|")
            for v in t['vulnerabilities'][:15]:
                L.append(f"| {v['severity']} | {v['description'][:90]} | {v['source']} |")
            L.append("")
        if t['cves']:
            L.append("**CVEs correlacionados:**")
            L.append("| CVE | CVSS | Exploit | Patch | rank_reason |\n|---|---|---|---|---|")
            for c in t['cves'][:8]:
                L.append(f"| {c['id']} | {c.get('cvss_score','-')} | {'SÍ' if c.get('exploit_available') else 'no'} | {'SÍ' if c.get('patched_version') else 'no'} | {c.get('rank_reason','-')} |")
            L.append("")
        if t['exploitation_plan_ref']:
            L.append(f"**Plan de explotación:** `{t['exploitation_plan_ref']}`  ")
        if t['config_issues']:
            L.append("**Configuración insegura (ofuscado):**")
            for ci in t['config_issues'][:8]:
                L.append(f"- {ci}")
        L.append("")
    L.append("## 4. Matriz de riesgo global\n")
    L.append("| Target | IP | Score | Riesgo |\n|---|---|---|---|")
    for t in report['targets']:
        L.append(f"| {t['id']} | {t['ip']} | {t['risk_score']} | {riesgo(t['risk_score'])} |")
    L.append("")
    L.append("## 5. Recomendaciones de remediación (por prioridad)\n")
    L.append("1. **ALTA** — Endurecer AdGuard Home (rotar credenciales admin, desactivar wizard, restringir acceso LAN).")
    L.append("2. **ALTA** — Actualizar OpenSSH (9.8p1 / backport USN-6859-1) si 9.6p1-3ubuntu13.18 NO incluye el fix.")
    L.append("3. **MEDIA** — Actualizar Unbound >= 1.19.1 y AdGuard Home >= 0.107.75.")
    L.append("4. **BAJA** — Confirmar falsos positivos de Nikto (Tomcat/Exchange) con validación manual.\n")
    L.append("## 6. Anexos\n")
    L.append("**Evidencia (paths absolutos):**")
    for tid, p in report['evidence_paths'].items():
        L.append(f"- `{tid}` → `{p}`")
    L.append("**Planes:** " + ", ".join(f"`{t['exploitation_plan_ref']}`" for t in report['targets'] if t['exploitation_plan_ref']) or "—")
    L.append("**CVE research:** `" + os.path.join(WS, "cve_research", "TGT-006_cves.json") + "`\n")
    L.append("---\n")
    L.append("*Datos sensibles ofuscados con `***`. La evidencia cruda no se modificó.*")
    return "\n".join(L) + "\n"
def generar_md_individual(t):
    L = []
    L.append(f"# Informe de Pentest — {t['id']} ({t['ip']})\n")
    L.append(f"**Target:** `{t['id']}` — `{t['ip']}`  ")
    L.append(f"**Riesgo:** {riesgo(t['risk_score'])} (score {t['risk_score']})\n")
    L.append("## 1. Resumen del target\n")
    if t['services']:
        L.append("Servicios detectados: " + ", ".join(f"`{s['port']}/{s['service']}` ({s['version']})" for s in t['services']) + "\n")
    else:
        L.append("Sin servicios detectados (target incomplete / sin puertos abiertos en top-1000).\n")
    if t['vulnerabilities']:
        L.append("Hallazgos: " + str(len(t['vulnerabilities'])) + " vulnerabilidades (ver tabla).\n")
    else:
        L.append("Sin vulnerabilidades confirmadas por las tools de recon.\n")
    if t['cves']:
        L.append("CVEs correlacionados: " + str(len(t['cves'])) + ".\n")
    L.append("## 2. Servicios\n")
    if t['services']:
        L.append("| Puerto | Servicio | Versión |\n|---|---|---|")
        for s in t['services']:
            L.append(f"| {s['port']} | {s['service']} | {s['version']} |")
        L.append("")
    else:
        L.append("Ninguno.\n")
    L.append("## 3. Vulnerabilidades (ofuscadas)\n")
    if t['vulnerabilities']:
        L.append("| Severidad | Hallazgo | Fuente |\n|---|---|---|")
        for v in t['vulnerabilities'][:20]:
            L.append(f"| {v['severity']} | {v['description'][:90]} | {v['source']} |")
        L.append("")
    else:
        L.append("Ninguna confirmada.\n")
    L.append("## 4. CVEs correlacionados\n")
    if t['cves']:
        L.append("| CVE | CVSS | Exploit | Patch | rank_reason |\n|---|---|---|---|---|")
        for c in t['cves'][:10]:
            L.append(f"| {c['id']} | {c.get('cvss_score','-')} | {'SÍ' if c.get('exploit_available') else 'no'} | {'SÍ' if c.get('patched_version') else 'no'} | {c.get('rank_reason','-')} |")
        L.append("")
    else:
        L.append("Ninguno.\n")
    L.append("## 5. Plan de explotación\n")
    L.append((f"Disponible: `{t['exploitation_plan_ref']}`" if t['exploitation_plan_ref'] else "No generado (sin hallazgos accionables).") + "\n")
    L.append("## 6. Configuración insegura\n")
    if t['config_issues']:
        for ci in t['config_issues'][:10]:
            L.append(f"- {ci}")
    else:
        L.append("Ninguna adicional.")
    L.append("")
    L.append("## 7. Evidencia\n")
    L.append(f"`{os.path.abspath(os.path.join(WS, 'evidence', t['ip']))}`\n")
    L.append("---\n")
    L.append("*Datos sensibles ofuscados con `***`.*")
    return "\n".join(L) + "\n"


def generar_json_individual(t, engagement_id):
    return {
        "engagement_id": engagement_id,
        "target_id": t["id"],
        "ip": t["ip"],
        "services": t["services"],
        "vulnerabilities": t["vulnerabilities"],
        "cves": t["cves"],
        "config_issues": t["config_issues"],
        "exploitation_plan_ref": t["exploitation_plan_ref"],
        "risk_score": t["risk_score"],
        "out_of_scope_findings": t["out_of_scope_findings"],
        "evidence_path": os.path.abspath(os.path.join(WS, "evidence", t["ip"])),
    }


def main2():
    report = main()
    os.makedirs(os.path.join(WS, "reports"), exist_ok=True)
    with open(os.path.join(WS, "reports", "final_report.json"), "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    with open(os.path.join(WS, "reports", "final_report.md"), "w") as f:
        f.write(generar_md(report))
    for t in report["targets"]:
        with open(os.path.join(WS, "reports", f"{t['id']}_report.md"), "w") as f:
            f.write(generar_md_individual(t))
        with open(os.path.join(WS, "reports", f"{t['id']}_report.json"), "w") as f:
            json.dump(generar_json_individual(t, report["engagement_id"]), f, ensure_ascii=False, indent=2)
        print("OK reports/%s_report.md + .json" % t["id"])
    print("OK reports/final_report.json + final_report.md")


if __name__ == "__main__":
    main2()