#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qa_check.py — QA DETERMINISTA para ReconArgentumAI
===================================================
Ejecuta 8 checks mecánicos sobre los artefactos generados por el pipeline.
NO alucina, NO interpreta, NO redacta. Solo verifica con comandos del sistema.

Salida:
  [PASS] CK-0X <detalle>
  [FAIL] CK-0X <detalle>
Exit code: 0 (todos PASS) | 1 (al menos un FAIL)

Uso:
  python3 scripts/qa_check.py
"""

import json, os, re, sys
from glob import glob

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
passed, failed = [], []
COL_P = "\033[92m[PASS]\033[0m"
COL_F = "\033[91m[FAIL]\033[0m"

def c(name, ok, detail=""):
    if ok:
        passed.append(name)
        print(f"  {COL_P} {name}   {detail}")
    else:
        failed.append(name)
        print(f"  {COL_F} {name}   {detail}")

# =====================================================================
# CHECKS
# =====================================================================

def ck01_scope(scope):
    targets = scope.get("authorized_targets", [])
    eng_id = scope.get("engagement_id")
    c("CK-01", len(targets) > 0 and bool(eng_id),
      f"engagement={eng_id}, targets={len(targets)}")
    return targets

def ck02_outputs(scope):
    for tg in scope.get("authorized_targets", []):
        ip = tg.get("ip", "")
        mid = tg.get("id", "?")
        mpath = os.path.join(WS, "evidence", ip, "manifest.json")
        if not os.path.exists(mpath):
            c("CK-02", False, f"manifest de {ip} ({mid}) no existe")
            continue
        try:
            manifest = json.load(open(mpath, encoding="utf-8"))
            broken = []
            for tool in manifest.get("tools_executed", []):
                if tool.get("status") != "success":
                    continue
                for out in tool.get("output", []):
                    fpath = os.path.join(WS, "evidence", ip, out)
                    if not os.path.exists(fpath):
                        broken.append(f"{tool['tool']}/{out}")
            if broken:
                c("CK-02", False, f"{ip}: {len(broken)} outputs faltan: {broken[:5]}")
            else:
                c("CK-02", True, f"{ip} ({mid}): outputs OK")
        except Exception as e:
            c("CK-02", False, f"{ip}: {e}")

def ck03_json():
    all_files = []
    all_files += glob(os.path.join(WS, "evidence", "*", "*.json"))
    all_files += glob(os.path.join(WS, "cve_research", "*_cves.json"))
    all_files += glob(os.path.join(WS, "reports", "*.json"))
    bad = []
    for fp in all_files:
        try:
            json.load(open(fp, encoding="utf-8"))
        except Exception as e:
            bad.append((fp, str(e)))
    if bad:
        for fp, err in bad[:5]:
            c("CK-03", False, f"{os.path.relpath(fp, WS)}: {err}")
    else:
        c("CK-03", True, f"{len(all_files)} JSONs válidos")

def ck04_cves():
    cve_files = glob(os.path.join(WS, "cve_research", "*_cves.json"))
    if not cve_files:
        c("CK-04", True, "Sin archivos CVE (no aplica)")
        return
    bad = 0
    for cf in cve_files:
        data = json.load(open(cf, encoding="utf-8"))
        s = data.get("summary", {})
        all_cves = []
        for svc in data.get("services_analyzed", []):
            all_cves.extend(svc.get("cves", []))
        for wt in data.get("web_technologies", []):
            all_cves.extend(wt.get("cves", []))
        if len(all_cves) != s.get("total_cves", 0):
            c("CK-04", False, f"{os.path.basename(cf)}: {len(all_cves)} listados vs {s.get('total_cves')} summary")
            bad += 1; continue
        cve_has_issues = False
        for cv in all_cves:
            if not cv.get("id") or cv.get("cvss_score") is None or not cv.get("rank_reason"):
                c("CK-04", False, f"{os.path.basename(cf)}: CVE {cv.get('id','?')} sin id/cvss/rank")
                bad += 1
                cve_has_issues = True
                break
        if not cve_has_issues:
            c("CK-04", True, f"{os.path.basename(cf)}: {s.get('total_cves')} CVEs OK")

def ck05_planes(scope):
    plan_files = glob(os.path.join(WS, "plans", "*_exploitation_plan.md"))
    if not plan_files:
        c("CK-05", True, "Sin planes de explotación generados")
        return
    for pf in plan_files:
        try:
            content = open(pf, encoding="utf-8").read()
            ev_refs = re.findall(r'evidence/[^\s/)\]]+(?:/[^\s/)\]]+)?', content)
            if not ev_refs:
                c("CK-05", False, f"{os.path.basename(pf)}: sin refs a evidence/")
                continue
            missing = [r for r in ev_refs if not os.path.exists(os.path.join(WS, r))]
            if missing:
                c("CK-05", False, f"{os.path.basename(pf)}: {len(missing)} refs inexistentes")
            else:
                c("CK-05", True, f"{os.path.basename(pf)}: {len(ev_refs)} refs OK")
        except Exception as e:
            c("CK-05", False, f"{os.path.basename(pf)}: {e}")

def ck06_report(scope):
    frp = os.path.join(WS, "reports", "final_report.json")
    if not os.path.exists(frp):
        c("CK-06", False, "reports/final_report.json no existe")
        return
    try:
        report = json.load(open(frp, encoding="utf-8"))
        r_targets = report.get("targets", [])
        r_ids = set(t.get("id") for t in r_targets if t.get("id"))
        s_ids = set(t.get("id") for t in scope.get("authorized_targets", []) if t.get("id"))
        problems = []
        if report.get("summary", {}).get("targets_count") != len(r_targets):
            problems.append(f"summary.count={report['summary']['targets_count']} != {len(r_targets)} reales")
        missing = s_ids - r_ids
        extra = r_ids - s_ids
        if missing: problems.append(f"targets scope no en report: {missing}")
        if extra: problems.append(f"targets report no en scope: {extra}")
        if problems:
            c("CK-06", False, "; ".join(problems[:3]))
        else:
            c("CK-06", True, f"{len(r_targets)} targets, consistente con scope")
    except Exception as e:
        c("CK-06", False, f"error: {e}")

def ck07_secrets():
    report_files = glob(os.path.join(WS, "reports", "*.json")) + glob(os.path.join(WS, "reports", "*.md"))
    if not report_files:
        c("CK-07", True, "Sin reportes")
        return
    pat = re.compile(r'(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*([^\s,;"]{4,})', re.IGNORECASE)
    found = []
    for rf in report_files:
        try:
            for line in open(rf, encoding="utf-8"):
                for m in pat.finditer(line):
                    if "***" not in m.group(1):
                        found.append((rf, m.group(1)[:50]))
        except: pass
    if found:
        for rf, val in found[:5]:
            c("CK-07", False, f"{os.path.relpath(rf, WS)}: secreto: '{val}'")
    else:
        c("CK-07", True, f"{len(report_files)} archivos sin secretos")

def ck08_f4():
    docs = glob(os.path.join(WS, "*", "*", "*_resumen_vulnerabilidades.doc"))
    txts = glob(os.path.join(WS, "*", "*", "*_resumen_breve.txt"))
    if docs or txts:
        c("CK-08", True, f"{len(docs)} .doc, {len(txts)} .txt")
    else:
        c("CK-08", True, "Sin deliverables F4 (no aplica si no se corrió)")

# =====================================================================
# MAIN
# =====================================================================

def main():
    print()
    print("=" * 60)
    print("  QA CHECK — RECONARGENTUM AI  (determinista)")
    print("=" * 60)
    print()
    scope_path = os.path.join(WS, "config", "scope.json")
    try:
        scope = json.load(open(scope_path, encoding="utf-8"))
    except Exception as e:
        print(f"  {COL_F} FATAL: {scope_path}: {e}")
        sys.exit(1)
    targets = ck01_scope(scope)
    if targets:
        ck02_outputs(scope)
    else:
        c("CK-02", True, "Sin targets — saltado")
    ck03_json()
    ck04_cves()
    ck05_planes(scope)
    ck06_report(scope)
    ck07_secrets()
    ck08_f4()
    print()
    print("=" * 60)
    total = len(passed) + len(failed)
    print(f"  RESUMEN:  {len(passed)}/{total} PASS  |  {len(failed)}/{total} FAIL")
    print("=" * 60)
    print()
    if failed:
        print("  ❌  QA FALLIDO — Revisar [FAIL] antes de continuar.")
        print("      Críticos: CK-04, CK-06, CK-07 (bloquean pipeline).")
        sys.exit(1)
    else:
        print("  ✅  QA OK  —  Todos los checks deterministas pasaron.")
        sys.exit(0)

if __name__ == "__main__":
    main()