#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qa_check.py — QA DETERMINISTA para ReconArgentumAI
===================================================
Ejecuta 9 checks mecánicos sobre los artefactos generados por el pipeline.
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
    """CK-01: scope válido (targets + engagement_id) y target_id ÚNICOS.

    Un id repetido entre targets hace que los manifiestos y los informes por target
    se pisen entre sí (bug real del run de octubre 2026: 4 IPs con id
    `S-10.10.10.80` y 5 con `S-10.10.10.195`, lo que sobreescribía
    `cve_research/<id>_cves.json`).
    """
    targets = scope.get("authorized_targets", [])
    eng_id = scope.get("engagement_id")
    base_ok = len(targets) > 0 and bool(eng_id)
    ids = [str(t.get("id") or "") for t in targets]
    sin_id = [t.get("ip") for t in targets if not str(t.get("id") or "").strip()]
    dups = sorted({i for i in ids if i and ids.count(i) > 1})
    problemas = []
    if not base_ok:
        problemas.append("engagement_id o authorized_targets faltantes")
    if sin_id:
        problemas.append("targets sin id: " + ", ".join(str(x) for x in sin_id[:4]))
    if dups:
        problemas.append("target_id duplicados: " + ", ".join(dups[:4]))
    if problemas:
        c("CK-01", False, "; ".join(problemas))
    else:
        c("CK-01", True, f"engagement={eng_id}, targets={len(targets)}, ids únicos")
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

def _json_file_status(fp):
    """(ok, kind, err) — acepta JSON, JSONL y archivos vacíos.

    - JSONL: httpx/nuclei de ProjectDiscovery escriben un JSON por línea
      (`{"timestamp":...}\\n{...}`) → `json.load` falla con "Extra data" y NO es
      corrupción.
    - VACÍO: un `nuclei.json` de 0 bytes significa "el step corrió y no encontró
      nada" (o quedó failed, según el manifest). No es evidencia corrupta.
    El check caza únicamente JSON ILEGIBLE.
    """
    try:
        with open(fp, encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except Exception as e:
        return False, "unreadable", str(e)
    if not txt.strip():
        return True, "empty", ""
    try:
        json.loads(txt)
        return True, "json", ""
    except Exception as e_full:
        for line in (ln for ln in txt.splitlines() if ln.strip()):
            try:
                json.loads(line)
            except Exception:
                return False, "invalid", str(e_full)
        return True, "jsonl", ""


def ck03_json():
    all_files = []
    all_files += glob(os.path.join(WS, "evidence", "*", "*.json"))
    all_files += glob(os.path.join(WS, "cve_research", "*_cves.json"))
    all_files += glob(os.path.join(WS, "cve_research", "*_php2shell.json"))
    all_files += glob(os.path.join(WS, "reports", "*.json"))
    kinds, bad = {"json": 0, "jsonl": 0, "empty": 0}, []
    for fp in all_files:
        ok, kind, err = _json_file_status(fp)
        if ok:
            kinds[kind] = kinds.get(kind, 0) + 1
        else:
            bad.append((fp, err))
    if bad:
        for fp, err in bad[:5]:
            c("CK-03", False, f"{os.path.relpath(fp, WS)}: {err}")
    else:
        c("CK-03", True, f"{len(all_files)} archivos OK "
                         f"({kinds['json']} JSON, {kinds['jsonl']} JSONL, "
                         f"{kinds['empty']} vacíos)")

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
            content = open(pf, encoding="utf-8", errors="replace").read()
            # La ref suele ir entre backticks (`evidence/<ip>/x.json`) → se descarta la
            # puntuación de cierre para no generar falsos positivos (bug detectado 2026-10-22
            # al añadir refs inline en los planes).
            ev_refs = [r.rstrip("`.,;:)>'\"") for r in
                       re.findall(r'evidence/[^\s/)\]]+(?:/[^\s/)\]]+)?', content)]
            ev_refs = [r for r in ev_refs if r]
            if not ev_refs:
                # Spec (openspec/specs/qa-validation/spec.md, CK-05): "Plan sin refs
                # a evidence/ → PASS" (no bloqueante). Se deja constancia en el
                # detalle para que la falta de trazabilidad quede visible.
                c("CK-05", True,
                  f"{os.path.basename(pf)}: sin refs a evidence/ (no bloqueante)")
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
        c("CK-06", True, "Sin reporte final (no aplica si no se generó)")
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
        c("CK-07", True, "Sin reportes (no aplica)")
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

EXPECTED_STEPS = [(1, "nmap_ports"), (2, "httpx"), (3, "nmap_detailed"), (4, "nuclei"), (5, "nikto"), (6, "whatweb"), (7, "gobuster"), (8, "sslyze"), (9, "iis_shortname"), (10, "smbclient_enum"), (11, "ldap_enum"), (12, "enum4linux")]
VALID_STATUS = {"success", "failed", "skipped", "skipped_no_ports", "skipped_no_web", "skipped_no_domain", "skipped_no_tftp", "skipped_no_tls", "skipped_no_iis", "skipped_no_smb", "skipped_no_ldap", "skipped_unsupported_os"}


def ck09_dag_contract(scope):
    """CK-09: contrato del DAG (12 steps) - steps, herramientas y estados esperados."""
    problemas, avisos, vistos = [], [], 0
    for tg in scope.get("authorized_targets", []):
        ip = tg.get("ip", "")
        mpath = os.path.join(WS, "evidence", ip, "manifest.json")
        if not os.path.exists(mpath):
            continue
        vistos += 1
        try:
            man = json.load(open(mpath, encoding="utf-8"))
        except Exception as e:
            problemas.append("%s: manifest ilegible (%s)" % (ip, e))
            continue
        tools = man.get("tools_executed", [])
        if len(tools) != len(EXPECTED_STEPS):
            problemas.append("%s: %d steps (se esperan %d)" % (ip, len(tools), len(EXPECTED_STEPS)))
        por_step = {}
        for t in tools:
            try:
                por_step[int(t.get("step"))] = t
            except Exception:
                problemas.append("%s: step invalido (%s)" % (ip, t.get("step")))
        for st, tool in EXPECTED_STEPS:
            t = por_step.get(st)
            if not t:
                problemas.append("%s: falta el step %d (%s)" % (ip, st, tool))
                continue
            if t.get("tool") != tool:
                problemas.append("%s: step %d = %s (se esperaba %s)" % (ip, st, t.get("tool"), tool))
            if t.get("status") not in VALID_STATUS:
                problemas.append("%s: step %d status invalido (%s)" % (ip, st, t.get("status")))
            if st in (11, 12) and t.get("status") == "success" and not t.get("output"):
                avisos.append("%s: step %d success con output vacio (evidencia condicional descartada)" % (ip, st))
    if problemas:
        c("CK-09", False, "; ".join(problemas[:4]))
    else:
        det = ("%d manifest(s) con 12 steps OK" % vistos) if vistos else "Sin manifests para validar"
        if avisos:
            det += " | aviso: " + avisos[0]
        c("CK-09", True, det)


def ck10_php2shell():
    """CK-10: PHP2Shell (CVE-2026-109618/109619) — advisory crítico no reportado.

    Para cada target auditado por `php2shell_audit.py` con estado `affected` o
    `eol_sin_parche`, exige que los CVEs del advisory estén presentes en
    `cve_research/<target_id>_cves.json` (el artefacto que consume la Fase 5).
    Desactivable con QA_PHP2SHELL_BLOCKING=0 (queda como aviso).
    """
    audits = glob(os.path.join(WS, "cve_research", "*_php2shell.json"))
    if not audits:
        c("CK-10", True, "Sin auditoría PHP2Shell (no aplica)")
        return
    blocking = os.environ.get("QA_PHP2SHELL_BLOCKING", "1") != "0"
    problemas, avisos, ok = [], [], 0
    for af in audits:
        try:
            data = json.load(open(af, encoding="utf-8"))
        except Exception as e:
            problemas.append("%s: ilegible (%s)" % (os.path.basename(af), e))
            continue
        php = data.get("php") or {}
        status = php.get("status")
        tid = data.get("target_id") or data.get("target")
        advisory_cves = [x.upper() for x in (data.get("advisory_cves") or [])]
        if status in ("patched", "not_affected_branch"):
            ok += 1
            continue
        if status in ("unknown_version", "no_php_evidence", None):
            if status == "unknown_version":
                avisos.append("%s: PHP sin versión (requiere fingerprint activo)" % tid)
            ok += 1
            continue
        if status not in ("affected", "eol_sin_parche"):
            avisos.append("%s: estado no contemplado (%s)" % (tid, status))
            ok += 1
            continue
        reported = set()
        # El *_cves.json del Agente 4 se nombra con el id con que se lo invocó (en este
        # engagement: la IP). El auditor puede traer el id canónico (`S-<ip>`), así que
        # se prueban las DOS convenciones antes de declarar el CVE como no reportado.
        cf = os.path.join(WS, "cve_research", "%s_cves.json" % tid)
        if not os.path.exists(cf):
            ip_name = data.get("target") or tid
            cf = os.path.join(WS, "cve_research", "%s_cves.json" % ip_name)
        if os.path.exists(cf):
            try:
                cd = json.load(open(cf, encoding="utf-8"))
                for group in (cd.get("services_analyzed", []),
                              cd.get("web_technologies", [])):
                    for item in group:
                        for cv in item.get("cves", []):
                            if cv.get("id"):
                                reported.add(str(cv["id"]).upper())
            except Exception as e:
                problemas.append("%s: %s ilegible (%s)" % (tid, os.path.basename(cf), e))
                continue
        faltan = [x for x in advisory_cves if x not in reported]
        if faltan:
            msg = ("%s: PHP %s %s sin CVE en cve_research (faltan %s)"
                   % (tid, php.get("version") or "?", status, ", ".join(faltan)))
            (problemas if blocking else avisos).append(msg)
        else:
            ok += 1
    if problemas:
        c("CK-10", False, "; ".join(problemas[:3]))
    elif avisos:
        c("CK-10", True, "%d auditorías OK | aviso: %s" % (ok, avisos[0]))
    else:
        c("CK-10", True, "%d auditoría(s) PHP2Shell consistentes" % ok)


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
    flt = os.environ.get("SCOPE_FILTER_IP", "").strip()
    if flt:
        scope = dict(scope)
        scope["authorized_targets"] = [t for t in scope.get("authorized_targets", []) if t.get("ip") == flt]
        print("  (filtro) SCOPE_FILTER_IP=%s -> solo se evaluan los checks POR TARGET de esa IP" % flt)
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
    ck09_dag_contract(scope)
    ck10_php2shell()
    print()
    print("=" * 60)
    total = len(passed) + len(failed)
    print(f"  RESUMEN:  {len(passed)}/{total} PASS  |  {len(failed)}/{total} FAIL")
    print("=" * 60)
    print()
    if failed:
        print("  ❌  QA FALLIDO — Revisar [FAIL] antes de continuar.")
        print("      Críticos: CK-01, CK-04, CK-05, CK-07, CK-10 (bloquean pipeline).")
        sys.exit(1)
    else:
        print("  ✅  QA OK  —  Todos los checks deterministas pasaron.")
        sys.exit(0)

if __name__ == "__main__":
    main()