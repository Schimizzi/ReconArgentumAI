#!/usr/bin/env python3
"""Regresión Agente 4: evidencia de campo (prioridad), implied_by y guardas del advisory.

Promovido desde /tmp en el Lote 4 de chore/cleanup-audit (2026-10-22).

Depende de evidencia real (gitignored). Si no está presente (clon limpio), hace SKIP
con exit 0 para no romper CI local.

Uso:
    python3 tests/test_agente4_field_evidence.py
"""
import importlib.util
import os
import sys
import tempfile

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(WS)

# Evidencia requerida por los casos 1 y 6 (gitignored). Sin ella → SKIP.
_REQUIRED = [
    os.path.join(WS, "evidence", "10.10.12.127"),
    os.path.join(WS, "evidence", "10.10.10.203"),
    os.path.join(WS, "config", "advisories"),
    os.path.join(WS, "scripts", "cve_research_vulnx.py"),
]
if not all(os.path.exists(p) for p in _REQUIRED):
    print("SKIP: falta evidencia local (%s) — test no aplicable en este clon." %
          ", ".join(p for p in _REQUIRED if not os.path.exists(p)))
    sys.exit(0)

spec = importlib.util.spec_from_file_location("cr", "scripts/cve_research_vulnx.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print("  PASS", name)
    else:
        fail += 1
        print("  FAIL", name, extra)


# 1) La versión de campo prevalece sobre la del escaneo (Nikto 8.2.31 vs campo 8.2.33)
ev = m._load_evidence_web_versions("evidence/10.10.12.127", ["CLIENTE/10.10.12.127/outputs"])
php = [e for e in ev if e["technology"].lower() == "php"]
check("campo prevalece (8.2.33)", bool(php) and php[0]["version"] == "8.2.33", php)
check("superseded = ['8.2.31']", bool(php) and php[0].get("superseded") == ["8.2.31"], php)
check("source php2shell_*", bool(php) and php[0]["source"].startswith("php2shell_"), php)

# 2) Advisory: implied_by (Drupal/DokuWiki ⇒ PHP) y no-falso-positivo con IIS
advs = m._load_advisories("config/advisories")
check("advisory activo con implied_by", bool(advs) and bool(advs[0].get("implied_by")), advs[:1])
check("_advisory_implied(Drupal)", m._advisory_implied(advs[0], "Drupal"))
check("_advisory_implied(DokuWiki)", m._advisory_implied(advs[0], "DokuWiki"))
check("_advisory_implied(IIS) = False", not m._advisory_implied(advs[0], "Microsoft-IIS"))
check("_advisory_matches(PHP, 8.2.33)", m._advisory_matches(advs[0], "PHP", "8.2.33"))

# 3) Drupal sin versión de PHP → needs_fingerprint, unknown_version, sin CVEs
web = [{"technology": "Drupal", "version": ""}]
matches = m._apply_advisories(advs, [], web, set())
check("Drupal needs_fingerprint", web[0].get("needs_fingerprint") is True, web[0])
check("Drupal watchlist unknown_version",
      web[0].get("watchlist", {}).get("status") == "unknown_version", web[0])
check("Drupal sin CVEs inyectados", not web[0].get("cves"), web[0])
check("matches registra el hit", any(x.get("status") == "unknown_version" for x in matches), matches)

# 4) Guardas de versión: 8.2.33 affected / 8.2.35 patched
web2 = [{"technology": "PHP", "version": "8.2.33"}]
m._apply_advisories(advs, [], web2, set())
ids = {c["id"] for c in web2[0].get("cves", [])}
check("8.2.33 affected + 2 CVEs",
      web2[0]["watchlist"]["status"] == "affected"
      and ids == {"CVE-2026-109618", "CVE-2026-109619"}, web2[0])
web3 = [{"technology": "PHP", "version": "8.2.35"}]
m._apply_advisories(advs, [], web3, set())
check("8.2.35 patched sin CVEs",
      web3[0]["watchlist"]["status"] == "patched" and not web3[0].get("cves"), web3[0])

# 5) Línea canónica del host-check de Windows (PHP-Version:)
tmp = tempfile.mkdtemp()
with open(os.path.join(tmp, "php2shell_hostcheck.txt"), "w") as f:
    f.write("PHP2Shell hostcheck\nPHP-Version: 7.4.33\nPHP-SAPI: php-fpm\n")
ev4 = m._load_evidence_web_versions(tmp, [])
check("lee 'PHP-Version:' del host-check",
      any(e["technology"].lower() == "php" and e["version"] == "7.4.33" for e in ev4), ev4)

# 6) No inventa PHP donde no hay evidencia (Drupal/IIS .203)
ev5 = m._load_evidence_web_versions("evidence/10.10.10.203", ["CLIENTE/10.10.10.203/outputs"])
check("PHP no inventado en .203",
      not [e for e in ev5 if e["technology"].lower() == "php"], ev5)

print("\n  RESULT: %d PASS | %d FAIL" % (ok, fail))
sys.exit(1 if fail else 0)
