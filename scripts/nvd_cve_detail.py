#!/usr/bin/env python3
"""Consulta NVD por CVE ID y printea métrica + descripción + rango de versiones MSSQL/OpenSSH."""
import json, sys, urllib.request, urllib.parse

def fetch_cve(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
    for i in range(3):
        try:
            with urllib.request.urlopen(url, timeout=25) as r:
                return json.load(r)
        except Exception as e:
            if i == 2:
                return {"error": str(e)}
    return {"error": "retries exhausted"}

if __name__ == "__main__":
    for cve_id in sys.argv[1:]:
        d = fetch_cve(cve_id)
        if "error" in d:
            print(cve_id, "ERR", d["error"])
            continue
        c = d["vulnerabilities"][0]["cve"]
        bs = c["metrics"].get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
        desc = c["descriptions"][0]["value"][:180].replace("\n", " ")
        # extraer versiones MSSQL relevantes de las configuraciones
        vers = set()
        for cfg in c.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    cr = m.get("criteria", "")
                    if "sql_server" in cr.lower() or "openssh" in cr.lower():
                        vers.add(cr)
        v = "; ".join(sorted(vers)[:4])
        print(f"\n{cve_id} | cvss={bs}")
        print("  desc:", desc)
        if v:
            print("  cpe:", v)