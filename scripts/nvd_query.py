#!/usr/bin/env python3
import json, sys, urllib.request, urllib.parse

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?"

def fetch(params, retries=3):
    url = URL + urllib.parse.urlencode(params)
    for i in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=25) as r:
                return json.load(r)
        except Exception as e:
            if i == retries - 1:
                return {"error": str(e)}
    return {"error": "retries exhausted"}

if __name__ == "__main__":
    q = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    d = fetch({"keywordSearch": q, "resultsPerPage": n})
    if "error" in d:
        print("ERR:", d["error"])
    else:
        print("total:", d.get("totalResults"), "returned:", len(d.get("vulnerabilities", [])))
        for c in d.get("vulnerabilities", [])[:n]:
            cve = c["cve"]
            bs = cve["metrics"].get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
            desc = cve["descriptions"][0]["value"][:140].replace("\n", " ")
            print(f"{cve['id']} | {bs} | {desc}")