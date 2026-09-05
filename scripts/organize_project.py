#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
organize_project.py — Consolida la evidencia de TODOS los targets escaneados
en un directorio con el nombre del proyecto.

Estructura de salida (bajo <WORKSPACE>/<PROYECTO>/):

  <PROYECTO>/
    README.md
    <TARGET_IP>/
      data/                                    <- documentos consolidados (nombres ORIGINALES, en Markdown)
        <target_id>_exploitation_plan.md       <- copia de plans/
        <target_id>_report.md                  <- copia de reports/
      outputs/                                 <- evidencia cruda (nombres ORIGINALES)
        nmap_detailed.xml, httpx.json, nuclei.json,
        nikto_*, gobuster_*, sslyze_*, ...     <- copias de evidence/<ip>/

Ningun archivo existente se renombra: todas las copias preservan su nombre tal
como lo creo el escaneo. Solo se copia UNA evidencia por escaneo: si una tool
genera varios formatos del mismo scan (ej. nmap_detailed.xml/.txt/.json), se
copia el mas completo (.xml). Quedan fuera del consolidado: `nmap_ports.*`
(Step 1, solo descubre puertos), `manifest.json`, `open_ports.txt`
`web_endpoints.txt` (intermedios) y `<target_id>_report.json` (duplicado del
.md). Los logs de ejecucion `_step.log`/`_errors.log` SI se consolidan (van a
`outputs/` como evidencia de la corrida). El UNICO archivo nuevo es
README.md (por proyecto).

Uso:
  python3 scripts/organize_project.py [--project NOMBRE] [--target IP]...
                                      [--scope] [--dry-run] [--no-clobber]

- Sin args: procesa TODOS los targets con carpeta en evidence/ (los escaneados).
- --project: nombre del directorio destino (default: CLIENTE).
- --target IP: procesa solo ese target (repetible).
- --scope: filtra a los targets registrados en config/scope.json (authorized + all_ips).
- --dry-run: solo imprime la estructura de salida, no crea ni copia nada.
- --no-clobber: no sobrescribe archivos ya existentes en el destino.

El target_id se toma del manifest.json (el id real usado en plans/
cve_research/reports), con fallback a config/scope.json y luego a la IP pura.
"""
import argparse
import glob
import json
import os
import re
import shutil
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Formatos preferidos para la deduplicacion de evidencia: si un escaneo genera
# varios formatos del mismo scan, se copia UNO SOLO (el mas completo primero).
_EXT_PRIORIDAD = {".xml": 0, ".json": 1, ".txt": 2, ".gnmap": 3}

# Outputs de evidence/<ip>/ que NO se copian al CLIENTE: intermedios del
# pipeline, metadata de ejecucion y duplicados del reporte. (_step.log y
# _errors.log quedan FUERA de esta lista: SI se consolidan al CLIENTE.)
_EXCLUIR_EVIDENCIA = {
    "manifest.json",
    "open_ports.txt",
    "web_endpoints.txt",
}


def warn(msg):
    """Aviso por consola (no rompe el procesamiento)."""
    print(f"  ⚠️ {msg}")


def ofuscar(t):
    """Redacta credenciales/tokens/keys con *** (solo este consolidado; los
    datos crudos originales en evidence/ NO se modifican)."""
    if not isinstance(t, str):
        return t
    t = re.sub(r"(password\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(passwd\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(default password is\s+)(\w+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(token\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(api[_-]?key\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(secret\s*[=:]\s*)([^\s,;]+)", r"\1***", t, flags=re.I)
    t = re.sub(r"(Basic\s+)[A-Za-z0-9+/=]+", r"\1***", t, flags=re.I)
    t = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", t, flags=re.I)
    return t


def sanitize_celda(v):
    """Normaliza un valor para usarlo dentro de una celda de tabla markdown."""
    s = ofuscar(str(v)) if v is not None else "-"
    s = s.replace("|", "\\|").replace("\n", " ")
    return s if s.strip() else "-"


def load_json(path):
    """Carga un JSON (None si falta o falla, sin romper el flujo)."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception as e:
        warn(f"JSON invalido, se ignora: {os.path.relpath(path, WS)} ({e})")
        return None


def load_jsonl(path):
    """Carga JSONL: una linea = un objeto JSON (nuclei.json, httpx.json).
    Devuelve lista; lineas corruptas se ignoran."""
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        warn(f"No se pudo leer JSONL: {os.path.relpath(path, WS)} ({e})")
    return out


def load_scope():
    """Carga config/scope.json (dict vacio si no existe)."""
    sp = os.path.join(WS, "config", "scope.json")
    if not os.path.exists(sp):
        return {}
    data = load_json(sp)
    return data if isinstance(data, dict) else {}


def build_ip_to_id(scope):
    """Mapa IP -> target_id desde scope.json (authorized_targets + all_ips)."""
    mapping = {}
    for key in ("authorized_targets", "all_ips"):
        for t in scope.get(key, []) or []:
            if isinstance(t, dict) and t.get("ip") and t.get("id"):
                mapping[t["ip"]] = str(t["id"])
    return mapping


def get_target_id(ip, manifest, ip_to_id):
    """target_id real: manifest > scope.json > IP pura."""
    if isinstance(manifest, dict) and manifest.get("target_id"):
        return str(manifest["target_id"])
    if ip in ip_to_id:
        return ip_to_id[ip]
    return ip


def descubrir_targets(scope, only_targets, use_scope):
    """Lista de IPs a procesar (subcarpetas de evidence/)."""
    ev_root = os.path.join(WS, "evidence")
    if not os.path.isdir(ev_root):
        print(f"❌ No existe {os.path.relpath(ev_root, WS)}/ — corre primero el pipeline.")
        sys.exit(1)

    scope_ips = set()
    for key in ("authorized_targets", "all_ips"):
        for t in scope.get(key, []) or []:
            if isinstance(t, dict) and t.get("ip"):
                scope_ips.add(t["ip"])

    if only_targets:
        targets = []
        for ip in only_targets:
            if os.path.isdir(os.path.join(ev_root, ip)):
                targets.append(ip)
            else:
                warn(f"target {ip} no tiene carpeta en evidence/ — omitido")
    else:
        targets = sorted(
            d for d in os.listdir(ev_root)
            if os.path.isdir(os.path.join(ev_root, d)) and not d.startswith(".")
        )
        if use_scope:
            for t in targets:
                if t not in scope_ips:
                    warn(f"target {t} esta en evidence/ pero no en scope.json → omitido (--scope)")
            targets = [t for t in targets if t in scope_ips]
    return [t for t in targets if os.path.isdir(os.path.join(ev_root, t))], ev_root


def copiar(src, dst, dry_run, no_clobber):
    """Copia un archivo. Devuelve True si el archivo destino existe/quedo creado."""
    if not os.path.exists(src):
        return False
    if no_clobber and os.path.exists(dst):
        warn(f"[no-clobber] ya existe: {os.path.relpath(dst, WS)}")
        return True
    if dry_run:
        print(f"    copiar {os.path.relpath(src, WS)} -> {os.path.relpath(dst, WS)}")
        return True
    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except Exception as e:
        warn(f"error copiando {os.path.relpath(src, WS)} → {dst}: {e}")
        return False


def _es_evidencia_excluida(name):
    """True si un output de evidence/<ip>/ no debe copiarse al CLIENTE."""
    if name.startswith("."):
        return True  # .run.lock, .DS_Store, ...
    if name in _EXCLUIR_EVIDENCIA:
        return True  # manifest.json, open_ports.txt, web_endpoints.txt
    if name in ("_step.log", "_errors.log"):
        return False  # logs de ejecución SÍ se consolidan al CLIENTE
    if name.startswith("_"):
        return True  # demás archivos internos del pipeline (_.run.lock, ...)
    if re.fullmatch(r"nmap_ports\..+", name):
        return True  # Step 1 solo descubre puertos; el detalle real es Step 3
    if re.fullmatch(r".+_report\.json", name):
        return True  # duplicado del <target_id>_report.md copiado en data/
    return False


def copiar_evidencia_cruda(ev_dir, out_dir, dry_run, no_clobber):
    """Copia outputs de evidence/<ip>/ a outputs/ (sin renombrar) con UNA unica
    evidencia por escaneo: si un scan genera varios formatos (ej. nmap_detailed
    .xml/.txt/.json) se copia solo el de mayor prioridad (.xml > json > txt)."""
    grupos = {}  # stem (nombre sin extension) -> [(ext, ruta), ...]
    for name in sorted(os.listdir(ev_dir)):
        if _es_evidencia_excluida(name):
            continue
        src = os.path.join(ev_dir, name)
        if os.path.isdir(src):
            continue
        stem, ext = os.path.splitext(name)
        grupos.setdefault(stem, []).append((ext.lower(), src))
    for stem in sorted(grupos):
        _ext, src = min(grupos[stem], key=lambda e: _EXT_PRIORIDAD.get(e[0], 99))
        copiar(src, os.path.join(out_dir, os.path.basename(src)), dry_run, no_clobber)


def buscar_artefacto(carpeta, target_id, ip, sufijo):
    """Busca <target_id>+sufijo en 'carpeta'; fallback <ip>+sufijo y unico
    archivo que termine en el sufijo. Devuelve ruta o None."""
    candidatos = []
    if target_id:
        candidatos.append(os.path.join(carpeta, f"{target_id}{sufijo}"))
    candidatos.append(os.path.join(carpeta, f"{ip}{sufijo}"))
    for c in candidatos:
        if os.path.isfile(c):
            return c
    if os.path.isdir(carpeta):
        try:
            match = [os.path.join(carpeta, f) for f in os.listdir(carpeta)
                     if f.endswith(sufijo) and os.path.isfile(os.path.join(carpeta, f))]
            if len(match) == 1:
                return match[0]
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Parsers de evidencia (formato real de cada tool del pipeline)
# ---------------------------------------------------------------------------

def read_nmap_services(ev_dir):
    """Puertos/servicios desde nmap_detailed.json (preferido) o nmap_ports.json.
    Se quedan los puertos 'open'; si none hay, se listan todos."""
    for nombre in ("nmap_detailed.json", "nmap_ports.json"):
        data = load_json(os.path.join(ev_dir, nombre))
        if not isinstance(data, dict) or "scan" not in data:
            continue
        rows = []
        for _host, hinfo in (data.get("scan") or {}).items():
            if not isinstance(hinfo, dict):
                continue
            for proto_key in ("tcp", "udp"):
                ports = hinfo.get(proto_key) or {}
                if not isinstance(ports, dict):
                    continue
                for port, pinfo in ports.items():
                    if not isinstance(pinfo, dict):
                        continue
                    state = ""
                    if isinstance(pinfo.get("state"), dict):
                        state = pinfo["state"].get("state", "") or ""
                    if not state:
                        state = pinfo.get("state", "") or ""
                    svc = pinfo.get("service") or {}
                    if not isinstance(svc, dict):
                        svc = {}
                    rows.append({
                        "port": port, "proto": proto_key, "state": state,
                        "service": svc.get("name") or "",
                        "product": svc.get("product") or "",
                        "version": svc.get("version") or "",
                        "extra": svc.get("extrainfo") or "",
                    })
        if rows:
            open_rows = [r for r in rows if r["state"] == "open"]
            return open_rows if open_rows else rows
    return []


def read_nuclei(ev_dir):
    """Findings Nuclei desde nuclei.json (JSONL), los mas criticos primero."""
    rows = []
    for item in load_jsonl(os.path.join(ev_dir, "nuclei.json")):
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        classif = info.get("classification") or {}
        if not isinstance(classif, dict):
            classif = {}
        cves = classif.get("cve-id") or []
        if isinstance(cves, list):
            cves_str = ", ".join(str(c) for c in cves)
        else:
            cves_str = str(cves)
        sev = str(info.get("severity") or "").lower()
        rows.append({
            "severity": sev or "-",
            "template": item.get("template-id") or item.get("template_id") or "",
            "name": info.get("name") or "",
            "cves": cves_str,
            "matched": item.get("matched-at") or item.get("matched_at") or "",
        })
    rows.sort(key=lambda r: _SEV_ORDER.get(r["severity"], 9))
    return rows


def read_nikto(ev_dir):
    """Hallazgos Nikto agrupados por puerto: nikto_<port>.json (lista de dicts)."""
    por_puerto = {}
    for path in sorted(glob.glob(os.path.join(ev_dir, "nikto_*.json"))):
        base = os.path.basename(path)
        port = base.replace("nikto_", "").replace(".json", "")
        data = load_json(path)
        if not isinstance(data, list):
            continue
        findings = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for v in entry.get("vulnerabilities", []) or []:
                if not isinstance(v, dict):
                    continue
                findings.append({
                    "id": v.get("id") or "",
                    "method": v.get("method") or "",
                    "msg": v.get("msg") or "",
                    "url": v.get("url") or "",
                })
        if findings:
            por_puerto[port] = findings
    return por_puerto


def count_cves(cve_data):
    """Cuenta CVEs consignados en un cve_research/<id>_cves.json."""
    if not isinstance(cve_data, dict):
        return 0
    total = 0
    for key in ("services_analyzed", "web_technologies"):
        for t in cve_data.get(key, []) or []:
            if isinstance(t, dict):
                total += len(t.get("cves", []) or [])
    return total


def procesar_target(ip, project_name, project_dir, scope, dry_run, no_clobber):
    """Consolida UN target: copia una evidencia por escaneo en outputs/,
    los documentos Markdown en data/ y devuelve sus estadisticas para
    el README."""
    ev_dir = os.path.join(WS, "evidence", ip)
    manifest = load_json(os.path.join(ev_dir, "manifest.json"))
    ip_to_id = build_ip_to_id(scope)
    target_id = get_target_id(ip, manifest, ip_to_id)

    data_dir_out = os.path.join(project_dir, ip, "data")
    out_dir = os.path.join(project_dir, ip, "outputs")
    print(f"\n► Target {ip}  (target_id: {target_id})")

    if not dry_run:
        os.makedirs(data_dir_out, exist_ok=True)
        os.makedirs(out_dir, exist_ok=True)

    # 1) Evidencia cruda completa -> outputs/ (sin renombrar)
    copiar_evidencia_cruda(ev_dir, out_dir, dry_run, no_clobber)

    # 2) Buscar y copiar/generar los artifacts por target (data/ y outputs/)
    cve_src = buscar_artefacto(os.path.join(WS, "cve_research"), target_id, ip, "_cves.json")
    plan_src = buscar_artefacto(os.path.join(WS, "plans"), target_id, ip, "_exploitation_plan.md")
    report_md_src = buscar_artefacto(os.path.join(WS, "reports"), target_id, ip, "_report.md")

    # data/: plan.md + report.md se copian tal cual. El <target_id>_report.json
    # NO se copia (duplicado del .md) y el JSON de cve_research NO se renderiza
    # a <target_id>_cves.md (solo se usa para contar CVEs en el README).
    for nombre, src, carpeta in (
        ("plan", plan_src, data_dir_out),
        ("report.md", report_md_src, data_dir_out),
    ):
        if src:
            copiar(src, os.path.join(carpeta, os.path.basename(src)), dry_run, no_clobber)
        else:
            warn(f"no se encontró {nombre} para {ip}")

    # 3) Estadisticas para el README
    try:
        n_serv = len(read_nmap_services(ev_dir))
        n_nuclei = len(read_nuclei(ev_dir))
        n_nikto = sum(len(v) for v in read_nikto(ev_dir).values())
        n_cves = count_cves(load_json(cve_src)) if cve_src else 0
    except Exception as e:
        warn(f"estadisticas de {ip} incompletas: {e}")
        n_serv = n_nuclei = n_nikto = n_cves = 0
    return {
        "ip": ip,
        "target_id": target_id,
        "servicios": n_serv,
        "vulns": n_nuclei + n_nikto,
        "cves": n_cves,
        "plan": bool(plan_src),
        "reporte": bool(report_md_src),
    }


def build_readme(project_name, infos):
    """Tabla indice del proyecto (raiz del directorio consolidado)."""
    L = []
    L.append(f"# Proyecto: {project_name}\n")
    L.append("**Generado:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " por `scripts/organize_project.py`.")
    L.append("")
    L.append(f"## Targets consolidados ({len(infos)})\n")
    L.append("| IP | Target ID | Servicios | Hallazgos crudos | CVEs | Plan | Reporte | Data | Outputs |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for t in infos:
        L.append(
            f"| `{t['ip']}` | {sanitize_celda(t['target_id'])} | {t['servicios']} | {t['vulns']} | {t['cves']} "
            f"| {'✅' if t['plan'] else '❌'} | {'✅' if t['reporte'] else '❌'} "
            f"| [data]({t['ip']}/data/) | [outputs]({t['ip']}/outputs/) |"
        )
    L.append("| **TOTAL** | | %s | %s | %s | | | | |" % (
        sum(t["servicios"] for t in infos),
        sum(t["vulns"] for t in infos),
        sum(t["cves"] for t in infos),
    ))
    L.append("")
    L.append(
        "> ℹ️ **Hallazgos crudos** = filas de evidencia (Nuclei + Nikto) contadas **sin**\n"
        "> filtrar ni deduplicar por `scripts/organize_project.py` — es un volumen crudo de\n"
        "> señales de las tools, NO el conteo final de vulnerabilidades. El detalle\n"
        "> consolidado, filtrado y deduplicado por target está en\n"
        "> `<target_id>_resumen_breve.txt` y `<target_id>_resumen_vulnerabilidades.doc`\n"
        "> (generados por el **Agente 6** — `scripts/make_vuln_report.py`)."
    )
    L.append("")
    L.append("### Estructura por target")
    L.append("- `data/` → `<target_id>_exploitation_plan.md` + `<target_id>_report.md` — los 2 en Markdown.")
    L.append("- `outputs/` → UNA evidencia por escaneo (nmap solo el `.xml`, sin duplicados).")
    L.append("")
    L.append("> ⚠️ Contiene datos sensibles del engagement — no publicar.")
    return "\n".join(L) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Consolida la evidencia de los targets escaneados en "
                    "<PROYECTO>/<TARGET>/{data,outputs}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--project", help="Nombre del directorio destino (default: engagement_id).")
    parser.add_argument("--target", action="append", metavar="IP",
                        help="Procesar solo ese target IP (repetible).")
    parser.add_argument("--scope", action="store_true",
                        help="Filtrar a los targets registrados en config/scope.json.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Solo imprimir la estructura; no crea ni copia nada.")
    parser.add_argument("--no-clobber", action="store_true",
                        help="No sobrescribir archivos existentes en el destino.")
    args = parser.parse_args()

    scope = load_scope()
    project_name = args.project or "CLIENTE"
    project_dir = os.path.join(WS, project_name)

    targets, _ev_root = descubrir_targets(scope, args.target, args.scope)
    if not targets:
        print("❌ No hay targets para procesar.")
        sys.exit(1)

    print(f"Proyecto destino: {os.path.relpath(project_dir, WS)}/ — {len(targets)} target(s)"
          + ("  (dry-run: no se crea nada)" if args.dry_run else ""))

    infos = []
    for ip in targets:
        infos.append(procesar_target(ip, project_name, project_dir, scope,
                                     args.dry_run, args.no_clobber))

    if args.dry_run:
        print("\n(dry-run) README.md se generaría en "
              + os.path.relpath(os.path.join(project_dir, "README.md"), WS))
    else:
        readme_path = os.path.join(project_dir, "README.md")
        try:
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(build_readme(project_name, infos))
            print(f"✅ README.md → {os.path.relpath(readme_path, WS)}")
        except Exception as e:
            warn(f"error escribiendo README.md: {e}")

    print("\n✅ Listo. Estructura en:", os.path.relpath(project_dir, WS) + "/")
    if args.dry_run:
        print("(modo --dry-run: el directorio NO se creó)")


if __name__ == "__main__":
    main()