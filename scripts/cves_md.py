#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Helpers para convertir cve_research/*.json a Markdown (cves.md)."""


def _cve_row(c):
    # Fila de tabla para un CVE (aplicando ofuscacion y escape).
    return (
        "| " + str(c.get('id') or '-') + " | " + str(c.get('cvss_score') or '-')
        + " | " + str(c.get('severity') or '-') + " | "
        + ("SI" if c.get('exploit_available') else "NO") + " | "
        + ("SI" if c.get('patched_version') else "NO") + " | "
        + str(c.get('rank_reason') or '-') + " |"
    )


def _cve_detalle(c):
    # Bloque Markdown con el detalle de un CVE.
    lines = []
    if c.get("description"):
        lines.append("**Descripcion:** " + str(c["description"]))
    if c.get("affected_versions"):
        lines.append("**Versiones afectadas:** " + str(c["affected_versions"]))
    if c.get("patched_version"):
        lines.append("**Version parcheada:** " + str(c["patched_version"]))
    poc = c.get("github_poc") or []
    if poc:
        items = []
        for p in poc:
            items.append("[" + str(p) + "](" + str(p) + ")")
        lines.append("**PoCs:** " + ", ".join(items))
    if c.get("exploit_db_id"):
        lines.append("**Exploit-DB:** " + str(c["exploit_db_id"]))
    refs = []
    if c.get("nvd_url"):
        refs.append("[NVD](" + str(c["nvd_url"]) + ")")
    if c.get("vendor_advisory"):
        refs.append("[Advisory](" + str(c["vendor_advisory"]) + ")")
    if refs:
        lines.append("**Referencias:** " + " | ".join(refs))
    return "\n".join(lines)


def _render_cves(cve_data, target_id):
    # Genera el texto Markdown de un cve_research JSON.
    if not isinstance(cve_data, dict):
        return None

    L = []
    L.append("# CVE Research - " + str(cve_data.get("target", target_id)) + "\n")
    if cve_data.get("research_timestamp"):
        L.append("- **Research timestamp:** " + str(cve_data["research_timestamp"]))
    summary = cve_data.get("summary")
    total = cve_data.get("total_cves")
    if total is None and isinstance(summary, dict):
        total = summary.get("total_cves")
    L.append("- **Total CVEs:** " + str(total if total is not None else "-"))

    if isinstance(summary, dict):
        L.append("  - Criticas: " + str(summary.get("critical"))
                 + " | Altas: " + str(summary.get("high"))
                 + " | Medias: " + str(summary.get("medium"))
                 + " | Bajas: " + str(summary.get("low")))
        L.append("  - Con exploit publico: " + str(summary.get("with_public_exploit"))
                 + " | Con parche disponible: " + str(summary.get("patched_available")))
    L.append("")

    # Servicios analizados
    if cve_data.get("services_analyzed"):
        L.append("## Servicios analizados\n")
        for svc in cve_data["services_analyzed"]:
            if not isinstance(svc, dict):
                continue
            titulo = str(svc.get("service") or "?")
            port = svc.get("port") or ""
            version = svc.get("version") or ""
            if port:
                titulo += " (puerto " + str(port)
                if version:
                    titulo += ", v" + str(version)
                titulo += ")"
            L.append("### " + titulo + "\n")
            cves = svc.get("cves") or []
            if not cves:
                L.append("_Sin CVEs._\n")
                continue
            L.append("| CVE | CVSS | Severidad | Exploit | Parche | Rank |")
            L.append("|---|---|---|---|---|---|")
            for c in cves:
                if isinstance(c, dict):
                    L.append(_cve_row(c))
            L.append("")
            for c in cves:
                if isinstance(c, dict):
                    L.append("**" + str(c.get("id")) + "**")
                    det = _cve_detalle(c)
                    if det:
                        L.append(det)
                        L.append("")

    # Tecnologias web
    if cve_data.get("web_technologies"):
        L.append("\n## Tecnologias web\n")
        for sw in cve_data["web_technologies"]:
            if not isinstance(sw, dict):
                continue
            titulo = str(sw.get("technology") or "?")
            version = sw.get("version") or ""
            if version:
                titulo += " (v" + str(version) + ")"
            L.append("### " + titulo + "\n")
            cves = sw.get("cves") or []
            if not cves:
                L.append("_Sin CVEs._\n")
                continue
            L.append("| CVE | CVSS | Severidad | Exploit | Parche | Rank |")
            L.append("|---|---|---|---|---|---|")
            for c in cves:
                if isinstance(c, dict):
                    L.append(_cve_row(c))
            L.append("")
            for c in cves:
                if isinstance(c, dict):
                    L.append("**" + str(c.get("id")) + "**")
                    det = _cve_detalle(c)
                    if det:
                        L.append(det)
                        L.append("")

    # Omisiones de fuentes
    if cve_data.get("source_omissions"):
        L.append("\n## Omisiones de fuentes\n")
        for om in cve_data["source_omissions"]:
            if not isinstance(om, dict):
                continue
            servi = om.get("service") or om.get("technology") or "?"
            razo = om.get("reason") or ""
            fuen = om.get("source") or ""
            L.append("- **" + str(servi) + "** (" + str(fuen) + "): " + str(razo))
        L.append("")

    # Nota de investigacion
    if cve_data.get("research_note"):
        L.append("## Nota de investigacion\n")
        L.append(str(cve_data["research_note"]))
        L.append("")

    L.append("\n---\n")
    L.append("*Generado por scripts/organize_project.py a partir de cve_research/"
            + str(target_id) + "_cves.json (el JSON original no se modifica).*")
    return "\n".join(L) + "\n"


def build_cves_md(target_id, cve_data):
    # Devuelve el Markdown para <target_id>_cves.md o None.
    return _render_cves(cve_data, target_id)