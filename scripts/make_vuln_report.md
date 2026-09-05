# `make_vuln_report.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **generador de informes de vulnerabilidades** (conocido en el proyecto como "Agente 6").
Lee la evidencia ya ordenada de un objetivo y arma **dos documentos por cada uno**:

- **`<objetivo>_resumen_vulnerabilidades.doc`** — un informe compatible con Word/LibreOffice con
  cada hallazgo (título, severidad, descripción, fuente).
- **`<objetivo>_resumen_breve.txt`** — resumen de una línea por hallazgo.

Su gracia: **no inventa nada**. Solo reporta lo que está **explícitamente escrito** en los
archivos de evidencia, y si la fuente no dice la severidad, lo indica como "no declarada".

## ⏱️ ¿Cuándo se usa?

En la fase de entrega (Fase 4), después de consolidar la evidencia con `organize_project.py`.

## ▶️ Cómo se usa

```bash
# Procesa todos los objetivos de la carpeta CLIENTE/
python3 scripts/make_vuln_report.py --project CLIENTE

# Solo un objetivo
python3 scripts/make_vuln_report.py --project CLIENTE --target 10.155.10.15

# Simular sin generar nada
python3 scripts/make_vuln_report.py --project CLIENTE --dry-run
```

## 📥 Entrada / 📤 Salida

- **Entrada:** los archivos de evidencia en `CLIENTE/<objetivo>/outputs/`
  (nuclei, nikto, sslyze, nmap, gobuster, cves, evidencia manual…).
- **Salida:** los dos documentos `.doc` y `.txt` en la carpeta de cada objetivo.

## ⚠️ Notas

- **Detección dinámica:** si copiás cualquier archivo nuevo con hallazgos a un `outputs/` (por
  ejemplo el `gobuster_checks_findings.json` que genera `check_gobuster_urls.sh`), se incorpora
  solo al siguiente informe. No hay que tocar el script.
- **Deduplicación:** si dos fuentes reportan lo mismo, aparece una vez con la fuente más completa.
- **Ofuscación:** contraseñas/tokens se escriben como `***` en el informe (la evidencia original
  no se modifica).