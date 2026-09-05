# `organize_project.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **archivero del proyecto**: junta y ordena toda la **evidencia** generada por los escaneos
(resultados de Nmap, Nuclei, Nikto, Gobuster, SSLyze, informes, planes…) y la deja organizada
**carpeta por objetivo** dentro de una carpeta del cliente (por defecto `CLIENTE/`).

Sin esto, la evidencia estaría esparcida por `evidence/`, `reports/`, `plans/`, `cve_research/`…
Este script la consolida y además genera un `README.md` del proyecto.

## ⏱️ ¿Cuándo se usa?

En la fase de **entrega / consolidación** (Fase 4), después de que todos los escaneos y análisis
terminaron. Es el paso previo a generar los informes de vulnerabilidades.

## ▶️ Cómo se usa

```bash
# Procesa todos los objetivos escaneados → carpeta CLIENTE/
python3 scripts/organize_project.py

# Solo simular qué haría (no crea ni copia nada)
python3 scripts/organize_project.py --dry-run

# Solo un objetivo en particular (se puede repetir)
python3 scripts/organize_project.py --target 10.155.10.15

# Solo los objetivos registrados como autorizados en config/scope.json
python3 scripts/organize_project.py --scope
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la evidencia en `evidence/`, `reports/`, `plans/`, `cve_research/`.
- **Salida:** en `CLIENTE/` una carpeta por objetivo con:
  - `outputs/` — la evidencia cruda (nombres originales, sin renombrar).
  - `data/` — los documentos de análisis (plan de explotación, reporte).
  - `README.md` — índice del proyecto.

## ⚠️ Notas

- **No renombra archivos**: copia la evidencia con el nombre que el escaneo dejó.
- Cuando una misma herramienta genera varios formatos del mismo resultado (XML/JSON), copia solo
  el más completo.
- `--no-clobber` evita sobrescribir archivos que ya existan en el destino.