# `cves_md.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Ayuda a **convertir la investigación de vulnerabilidades (CVE) en un documento de lectura fácil**.

Cuando se investigan vulnerabilidades conocidas de un servidor, los datos quedan en un formato de
archivo técnico (JSON). Este script los "traduce" a un documento **Markdown** (`<objetivo>_cves.md`)
con tablas y secciones que se entienden mejor y que se adjuntan al informe.

## ⏱️ ¿Cuándo se usa?

Lo usa el script `organize_project.py` cuando arma la carpeta del cliente: para cada objetivo
genera su documento CVE legible a partir del JSON de investigación. No se corre a mano.

## 📥 Entrada / 📤 Salida

- **Entrada:** el JSON de investigación CVE de un objetivo (`cve_research/<target>_cves.json`).
- **Salida:** texto Markdown listo para el archivo `<target>_cves.md`, con:
  - Resumen (total de CVEs, críticos, altos, con exploit público…).
  - Tabla de CVEs por servicio y por tecnología web.
  - Detalle de cada CVE (descripción, versiones afectadas, versión parcheada, PoCs, enlaces).

## ⚠️ Notas

- Este **no modifica el JSON original**: solo genera el documento legible a partir de él.
- Ofusca (oculta con `***`) datos sensibles y escapa caracteres especiales antes de escribirlos.