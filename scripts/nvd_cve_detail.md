# `nvd_cve_detail.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Consulta en la base de datos pública **NVD** por **un CVE específico** (por su código) y te
muestra su detalle: gravedad (CVSS), descripción y, si aplica, qué **versiones de SQL Server u
OpenSSH** están afectadas.

Es el "detalle fino" del script hermano `nvd_query.py`: si este ya sabés el código exacto del
CVE, este te trae la ficha completa.

## ⏱️ ¿Cuándo se usa?

Durante la investigación de vulnerabilidades, para confirmar el impacto de un CVE puntual antes
de reportarlo. Se consulta en línea (necesita internet).

## ▶️ Cómo se usa

```bash
# Uno o varios códigos CVE
python3 scripts/nvd_cve_detail.py CVE-2024-6387

# Varios a la vez
python3 scripts/nvd_cve_detail.py CVE-2024-6387 CVE-2024-12084
```

## 📥 Entrada / 📤 Salida

- **Entrada:** uno o más códigos de CVE.
- **Salida en pantalla (consola):** por cada CVE el puntaje de gravedad, su descripción y los
  criterios de afectación (CPE) de **MSSQL/OpenSSH** si los tiene.

## ⚠️ Notas

- Es muy útil para redactar la sección de cada vulnerabilidad del informe final (versiones
  afectadas y gravedad reales).