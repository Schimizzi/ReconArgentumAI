# `nvd_query.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

**Busca vulnerabilidades conocidas (CVE)** en la base de datos pública **NVD** (National
Vulnerability Database) usando una palabra clave.

Le escribís, por ejemplo, "Microsoft SQL Server" y te devuelve una lista de CVEs encontrados,
cada uno con su identificación, su puntaje de gravedad (CVSS) y una breve descripción.

## ⏱️ ¿Cuándo se usa?

Durante la fase de **investigación de vulnerabilidades** (Agente 4), para buscar CVEs de los
servicios detectados. Se consulta en línea (necesita internet).

## ▶️ Cómo se usa

```bash
# Busca por una palabra clave (ej. "apache tomcat 9")
python3 scripts/nvd_query.py "apache tomcat 9"

# Lo mismo pero pidiendo 15 resultados en vez de 10
python3 scripts/nvd_query.py "openssh" 15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** una frase de búsqueda y (opcional) cuántos resultados mostrar.
- **Salida en pantalla (consola):** por cada CVE una línea como:
  ```
  CVE-2024-6387 | 8.1 | Descripción breve...
  ```

## ⚠️ Notas

- La parte de gravedad que muestra es la **métrica CVSS 3.1** si existe.
- La base NVD puede tardar o caerse a veces; el script reintenta la consulta automáticamente.