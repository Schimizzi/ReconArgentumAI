# `step5_nikto.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 5 del pipeline**: usa la herramienta **Nikto**, un escáner de seguridad web que
revisa **cada sitio web** descubierto por HTTPX buscando problemas: archivos y directorios
conocidos, archivos de backup expuestos, servidores desactualizados, programas instalados,
cabeceras de seguridad faltantes y más.

Se ejecuta **una vez por cada endpoint web** (cada URL de `web_endpoints.txt`), de forma
secuencial.

## ⏱️ ¿Cuándo se usa?

Después del paso 4 (Nuclei), solo si hay sitios web confirmados. Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step5_nikto.sh <IP> <URL> <PORT>

# Ejemplo real:
bash scripts/host/step5_nikto.sh 10.155.10.15 http://10.155.10.15:8082 8082
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP, URL del sitio y puerto (una URL de `web_endpoints.txt` a la vez).
- **Salida:** `evidence/<IP>/nikto_<PORT>.json` — los hallazgos de ese sitio en formato JSON.

## 🧠 Detalles importantes

- **Tuning:** se usa `-Tuning 123b` para enfocar los tests en:
  - Interesante / Archivo visto en logs (`1`)
  - Archivo o directorio inesperado (`2`)
  - Ataques de inyección (XSS/SQLi) (`3`)
  - Enumeración de subdirectorios (`b` — "Bare bone")
- **Timeouts:** `nikto_maxtime_seconds` desde `config/stealth.yaml` (default 30s).
- **Watchdog:** algunos servidores (ESXi, HP embebidos) ignoran `-maxtime` y se cuelgan.
  `run_target.sh` tiene un watchdog que corta Nikto si excede `maxtime × 3`.

## ⚠️ Notas

- Solo web: no se ejecuta si no hay endpoints web confirmados.
- No revisa la web si la dirección no responde (evita colgarse).
- Nikto es más intrusivo que otras herramientas del pipeline (genera más tráfico).
- Los resultados JSON son quedan para su revisión manual.
