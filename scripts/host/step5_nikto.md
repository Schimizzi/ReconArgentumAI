# `step5_nikto.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Ejecuta **Nikto**, un escáner de seguridad web que revisa **cada sitio web** descubierto
por HTTPX en busca de problemas: archivos peligrosos, servidores desactualizados, programas
instalados, cabeceras de seguridad faltantes y más.

Se ejecuta **una vez por cada endpoint web** (cada URL de `web_endpoints.txt`).

## ⏱️ ¿Cuándo se usa?

Después de Nuclei (paso 4), solo si hay sitios web confirmados. Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step5_nikto.sh <IP> <URL> <PORT>
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `web_endpoints.txt` (una URL a la vez, secuencial).
- **Salida:**
  - `evidence/<IP>/nikto_<PORT>.json` — resultados JSON para ese puerto específico.

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
- Los resultados JSON son consumidos luego por el Agente 6 (consolidador de hallazgos).
- Nikto es más intrusivo que otras herramientas del pipeline (genera más tráfico).
# `step5_nikto.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 5 del pipeline**: usa la herramienta **Nikto**, un escáner de seguridad web que
revisa un sitio concreto buscando **archivos y directorios conocidos, malas configuraciones y
errores** (por ejemplo, archivos de backup expuestos, servidores desactualizados, headers mal
configurados).

Se ejecuta **una vez por cada sitio web** encontrado, de forma secuencial.

## ⏱️ ¿Cuándo se usa?

Después del paso 2 (que dejó la lista de sitios web). Lo corre `run_target.sh` para cada web.

## ▶️ Cómo se usa

```bash
# Recibe: objetivo, URL del sitio y puerto
bash scripts/host/step5_nikto.sh 10.155.10.15 http://10.155.10.15:8082 8082
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP, URL del sitio y puerto.
- **Salida:** `evidence/<IP>/nikto_<puerto>.json` — los hallazgos de ese sitio en formato JSON.

## 🧠 Detalles importantes

- El tiempo máximo por sitio sale de la configuración de sigilo (`config/stealth.yaml`).
- No revisa la web si la dirección no responde (evita colgarse).