# `step2_httpx.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 2 del pipeline**: usa la herramienta **HTTPX** (de ProjectDiscovery) para
descubrir **cuáles de los puertos abiertos son sitios web** y anotar sus características
básicas (dirección, estado, tecnologías, redirecciones…).

No todos los puertos abiertos son web: el 22 es SSH, el 3306 es MySQL… HTTPX los prueba y
responde "esto es un sitio web" o "esto no es web".

## ⏱️ ¿Cuándo se usa?

Inmediatamente después del paso 1 (Nmap), antes del escaneo detallado (paso 3) y de las
herramientas web (Nikto, WhatWeb, Gobuster). Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline automáticamente):
bash scripts/host/step2_httpx.sh <IP>

# Ejemplo real:
bash scripts/host/step2_httpx.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` — lista de IP:PUERTO abiertos (del paso 1).
- **Salida:**
  - `evidence/<IP>/httpx.json` — JSONL con todas las respuestas HTTP/HTTPS (completo).
  - `evidence/<IP>/web_endpoints.txt` — solo las URLs con esquema `http://` o `https://`,
    **deduplicadas** con `sort -u`.

## 🧠 Detalles importantes

- **Resolución del binario:** HTTPX de ProjectDiscovery tiene distintos nombres según el
  entorno: `httpx-toolkit` (Kali), `httpx-pd` (macOS) o `httpx` (si realmente es el PD, no
  el cliente Python). El script los prueba en ese orden.
- **Timeouts desde `config/stealth.yaml` (R5):** `httpx_timeout_seconds`, `httpx_retries`,
  `httpx_threads` — nunca hardcodeados.
- **Deduplicación:** HTTPX sigue redirects (ej. 80→443) y registraría la misma URL final
  dos veces. El script aplica `sort -u` para evitarlo.
- Si no hay puertos abiertos, el script se salta automáticamente.

## ⚠️ Notas

- HTTPX **no modifica nada** en los servidores: solo hace requests HTTP/HTTPS.
- El resultado completo (`httpx.json`) incluye también respuestas no-web (ej. TLS handshake
  fallido) que el pipeline usa para detectar servicios.
- La **lista de URLs web** (`web_endpoints.txt`) es la que consumen los pasos 5 (Nikto),
  6 (WhatWeb) y 7 (Gobuster).
