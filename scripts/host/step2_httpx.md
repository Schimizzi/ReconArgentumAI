# `step2_httpx.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **detector de sitios web** del pipeline. Toma la lista de puertos abiertos de Nmap
(`open_ports.txt`) y los analiza con **HTTPX** (la herramienta de ProjectDiscovery) para
descubrir **cuáles son servidores web**.

No todos los puertos abiertos son web: el 22 es SSH, el 3306 es MySQL… HTTPX los prueba y
responde "esto es un sitio web" o "esto no es web".

## ⏱️ ¿Cuándo se usa?

Inmediatamente después del paso 1 (Nmap), antes del escaneo detallado de Nmap y de las
herramientas web (Nikto, WhatWeb, Gobuster). Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline automáticamente):
bash scripts/host/step2_httpx.sh <IP>
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` — lista de IP:PUERTO abiertos.
- **Salida:**
  - `evidence/<IP>/httpx.json` — JSONL con todas las respuestas HTTP/HTTPS (completo).
  - `evidence/<IP>/web_endpoints.txt` — solo las URLs con esquema http:// o https://
    (deduplicadas con `sort -u` para evitar URLs repetidas por redirects 80→443).

## 🧠 Detalles importantes

- **Resolución del binario:** HTTPX de ProjectDiscovery tiene distintos nombres según el
  entorno: `httpx-toolkit` (Kali), `httpx-pd` (macOS) o `httpx` (si realmente es el PD, no
  el cliente Python). El script los prueba en ese orden.
- **Timeouts desde `config/stealth.yaml`:** `httpx_timeout_seconds`, `httpx_retries`,
  `httpx_threads` — nunca hardcodeados (R5).
- **Deduplicación:** HTTPX sigue redirects (ej. 80→443) y registraría la misma URL final
  dos veces. El script aplica `sort -u` para evitarlo.
- Si no hay puertos abiertos, el script se salta automáticamente.

## ⚠️ Notas

- HTTPX **no modifica nada** en los servidores: solo hace requests HTTP/HTTPS.
- El resultado completo (`httpx.json`) incluye también respuestas no-web (ej. TLS handshake
  fallido) que el pipeline usa para detectar servicios.
- La **lista de URLs web** (`web_endpoints.txt`) es la que consumen los pasos 5 (Nikto),
  6 (WhatWeb) y 7 (Gobuster).
# `step2_httpx.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 2 del pipeline**: usa la herramienta **HTTPX** para descubrir **cuáles de los
puertos abiertos son sitios web** y anotar sus características básicas (dirección, estado,
tecnologías, redirecciones…).

Además genera la lista `web_endpoints.txt` con las direcciones web, que usan los análisis de
páginas posteriores.

## ⏱️ ¿Cuándo se usa?

Después del paso 1 (que dejó `open_ports.txt`). Lo corre `run_target.sh`.

## ▶️ Cómo se usa

```bash
bash scripts/host/step2_httpx.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` (lista `IP:puerto` abiertos).
- **Salida:**
  - `evidence/<IP>/httpx.json` — resultados en formato JSON (una línea por respuesta web).
  - `evidence/<IP>/web_endpoints.txt` — solo las direcciones web (`http://...`).

## 🧠 Detalles importantes

- Timeouts, reintentos y paralelismo salen de `config/stealth.yaml` (bajo ruido).
- Usa el binario de ProjectDiscovery (`httpx-toolkit` en Kali, `httpx-pd` en macOS), no
  confundir con el comando `httpx` de Python.
- La lista `web_endpoints.txt` queda **deduplicada** (`sort -u`): cuando HTTPX sigue una
  redirección (ej. del puerto 80 → 443) registra la misma dirección final varias veces; sin
  deduplicar, los pasos 5 (Nikto) y 7 (Gobuster) escanean por duplicado.