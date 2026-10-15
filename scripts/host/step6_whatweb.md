# `step6_whatweb.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 6 del pipeline**: usa la herramienta **WhatWeb** para **identificar la
tecnología** de cada sitio web del objetivo (qué software, librería o framework usa: Apache,
Nginx, IIS, WordPress, Joomla, ASP.NET, React, Django, jQuery, Bootstrap, cierta versión…).

Esa "huella" tecnológica sirve para saber contra qué buscar vulnerabilidades conocidas.

## ⏱️ ¿Cuándo se usa?

Después del paso 5 (Nikto), solo si hay sitios web confirmados. Lo llama `run_target.sh`.

> ℹ️ **Actualizado (2026-09-07):** el Step 6 pasó a **auto-detección**. Si existe un binario
> WhatWeb (en el `PATH` —Kali lo trae instalado por defecto— o en `tools/WhatWeb/whatweb`) se
> ejecuta y genera `whatweb.json`; si no existe ningún binario, queda `skipped` (mantiene la
> decisión original de Fase 0: "saltar si no está instalado").
>
> ⚠️ Nota histórica: en una versión previa este paso estaba **siempre saltado** (decisión
> Fase 0 / macOS donde se consideró "no instalado"); eso se cambió porque ocultaba un
> fingerprint útil de tecnología en sistemas donde WhatWeb sí está disponible (Kali).

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step6_whatweb.sh <IP>

# Ejemplo real:
bash scripts/host/step6_whatweb.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/web_endpoints.txt` — lista de URLs web.
- **Salida:** `evidence/<IP>/whatweb.json` — JSON con las tecnologías detectadas. WhatWeb usa
  `--log-json`, que es *append-only*; por eso el script **borra el archivo antes** de cada
  ejecución.

## 🧠 Detalles importantes

- **Auto-detección del binario:** WhatWeb puede estar en el PATH (`command -v whatweb`) o en
  `tools/WhatWeb/whatweb` (git clone local en macOS, donde no hay fórmula Homebrew). El
  script prueba ambas ubicaciones.
- **Agresión pasiva:** se usa `-a 1` (nivel de agresión 1 — el más suave); los niveles 2, 3
  y 4 son más intrusivos e irrelevantes para recon pasivo.
- **Version 0.6.4:** `-a` solo acepta 1, 3 o 4. El nivel 2 no existe. Por eso se usa `-a 1`.
- **Timeouts desde `stealth.yaml`:** `whatweb_timeout_seconds` (10s) y
  `whatweb_read_timeout_seconds` (20s). **Threads:** `whatweb_threads` (default 5).

## ⚠️ Notas

- Solo se ejecuta si `web_endpoints.txt` no está vacío **y** el binario de WhatWeb está
  disponible (en PATH o en `tools/WhatWeb/`).
- Si el binario no existe → `skipped` (no es error del escaneo, solo de instalación).
- WhatWeb **no modifica nada** en los servidores: solo analiza las respuestas HTTP.
