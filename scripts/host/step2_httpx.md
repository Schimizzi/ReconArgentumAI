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
- Usa el binario `httpx-pd` (ProjectDiscovery), no confundir con el comando `httpx` de Python.