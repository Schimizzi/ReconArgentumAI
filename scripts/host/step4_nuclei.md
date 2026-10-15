# `step4_nuclei.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 4 del pipeline**: usa la herramienta **Nuclei**, un escáner de vulnerabilidades
que aplica **plantillas** (pequeños programas de prueba, como "recetas") para detectar
problemas de seguridad conocidos: configuraciones inseguras, CVEs, puertos expuestos, etc.

A diferencia de las herramientas exclusivamente web (Nikto, WhatWeb), **Nuclei es
multiprotocolo**: escanea tanto servicios web como no-web (SSH, DNS, TLS, SMTP, RDP…), así
que se examina **todo lo abierto**, no solo páginas web.

## ⏱️ ¿Cuándo se usa?

Después del paso 3 (Nmap detallado). Se ejecuta **siempre** que haya al menos un puerto
abierto en `open_ports.txt`, sin importar si hay servicios web o no. Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step4_nuclei.sh <IP>

# Ejemplo real:
bash scripts/host/step4_nuclei.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` — lista de IP:PUERTO abiertos.
- **Salida:** `evidence/<IP>/nuclei.json` — JSONL (una línea JSON por hallazgo), filtrado a
  severidades `critical, high, medium`.

## 🧠 Detalles importantes

- **Multiprotocolo:** desde la optimización de 2026-08-31, Nuclei corre contra
  `open_ports.txt` (no contra `web_endpoints.txt`). Así aplica plantillas de red, SSH,
  DNS, TLS y web a todos los puertos abiertos.
- **Parámetros desde `stealth.yaml` (R5):** todos los flags se resuelven desde la
  configuración: `nuclei_rate_limit`, `nuclei_timeout_seconds`, `nuclei_retries`,
  `nuclei_max_host_error`, `nuclei_bulk_size`, `nuclei_concurrency`.
- **Filtro de severidad:** solo se registran hallazgos `critical`, `high` y `medium`
  (flag `-s`). Los de severidad `low` e `info` se descartan.
- **Plantillas:** Nuclei descarga automáticamente las plantillas oficiales en la primera
  ejecución (`nuclei -ut`, necesita internet).

## ⚠️ Notas

- Si `open_ports.txt` está vacío → `skipped_no_ports` (no es un error).
- Nuclei no ejecuta exploits: solo detecta condiciones de vulnerabilidad según las
  plantillas cargadas.
- Las plantillas se actualizan periódicamente; mantener la imagen Docker al día
  (`docker compose build`) asegura las últimas detecciones.
