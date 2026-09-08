# `run_target.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es **el "director de orquesta" del escaneo** para un solo objetivo (una IP). Recibe la IP y
ejecuta, en orden y respetando tiempos de espera, **los 10 pasos** del pipeline de reconocimiento:

1. **Nmap** — ver qué puertos/servicios están abiertos.
2. **HTTPX** — cuáles son sitios web.
3. **Nmap detallado** — qué programa y versión corre en cada puerto.
4. **Nuclei** — busca vulnerabilidades conocidas.
5. **Nikto** — escáner web complementario.
6. **WhatWeb** — identifica tecnologías (auto-detección desde 2026-09-07: corre si hay binario
   en el PATH o en `tools/WhatWeb/`; si no, queda `skipped`).
7. **Gobuster** — descubre carpetas ocultas.
8. **SSLyze** — analiza seguridad de conexiones cifradas.
9. **IIS Shortname (8.3)** — detecta divulgación de nombres cortos de IIS, **solo si** hay web
   (`web_on`) y el `httpx.json` reporta `Server: Microsoft-IIS`; si no, queda `skipped_no_iis`.
10. **SMB Enum** (`step10_smbclient_enum.sh`) — lista recursos compartidos SMB vía *null session*,
    **solo si** el TCP 139/445 está abierto (`open_ports.txt` o `nmap_detailed.xml`, service-based
    como Nuclei); si no, queda `skipped_no_smb`.

Al final genera el **manifest.json**: la "ficha" que registra qué se ejecutó, qué produjo cada
paso y si hubo errores.

## ⏱️ ¿Cuándo se usa?

Cuando se quiere escanear **una IP autorizada** de punta a punta. El script `run_fase1_run3.sh`
lo llama para cada objetivo de la lista.

## ▶️ Cómo se usa

```bash
bash scripts/host/run_target.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la IP del objetivo.
- **Salida:** carpeta `evidence/<IP>/` con la evidencia de cada paso + `manifest.json`.
  Todo el detalle de ejecución queda en `evidence/<IP>/_step.log` (y errores en `_errors.log`).

## ⚠️ Notas — guarda reglas internas

- **R1 (scope):** si la IP no está en la lista de autorizados o está excluida, **aborta**.
- **R3 (sigilo):** espera un delay entre herramientas (por defecto 30 s) para no hacer ruido;
  y si ya hay una corrida sobre el mismo objetivo, **no deja que otra empiece** (usa un "candado").
- **Retry:** si un paso falla, lo intenta **una vez más** antes de declararlo fallido.
- Si el paso 1 no encuentra puertos abiertos, el objetivo queda marcado como "incomplete" (no
  tiene sentido seguir).