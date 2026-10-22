# `run_target.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es **el "director de orquesta" del escaneo** para un solo objetivo (una IP). Recibe la IP y
ejecuta, en orden y respetando tiempos de espera, **los 12 pasos** del pipeline de reconocimiento:

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
11. **LDAP Enum** (`step11_ldap_enum.sh`) - LDAP/AD con `ldapsearch`: root DSE anónimo y, si la Fase 0
    aprobó credenciales, usuarios y SPN. **Corre en Linux y macOS**; solo si 389/636/3268/3269 está abierto.
12. **Enum4linux** (`step12_enum4linux_enum.sh`) - enumeración AD anónima (usuarios, grupos,
    política de contraseñas, dominio) vía sesión nula; **solo Linux**: en macOS queda
    `skipped_unsupported_os` **sin generar tráfico**, y en Linux **solo si** TCP 139/445 está
    abierto (si no, `skipped_no_smb`). Evidencia: `enum4linux.txt` + `enum4linux.json`.

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
- **R3 (sigilo):** espera un delay entre herramientas (por defecto 30 segundos, de
  `config/stealth.yaml`) para no hacer ruido. Si ya hay una corrida sobre el mismo objetivo,
  **no deja que otra empiece** (usa un candado `evidence/<IP>/.run.lock` con `mkdir` atómico).
- **Watchdog de Nikto:** algunos servidores (ESXi, HP embebidos) ignoran `-maxtime` y se cuelgan.
  El script implementa un watchdog: timeout = `nikto_maxtime_seconds × 3`, mata el proceso y marca
  el paso como `failed`.
- **Cutoff de Gobuster:** si Gobuster no responde al diccionario (timeouts en ~23.7k requests),
  el script lo corta tras `gobuster_max_seconds` (default 180s) y marca `failed`.
- **Retry:** si un paso falla, lo intenta **una vez más** antes de declararlo fallido. Excepción:
  Step 1 (Nmap) marca el target `incomplete` si falla dos veces.
- Si el paso 1 no encuentra puertos abiertos, el objetivo queda marcado como `incomplete` (no
  tiene sentido seguir).