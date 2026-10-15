# `step7_gobuster.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 7 del pipeline**: usa la herramienta **Gobuster** para **descubrir carpetas,
archivos y subdominios "ocultos"**, probando una lista de nombres típicos (admin, backup,
.git, config, etc.). Es como "tocar la puerta" con muchos nombres comunes a ver cuál responde,
y así encontrar superficie de ataque que no estaba a la vista.

Gobuster puede trabajar en **tres modos**, según qué haya que probar:

| Modo | Para qué |
|---|---|
| `dir` | Descubre rutas/carpetas y archivos en sitios web (ej. `/admin`, `/backup.zip`). |
| `dns` | Descubre subdominios de un dominio (ej. `mail.ejemplo.com`). |
| `tftp` | Busca archivos vía protocolo TFTP (si el objetivo tiene el puerto 69/UDP abierto). |

## ⏱️ ¿Cuándo se usa?

Después del paso 6 (WhatWeb). Lo llama `run_target.sh`, que decide qué modo(s) activar.

## ▶️ Cómo se usa

```bash
# Modo dir sobre una URL web
bash scripts/host/step7_gobuster.sh <IP> <URL> <PORT> dir

# Modo dns sobre un dominio
bash scripts/host/step7_gobuster.sh <IP> <DOMINIO> 0 dns

# Modo tftp sobre una IP
bash scripts/host/step7_gobuster.sh <IP> <IP> 69 tftp

# Ejemplo real (modo dir):
bash scripts/host/step7_gobuster.sh 10.155.10.15 http://10.155.10.15:8082 8082 dir
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP del objetivo, la URL (o dominio/IP) y el modo. En modo `dir` sale de
  `web_endpoints.txt`; en modo `dns`, el dominio de la URL; en modo `tftp`, el probe UDP 69.
- **Salida:**
  - `evidence/<IP>/gobuster_<PORT>.txt` (modo dir) — rutas encontradas con su estado
    (ej. `Content (Status: 301)`, `admin (Status: 200)`).
  - `evidence/<IP>/gobuster_dns.txt` (modo dns).
  - `evidence/<IP>/gobuster_tftp.txt` (modo tftp).

## 🧠 Detalles importantes

- **Wordlists portables:** la wordlist se resuelve probando varias ubicaciones en orden:
  `/opt/SecLists/...` → `/usr/share/seclists/...` → `~/Documents/SecLists/...` →
  `tools/seclists_common.txt` (cache local). Así funciona igual en Docker, VM Kali y macOS.
- **Timeouts desde `stealth.yaml`:** `gobuster_threads`, `gobuster_timeout_seconds`,
  `gobuster_max_seconds` (cutoff de tiempo).
- **Cutoff de tiempo:** si Gobuster no termina antes del cutoff (default 180s), se mata el
  proceso y se marca `failed`. Evita que servidores que no responden al diccionario bloqueen
  el pipeline durante horas.
- **TLS autofirmado:** se usa `-k` (`--no-tls-validation`): los equipos embebidos de la LAN
  (Avaya IP Office, etc.) usan certificados autofirmados; sin `-k` Gobuster fallaba el
  arranque y cada consulta se colgaba hasta el cutoff.
- **Métodos/status permitidos:** en modo `dir` solo se reportan status 200, 204, 301, 307 y 403.

## ⚠️ Notas

- Gobuster es más intrusivo que las herramientas anteriores (genera muchas requests).
- El modo `tftp` se activa solo si el probe UDP 69 detecta el puerto abierto.
- El modo `dns` se activa solo si el target es un nombre de dominio (no una IP cruda).
- Si no hay sitios web, ni dominio, ni TFTP, el paso se marca como "saltado".
