# `install_host_tools.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **instalador de las herramientas** que el proyecto necesita cuando se usa en el modo
"Host" (es decir, corriendo directamente en una Mac, sin Docker).

Las herramientas de pentest no vienen instaladas por defecto: este script las descarga e instala
automáticamente.

## ⏱️ ¿Cuándo se usa?

**Una sola vez**, al preparar el entorno de trabajo. No es parte del escaneo.

## ▶️ Cómo se usa

```bash
bash scripts/install_host_tools.sh
```

## 🧰 ¿Qué instala?

| Herramienta | Para qué sirve | Cómo se instala |
|---|---|---|
| `nmap` | Descubre puertos/servicios abiertos | `brew` |
| `nikto` | Escáner de seguridad web | `brew` |
| `gobuster` | Descubre carpetas ocultas en webs | `brew` |
| `nuclei` | Escáner de vulnerabilidades multiprotocolo | `brew` |
| `hydra` | Auditoría manual de credenciales | `brew` |
| `sslyze` | Analiza seguridad de conexiones cifradas (TLS) | `pipx` |
| `whatweb` | Identifica la tecnología de los sitios web | descarga manual (git clone) |
| `httpx` | Probe web de ProjectDiscovery | `brew install httpx-toolkit` |
| `jq` | Procesa archivos JSON en scripts | `brew` |
| `smbclient` | Enumera recursos compartidos SMB | `brew install samba` |
| `python3` | Ejecuta scripts Python del pipeline | `brew` |
| `ldapsearch` | Enumeración LDAP/AD del Step 11 (Linux y macOS) | `ldap-utils` (ya presente en macOS `/usr/bin`) |
| `enum4linux-ng` | Enumeración AD anónima del Step 12 - **solo Linux** | `sudo apt install enum4linux-ng` (no aplica en macOS) |

También verifica al final que todas las herramientas queden accesibles y guarda un registro del
proceso en `/tmp/tools_install2.log`.

## ⚠️ Notas

- Está pensado para **macOS** (usa Homebrew y pipx).
- `enum4linux-ng` **no aplica en macOS**: el Step 11 del pipeline solo corre en Linux/Debian (o el contenedor Docker).
- WhatWeb no tiene instalador automático oficial, por eso se clona en la carpeta `tools/WhatWeb/`.
- **HTTPX (probe PD):** el repo **no** versiona el binario `httpx-pd` (~51 MB, removido del árbol en
  2026-10-22). El pipeline lo resuelve por `PATH` (`command -v httpx-pd`); instalarlo aparte
  (Kali: `sudo apt install httpx-toolkit`; macOS: `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
  y crear el symlink `httpx-pd`).
- Si una herramienta ya está instalada, la detecta y no la reinstala.