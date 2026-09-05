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
| `nikto` | Escáner de seguridad web | `brew` |
| `gobuster` | Descubre carpetas ocultas en webs | `brew` |
| `sslyze` | Analiza seguridad de conexiones cifradas (TLS) | `pipx` |
| `whatweb` | Identifica la tecnología de los sitios web | descarga manual (git clone) |

También verifica al final que todas las herramientas queden accesibles y guarda un registro del
proceso en `/tmp/tools_install2.log`.

## ⚠️ Notas

- Está pensado para **macOS** (usa Homebrew y pipx).
- WhatWeb no tiene instalador automático oficial, por eso se clona en la carpeta `tools/WhatWeb/`.
- Si una herramienta ya está instalada, la detecta y no la reinstala.