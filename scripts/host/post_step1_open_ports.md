# `post_step1_open_ports.sh` — Qué hace (guía sin saber de código)

> ⚠️ **OBSOLETO / HUÉRFANO (2026-10-22).** Ningún script ni agente lo invoca (0 referencias de código).
> El runner `scripts/host/run_target.sh` genera `open_ports.txt` **inline** con `jq`
> (ver `run_target.sh:112-113`). Se conserva **sólo** como referencia/manual; su documentación
> ("único post-proceso unificado") describe un estado anterior del pipeline.

## 🧩 ¿Qué es?

Es un **post-proceso del paso 1** (escaneo de puertos) en su versión para **modo Host (Mac)**.
Toma el resultado de Nmap en formato JSON y genera un archivo simple `open_ports.txt` con la
lista de `IP:PUERTO` abiertos.

Ese archivo es el "menú" que los pasos siguientes (HTTPX, Nuclei, Nmap detallado…) usan para
saber contra qué servicios continuar.

> Este es el **único** post-proceso del paso 1 (script unificado: host, VM Kali y contenedor Docker).

## ⏱️ ¿Cuándo se usa?

Inmediatamente después de escanear puertos con `run_target.sh` (o manualmente tras el paso 1).

## ▶️ Cómo se usa

```bash
bash scripts/host/post_step1_open_ports.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/nmap_ports.json`.
- **Salida:** `evidence/<IP>/open_ports.txt` — una línea por puerto abierto:
  ```
  10.155.10.15:8082
  10.155.10.15:8085
  ```

## ⚠️ Notas

- Si el archivo de Nmap está vacío o no existe, avisa con error.
- Si no hay puertos abiertos, muestra el mensaje `open_ports.txt VACIO`.