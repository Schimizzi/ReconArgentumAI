# `post_step1_open_ports.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un **post-proceso del paso 1**: toma el resultado de puertos abiertos que dejó Nmap y genera
un **archivo simple con la lista de "IP:puerto" abiertos** (`open_ports.txt`).

Ese archivo es el "menú" que el resto del pipeline usa para saber contra qué servicios seguir
escaneando (pasos 2, 3, 4…).

> ⚠️ Existen dos versiones casi iguales:
> - `scripts/post_step1_open_ports.sh` — para entorno Docker/Kali (rutas `/workspace/...`).
> - `scripts/host/post_step1_open_ports.sh` — para ejecutar en la Mac (rutas del proyecto).

## ⏱️ ¿Cuándo se usa?

Inmediatamente después del paso 1 (escaneo de puertos), antes de continuar con el resto.

## ▶️ Cómo se usa

```bash
bash scripts/host/post_step1_open_ports.sh <IP>
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/nmap_ports.json` (el JSON con los resultados de Nmap).
- **Salida:** `evidence/<IP>/open_ports.txt` — una línea por puerto abierto, con el formato
  `IP:PUERTO` (ej. `10.155.10.15:8082`).

## ⚠️ Notas

- Si no hay puertos abiertos, avisa "open_ports.txt VACÍO" y el pipeline decide por sí mismo que
  no tiene sentido seguir escaneando ese objetivo.