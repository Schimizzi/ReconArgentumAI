# `make_manifest.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Genera o regenera el **manifest.json** de un objetivo: el archivo "ficha" que registra, paso por
paso, qué se ejecutó sobre ese equipo y qué archivos de evidencia quedaron.

Es como la **hoja de ruta / comprobante** de cada escaneo: dice cuál de los 8 pasos terminó bien,
cuál se saltó (y por qué) y cuáles fueron los errores.

## ⏱️ ¿Cuándo se usa?

Lo usa el runner `run_target.sh` al terminar de escanear un objetivo. También sirve para
**regenerar** el manifest si se perdió o si se quiere actualizar con la evidencia real en disco.

## ▶️ Cómo se usa

```bash
# Genera/actualiza el manifest del objetivo dado
python3 scripts/host/make_manifest.py 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la IP del objetivo (y, opcionalmente, las fechas de inicio/fin).
- **Salida:** `evidence/<IP>/manifest.json`.

## 🧠 ¿Cómo decide si un paso "está hecho"?

- Si encuentra archivos de evidencia del paso → lo marca como `success` (bien).
- Si no hay evidencia → usa una lógica por paso (por ejemplo: sin puertos → `skipped_no_ports`;
  sin web → `skipped_no_web`; WhatWeb quedó saltado por el usuario → `skipped`).
- Si existía un manifest anterior, **conserva** el estado que ya tenían los pasos y solo
  actualiza lo que corresponda.