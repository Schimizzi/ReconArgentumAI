# `step1_nmap_ports.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **primer paso del escaneo** de un objetivo (IP). Su trabajo es averiguar **qué "puertos"
(servicios) están abiertos** en ese equipo usando la herramienta **Nmap**.

Un servidor tiene "puertas" numeradas por donde ofrecen servicios (web en el 80/443, correo,
escritorio remoto, base de datos…). Este paso es la foto inicial que dice: "en esta IP hay
abiertos los puertos X, Y y Z".

> ⚠️ ✓ Este script es la **versión para Docker/Kali** (usa `-sS`, escaneo con privilegios).
> La versión para ejecutar en la Mac directamente está en `scripts/host/step1_nmap_ports.sh`.

## ⏱️ ¿Cuándo se usa?

Siempre que se escanea un objetivo nuevo; es el **paso 1 de 8** del pipeline.

## ▶️ Cómo se usa

```bash
bash scripts/step1_nmap_ports.sh <IP>
# ejemplo:
bash scripts/step1_nmap_ports.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la dirección IP del objetivo.
- **Salida:** varios archivos de evidencia en `evidence/<IP>/`:
  - `nmap_ports.xml` / `.txt` / `.gnmap` — resultados del escaneo en distintos formatos.
  - `nmap_ports.json` — versión en formato JSON (derivada del XML), que es la que usan los demás pasos.

## ⚠️ Notas

- Revisa los **1000 puertos más comunes**.
- Usa un **workaround** interno: en cierto sistema (Kali arm64) el formato JSON de Nmap viene
  roto, así que se obtiene el JSON a partir del XML.
- Las velocidades y reintentos del escaneo se toman de la configuración de sigilo del proyecto
  (`config/stealth.yaml`), nunca "a dedo".