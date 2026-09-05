# `step3_nmap_detailed.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 3 del pipeline**: hace un **escaneo detallado con Nmap** **solo sobre los puertos
que ya se descubrieron abiertos** en el paso 1, para averiguar **qué programa y qué versión**
corre en cada uno (ej. "Apache 2.4.49", "IIS", "Tomcat 9.0.80", "MSSQL 2019").

Conocer la versión exacta es clave: después sirve para buscar vulnerabilidades conocidas (CVEs)
de ese programa puntual.

## ⏱️ ¿Cuándo se usa?

Después del paso 1 (que dejó `open_ports.txt`). Lo corre `run_target.sh`.

## ▶️ Cómo se usa

```bash
bash scripts/host/step3_nmap_detailed.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt`.
- **Salida:** en `evidence/<IP>/`:
  - `nmap_detailed.xml` / `.txt` — detalle del escaneo.
  - `nmap_detailed.json` — la versión JSON (derivada del XML), con servicio, producto y versión
    por puerto.

## 🧠 Detalles importantes

- Sobre cada puerto abierto ejecuta los scripts de detección por defecto de Nmap (`-sC`) y la
  detección de versiones (`-sV`).
- La velocidad del escaneo sale de la configuración de sigilo (`config/stealth.yaml`).
- Igual que el paso 1, deriva el JSON a partir del XML para no depender del formato directo roto.