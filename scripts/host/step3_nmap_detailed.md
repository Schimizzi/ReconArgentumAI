# `step3_nmap_detailed.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 3 del pipeline**: ejecuta un **escaneo Nmap detallado** (`-sC -sV`) **solo sobre
los puertos que ya se descubrieron abiertos** en el paso 1, para averiguar **qué programa y
qué versión** corre en cada uno (ej. "Apache 2.4.41", "OpenSSH 8.9p1", "Microsoft IIS 10.0",
"Tomcat 9.0.80").

Conocer la versión exacta es clave: después sirve para buscar vulnerabilidades conocidas
(CVEs) de ese programa puntual.

## ⏱️ ¿Cuándo se usa?

Después del paso 1 (Nmap port scan) y del paso 2 (HTTPX probe). Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step3_nmap_detailed.sh <IP>

# Ejemplo real:
bash scripts/host/step3_nmap_detailed.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` — lista de IP:PUERTO abiertos.
- **Salida:** en `evidence/<IP>/`:
  - `nmap_detailed.xml` — resultado en XML (formato principal).
  - `nmap_detailed.json` — derivado del XML (workaround `-oJ` roto).
  - `nmap_detailed.txt` — resultado legible para humanos.

## 🧠 Detalles importantes

- **Escaneo selectivo:** solo escanea los puertos de `open_ports.txt` (nunca rangos
  completos). Esto ahorra tiempo y reduce el tráfico de red.
- **Plugins NSE:** `-sC` ejecuta los scripts de categoría "default" de Nmap (detección de
  versiones, fingerprinting y algunos checks de seguridad); `-sV` es la detección de versiones.
- **Tipo de scan autodetectado por privilegios:**
  - `EUID == 0` (root: VM Kali, contenedor Docker) → `-sS` (SYN scan).
  - `EUID != 0` (macOS sin sudo) → `-sT` (TCP Connect scan).
- **Timing:** usa el timing por defecto de Nmap (equivalente a T3) — no se aplican `-T5`
  ni `--max-rate` del stealth.yaml para este paso.

## ⚠️ Notas

- **Workaround `-oJ`** (JSON directo de Nmap): en la versión 7.99 de Kali (arm64) el flag
  `-oJ` está roto. El script usa `-oX` (XML) y luego deriva el JSON con
  `scripts/xml_to_nmap_json.py`.
- Si `open_ports.txt` está vacío, el script falla (el runner lo captura como
  `skipped` y continúa).
- La evidencia `nmap_detailed.json` es la que consumen los pasos 8 (SSLyze, para detectar
  puertos TLS) y 10 (SMB Enum, para detectar 139/445).
