# `step3_nmap_detailed.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Ejecuta un **escaneo Nmap detallado** (`-sC -sV`) **solo sobre los puertos que están
abiertos** (los que descubrió el paso 1). Para cada puerto abierto averigua **qué programa
y versión** está corriendo (ej. "Apache 2.4.41", "OpenSSH 8.9p1", "Microsoft IIS 10.0").

Con esto se puede saber si un servicio tiene versiones viejas con vulnerabilidades conocidas.

## ⏱️ ¿Cuándo se usa?

Después del paso 1 (Nmap port scan) y del paso 2 (HTTPX probe). Lo llama `run_target.sh`.

## ▶️ Cómo se usa

```bash
# Normal (lo llama el pipeline):
bash scripts/host/step3_nmap_detailed.sh <IP>
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt` — lista de IP:PUERTO abiertos.
- **Salida:**
  - `evidence/<IP>/nmap_detailed.xml` — resultado en XML (formato principal).
  - `evidence/<IP>/nmap_detailed.json` — derivado del XML (workaround `-oJ` roto).
  - `evidence/<IP>/nmap_detailed.txt` — resultado legible para humanos.

## 🧠 Detalles importantes

- **Escaneo selectivo:** solo escanea los puertos de `open_ports.txt` (nunca rangos
  completos). Esto ahorra tiempo y reduce el tráfico de red.
- **Tipo de scan autodetectado:** según los privilegios del proceso:
  - `EUID == 0` (root: VM Kali, contenedor Docker) → `-sS` (SYN scan).
  - `EUID != 0` (macOS sin sudo) → `-sT` (TCP Connect scan).
- **Timing:** usa el timing por defecto de Nmap (equivalente a T3) — no se aplican `-T5`
  ni `--max-rate` del stealth.yaml para este paso.
- **Plugins NSE:** `-sC` ejecuta los scripts de categoría "default" de Nmap, que incluyen
  detección de versiones, fingerprinting y algunos checks de seguridad.

## ⚠️ Notas

- Workaround `-oJ` (JSON directo de Nmap): en la versión 7.99 de Kali (arm64) el flag
  `-oJ` está roto. El script usa `-oX` (XML) y luego deriva el JSON con
  `scripts/xml_to_nmap_json.py`.
- Si `open_ports.txt` está vacío, el script falla (el runner lo captura como
  `skipped` y continúa).
- La evidencia `nmap_detailed.json` es la que consumen los pasos 8 (SSLyze, para detectar
  puertos TLS) y 10 (SMB Enum, para detectar 139/445).
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