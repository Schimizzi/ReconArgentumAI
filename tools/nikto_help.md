# NIKTO — Reference Help
> VERIFICADO: Nikto **2.6.1 (LW 2.5)** instalado en el contenedor Docker del Paso 2
> (`nikto -Version` + `nikto -H`, 2026-08-30). Soporta `-Format json` ✅.
> `-maxtime` acepta duraciones (ej. `30s`). `-nocheck` evita el chequeo de updates.

## QUÉ ES
Nikto es un escáner de configuración/vulnerabilidades web server-side. Ruidoso por
naturaleza: generar MUCHOS requests por URL. En modo stealth, limitar con
`-maxtime` (resolver de `{{nikto_maxtime_seconds}}` → `30s`) y usar `-Tuning` acotado.

## FLAGS PRINCIPALES (v2.6.1)
- `-h <host>` Host objetivo (URL completa: `http://IP:port` o `https://IP:port`).
- `-p <port>` Puerto (si no está en la URL).
- `-Format <formato>` Formato de output: `json`, `html`, `csv`, `txt`, `xml`.
  - ✅ `-Format json` VERIFICADO en 2.6.1 (el nombre debe terminar en `.json`).
  - Fallback documentado por si fallara: `.html` + volcar stdout a `.txt`.
- `-o <file>` Archivo de output.
- `-Tuning <valores>` Qué pruebas correr. Valores comunes:
  - `1` archivos interesantes / `2` misconfiguration / `3` archivos de info
  - `4` inyección / `5` remote file retrieval / `6` denial of service (EVITAR en stealth)
  - `0` archivo de upload / `x` extensiones misc.
  - Ej `-Tuning 123b` (aprobado en Fase 0; sin DoS).
- `-maxtime <dur>` Tiempo máximo por host (acepta `30s`, `60m`). ← `{{nikto_maxtime_seconds}}s`
- `-nocheck` No verificar updates al arrancar (evita llamada de red extra). ← aprobado en Fase 0
- `-ssl` Forzar SSL/TLS.
- `-evasion <estrategia>` Técnicas anti-IDS (1-8).
- `-no404` No detectar archivos 404 (acelera).
- `-Plugins` Plugins específicos (por defecto todos).

## EJEMPLO ÚTIL (Step 5 — audit por endpoint, secuencial) — VERIFICADO en 2.6.1
```bash
nikto -h <URL> \
  -Format json \
  -o /workspace/evidence/<target>/nikto_<port>.json \
  -Tuning 123b \
  -maxtime {{nikto_maxtime_seconds}}s \
  -nocheck

# Fallback sin JSON (documentado; el manifest refleja el formato real):
nikto -h <URL> \
  -o /workspace/evidence/<target>/nikto_<port>.html \
  -Tuning 123b \
  -maxtime {{nikto_maxtime_seconds}}s 2>&1 | tee /workspace/evidence/<target>/nikto_<port>.txt
```

## NOTAS PARA EL AGENTE
- Ejecutar de forma SECUENCIAL, uno por cada endpoint de `web_endpoints.txt` (`nikto_<port>.<ext>`).
- Nunca incluir `-Tuning 6` (DoS) en un engagement de stealth.
- La evidencia es `.json` (verificado); si algo falla, registrar el formato real en el manifest.
- Por defecto Nikto prueba `/`; para apps específicas considerar `-root` o el path base real.