# `detect_tls_ports.py` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un **detector de puertos seguros (TLS/SSL)**: mira la evidencia del escaneo detallado de Nmap
(paso 3) y averigua **qué puertos usan cifrado**, porque a esos hay que pasarles el análisis de
seguridad SSLyze (paso 8).

Salida: una línea por puerto con TLS, indicando si es **TLS directo** o si usa **STARTTLS** (y con
qué protocolo, por ejemplo smtp, imap, rdp).

## 🧠 ¿Cómo decide si un puerto tiene TLS?

Lo sabe por varias pistas, en orden:
1. Nmap dice que el servicio tiene túnel `ssl` → TLS directo.
2. El nombre del servicio ya indica TLS (https, imaps, smtps, ldaps…) → TLS directo.
3. El número de puerto es uno de los "de siempre" con TLS (443, 8443, 993, 995, 636, 465…) →
   TLS directo.
4. Puerto 3389 (escritorio remoto RDP) → STARTTLS rdp.
5. Servicios que negocian TLS después de conectarse (smtp, imap, pop3, ftp, ldap…) → STARTTLS
   con ese protocolo.

## ⏱️ ¿Cuándo se usa?

Lo llama el runner (`run_target.sh`) justo antes del paso 8 para saber contra qué puertos correr
SSLyze.

## ▶️ Cómo se usa

```bash
python3 scripts/host/detect_tls_ports.py evidence/10.155.10.15 --with-starttls
```

## 📥 Entrada / 📤 Salida

- **Entrada:** la carpeta de evidencia de un objetivo (usa `nmap_detailed.json`, o el XML como
  respaldo).
- **Salida en pantalla:** una línea por puerto TLS, por ejemplo:
  ```
  443 https tls
  25 smtp starttls smtp
  ```