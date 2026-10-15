# `step8_sslyze.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 8 del pipeline**: usa la herramienta **SSLyze** para revisar la **seguridad de
las conexiones cifradas (SSL/TLS)** de cada puerto que usa cifrado (443 HTTPS, 993 IMAPS,
636 LDAPS, 8443…). Detecta:

- Cifrados débiles o inseguros (RC4, 3DES…).
- Versiones de TLS obsoletas (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
- Vulnerabilidades conocidas (Heartbleed, ROBOT, CCS injection).
- Configuración de certificados y renegociación segura (`--certinfo`).

## ⏱️ ¿Cuándo se usa?

Después del paso 7 (Gobuster). Se ejecuta **solo si** el paso 3 (Nmap detallado) detectó
puertos con túnel SSL/TLS. Lo llama `run_target.sh`, **una vez por puerto TLS**, de forma
secuencial.

## ▶️ Cómo se usa

```bash
# TLS directo (https, imaps, ldaps…)
bash scripts/host/step8_sslyze.sh <IP> <PORT> tls

# STARTTLS (smtp, imap, pop3, ftp, ldap, rdp, postgres…)
bash scripts/host/step8_sslyze.sh <IP> <PORT> starttls <PROTOCOLO>

# Ejemplos reales
bash scripts/host/step8_sslyze.sh 10.155.10.15 443
bash scripts/host/step8_sslyze.sh 10.155.10.15 25 starttls smtp
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP del objetivo, puerto TLS y modo (`tls` o `starttls` con su protocolo). La
  lista de puertos TLS la detecta `detect_tls_ports.py` desde `nmap_detailed.json`
  (o `nmap_detailed.xml` como fallback).
- **Salida:** `evidence/<IP>/sslyze_<PORT>.json` — el análisis completo en formato JSON
  (incluye `--certinfo`).

## 🧠 Detalles importantes

- **Optimización multiprotocolo (2026-08-31):** SSLyze ya no depende de `web_endpoints.txt`;
  usa `detect_tls_ports.py`, que analiza el JSON de Nmap (Step 3) para encontrar puertos TLS.
- **Detección de STARTTLS:** servicios como SMTP, IMAP, POP3, FTP, LDAP, RDP y PostgreSQL
  negocian TLS después de establecer la conexión (STARTTLS). SSLyze lo soporta con
  `--starttls <protocolo>`.
- **Comando:** SSLyze se ejecuta en modo silencioso (`--quiet`) con información de
  certificados (`--certinfo`).
- **Workaround Bash 3.2 (macOS):** como SSLyze puede ejecutarse sin argumentos extra (TLS
  directo), el script usa `"${ARGS[@]+"${ARGS[@]}"}"` para evitar el error "unbound variable"
  con arrays vacíos.
- **Timeout:** SSLyze 6.x no expone flag CLI de timeout; el valor en `stealth.yaml`
  (`sslyze_connect_timeout`) es el umbral que usa el Orchestrator para esperar antes de
  declarar fallo.

## ⚠️ Notas

- Si no hay puertos TLS → `skipped_no_tls` (el pipeline continúa sin problema).
- SSLyze **no modifica nada** en los servidores: solo analiza la configuración TLS.
- Instalación: en macOS vía `pipx install sslyze`; en Kali/Docker vía `pip install sslyze`.
