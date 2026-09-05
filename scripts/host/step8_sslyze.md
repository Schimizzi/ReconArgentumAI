# `step8_sslyze.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 8 (último) del pipeline**: usa la herramienta **SSLyze** para revisar la **seguridad
de las conexiones cifradas (TLS/SSL)** de cada puerto que usa cifrado.

Revisa cosas como:
- ¿Soportan protocolos **viejos e inseguros** (SSLv2, SSLv3, TLS 1.0/1.1)?
- ¿Hay **cifrados débiles** (RC4, 3DES)?
- ¿Hay fallas conocidas (Heartbleed, ROBOT, CCS injection)?
- ¿Reniega de renegociación segura?
- Detalles del **certificado** (`--certinfo`).

## ⏱️ ¿Cuándo se usa?

Después del paso 3 (que dejó identificados los puertos TLS). Lo corre `run_target.sh` **una vez
por puerto TLS**, de forma secuencial.

## ▶️ Cómo se usa

```bash
# TLS directo (ej. 443, 8443, 993…)
bash scripts/host/step8_sslyze.sh 10.155.10.15 443

# STARTTLS (protocolo que negocia el cifrado después de conectarse, ej. smtp/imap)
bash scripts/host/step8_sslyze.sh 10.155.10.15 25 starttls smtp
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP del objetivo, puerto TLS y modo (tls o starttls con su protocolo).
- **Salida:** `evidence/<IP>/sslyze_<puerto>.json` — el análisis completo en formato JSON.

## 🧠 Detalles importantes

- Solo se ejecuta si hay puertos con TLS/SSL detectados; si no, queda `skipped_no_tls`.
- La detección de cuáles puertos son TLS la hace el script helper `detect_tls_ports.py`.