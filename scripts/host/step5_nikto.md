# `step5_nikto.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 5 del pipeline**: usa la herramienta **Nikto**, un escáner de seguridad web que
revisa un sitio concreto buscando **archivos y directorios conocidos, malas configuraciones y
errores** (por ejemplo, archivos de backup expuestos, servidores desactualizados, headers mal
configurados).

Se ejecuta **una vez por cada sitio web** encontrado, de forma secuencial.

## ⏱️ ¿Cuándo se usa?

Después del paso 2 (que dejó la lista de sitios web). Lo corre `run_target.sh` para cada web.

## ▶️ Cómo se usa

```bash
# Recibe: objetivo, URL del sitio y puerto
bash scripts/host/step5_nikto.sh 10.155.10.15 http://10.155.10.15:8082 8082
```

## 📥 Entrada / 📤 Salida

- **Entrada:** IP, URL del sitio y puerto.
- **Salida:** `evidence/<IP>/nikto_<puerto>.json` — los hallazgos de ese sitio en formato JSON.

## 🧠 Detalles importantes

- El tiempo máximo por sitio sale de la configuración de sigilo (`config/stealth.yaml`).
- No revisa la web si la dirección no responde (evita colgarse).