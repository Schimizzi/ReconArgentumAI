# `step4_nuclei.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 4 del pipeline**: usa la herramienta **Nuclei**, que busca **vulnerabilidades
conocidas** en todos los puertos abiertos usando "plantillas" (pequeños programas de prueba
escritos por la comunidad de seguridad).

Nuclei es "multiprotocolo": además de aplicaciones web, cubre servicios de red (SSH, DNS, TLS,
etc.), con lo cual se examina **todo lo abierto**, no solo páginas web.

## ⏱️ ¿Cuándo se usa?

Siempre que haya al menos un puerto abierto. Lo corre `run_target.sh`.

## ▶️ Cómo se usa

```bash
bash scripts/host/step4_nuclei.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/open_ports.txt`.
- **Salida:** `evidence/<IP>/nuclei.json` — las vulnerabilidades detectadas en formato JSON
  (una por línea), y un mensaje con cuántos hallazgos hubo.

## 🧠 Detalles importantes

- Por defecto solo reporta severidades **crítica, alta y media** (para no inundar de ruido).
- Rate de peticiones, timeouts y concurrencia se toman de `config/stealth.yaml` (bajo ruido).
- La primera vez que se usa descarga automáticamente las plantillas de Nuclei (necesita internet).