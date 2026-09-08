# `step6_whatweb.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 6 del pipeline**: usa la herramienta **WhatWeb** para **identificar la tecnología**
de cada sitio web del objetivo (qué software o plataforma usa: WordPress, ASP.NET, Apache,
IIS, cierta versión de jQuery, etc.).

Esa "huella" tecnológica sirve para saber contra qué buscar vulnerabilidades conocidas.

## ⏱️ ¿Cuándo se usa?

Después del paso 2 (que dejó la lista de sitios web). 

> ℹ️ **Actualizado (2026-09-07):** el Step 6 pasó a **auto-detección**. Si existe un binario
> WhatWeb (en el `PATH` —Kali lo trae instalado por defecto— o en `tools/WhatWeb/whatweb`) se
> ejecuta y genera `whatweb.json`; si no existe ningún binario, queda `skipped` (mantiene la
> decisión original de Fase 0: "saltar si no está instalado").
>
> ⚠️ Nota histórica: en una versión previa este paso estaba **siempre saltado** (decisión
> Fase 0 / macOS donde se consideró "no instalado"); eso se cambió porque ocultaba un
> fingerprint útil de tecnología en sistemas donde WhatWeb sí está disponible (Kali).

## ▶️ Cómo se usa

```bash
bash scripts/host/step6_whatweb.sh 10.155.10.15
```

## 📥 Entrada / 📤 Salida

- **Entrada:** `evidence/<IP>/web_endpoints.txt` (la lista de sitios web).
- **Salida:** `evidence/<IP>/whatweb.json` — las tecnologías detectadas en formato JSON.

## 🧠 Detalles importantes

- WhatWeb no tiene instalador automático en macOS; se usa el que está en la carpeta `tools/WhatWeb/`.
- Al inicio **limpia** el archivo de salida anterior (WhatWeb agrega resultados si no se limpia).