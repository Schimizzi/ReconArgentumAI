# `step6_whatweb.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **paso 6 del pipeline**: usa la herramienta **WhatWeb** para **identificar la tecnología**
de cada sitio web del objetivo (qué software o plataforma usa: WordPress, ASP.NET, Apache,
IIS, cierta versión de jQuery, etc.).

Esa "huella" tecnológica sirve para saber contra qué buscar vulnerabilidades conocidas.

## ⏱️ ¿Cuándo se usa?

Después del paso 2 (que dejó la lista de sitios web). 

> ⚠️ **Importante:** en el proyecto, el usuario decidió en la Fase 0 **saltar este paso**
> (WhatWeb queda `skipped`). Por eso en la práctica no se ejecuta, pero el script está listo
> por si se quiere activar.

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