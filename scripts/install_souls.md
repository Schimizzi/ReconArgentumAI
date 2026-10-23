# `install_souls.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Instala, en tu máquina, los **4 perfiles de comportamiento (SOUL)** de Hermes Agent que usa el pipeline:
`orchestrator`, `recon`, `analyst` y `reporter`. Cada perfil es una copia saneada del `SOUL.md` que vive en
`SOULs/` dentro del repo.

## ⏱️ ¿Cuándo se usa?

**Una sola vez por máquina**, si vas a orquestar el pipeline con **Hermes Agent** (`hermes -p <perfil>`).
Si usás Cline/Roo Code con el prompt maestro, **no** hace falta.

> 🖐️ **USO MANUAL — FUERA DEL PIPELINE AUTOMATIZADO.** Ningún step ni agente lo invoca; lo corre el usuario.

## ▶️ Cómo se usa

```bash
# Desde la raíz del proyecto clonado
bash scripts/install_souls.sh
```

## 📥 Entrada / 📤 Salida

- **Entrada:** los `SOULs/<perfil>/SOUL.md` del repo.
- **Salida:** `~/.hermes/profiles/<perfil>/SOUL.md` (4 perfiles), con la ruta del workspace ajustada a tu
  instalación local.

## ⚠️ Notas

- **No modifica** los SOUL del repo: sólo crea copias instaladas.
- Requiere el CLI `hermes` disponible en el `PATH`.
- Si un perfil ya existe, lo actualiza (re-ejecutarlo tras editar un `SOUL.md`).
- También crea `.cline/master_prompt.md` a partir de la plantilla versionada si falta (ver `.gitignore`).
- Detalle y flujo completo: [`SOULs/README.md`](../SOULs/README.md).
