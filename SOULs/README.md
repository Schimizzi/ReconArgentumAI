# SOULs — Perfiles Hermes Agent para ReconArgentumAI

> 📦 **Contenido del repositorio.** Esta carpeta contiene los perfiles de comportamiento de los **agentes Hermes** que ejecutan el pipeline `ReconArgentumAI`. Vive en el repo para que cualquier persona que clone el proyecto pueda instalarla en su propia máquina.

## 🤖 ¿Qué es un SOUL?

En **Hermes Agent** (framework de agentes CLI), un `SOUL.md` define la identidad, las reglas y las instrucciones de comportamiento de un bot. Es lo que Hermes carga en el contexto del agente al invocarlo.

## 📁 Estructura

```
SOULs/
├── orchestrator/    OrchestratorBot  — coordina las 6 fases del pipeline
│   └── SOUL.md
├── recon/           ReconBot         — ejecuta la Fase 1 (escaneo)
│   └── SOUL.md
├── analyst/         AnalystBot       — Fase 2a (CVE research) + Fase 2b (plan de explotación)
│   └── SOUL.md
└── reporter/        ReporterBot      — Fase 3, 4 (reportes) + Fase 5 (QA)
    └── SOUL.md
```

## 🚀 Instalación

Hermes espera cada perfil en `~/.hermes/bots/<nombre_agente>/SOUL.md`.

### Opción 1 — Script automático (recomendado)

```bash
# Desde la raíz del proyecto clonado
bash scripts/install_souls.sh
```

El script:
1. Detecta automáticamente el directorio donde clonaste el proyecto (tu WORKSPACE).
2. Genera una copia de cada SOUL reemplazando la ruta absoluta del proyecto original por la tuya.
3. Instala las 4 copias en `~/.hermes/bots/<agente>/SOUL.md`.
4. Verifica la instalación.

> ⚠️ **Resultado:** los SOULs en `~/.hermes/bots/` quedan apuntando a TU ruta local. Los originales del repo `SOULs/` **no se modifican**.

### Opción 2 — Manual

```bash
# 1. Copia cada perfil a ~/.hermes/bots/
cp -r SOULs/orchestrator ~/.hermes/bots/orchestrator
cp -r SOULs/recon        ~/.hermes/bots/recon
cp -r SOULs/analyst      ~/.hermes/bots/analyst
cp -r SOULs/reporter     ~/.hermes/bots/reporter

# 2. ¡IMPORTANTE! Edita cada SOUL.md y reemplaza la ruta del workspace
#    /Users/claudio/Recon_Workspace/ReconArgentumAI
#    por la ruta absoluta de TU proyecto local.
#    Ejemplo: sed -i 's|/Users/claudio/Recon_Workspace/ReconArgentumAI|/home/tuuser/proyectos/ReconArgentumAI|g' \
#       ~/.hermes/bots/*/SOUL.md
```

## ⚙️ Verificación

```bash
# ¿Están los 4 perfiles instalados?
ls ~/.hermes/bots/*/SOUL.md

# ¿La ruta apunta a tu workspace?
grep -l '/Users/claudio/Recon_Workspace/ReconArgentumAI' ~/.hermes/bots/*/SOUL.md
# Debería devolver NADA (ningún archivo debe contener la ruta del autor original)
```

## 🧪 Prueba rápida (one-shot)

Desde la raíz de tu proyecto, prueba que un agente responde:

```bash
hermes --in ~/.hermes/bots/recon -z "IDIOMA: ESPAÑOL. ¿Cuál es tu rol?" chat
```

## 🔗 Referencias

- **Manual operativo (quién ejecuta qué y cómo):** [`RUNBOOK.md`](../RUNBOOK.md)
- **Specs operativas por agente:** [`specs/`](../specs/)
- **Especificaciones formales OpenSpec:** [`openspec/specs/`](../openspec/specs/)
- **Scripts del pipeline:** [`scripts/`](../scripts/)

## ⚠️ Notas

- Los SOULs contienen rutas absolutas del autor original (`/Users/claudio/Recon_Workspace/ReconArgentumAI`). **Deben re-escribirse** al path local — el script `install_souls.sh` lo hace automáticamente.
- Los perfiles están diseñados para la invocación **One-Shot (`-z`)** desde el Orchestrator. No uses `delegate_task` u otros mecanismos de subagentes internos.