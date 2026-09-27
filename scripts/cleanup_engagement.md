# `cleanup_engagement.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **limpiador del proyecto**: cuando termina el trabajo con un cliente (todo el pipeline:
escaneos, planes de explotación, investigación de CVEs, informes y entregables) borra en un solo
paso toda la evidencia y deja el repositorio **limpio y listo para el próximo cliente**.

## ⏱️ ¿Cuándo se usa?

Al **final del engagement**, después de entregar los informes al cliente. Es el último paso del
flujo y el primero que conviene correr antes de empezar uno nuevo.

## ▶️ Cómo se usa

```bash
# 1) Simular primero (NO borra nada — recomendado, es el comportamiento por defecto)
bash scripts/cleanup_engagement.sh

# 2) Ejecutar la limpieza (pide confirmación Y/N)
bash scripts/cleanup_engagement.sh --yes

# 3) Ejecutar sin preguntar (para automatizar)
bash scripts/cleanup_engagement.sh --force
```

### Opciones

| Opción | Efecto |
|---|---|
| *(sin flags)* | Simulación (`--dry-run`): muestra el plan y el espacio a liberar, no borra nada. |
| `--yes` | Ejecuta la limpieza (pide confirmación Y/N antes de borrar). |
| `--force` | Ejecuta la limpieza sin pedir confirmación. |
| `--keep-config` | No toca `config/scope.json` ni `config/approved_commands.md`. |
| `--no-recreate` | No recrea las carpetas vacías al final. |
| `--dry-run` | Fuerza la simulación (comportamiento por defecto). |
| `-h`, `--help` | Muestra la ayuda. |

## 📥 Entrada / 📤 Salida

- **Entrada:** las carpetas con datos del cliente — `evidence/`, `reports/`, `plans/`,
  `cve_research/`, `logs/`, `CLIENTE/` (y `outputs/` en la raíz si existe), además de
  `config/approved_commands.md` y `config/scope.json`.
- **Salida:** proyecto limpio, con las carpetas de trabajo vacías listas para el próximo cliente
  y `config/scope.json` restaurado desde la plantilla de ejemplo (sin IPs reales).

## ⚠️ Notas

- **No se puede deshacer**: la evidencia se elimina de forma definitiva (`rm -rf`). Corré primero
  el `--dry-run` y, si hace falta conservar algo para la entrega, copialo fuera del repo antes.
- **Configuración**: `config/scope.json` se restaura desde `config/scope.json.template` (la
  plantilla sin datos reales) y `config/approved_commands.md` se elimina porque la Fase 0 del
  próximo engagement lo regenera solo. Usá `--keep-config` si no querés tocarlos.
- **Pipeline activo**: si el escaneo está corriendo (hay un lock activo en `evidence/`) el script
  **aborta** automáticamente para no borrar evidencia a mitad de una corrida.
- **Lo que nunca borra**: código fuente, `scripts/`, `specs/`, `openspec/`, `tools/`,
  `config/stealth.yaml`, `config/scope.json.template`, `.cline/`, `.clinerules/` ni `.git/`.