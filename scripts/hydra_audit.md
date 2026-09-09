# `hydra_audit.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un script de **auditoría manual de credenciales débiles** con **Hydra**. Revisa si los
servicios de red de un objetivo autorizado (FTP, SSH, Redis, RDP, bases de datos, paneles web…)
aceptan contraseñas fáciles de adivinar. **No forma parte del pipeline de Fase 1**: se ejecuta
**bajo demanda**, solo cuando el analista lo decide (ej. cuando un puerto parece requerir
validación de credenciales).

## ⁉️ ¿Qué significa el resultado?

Por cada servicio auditado el script responde **una** de tres cosas:

| Resultado | Significado |
|---|---|
| 🟥 **`VULNERABLE`** | Hydra **encontró un login válido** con la lista probada. Es un hallazgo: se guarda evidencia en `evidence/<IP>/hydra_<servicio>_<puerto>.txt`. |
| 🟩 **`NO_VULNERABLE`** | Hydra **probó la lista completa (hasta 25 intentos) sin bloqueos** y **no** encontró login válido. Con esa lista, el servicio no es vulnerable a fuerza bruta. |
| 🟧 **`INCONCLUSO`** | Hydra **no pudo terminar la lista completa**: se cortó por watchdog, hubo `[ERROR]`, timeout, bloqueo (`too many bad logins`, etc.) o el servicio no respondió. **No se puede afirmar "no vulnerable"**; queda el motivo en el log. |

> ⚠️ "No vulnerable" es siempre **con la lista probada**. Si cambiás la wordlist, el resultado
> puede cambiar (por eso todo queda registrado en `logs/hydra.log`).

## ⏱️ ¿Cuándo se usa?

- Después de correr la **Fase 1** (para que exista `evidence/<IP>/` con los puertos abiertos),
  cuando querés **evidenciar** que un servicio tiene credenciales débiles.
- Para un puerto puntual que "pida a gritos" una prueba de autenticación (21, 22, 1433, 3306,
  3389, 6379, …).
- **Nunca** como paso automático del pipeline: es **manual y con autorización** por decisión del operador.

## ▶️ Cómo se usa

```bash
# UNA corrida sobre TODOS los targets autorizados × TODOS sus puertos auditables:
bash scripts/hydra_audit.sh --all

# Igual pero solo ciertos servicios:
bash scripts/hydra_audit.sh --all --services ftp,ssh,redis

# Un target puntual, todos sus puertos auditables (desde la evidencia de Fase 1):
bash scripts/hydra_audit.sh 10.150.40.50

# Un target + un servicio puntual:
bash scripts/hydra_audit.sh 10.150.40.50 ftp

# Con tus propias credenciales/wordlists (sigue topando en 25 intentos):
bash scripts/hydra_audit.sh 10.150.40.50 ssh -L users.txt -P passwords.txt
bash scripts/hydra_audit.sh 10.150.40.50 -L users.txt -P passwords.txt -C combos.txt

# Re-auditar sobrescribiendo evidencia previa (default: no-clobber):
bash scripts/hydra_audit.sh --all --force

# Previsualizar los comandos sin ejecutarlos:
bash scripts/hydra_audit.sh --all --dry-run
```

**Reglas automáticas del script (no hay que configurarlas):**

- **Alcance (R1):** solo targets de `config/scope.json` no excluidos. Un IP fuera de scope
  aborta la corrida.
- **Límite de 25 intentos** por servicio (desde `config/stealth.yaml`, `hydra_max_attempts`):
  trunca la lista más grande y **avisa**. Es fuerza bruta **limitada**, solo para evidenciar
  la vulnerabilidad, no para romper el servicio.
- **Usuarios/passwords por defecto:** si no pasás `-L`/`-l`/`-P`/`-p`/`-C` usa
  `root, admin, test, guest, user` + `tools/seclists_common.txt` (truncada a 25 intentos).
- **Velocidad baja + delays:** threads `-t` desde `stealth.yaml` (`hydra_threads: 4`),
  RDP siempre con `-t 1`, y los delays del pipeline (`delay_between_tools_seconds`,
  `delay_between_targets_minutes`) entre auditorías.
- **`-f`:** hydra corta en el **primer** login encontrado (no sigue probando).
- **Wordlist default de contraseñas extraídas de `tools/seclists_common.txt`** (cache del repo).

## 📥 Qué necesita / 📤 qué genera

- **Entrada:** `config/scope.json` (obligatorio, R1) y, en modo `--all`/target-auto, la
  evidencia `evidence/<IP>/open_ports.txt` (o `nmap_detailed.xml`) de una Fase 1 previa.
  Para `<IP> <servicio>` no hace falta evidencia: audita el servicio que le indicás.
- **Salidas:**
  - `logs/hydra.log` — **log central acumulado con TODAS las ejecuciones** (comando, intentos,
    resultado, hallazgo y **salida verbosa completa de hydra**). Nunca se borra.
  - `evidence/<IP>/hydra_<servicio>_<puerto>.txt` — **solo si hay hallazgo** (`VULNERABLE`).
    Si ya existe una carpeta `CLIENTE/<IP>/outputs`, se copia ahí y el **Agente 6 lo detecta
    automáticamente** en la próxima corrida (patrón del proyecto).

## ⚠️ Notas

- **Fuerza bruta = tráfico activo e intrusivo.** Solo sobre infraestructura **autorizada por
  escrito** para ese target. El script arranca `--all` sin pedir confirmación (requisito del
  operador): mejor revisá antes qué targets contiene `config/scope.json`.
- **`--dry-run`** imprime los comandos exactos que ejecutaría (útil para revisar antes).
- **No-clobber:** si la evidencia de un servicio ya existe, la corrida la salta (`SKIP`) salvo
  `--force`.
- **Estado `INCONCLUSO` NO es "no vulnerable"**: significa que no se pudo completar la prueba
  (bloqueo, timeout, firewall). Revisá el detalle en `logs/hydra.log`.
- **R2:** el script nunca explota el acceso; se limita a comprobar LOGIN y conservar la
  evidencia del hallazgo.
- La tabla **puerto → módulo Hydra** y los ejemplos por servicio están en
  [`tools/hydra_help.md`](../tools/hydra_help.md).