# `step10_smbclient_enum.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un script de **enumeración de recursos compartidos SMB** (las "carpetas compartidas"
de Windows/Linux vía SMB, puertos 139 y 445). Usa la herramienta **smbclient** con
*null session* (es decir, **sin usuario ni contraseña**, solo una conexión anónima),
que es una forma de **solo lectura** de ver qué carpetas comparte un equipo.

## ⏱️ ¿Cuándo se usa?

Cuando ya se escaneó un objetivo con el pipeline y en sus resultados (`outputs/`) aparece
que tiene el **puerto 139 o 445 abierto** (servicios SMB). Sirve para responder:
"¿este equipo comparte carpetas sin necesidad de credenciales?".

Hoy vive en `scripts/host/` y tiene dos modos:

- **Modo manual** (bajo demanda sobre `CLIENTE/`): el flujo original, sin cambios.
- **Modo pipeline** (`--ev-dir`): lo invoca `run_target.sh` en el **Step 10**, apuntando directo
  a `evidence/<IP>/` (donde el pipeline escribe), sin pasar por `CLIENTE/`.

## ▶️ Cómo se usa

### Modo manual (bajo demanda, como siempre)

```bash
# Desde la raíz del proyecto. El script resuelve automáticamente la carpeta del
# target en CLIENTE/ (acepta la IP pura o la carpeta con sufijo _vuln/_no_vuln):
bash scripts/host/step10_smbclient_enum.sh <IP>

# Ejemplo real:
bash scripts/host/step10_smbclient_enum.sh 10.150.40.155
# (si la carpeta real es 10.150.40.155_vuln, el script la encuentra solo)

# TODOS los targets de CLIENTE con nmap_detailed.xml (secuencial, 1 por vez):
bash scripts/host/step10_smbclient_enum.sh --all

# Con otra carpeta de proyecto que no se llame CLIENTE:
bash scripts/host/step10_smbclient_enum.sh 10.150.40.155 OTRO_CLIENTE
bash scripts/host/step10_smbclient_enum.sh --all OTRO_CLIENTE

# Re-enumerar aunque ya exista evidencia previa (la sobrescribe):
bash scripts/host/step10_smbclient_enum.sh 10.150.40.155 --force
bash scripts/host/step10_smbclient_enum.sh --all --force

# Saltar el chequeo de ping (solo si sabés que el host bloquea ICMP):
bash scripts/host/step10_smbclient_enum.sh 10.150.40.155 --no-ping-check
```

### Modo pipeline (lo llama el Step 10 de `run_target.sh`)

```bash
# Apunta directo a un dir de evidencia del pipeline (evidence/<IP>). El XML de
# entrada es <DIR>/nmap_detailed.xml y las salidas van al mismo <DIR>.
bash scripts/host/step10_smbclient_enum.sh --ev-dir evidence/10.150.40.155 --force --no-ping-check
```

> `--force` en modo pipeline porque el pipeline regenera evidencia en cada corrida
> (al contrario del no-clobber del modo manual). `--no-ping-check` porque el target
> ya respondió en los Steps 1-3 de la misma corrida (no se duplica el gate ICMP).

- **Entrada:** el XML de Nmap del paso 3 (`outputs/nmap_detailed.xml`), que el script localiza
  solo: si en `CLIENTE/` la carpeta del target tiene sufijo `_vuln` / `_no_vuln` (como la deja
  `organize_project.py`), la encuentra automáticamente pasándole solo la IP.
- **Salida** (en la misma carpeta `CLIENTE/<IP>/outputs/`):
  - `smbclient_shares.txt` — la lista completa de recursos compartidos.
  - `smbclient_<share>.txt` — el contenido (archivos) de cada recurso accesible vía null session.

  > La evidencia **solo se conserva** cuando la corrida produce un resultado útil: el server
  > acepta **login anónimo** (`Anonymous login successful`) o hay al menos un **share de tipo
  > Disk accesible** (información expuesta). Si no (ej. `session setup failed:
  > NT_STATUS_ACCESS_DENIED`, sin respuesta, etc.), el archivo `smbclient_shares.txt` no se
  > genera/se elimina: es ruido sin hallazgo y no se entrega al Agente 6.
- **Resumen de corrida `--all`** (en `CLIENTE/smbclient_checks/`):
  - `smbclient_summary.txt` — log acumulado por corrida (no se borran corridas previas, igual
    que `iis_shortname_summary.txt`). Por cada target deja: `estado`, `ports`, `shares_disk`,
    `accesibles`, `anon_login` y `detalle`, con el total de `ejecutados / con_vuln /
    anon_login / no_ping / no_smb / skip_existente` al final de cada corrida.

> Los archivos quedan dentro de `outputs/` a propósito: el **Agente 6** (consolidador de
> hallazgos) detecta cualquier archivo nuevo en `outputs/` y lo considera automáticamente
> en la siguiente corrida, sin tocar ningún script.

## ⚠️ Notas

- **No sobrescribe evidencia ya generada (no-clobber):** si `outputs/smbclient_shares.txt` ya
  existe, muestra `[SKIP]` y **no toca nada** (protege lo hecho en corridas anteriores).
  Lo mismo aplica por cada `outputs/smbclient_<share>.txt`. Usá `--force` para re-enumerar
  y sobrescribir.
- **Chequeo de conectividad (ping):** antes de tocar el target, el script verifica que
  responda a **un solo ping** (timeout en `config/stealth.yaml`, `smbclient_ping_timeout_seconds`).
  Si no responde → `skipped_no_ping` y **no se ejecuta ningún comando de smbclient**. Si el
  host bloquea ICMP pero sabés que está vivo, usá `--no-ping-check`.
- **Solo lectura y sin credenciales**: no monta unidades, no escribe archivos y nunca usa
  `-U usuario%password`. Si la null session está denegada, el script lo avisa y deja la
  salida cruda igual (evidencia de que el servicio SMB no permite anónimos).
- Si el objetivo **no tiene** 139/445 abiertos, muestra `skipped_no_smb` y **no genera
  tráfico** hacia él.
- **Evidencia condicional:** si la corrida no produce login anónimo ni shares accesibles,
  el `smbclient_shares.txt` no se conserva (se elimina). Así, solo quedan en `outputs/` los
  targets con hallazgo real (anon) o exposición verificada (shares Disk legibles).
- En el modo `--all`, además del detalle por target en consola, queda el resumen acumulado
  en `CLIENTE/smbclient_checks/smbclient_summary.txt` (mismo patrón de
  `iis_shortname_checks`): ejecutados, targets que no respondieron al ping y targets con
  shares accesibles (potencial hallazgo).
- **`anon_login=si`** marca que el server SMB **acepta** la sesión anónima (null session
  habilitada), pero eso **no** se cuenta como `con_vuln` (vulnerabilidad): solo hay hallazgo
  confirmado cuando `accesibles > 0`, es decir, cuando la null session además permite
  **leer contenido** de un share (información realmente expuesta). Un `anon_login=si` sin
  shares accesibles es una **condición de configuración a validar** por el analista
  (posible hardening / information disclosure), no un hallazgo verificado.
- El timeout de cada operación se lee de `config/stealth.yaml`
  (`smbclient_timeout_seconds`), nunca está fijo en el script.
- **Ética/alcance:** solo debe usarse sobre infraestructura **autorizada**. Buscar carpetas
  compartidas sin permiso es acceso no autorizado a información.