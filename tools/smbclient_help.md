# SMBCLIENT — Reference Help
> VERIFICADO: **smbclient 4.24.6** instalado en el host macOS (`/opt/homebrew/bin/smbclient`,
> fórmula brew `samba`). Soporta `-L`, `-N`, `-t`, `-c`, `--max-protocol`.
> En Docker/Kali viene con el paquete `smbclient` (apt).

## QUÉ ES
smbclient es el cliente SMB/CIFS de Samba. Se usa en este proyecto para **enumerar
recursos compartidos con null session** (`-N`: sin credenciales) cuando el Step 3 detecta
SMB (TCP 139/445). Es **solo lectura** (listar shares y contenido), nunca explota (R2).

## FLAGS PRINCIPALES (v4.24.6)
- `-L, --list=HOST` — Lista los recursos compartidos de un host (`smbclient -L //IP -N`).
  Formato de salida: tabla con columnas `Sharename`, `Type` (`Disk`/`IPC`/`Printer`), `Comment`.
- `-N, --no-pass` — Null session: no preguntar contraseña (acceso anónimo).
- `-t, --timeout=SECONDS` — Timeout por operación. ← `{{smbclient_timeout_seconds}}` de `stealth.yaml`.
- `-c, --command=STRING` — Ejecuta comandos SMB separados por `;` (ej. `'ls'`, `'cd dir; ls'`, `'exit'`).
- `-p, --port=PORT` — Puerto a conectar (por defecto 445; usar `139` si solo hay netbios-ssn).
- `-U, --user=[DOMAIN/]USERNAME[%PASSWORD]` — Con credenciales. **NO usar en este script** (R2/no-cred).
- `-m, --max-protocol=MAXPROTOCOL` — Forzar protocolo máximo (`SMB3`, `SMB2`, `NT1`). Útil si
  el host cae con versiones nuevas (ej. `-m SMB2` o `-m NT1`).
- `-g, --grepable` — Salida fácil de parsear (líneas `|share|Disk|...|`).
- `-V, --version` — Versión.

## EJEMPLO ÚTIL (enumeración null session — VERIFICADO en 4.24.6)
```bash
# 1) Listar shares — deja la salida cruda como evidencia:
smbclient -L //<IP> -N -t {{smbclient_timeout_seconds}} > outputs/smbclient_shares.txt

# 2) Ver el contenido de un share tipo Disk accesible:
smbclient //<IP>/<share> -N -t {{smbclient_timeout_seconds}} -c 'ls' > outputs/smbclient_<share>.txt

# 3) Si falla con protocolo nuevo, bajar el máximo:
smbclient -L //<IP> -N -m SMB2 -t {{smbclient_timeout_seconds}}
```

## NOTAS PARA EL AGENTE
- **Nunca** usar `-U ...%password` ni montar el share: es enumeración anónima de solo lectura (R2).
- La detección de SMB sale del `nmap_detailed.xml` del Step 3 (puertos 139/445 con
  `state="open"`); no re-escanear por puertos. El script resuelve solo la carpeta del target
  (`CLIENTE/<IP>_vuln` / `_no_vuln`) si se le pasa la IP pura, y el modo `--all` recorre
  todos los targets de `CLIENTE/` con `nmap_detailed.xml` (secuencial, respetando gate de
  ping, no-clobber y `--force`).
- **Gate de ping:** si el target no responde a ICMP → `skipped_no_ping`, no ejecutar smbclient.
- La evidencia se guarda en `CLIENTE/<IP>/outputs/` → la detecta el Agente 6 automáticamente.
  **Solo se conserva si hay `Anonymous login successful` o un share `Disk` accesible; si no,
  se elimina** (ruido sin hallazgo).
- **Resumen `--all`:** `CLIENTE/smbclient_checks/smbclient_summary.txt` (log acumulado por
  corrida, patrón de `iis_shortname_checks`). Columnas: estado (`ejecutado`, `no_ping`,
  `no_smb`, `skip_existente`, `error`), ports, shares_disk, accesibles, `anon_login` y
  detalle. `con_vuln` se cuenta solo con `accesibles > 0` (share Disk legible). `anon_login=si`
  es una señal de null session habilitada (condición a validar), **no** un hallazgo.
- **No-clobber:** si `smbclient_shares.txt` o un `smbclient_<share>.txt` ya existe, no
  sobrescribirlo; usar `--force` en `scripts/host/step10_smbclient_enum.sh` solo si se quiere re-enumerar.
- `smbclient -L` puede devolver rc≠0 incluso habiendo impreso la lista (fallas de resolución);
  la salida cruda es la evidencia que cuenta, no el rc.
- Reflejo de los comandos aprobados en Fase 0: este script es de ejecución manual y solo
  usa `-L`, `-N`, `-t` y `-c 'ls'`.