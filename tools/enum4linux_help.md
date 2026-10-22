# ENUM4LINUX - Reference Help
> VERIFICADO: **enum4linux-ng 1.3.10** (paquete Kali `enum4linux-ng`; dependencias
> `python3-impacket python3-ldap3 python3-yaml samba-common-bin smbclient`) y **enum4linux 0.9.1**
> (paquete Kali `enum4linux`, Perl; dependencias `ldap-utils perl polenum samba`).
> NO existe en macOS (no hay paquete oficial): el framework lo ejecuta **solo en Linux/Debian o contenedor**.

## QUÉ ES
enum4linux es un wrapper sobre las herramientas Samba (`nmblookup`, `net`, `rpcclient`, `smbclient`)
más `polenum` y LDAP propios (en la versión ng) para enumerar información de Windows/Samba: usuarios,
grupos, política de contraseñas, shares, servicios/impresoras e información de dominio (LDAP) usando
sesión nula (null session). En este proyecto es el **Step 12** del pipeline, **solo lectura** (R2) y
solo para targets con TCP 139/445 abiertos.

## FLAGS PRINCIPALES - enum4linux-ng (v1.3.10)
- `-A` - Toda la enumeración simple: `-U -G -S -P -O -N -I -L`. **NO USAR en este proyecto** (incluye
  write checks sobre shares). Usar `-As`.
- `-As` - Igual que `-A` pero sin NetBIOS lookup (`-U -G -S -P -O -I -L`). Es el **modo por defecto
  del Step 11**.
- `-U` / `-G` / `-Gm` - usuarios / grupos / grupos con miembros (RPC).
- `-S` - shares (RPC).
- `-P` - política de contraseñas (password policy).
- `-O` - información de OS (RPC).
- `-L` - información adicional de dominio vía LDAP/LDAPS (solo DCs).
- `-I` - información de impresoras (RPC).
- `-R [BULK_SIZE]` - RID cycling para enumerar usuarios (no está incluido en `-A`). **Opt-in** en
  este proyecto (flag `--rid`) y requiere aprobación explícita en Fase 0.
- `-N` - NetBIOS names lookup (similar a nbtstat).
- `-s SHARES_FILE` - fuerza bruta de nombres de shares. Opt-in, mismo criterio que `-R`.
- `-w DOMAIN` - workgroup/dominio manual (si no, autodetecta). El Step 11 lo pasa **autodetectado
  de la evidencia** (smb-os-discovery o `ldapServiceName`).
- `-u USER` / `-p PW` / `-K TICKET_FILE` / `-H NTHASH` / `--local-auth` - autenticación.
  **NO usar en este proyecto** (R2: solo anónimo).
- `-d` - detalle en usuarios/grupos (aplica a `-U`, `-G` y `-R`).
- `-k USERS` / `-r RANGES` - usuarios conocidos y rangos RID (default 500-550,1000-1050).
- `-t TIMEOUT` - timeout de conexión en segundos. Es `{{enum4linux_timeout_seconds}}` de `stealth.yaml`.
- `-v`, `--keep` - verbose y conservar la config Samba temporal tras la corrida.
- `-oJ OUT_JSON_FILE` / `-oY OUT_YAML_FILE` / `-oA OUT_FILE` - export JSON / YAML / ambos
  (la extensión se agrega automáticamente).

## FLAGS PRINCIPALES - enum4linux (Perl, v0.9.1) [fallback]
- `-a` - Toda la enumeración simple (`-U -S -G -P -r -o -n -i`).
- `-U`, `-S`, `-G`, `-P`, `-o`, `-i`, `-n`, `-M` - usuarios, shares, grupos, política de
  contraseñas, OS, impresoras, NetBIOS y lista de máquinas.
- `-r -R <rangos> -K <n>` - RID cycling (opt-in aquí, igual que en ng).
- `-l` - información limitada vía LDAP 389/TCP (solo DCs).
  (`-L`, `-N`, `-D`, `-f` de enum.exe NO están implementados en esta versión.)
- `-w <workgroup>` / `-k <usuarios>` / `-s <archivo de shares>` / `-d` / `-v` / `-u` / `-p` -
  mismos conceptos que en ng.
- `-A` - Aggressive (write checks sobre shares). **Prohibido en este proyecto**.

## EJEMPLOS ÚTILES (modo pasivo anónimo - lo que genera el Step 11)
```bash
# enum4linux-ng (Linux): -As sin NetBIOS, workgroup autodetectado, timeout de stealth.yaml
enum4linux-ng -As -w <WORKGROUP> -t {{enum4linux_timeout_seconds}} -oA evidence/<target>/enum4linux <IP>

# Fallback Perl:
enum4linux -U -S -G -P -o -l -w <WORKGROUP> <IP>

# Con RID cycling (SOLO con aprobación explícita en Fase 0):
enum4linux-ng -As -R 200 -w <WORKGROUP> -t {{enum4linux_timeout_seconds}} <IP>
```

## NOTAS PARA EL AGENTE
- **Guard de plataforma:** el Step 11 NO se ejecuta en macOS (`uname -s` = Darwin ->
  `skipped_unsupported_os`, sin tráfico). El framework corre enum4linux **solo en Linux/Debian o contenedor**.
- **Gate Service-Based:** solo si TCP 139/445 están abiertos (ng aborta si no puede establecer
  sesión SMB). Sin 139/445 -> `skipped_no_smb` y no se genera tráfico hacia el target.
- **Nunca** credenciales (`-u`/`-p`/`-H`/`-K`) ni `-A` (write checks): es enumeración anónima de solo
  lectura (R2).
- **Timeout** siempre desde `{{enum4linux_timeout_seconds}}` (R5), nunca hardcodeado.
- **Evidencia** en `evidence/<target>/` (pipeline) o `CLIENTE/<IP>/outputs/` (manual):
  `enum4linux.txt` (primera línea = comando ejecutado) + `enum4linux.json`/`enum4linux.yaml`.
  **Solo se conserva** si hubo sesión establecida y al menos una sección con datos; si no, se elimina.
- El Agente 6 (`scripts/make_vuln_report.py`) tiene un parser `parse_enum4linux()` dedicado; si se
  agregan archivos nuevos, el fallback genérico los detecta igual.
- **Riesgo de detección ALTO** en AD auditado (binds anónimos LDAP/SMB y `lookupsids`): usar solo en
  ventanas autorizadas.
- Reflejo de los comandos aprobados en Fase 0: este step solo usa el modo pasivo anónimo salvo que el
  usuario apruebe RID cycling.
