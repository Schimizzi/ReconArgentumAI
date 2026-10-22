# Recon Pipeline Specification

## Purpose

Define la ejecucion secuencial del pipeline de recon contra cada target: el DAG lineal de **12 steps**
sobre las herramientas (agrega LDAP Enum como Step 11 y Enum4linux como Step 12 -solo Linux este ultimo-), los inputs/outputs y
post-procesos por step, el **Service-Based Routing** por step (herramientas multiprotocolo como
Nuclei/Gobuster/SSLyze/IIS-Shortname/SMB-Enum/Enum4linux se ejecutan segun los servicios detectados,
no solo segun endpoints web), los timeouts parametrizados desde `config/stealth.yaml`, el manifest
por target, el manejo de errores, la autodeteccion del scan type de Nmap por privilegios, las
wordlists portables y los workarounds integrados (watchdog Nikto, cutoff Gobuster, -oJ roto).

## ADDED Requirements

### Requirement: Step 12 - Enum4linux (enum4linux-ng / enum4linux)
El sistema SHALL ejecutar `enum4linux-ng` (fallback `enum4linux`) contra el target **solo en Linux** y
**solo si** los puertos TCP 139 o 445 figuran abiertos en `open_ports.txt` (Step 1) o en
`nmap_detailed.xml` (Step 3), mediante `step12_enum4linux_enum.sh --ev-dir <DIR>` (sesion
nula/anonima, solo lectura). El modo por defecto SHALL ser **pasivo y sin credenciales** y SHALL
guardar la salida cruda completa en `evidence/<target>/enum4linux.txt` (primera linea = comando
ejecutado) mas el export estructurado `enum4linux.json`/`enum4linux.yaml` cuando el binario lo
soporte (`-oA`). El timeout SHALL resolverse de `config/stealth.yaml`
(`enum4linux_timeout_seconds`). El sistema SHALL NOT usar la opcion `-A` (Aggressive) de enum4linux
ni escribir en el target (regla R2). RID cycling (`-R`) y el brute force de shares (`-s`) son
opt-in y requieren aprobacion explicita en Fase 0.

#### Scenario: Target con SMB abierto y sesion anonima aceptada (Linux)
- **WHEN** el pipeline corre en Linux, el Step 3 reporta TCP 139 o 445 abierto y el target acepta sesion nula SMB
- **THEN** el Step 12 ejecuta `step12_enum4linux_enum.sh --ev-dir` en modo pasivo y deja `enum4linux.txt` (+ `enum4linux.json`) en el dir de evidencia

#### Scenario: Target sin 139/445 abiertos
- **WHEN** el Step 3 no reporta TCP 139 ni 445 abiertos
- **THEN** el Step 12 queda `skipped_no_smb` y NO se genera trafico hacia el target

#### Scenario: Ejecucion en macOS (Darwin)
- **WHEN** el pipeline corre en macOS
- **THEN** el Step 12 NO se ejecuta, no se envia trafico al target y el manifest registra `skipped_unsupported_os`

#### Scenario: Binario ausente en Linux
- **WHEN** el pipeline corre en Linux y no existe `enum4linux-ng` ni `enum4linux` en el PATH
- **THEN** el Step 12 queda `skipped` sin ejecutar ninguna herramienta y el pipeline continua con el target

#### Scenario: Sesion nula rechazada
- **WHEN** el target responde `NT_STATUS_LOGON_FAILURE` o equivalente (sin sesion anonima)
- **THEN** la evidencia `enum4linux.*` NO se conserva (se elimina) y no quedan archivos de este step

#### Scenario: Workgroup autodetectado
- **WHEN** la evidencia del target trae el workgroup/dominio (smb-os-discovery de `nmap_detailed.xml` o `ldapServiceName`/`defaultNamingContext` de la evidencia LDAP)
- **THEN** el Step 12 lo pasa como `-w` a enum4linux en lugar de depender de la autodeteccion del tool

#### Scenario: RID cycling sin aprobacion
- **WHEN** el operador no aprobo el flag de RID cycling en Fase 0
- **THEN** el Step 12 NO ejecuta `-R` (queda en modo pasivo) y no realiza `lookupsids` masivos

### Requirement: Step 11 - LDAP Enum (ldapsearch)
El sistema SHALL ejecutar `ldapsearch` contra el target **solo si** TCP 389, 636, 3268 o 3269 figura
abierto en `nmap_detailed.xml` (Step 3), mediante `step11_ldap_enum.sh --ev-dir <DIR>`. El step corre tanto
en **Linux** como en **macOS** (sin guard de plataforma). Por defecto SHALL ser **anonimo y de solo lectura**
(root DSE + objeto raiz del dominio). El modo credencializado (`--ldap-user` + `--ldap-pass`, usuarios y SPN)
SHALL ser **opt-in** y requerir aprobacion explicita en Fase 0; el password SHALL pasarse por archivo temporal
0600 (`-y`) y registrarse como `<REDACTED>` en la linea de comando guardada, sin quedar nunca en la evidencia.
El timeout SHALL resolverse de `config/stealth.yaml` (`ldapsearch_timeout_seconds`). SHALL NOT usarse
`ldapmodify`/`ldapadd`/`ldappasswd` (solo busquedas, R2).

#### Scenario: Target con LDAP/GC abierto (Linux o macOS)
- **WHEN** el Step 3 reporta TCP 389, 636, 3268 o 3269 abierto
- **THEN** el Step 11 ejecuta `step11_ldap_enum.sh --ev-dir` y deja `ldapsearch.txt` (root DSE, 1a linea = comando) + `ldapsearch_domain.txt` en el dir de evidencia, en cualquier SO

#### Scenario: Target sin puertos LDAP
- **WHEN** el Step 3 no reporta 389, 636, 3268 ni 3269
- **THEN** el Step 11 queda `skipped_no_ldap` y NO se genera trafico

#### Scenario: Modo anonimo (default)
- **WHEN** el operador no aprobo credenciales en Fase 0
- **THEN** el Step 11 consulta solo el root DSE y el objeto raiz del dominio, sin `-D`/`-y`

#### Scenario: Modo credencializado aprobado
- **WHEN** el operador aprobo `--ldap-user`/`--ldap-pass` en Fase 0
- **THEN** el Step 11 agrega `ldapsearch_users.txt` y `ldapsearch_spn.txt` y la linea de comando guardada muestra `-y <REDACTED>`

#### Scenario: Password fuera de la evidencia
- **WHEN** el Step 11 corre en modo credencializado
- **THEN** ningun archivo de la evidencia contiene el password y el archivo temporal se elimina al terminar

#### Scenario: Binario ausente
- **WHEN** no existe `ldapsearch` en el PATH
- **THEN** el Step 11 queda `skipped` sin generar trafico

#### Scenario: LDAPS cuando no hay 389
- **WHEN** el unico puerto LDAP abierto es 636 o 3269
- **THEN** el Step 11 usa `ldaps://` con `LDAPTLS_REQCERT=never` (certificados autofirmados de DC)

## MODIFIED Requirements

### Requirement: DAG secuencial de recon
El sistema SHALL ejecutar los steps en este orden lineal, uno por target y sin paralelismo: (1) Nmap
port scan -> (2) HTTPX probe web -> (3) Nmap -sC -sV detallado solo sobre puertos abiertos ->
(4) Nuclei -> (5) Nikto -> (6) WhatWeb -> (7) Gobuster/Dirsearch -> (8) SSLyze -> (9) IIS Shortname
(8.3) -> (10) SMB Enum (smbclient) -> (11) LDAP Enum (ldapsearch; Linux y macOS) → (12) Enum4linux (enum4linux-ng; solo en Linux).

#### Scenario: Ejecucion completa de un target con servicios web
- **WHEN** el pipeline procesa un target que tiene al menos un endpoint web confirmado por HTTPX
- **THEN** los steps aplicables se ejecutan en orden (1 a 11), con el delay de stealth entre cada uno, y los no aplicables quedan con su estado skipped_* de Service-Based Routing

#### Scenario: Ejecucion en macOS (Darwin)
- **WHEN** el pipeline corre en macOS
- **THEN** los steps 1 a 11 se ejecutan normalmente y el Step 12 se registra como skipped_unsupported_os en el manifest (sin trafico)

### Requirement: Timeouts parametrizados desde stealth.yaml
El sistema SHALL NO hardcodear timeouts, rate-limits ni cantidades de threads en los comandos base.
Todos esos valores SHALL provenir de variables de `config/stealth.yaml` (ej. `httpx_timeout_seconds`,
`nuclei_rate_limit`, `gobuster_threads`, `smbclient_timeout_seconds`, `enum4linux_timeout_seconds`, `ldapsearch_timeout_seconds`),
de modo que un cambio en el archivo se refleje en todos los comandos.

#### Scenario: Cambio de timeout en stealth.yaml
- **WHEN** el usuario modifica `httpx_timeout_seconds` de 10 a 20 en `config/stealth.yaml`
- **THEN** el comando de HTTPX propuesto y ejecutado usa 20s sin necesidad de editar la spec del pipeline

#### Scenario: Timeout de enum4linux desde stealth.yaml
- **WHEN** el usuario modifica `enum4linux_timeout_seconds` en `config/stealth.yaml`
- **THEN** el Step 12 usa ese valor como `-t` al invocar enum4linux, sin editarlo en el script

#### Scenario: Timeout de LDAP desde stealth.yaml
- **WHEN** el usuario modifica `ldapsearch_timeout_seconds` en `config/stealth.yaml`
- **THEN** el Step 11 usa ese valor como `-o nettimeout` y `-l` al invocar ldapsearch, sin editarlo en el script

### Requirement: Service-Based Routing por step (Optimización Multiprotocolo)
El sistema SHALL decidir la ejecución de los Steps 4-12 según los servicios detectados por step
(Service-Based Routing, 2026-08-31), NO aplanar los steps ante la ausencia de web. El sistema
SHALL ejecutar: **Nuclei (Step 4)** SIEMPRE que `open_ports.txt` tenga ≥1 puerto abierto,
apuntando a las líneas `IP:PORT` para aplicar plantillas multiprotocolo (red, SSH, DNS, TLS,
además de web). **Nikto (Step 5) y WhatWeb (Step 6)** SHALL ejecutarse solo si
`web_endpoints.txt` no está vacío. **Gobuster (Step 7)** SHALL rutear por modo: `dir` si hay
web, `dns` si el target es un dominio (no IP cruda), y `tftp` si el puerto 69/UDP está abierto
(probe UDP parametrizado desde `stealth.yaml`). **SSLyze (Step 8)** SHALL ejecutarse contra
los puertos con túnel SSL/TLS detectados en la salida de Nmap del Step 3 (tunnel="ssl",
servicios TLS conocidos, puertos TLS bien conocidos: 443/465/636/990/992/993/995/3389-RDP/
5986-WinRM/etc.), con soporte `--starttls` (rdp, smtp, imap, pop3, ftp, ldap, postgres, mysql, xmpp).
**IIS Shortname (Step 9)** SHALL ejecutarse solo si `web_on` es verdadero (hay endpoints web
confirmados por HTTPX) y el `httpx.json` del Step 2 reporta la firma del servidor
`Microsoft-IIS`/`IIS` en el campo `webserver`; se ejecuta con `step9_iis_shortname_scan.py --ev-dir`
sobre el dir de evidencia del target. **SMB Enum (Step 10)** SHALL ejecutarse solo si los
puertos TCP 139 o 445 figuran abiertos en `open_ports.txt` (Step 1) o en `nmap_detailed.xml`
(Step 3), mediante `step10_smbclient_enum.sh --ev-dir` (null session, solo lectura).
**LDAP Enum (Step 11)** SHALL ejecutarse solo si TCP 389, 636, 3268 o 3269 esta abierto, en **Linux y macOS**, con root DSE anonimo por defecto y modo credencializado **opt-in** (usuarios/SPN) aprobado en Fase 0. **Enum4linux (Step 12)** SHALL ejecutarse solo en Linux y solo si los puertos TCP 139 o 445
figuran abiertos, mediante `step12_enum4linux_enum.sh --ev-dir` (sesión nula/anónima, solo lectura);
en macOS el step queda `skipped_unsupported_os`.

#### Scenario: Target sin web pero con puertos abiertos no-web
- **WHEN** tras el Step 2 `web_endpoints.txt` está vacío pero `open_ports.txt` tiene SMB/RDP/SSH abiertos
- **THEN** Nuclei se ejecuta contra `open_ports.txt` (plantillas no-web), Nikto/WhatWeb se marcan
  `skipped_no_web`, Gobuster evalúa su modo según dominio/UDP69, SSLyze audita los puertos TLS
  detectados (ej. 3389-RDP con `--starttls rdp` o 5986-WinRM), IIS Shortname queda
  `skipped_no_iis` (no hay web), SMB Enum se ejecuta si 139/445 están abiertos y Enum4linux
  (Step 12) también en Linux (o quedan `skipped_no_smb` si no lo están).

#### Scenario: Target con web no-IIS
- **WHEN** hay endpoints web pero el `httpx.json` no reporta `webserver` con `IIS`/`Microsoft-IIS`
- **THEN** el Step 9 queda `skipped_no_iis` y no se envía ningún request de tilde enumeration

#### Scenario: Target con SMB abierto
- **WHEN** `open_ports.txt` o `nmap_detailed.xml` reporta TCP 139 o 445 abierto
- **THEN** el Step 10 ejecuta `step10_smbclient_enum.sh --ev-dir evidence/<target>` (null session
  `-N`, solo lectura) y genera `smbclient_shares.txt`/`smbclient_<share>.txt`
- **AND** en Linux el Step 12 ejecuta `step12_enum4linux_enum.sh --ev-dir evidence/<target>` y genera
  `enum4linux.txt` (+ `enum4linux.json`)

#### Scenario: Puerto TLS no-https detectado por Nmap
- **WHEN** el Step 3 detecta un servicio con `tunnel="ssl"` o un puerto TLS conocido (993 IMAPS, 990 FTPS, 3389 RDP, 5986 WinRM)
- **THEN** SSLyze se ejecuta contra ese puerto (con `--starttls` cuando aplique) y genera `sslyze_<port>.json`

#### Scenario: Target es un dominio
- **WHEN** el target del engagement es un nombre de dominio (no una IP cruda)
- **THEN** Gobuster ejecuta el modo `dns` (`gobuster dns -d <dominio> -w <wordlist DNS>`)

#### Scenario: Puerto 69/UDP abierto
- **WHEN** el probe UDP 69 (parametrizado desde `config/stealth.yaml`) reporta el puerto 69 UDP abierto
- **THEN** Gobuster ejecuta el modo `tftp` (`gobuster tftp -s <target> -w <wordlist>`)

#### Scenario: Sin puertos abiertos en Step 1
- **WHEN** `open_ports.txt` queda vacío tras un Step 1 exitoso
- **THEN** el target se registra `incomplete` y los Steps 2-12 quedan `skipped` en el manifest

#### Scenario: Target con AD y sesión nula en Linux
- **WHEN** el target acepta sesión nula SMB y el pipeline corre en Linux
- **THEN** el Step 11 enumera usuarios/grupos/política/dominio en modo pasivo y la evidencia queda en `enum4linux.txt`/`enum4linux.json`

### Requirement: Manifest por target
Al terminar el pipeline de un target, el sistema SHALL generar `evidence/<target>/manifest.json` con:
target e ID, timestamps de inicio/fin, lista de tools ejecutados (step, tool, status, output),
`out_of_scope_findings` y `errors`. Los estados válidos de `status` son: `success`, `failed`,
`skipped` (herramienta no disponible: WhatWeb sin binario o Enum4linux sin binario en Linux),
`skipped_no_ports` (Nuclei/HTTPX sin puertos), `skipped_no_web` (Nikto/WhatWeb/Gobuster-dir sin web),
`skipped_no_domain`, `skipped_no_tftp`, `skipped_no_tls`, `skipped_no_iis` (Step 9 sin web o sin
firma Microsoft-IIS en httpx.json), `skipped_no_smb` (Steps 10/12 sin 139/445 abiertos), `skipped_no_ldap` (Step 11 sin 389/636/3268/3269) y
`skipped_unsupported_os` (Step 11 en macOS). `tools_executed` SHALL contener siempre los 12 steps
(entradas completas, inclusive las saltadas).

#### Scenario: Manifest de target completo
- **WHEN** el pipeline termina un target sin fallos
- **THEN** `manifest.json` existe y lista los 11 steps con su estado y sus archivos de output

#### Scenario: Target sin puertos abiertos
- **WHEN** el Step 1 no reporta puertos abiertos
- **THEN** el manifest registra el target `incomplete` y los Steps 2-12 quedan `skipped` con estados específicos

#### Scenario: Pipeline en macOS
- **WHEN** el pipeline corre en macOS y el target tiene SMB abierto
- **THEN** el manifest tiene 11 entradas y la del Step 11 (tool `enum4linux`) queda `skipped_unsupported_os` sin archivos de output

### Requirement: Nota de sesión SMB anónima rechazada (Steps 10/12)
Cuando los Steps 10 (`smbclient`) o 12 (`enum4linux`) descartan la evidencia cruda porque la **sesión
anónima fue rechazada** (sin `Anonymous login` ni shares Disk accesibles en el Step 10; sin sesión estable
ni datos en el Step 12), el sistema SHALL conservar una **nota** `smbclient_sin_sesion.txt` /
`enum4linux_sin_sesion.txt` con el comando ejecutado y el motivo literal (ej. `NT_STATUS_LOGON_FAILURE`),
SHALL declararla en `output[]` del `manifest.json` y SHALL emitir en consola
`STEP_SMBCLIENT_NOTE sin_sesion` / `STEP_ENUM4LINUX_NOTE sin_sesion`. El Agente 6 SHALL reportarla como
hallazgo informativo *"Sesion SMB anonima rechazada (\<herramienta\>)"* (severidad "No declarada en
fuente", evidencia literal). El `status` del step NO cambia (`success`) y los **12 steps** del DAG y el
vocabulario de estados quedan intactos.

#### Scenario: Sesión anónima rechazada en el Step 12
- **WHEN** `enum4linux-ng` no logra sesión anónima estable ni datos
- **THEN** se eliminan `enum4linux.txt/.json/.yaml`, se conserva `enum4linux_sin_sesion.txt` con el motivo literal, el manifest la lista en `output[]` y el reporte incluye el hallazgo de rechazo

#### Scenario: Sesión anónima rechazada en el Step 10
- **WHEN** `smbclient -L //<IP> -N` no obtiene `Anonymous login` y no hay shares Disk accesibles
- **THEN** se eliminan `smbclient_shares.txt`/`smbclient_<share>.txt`, se conserva `smbclient_sin_sesion.txt` con el motivo literal y el reporte incluye el hallazgo de rechazo

#### Scenario: Sesión anónima aceptada o shares accesibles (sin cambios)
- **WHEN** hay `Anonymous login` o al menos un share Disk accesible
- **THEN** se conserva la evidencia cruda como hasta ahora (`smbclient_shares.txt` / `enum4linux.*`) y NO se genera la nota

