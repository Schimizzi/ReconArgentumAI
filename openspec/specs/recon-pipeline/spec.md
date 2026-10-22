# Recon Pipeline Specification

## Purpose

Define la ejecución secuencial del pipeline de recon contra cada target: el DAG lineal de 10 steps sobre las herramientas, los inputs/outputs y post-procesos por step, el **Service-Based Routing** por step (herramientas multiprotocolo como Nuclei/Gobuster/SSLyze/IIS-Shortname/SMB-Enum se ejecutan según servicios detectados, no solo según endpoints web), los timeouts parametrizados desde `config/stealth.yaml`, el manifest por target, el manejo de errores, la autodetección del scan type de Nmap por privilegios, las wordlists portables y los workarounds integrados (watchdog Nikto, cutoff Gobuster, -oJ roto).

## Requirements

### Requirement: DAG secuencial de recon
El sistema SHALL ejecutar los steps en este orden lineal, uno por target y sin paralelismo: (1) Nmap port scan → (2) HTTPX probe web → (3) Nmap -sC -sV detallado solo sobre puertos abiertos → (4) Nuclei → (5) Nikto → (6) WhatWeb → (7) Gobuster/Dirsearch → (8) SSLyze → (9) IIS Shortname (8.3) → (10) SMB Enum (smbclient).

#### Scenario: Ejecución completa de un target con servicios web
- **WHEN** el pipeline procesa un target que tiene al menos un endpoint web confirmado por HTTPX
- **THEN** los 10 steps se ejecutan en orden, con el delay de stealth entre cada uno

### Requirement: Step 1 — Port scan inicial
El sistema SHALL ejecutar Nmap sobre el target con los parámetros aprobados en Fase 0, guardando `nmap_ports.xml` y `nmap_ports.json` completos en `evidence/<target>/`. Como post-proceso SHALL extraer los puertos abiertos en formato `IP:PORT` (uno por línea) a `evidence/<target>/open_ports.txt`.

#### Scenario: Extracción de puertos abiertos
- **WHEN** el port scan termina con éxito
- **THEN** `open_ports.txt` contiene una línea por cada puerto abierto en formato `IP:PORT`

#### Scenario: Step 1 falla de forma definitiva
- **WHEN** Nmap Step 1 falla y su retry único también falla
- **THEN** el target se marca como `incomplete` en el manifest y el pipeline pasa al siguiente target

#### Scenario: Lista de puertos personalizada (clienteP)
- **WHEN** `config/stealth.yaml` define `clienteP` con una lista de puertos (ej. 98 puertos del cliente)
- **THEN** el Step 1 escanea esos puertos específicos en lugar de `--top-ports 1000`
- **AND** si `clienteP` no existe o está vacío, el fallback es `--top-ports 1000`

#### Scenario: Workaround -oJ (JSON output roto en Kali arm64)
- **WHEN** el Step 1 se ejecuta en Kali 7.99 (arm64/aarch64)
- **THEN** el flag `-oJ` de Nmap está roto y no produce archivo; el script usa `-oX` (XML) y deriva JSON con `scripts/xml_to_nmap_json.py`
- **AND** el pipeline funciona correctamente porque el JSON derivado tiene el mismo sub-schema que el esperado por los pasos siguientes

### Requirement: Step 2 — Probe de servicios web
El sistema SHALL ejecutar HTTPX sobre `open_ports.txt`, guardando `httpx.json` completo (incluyendo resultados no-web). Como post-proceso SHALL extraer únicamente las URLs con esquema `http://` o `https://` a `evidence/<target>/web_endpoints.txt`. El binario de HTTPX SHALL resolverse con prioridad `httpx-toolkit` (Kali) → `httpx-pd` (macOS) → `httpx` (solo si soporta el flag `-l`, demostrando que es el binario de ProjectDiscovery y no el cliente Python).

#### Scenario: Extracción de endpoints web
- **WHEN** HTTPX termina con éxito
- **THEN** `web_endpoints.txt` contiene una URL por línea, solo aquellas con esquema http o https

#### Scenario: Deduplicación de endpoints web por redirect
- **WHEN** HTTPX sigue un redirect de HTTP 80 a HTTPS 443 y registra la misma URL final dos veces
- **THEN** el post-proceso aplica `sort -u` sobre las URLs extraídas antes de escribirlas a `web_endpoints.txt`
- **AND** Nikto, WhatWeb y Gobuster no escanean el mismo endpoint duplicado

### Requirement: Service-Based Routing por step (Optimización Multiprotocolo)
El sistema SHALL decidir la ejecución de los Steps 4-10 según los servicios detectados por step
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

#### Scenario: Target sin web pero con puertos abiertos no-web
- **WHEN** tras el Step 2 `web_endpoints.txt` está vacío pero `open_ports.txt` tiene SMB/RDP/SSH abiertos
- **THEN** Nuclei se ejecuta contra `open_ports.txt` (plantillas no-web), Nikto/WhatWeb se marcan
  `skipped_no_web`, Gobuster evalúa su modo según dominio/UDP69, SSLyze audita los puertos TLS
  detectados (ej. 3389-RDP con `--starttls rdp` o 5986-WinRM), IIS Shortname queda
  `skipped_no_iis` (no hay web) y SMB Enum se ejecuta si 139/445 están abiertos (o queda
  `skipped_no_smb` si no lo están).

#### Scenario: Target con web no-IIS
- **WHEN** hay endpoints web pero el `httpx.json` no reporta `webserver` con `IIS`/`Microsoft-IIS`
- **THEN** el Step 9 queda `skipped_no_iis` y no se envía ningún request de tilde enumeration

#### Scenario: Target con SMB abierto
- **WHEN** `open_ports.txt` o `nmap_detailed.xml` reporta TCP 139 o 445 abierto
- **THEN** el Step 10 ejecuta `step10_smbclient_enum.sh --ev-dir evidence/<target>` (null session
  `-N`, solo lectura) y genera `smbclient_shares.txt`/`smbclient_<share>.txt`

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
- **THEN** el target se registra `incomplete` y los Steps 2-10 quedan `skipped` en el manifest

### Requirement: Step 3 — Scan detallado solo de puertos abiertos
El sistema SHALL ejecutar Nmap -sC -sV únicamente sobre los puertos que el Step 1 confirmó abiertos (nunca sobre un rango completo), guardando `nmap_detailed.json`, `nmap_detailed.xml` y `nmap_detailed.txt` completos.

#### Scenario: Restricción de puertos
- **WHEN** el Step 3 se ejecuta
- **THEN** su parámetro de puertos contiene exactamente la lista de `open_ports.txt`, sin rangos adicionales

### Requirement: Steps estrictamente web sobre endpoints confirmados
El sistema SHALL ejecutar Nikto (Step 5) y WhatWeb (Step 6) únicamente sobre las URLs de
`web_endpoints.txt`, de forma secuencial por endpoint, guardando un archivo de evidencia por
cada uno (ej. `nikto_<port>.json`, `whatweb.json`). El sistema SHALL ejecutar Gobuster en modo
`dir` únicamente sobre las URLs de `web_endpoints.txt`, generando `gobuster_<port>.txt` por
endpoint.

#### Scenario: Múltiples endpoints web
- **WHEN** `web_endpoints.txt` contiene 3 URLs (puertos 80, 443 y 5989)
- **THEN** Nikto se ejecuta secuencialmente contra cada una, generando `nikto_80`, `nikto_443` y `nikto_5989`

### Requirement: Timeouts parametrizados desde stealth.yaml
El sistema SHALL NO hardcodear timeouts, rate-limits ni cantidades de threads en los comandos base. Todos esos valores SHALL provenir de variables de `config/stealth.yaml` (ej. `httpx_timeout_seconds`, `nuclei_rate_limit`, `gobuster_threads`), de modo que un cambio en el archivo se refleje en todos los comandos.

#### Scenario: Cambio de timeout en stealth.yaml
- **WHEN** el usuario modifica `httpx_timeout_seconds` de 10 a 20 en `config/stealth.yaml`
- **THEN** el comando de HTTPX propuesto y ejecutado usa 20s sin necesidad de editar la spec del pipeline

### Requirement: Manifest por target
Al terminar el pipeline de un target, el sistema SHALL generar `evidence/<target>/manifest.json` con: target e ID, timestamps de inicio/fin, lista de tools ejecutados (step, tool, status, output), `out_of_scope_findings` y `errors`. Los estados válidos de `status` son: `success`, `failed`, `skipped` (WhatWeb SALTADO por usuario), `skipped_no_ports` (Nuclei/HTTPX sin puertos), `skipped_no_web` (Nikto/WhatWeb/Gobuster-dir sin web), `skipped_no_domain`, `skipped_no_tftp`, `skipped_no_tls`, `skipped_no_iis` (Step 9 sin web o sin firma Microsoft-IIS en httpx.json), `skipped_no_smb` (Step 10 sin 139/445 abiertos). `tools_executed` SHALL contener siempre los 10 steps (entradas completas, inclusive las saltadas).

#### Scenario: Manifest de target completo
- **WHEN** el pipeline termina un target sin fallos
- **THEN** `manifest.json` existe y lista los 10 steps con estado `success` y sus archivos de output

#### Scenario: Target sin puertos abiertos
- **WHEN** el Step 1 no reporta puertos abiertos
- **THEN** el manifest registra el target `incomplete` y los Steps 2-10 quedan `skipped` con estados específicos

### Requirement: Manejo de errores por herramienta
Si una herramienta falla, el sistema SHALL reintentar UNA vez con el mismo comando. Si vuelve a fallar, SHALL marcarla `failed` con su error en el manifest y continuar con el step siguiente sin abortar el target completo (excepción: Step 1, que marca el target `incomplete`).

#### Scenario: Fallo transitorio resuelto por retry
- **WHEN** Nuclei falla en su primera ejecución y el retry tiene éxito
- **THEN** el manifest registra `success` y el pipeline continúa

#### Scenario: Fallo definitivo de herramienta intermedia
- **WHEN** Nikto falla dos veces consecutivas contra un endpoint
- **THEN** el manifest registra `failed` con el error y el pipeline continúa con WhatWeb

### Requirement: Scan type autodetectado por privilegios (Unificación Kali/Docker 2026-09-07)
Los Steps 1 y 3 SHALL autodetectar el tipo de scan de Nmap según los privilegios del proceso: si `EUID` es 0 (root en VM Kali o contenedor Docker) SHALL usar `-sS` (SYN scan); en caso contrario (macOS sin sudo) SHALL usar `-sT` (TCP Connect scan). El mismo script SHALL funcionar en los tres entornos (host macOS, VM Kali, contenedor Docker) sin editar comandos.

#### Scenario: Contenedor Docker con root
- **WHEN** el Step 1 se ejecuta dentro del contenedor Docker (EUID == 0)
- **THEN** Nmap usa `-sS` y raw sockets (requiere `cap_add: NET_RAW` en docker-compose.yml)

#### Scenario: Host macOS sin privilegios
- **WHEN** el Step 1 se ejecuta en macOS sin sudo (EUID != 0)
- **THEN** Nmap usa `-sT` (TCP Connect scan), que funciona sin permisos especiales

### Requirement: Wordlists portables (Unificación Kali/Docker 2026-09-07)
El sistema SHALL resolver las wordlists de Gobuster y del preflight probando ubicaciones en orden portable: `/opt/SecLists/...` → `/usr/share/seclists/...` → `$HOME/Documents/SecLists/...` → `tools/seclists_common.txt` (fallback solo web). Esto SHALL funcionar idénticamente en host macOS, VM Kali y contenedor Docker.

#### Scenario: Wordlist en contenedor Docker
- **WHEN** el Step 7 se ejecuta dentro del contenedor Docker
- **THEN** la wordlist se resuelve a `/opt/SecLists/Discovery/Web-Content/common.txt` (instalada en el Dockerfile)

#### Scenario: Wordlist en macOS sin SecLists
- **WHEN** el Step 7 se ejecuta en macOS y no existe `/opt/SecLists` ni `~/Documents/SecLists`
- **THEN** se usa `tools/seclists_common.txt` como fallback (cache web mínimo del repositorio)

### Requirement: Workarounds de ejecución (Nikto watchdog y Gobuster cutoff)
El sistema SHALL implementar dos workarounds para herramientas que no responden dentro de los timeouts estándar: (1) un **watchdog para Nikto** que corta el proceso si su duración supera `nikto_maxtime_seconds × 3` (algunos servidores como ESXi/HP embebidos ignoran `-maxtime`); (2) un **cutoff para Gobuster** que lo corta tras `gobuster_max_seconds` (default 180s) si el servidor no responde a las solicitudes del diccionario.

#### Scenario: Servidor que ignora -maxtime de Nikto
- **WHEN** Nikto se cuelga contra un servidor que ignora `-maxtime` (maxtime=30s pero el proceso sigue activo >90s)
- **THEN** el watchdog mata el proceso y marca el paso como `failed` en el manifest
- **AND** el pipeline continúa con el siguiente step sin abortar el target

#### Scenario: Gobuster sin respuesta a dict
- **WHEN** el servidor web no responde a las solicitudes del diccionario (~23.7k requests causan timeouts en cadena)
- **THEN** el cutoff corta Gobuster tras `gobuster_max_seconds` (180s) y marca `failed`
- **AND** el pipeline continúa con el siguiente step

### Requirement: Bloqueo por target (R3 Lock)
El sistema SHALL implementar un mecanismo de bloqueo por target mediante `mkdir` atómico en `evidence/<target>/.run.lock`. Si dos instancias de `run_target.sh` intentan ejecutarse concurrentemente sobre el mismo target, la segunda SHALL abortar inmediatamente para evitar corrupción de evidencia.

#### Scenario: Intento de ejecución concurrente
- **WHEN** una segunda instancia de `run_target.sh` se ejecuta sobre un target que ya tiene un lock activo
- **THEN** la segunda instancia aborta con el mensaje `R3-FAIL: otro pipeline está corriendo sobre X`
- **AND** la primera instancia continúa sin interrupción y libera el lock al terminar (trap EXIT)

### Requirement: Verificación de campo PHP2Shell (fuera del DAG)
El sistema SHALL proveer una verificación **fuera del DAG** para advisories críticos de software web (`scripts/host/php2shell_check.sh`), de ejecución manual por el operador **desde la VM con VPN** y por target. El DAG SHALL permanecer en **12 steps** y el contrato del manifest NO SHALL alterarse por esta verificación. El script SHALL soportar cuatro modos: `--passive` (por defecto; `curl -sS/-I` sobre rutas estándar, sólo lectura, aprobado), `--fingerprint` (intenta revelar la versión de PHP donde el banner está oculto, ej. Drupal/IIS; requiere aprobación por target), `--detect` (prueba NO destructiva del path OOM: un request multipart con `session.upload_progress` y una cookie `PHPSESSID` larga/percent-encoded; **exige** `--authorized` y NO envía payloads de shell ni escribe archivos) y `--host-check` (corre en el servidor: `php -v`, `session.upload_progress`, backports del vendor en `rpm -q --changelog php` / `dpkg`). Los timeouts SHALL resolverse de `config/stealth.yaml` (`php2shell_timeout_seconds`, `php2shell_max_paths`). La evidencia SHALL quedar en `evidence/<target>/php2shell_passive.txt`, `php2shell_fingerprint.txt`, `php2shell_detect.txt`, `php2shell_hostcheck.txt`, `php2shell_result.json` y `php2shell_summary.txt`.

#### Scenario: Verificación pasiva aprobada
- **WHEN** el operador ejecuta `php2shell_check.sh --target <IP> --passive`
- **THEN** el script hace GETs de sólo lectura a rutas estándar (y al easter egg de PHP), guarda los headers (`Server`, `X-Powered-By`, `Set-Cookie`) en `php2shell_passive.txt` y clasifica la versión contra la tabla del advisory

#### Scenario: Versión afectada detectada
- **WHEN** la respuesta incluye `X-Powered-By: PHP/8.2.31`
- **THEN** `php2shell_result.json` registra `status: "affected"`, el SAPI probable y el script sale con exit code `2`

#### Scenario: Ejecución de detección sin autorización
- **WHEN** se invoca `--detect` sin `--authorized`
- **THEN** el modo se SALTA con un mensaje explícito y NO se envía ningún request multipart

#### Scenario: Host que oculta la versión
- **WHEN** el target corre Drupal sobre IIS y el modo `--fingerprint` no logra exponer la versión
- **THEN** el resultado queda `unknown_version` con el siguiente paso documentado (no se asume versión ni se listan CVEs)

#### Scenario: Chequeo dentro del servidor
- **WHEN** el operador ejecuta `--host-check` en el propio servidor PHP
- **THEN** se guarda `php2shell_hostcheck.txt` con la versión, la configuración de sesión/memoria, el SAPI y el resultado de `rpm -q --changelog php | grep -i CVE-2026-10961[89]`


### Requirement: Nota de sesión SMB anónima rechazada (Steps 10/12)
Cuando los Steps 10 (`smbclient`) o 12 (`enum4linux`) descartan la evidencia cruda porque la **sesión anónima fue rechazada** (sin `Anonymous login` ni shares Disk accesibles en el Step 10; sin sesión estable ni datos en el Step 12), el sistema SHALL conservar una **nota** `smbclient_sin_sesion.txt` / `enum4linux_sin_sesion.txt` con el comando ejecutado y el motivo literal (ej. `NT_STATUS_LOGON_FAILURE`), SHALL declararla en `output[]` del `manifest.json` y SHALL emitir en consola `STEP_SMBCLIENT_NOTE sin_sesion` / `STEP_ENUM4LINUX_NOTE sin_sesion`. El Agente 6 SHALL reportarla como hallazgo informativo *"Sesion SMB anonima rechazada (<herramienta>)"* (severidad "No declarada en fuente", evidencia literal). El `status` del step NO cambia (`success`) y los **12 steps** del DAG y el vocabulario de estados quedan intactos.

#### Scenario: Sesión anónima rechazada en el Step 12
- **WHEN** `enum4linux-ng` no logra sesión anónima estable ni datos
- **THEN** se eliminan `enum4linux.txt/.json/.yaml`, se conserva `enum4linux_sin_sesion.txt` con el motivo literal, el manifest la lista en `output[]` y el reporte incluye el hallazgo de rechazo

#### Scenario: Sesión anónima rechazada en el Step 10
- **WHEN** `smbclient -L //<IP> -N` no obtiene `Anonymous login` y no hay shares Disk accesibles
- **THEN** se eliminan `smbclient_shares.txt`/`smbclient_<share>.txt`, se conserva `smbclient_sin_sesion.txt` con el motivo literal y el reporte incluye el hallazgo de rechazo

#### Scenario: Sesión anónima aceptada o shares accesibles (sin cambios)
- **WHEN** hay `Anonymous login` o al menos un share Disk accesible
- **THEN** se conserva la evidencia cruda como hasta ahora (`smbclient_shares.txt` / `enum4linux.*`) y NO se genera la nota

