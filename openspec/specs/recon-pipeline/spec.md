# Recon Pipeline Specification

## Purpose

Define la ejecución secuencial del pipeline de recon contra cada target: el DAG lineal de 8 steps sobre las 7 herramientas, los inputs/outputs y post-procesos por step, el **Service-Based Routing** por step (herramientas multiprotocolo como Nuclei/Gobuster/SSLyze se ejecutan según servicios detectados, no solo según endpoints web), los timeouts parametrizados desde `config/stealth.yaml`, el manifest por target y el manejo de errores.

## Requirements

### Requirement: DAG secuencial de recon
El sistema SHALL ejecutar los steps en este orden lineal, uno por target y sin paralelismo: (1) Nmap port scan → (2) HTTPX probe web → (3) Nmap -sC -sV detallado solo sobre puertos abiertos → (4) Nuclei → (5) Nikto → (6) WhatWeb → (7) Gobuster/Dirsearch → (8) SSLyze.

#### Scenario: Ejecución completa de un target con servicios web
- **WHEN** el pipeline procesa un target que tiene al menos un endpoint web confirmado por HTTPX
- **THEN** los 8 steps se ejecutan en orden, con el delay de stealth entre cada uno

### Requirement: Step 1 — Port scan inicial
El sistema SHALL ejecutar Nmap sobre el target con los parámetros aprobados en Fase 0, guardando `nmap_ports.xml` y `nmap_ports.json` completos en `evidence/<target>/`. Como post-proceso SHALL extraer los puertos abiertos en formato `IP:PORT` (uno por línea) a `evidence/<target>/open_ports.txt`.

#### Scenario: Extracción de puertos abiertos
- **WHEN** el port scan termina con éxito
- **THEN** `open_ports.txt` contiene una línea por cada puerto abierto en formato `IP:PORT`

#### Scenario: Step 1 falla de forma definitiva
- **WHEN** Nmap Step 1 falla y su retry único también falla
- **THEN** el target se marca como `incomplete` en el manifest y el pipeline pasa al siguiente target

### Requirement: Step 2 — Probe de servicios web
El sistema SHALL ejecutar HTTPX sobre `open_ports.txt`, guardando `httpx.json` completo (incluyendo resultados no-web). Como post-proceso SHALL extraer únicamente las URLs con esquema `http://` o `https://` a `evidence/<target>/web_endpoints.txt`.

#### Scenario: Extracción de endpoints web
- **WHEN** HTTPX termina con éxito
- **THEN** `web_endpoints.txt` contiene una URL por línea, solo aquellas con esquema http o https

### Requirement: Service-Based Routing por step (Optimización Multiprotocolo)
El sistema SHALL decidir la ejecución de los Steps 4-8 según los servicios detectados por step
(Service-Based Routing, 2026-08-31), NO aplanar los steps ante la ausencia de web. El sistema
SHALL ejecutar: **Nuclei (Step 4)** SIEMPRE que `open_ports.txt` tenga ≥1 puerto abierto,
apuntando a las líneas `IP:PORT` para aplicar plantillas multiprotocolo (red, SSH, DNS, TLS,
además de web). **Nikto (Step 5) y WhatWeb (Step 6)** SHALL ejecutarse solo si
`web_endpoints.txt` no está vacío. **Gobuster (Step 7)** SHALL rutear por modo: `dir` si hay
web, `dns` si el target es un dominio (no IP cruda), y `tftp` si el puerto 69/UDP está abierto
(probe UDP parametrizado desde `stealth.yaml`). **SSLyze (Step 8)** SHALL ejecutarse contra
los puertos con túnel SSL/TLS detectados en la salida de Nmap del Step 3 (tunnel="ssl",
servicios TLS conocidos, puertos TLS bien conocidos: 443/465/636/990/992/993/995/3389-RDP/
5986-WinRM/etc.), con soporte `--starttls` (rdp, smtp, imap, pop3, ftp, ldap, postgres).

#### Scenario: Target sin web pero con puertos abiertos no-web
- **WHEN** tras el Step 2 `web_endpoints.txt` está vacío pero `open_ports.txt` tiene SMB/RDP/SSH abiertos
- **THEN** Nuclei se ejecuta contra `open_ports.txt` (plantillas no-web), Nikto/WhatWeb se marcan
  `skipped_no_web`, Gobuster evalúa su modo según dominio/UDP69, y SSLyze audita los puertos TLS
  detectados (ej. 3389-RDP con `--starttls rdp` o 5986-WinRM)

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
- **THEN** el target se registra `incomplete` y los Steps 2-8 quedan `skipped` en el manifest

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
Al terminar el pipeline de un target, el sistema SHALL generar `evidence/<target>/manifest.json` con: target e ID, timestamps de inicio/fin, lista de tools ejecutados (step, tool, status, output), `out_of_scope_findings` y `errors`. Los estados válidos de `status` son: `success`, `failed`, `skipped` (WhatWeb SALTADO por usuario), `skipped_no_ports` (Nuclei/HTTPX sin puertos), `skipped_no_web` (Nikto/WhatWeb/Gobuster-dir sin web), `skipped_no_domain`, `skipped_no_tftp`, `skipped_no_tls`. `tools_executed` SHALL contener siempre los 8 steps (entradas completas, inclusive las saltadas).

#### Scenario: Manifest de target completo
- **WHEN** el pipeline termina un target sin fallos
- **THEN** `manifest.json` existe y lista los 8 steps con estado `success` y sus archivos de output

#### Scenario: Target sin puertos abiertos
- **WHEN** el Step 1 no reporta puertos abiertos
- **THEN** el manifest registra el target `incomplete` y los Steps 2-8 quedan `skipped` con estados específicos

### Requirement: Manejo de errores por herramienta
Si una herramienta falla, el sistema SHALL reintentar UNA vez con el mismo comando. Si vuelve a fallar, SHALL marcarla `failed` con su error en el manifest y continuar con el step siguiente sin abortar el target completo (excepción: Step 1, que marca el target `incomplete`).

#### Scenario: Fallo transitorio resuelto por retry
- **WHEN** Nuclei falla en su primera ejecución y el retry tiene éxito
- **THEN** el manifest registra `success` y el pipeline continúa

#### Scenario: Fallo definitivo de herramienta intermedia
- **WHEN** Nikto falla dos veces consecutivas contra un endpoint
- **THEN** el manifest registra `failed` con el error y el pipeline continúa con WhatWeb