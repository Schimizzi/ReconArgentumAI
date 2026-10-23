# 📂 Carpeta `scripts/` — Guía de entrada

> **Para quién es esto:** si abriste esta carpeta y ves archivos como `run_target.sh` o
> `check_gobuster_urls.sh` y no sabés qué significan, esta guía te orienta en **lenguaje simple**.
> **No hace falta saber programar.**

**En una frase:** estos archivos son las "recetas automáticas" del proyecto ReconArgentumAI para
hacer reconocimiento de una red **autorizada**: descubrir equipos, servicios, carpetas web y
vulnerabilidades, y después armar los informes.

**Cada script tiene su propio documento de explicación** (un `.md` con el mismo nombre que el
archivo, al lado de él). Esta guía solo es el punto de entrada con la lista completa.

---

## 📘 Cómo leer los documentos individuales

Cada `.md` que acompaña a un script explica, sin código:

- 🧩 **Qué es** (en una frase simple).
- ⏱️ **Cuándo se usa** y quién lo invoca.
- ▶️ **Cómo se ejecuta a mano** (si corresponde).
- 📥 **Qué necesita** y **qué genera** (archivos de salida).
- ⚠️ **Notas importantes** (requisitos, sigilo, alcance).

---

## 🗂️ Índice de documentos por script

### Scripts generales (`scripts/`)

| Script | Qué hace (resumen) | Documento |
|---|---|---|
| `check_gobuster_urls.sh` | Revisa las URLs descubiertas buscando pistas de vulnerabilidades (headers, listados, credenciales, métodos peligrosos…) | [▶ check_gobuster_urls.md](check_gobuster_urls.md) |
| `gobuster_urls.sh` | Arma la lista única de URLs a partir de los resultados de Gobuster | [▶ gobuster_urls.md](gobuster_urls.md) |
| `install_host_tools.sh` | Instala las herramientas de pentest en la Mac (una sola vez) | [▶ install_host_tools.md](install_host_tools.md) |
| `install_souls.sh` | Instala los 4 perfiles (SOUL) de Hermes Agent en `~/.hermes/profiles/` (uso manual) | [▶ install_souls.md](install_souls.md) |
| `xml_to_nmap_json.py` | Convierte el XML de Nmap a JSON | [▶ xml_to_nmap_json.md](xml_to_nmap_json.md) |
| `cves_md.py` | Convierte la investigación CVE a un documento legible | [▶ cves_md.md](cves_md.md) |
| `cve_research_vulnx.py` | Investiga CVEs de cada servicio/tecnología con `vulnx` + watchlist local de advisories (Agente 4, Fase 2) | [▶ cve_research_vulnx.md](cve_research_vulnx.md) |
| `php2shell_audit.py` | Auditoría **offline** de PHP2Shell (CVE-2026-109618/109619) sobre toda la evidencia: versión, SAPI, afectados (alimenta el check CK-10) | [▶ php2shell_audit.md](php2shell_audit.md) |
| `resumen_exploit.py` | Pre-filtra la evidencia por target y arma un resumen compacto para el Agente 3 (Fase 2) | [▶ resumen_exploit.md](resumen_exploit.md) |
| `gen_exploitation_draft.py` | Genera el **borrador** del plan de explotación (Agente 3, Fase 2b) desde la evidencia — rotulado, sin ejecutar nada (uso manual, no entra al DAG) | [▶ gen_exploitation_draft.md](gen_exploitation_draft.md) |
| `audit_exploitation_plans.py` | Contrasta los planes contra la evidencia: puertos inventados/omitidos, CVEs sin respaldo y PoC promovidas (control de fiabilidad, solo lectura) | [▶ audit_exploitation_plans.md](audit_exploitation_plans.md) |
| `organize_project.py` | Ordena y consolida toda la evidencia en la carpeta del cliente | [▶ organize_project.md](organize_project.md) |
| `hydra_audit.sh` | Auditoría **manual** de credenciales débiles con Hydra (por target o `--all`) — fuera del pipeline, con límite de intentos y log central | [▶ hydra_audit.md](hydra_audit.md) |
| `cleanup_engagement.sh` | Borra toda la evidencia del cliente y deja el repo listo para el próximo | [▶ cleanup_engagement.md](cleanup_engagement.md) |

### Scripts del pipeline de escaneo (`scripts/host/`)

| Script | Qué hace (resumen) | Documento |
|---|---|---|
| `run_fase1_run3.sh` | Recorre todos los objetivos autorizados y los escanea uno por uno | [▶ run_fase1_run3.md](host/run_fase1_run3.md) |
| `validate_step11_12.sh` | Validación asistida de los Steps 11/12 (LDAP + Enum4linux): incremental, gates, anti-fuga del password, contrato del manifest (12 entradas) y **V-08a expectation-aware** (`--v08a-only` corre sólo el check del reporte, sin tráfico) | [▶ validate_step11_12.md](host/validate_step11_12.md) |
| `run_target.sh` | Director del escaneo de un solo objetivo (12 pasos) | [▶ run_target.md](host/run_target.md) |
| `detect_tls_ports.py` | Detecta qué puertos usan cifrado TLS (para SSLyze) | [▶ detect_tls_ports.md](host/detect_tls_ports.md) |
| `step9_iis_shortname_scan.py` | Detecta y enumera IIS Short File Name Disclosure (8.3) — integrado como Step 9, con modo manual `--proyecto CLIENTE` intacto | [▶ step9_iis_shortname_scan.md](host/step9_iis_shortname_scan.md) |
| `step10_smbclient_enum.sh` | Enumeración anónima (null session) de recursos SMB (139/445) — integrado como Step 10, con modo manual `--all` intacto | [▶ step10_smbclient_enum.md](host/step10_smbclient_enum.md) |
| `step11_ldap_enum.sh` | Enumeración LDAP/AD con `ldapsearch` — integrado como Step 11 (**Linux y macOS**), con creds opt-in y modo manual `--all` | [▶ step11_ldap_enum.md](host/step11_ldap_enum.md) |
| `step12_enum4linux_enum.sh` | Enumeración AD anónima (enum4linux-ng) — integrado como Step 12, **solo Linux** (macOS: `skipped_unsupported_os`), con modo manual `--all` | [▶ step12_enum4linux_enum.md](host/step12_enum4linux_enum.md) |
| `php2shell_check.sh` | **Fuera del DAG (manual, desde la VM):** verificación de PHP2Shell en campo — pasiva, fingerprint de versión, detección no invasiva y chequeo de backports del host | [▶ php2shell_check.md](host/php2shell_check.md) |
| `php2shell_hostcheck_win.ps1` | **Verificación LOCAL en un host Windows/IIS** (PHP-Version desde binario/registro/handler de IIS) — para los Drupal 7/IIS donde la versión no es visible remotamente | [▶ php2shell_hostcheck_win.md](host/php2shell_hostcheck_win.md) |

**Los 12 pasos del escaneo:**

| Paso | Script | Qué herramienta usa | Documento |
|---|---|---|---|
| 1 | `host/step1_nmap_ports.sh` | Nmap — puertos abiertos | [▶ paso 1](host/step1_nmap_ports.md) |
| 1 aux | `host/post_step1_open_ports.sh` | Nmap — ordena puertos abiertos | [▶ paso 1 aux](host/post_step1_open_ports.md) |
| 2 | `step2_httpx.sh` | HTTPX — detecta sitios web | [▶ paso 2](host/step2_httpx.md) |
| 3 | `step3_nmap_detailed.sh` | Nmap — versión de cada servicio | [▶ paso 3](host/step3_nmap_detailed.md) |
| 4 | `step4_nuclei.sh` | Nuclei — vulnerabilidades conocidas | [▶ paso 4](host/step4_nuclei.md) |
| 5 | `step5_nikto.sh` | Nikto — escáner web complementario | [▶ paso 5](host/step5_nikto.md) |
| 6 | `step6_whatweb.sh` | WhatWeb — tecnología de los sitios (saltado por el usuario) | [▶ paso 6](host/step6_whatweb.md) |
| 7 | `step7_gobuster.sh` | Gobuster — carpetas ocultas | [▶ paso 7](host/step7_gobuster.md) |
| 7 aux | `step7_udp_probe.sh` | Nmap — sondea TFTP (UDP 69) | [▶ paso 7 aux](host/step7_udp_probe.md) |
| 8 | `step8_sslyze.sh` | SSLyze — seguridad de conexiones cifradas | [▶ paso 8](host/step8_sslyze.md) |
| 9 | `step9_iis_shortname_scan.py` | IIS Shortname 8.3 — solo si `web_on` y el `httpx.json` reporta `Server: Microsoft-IIS` | [▶ paso 9](host/step9_iis_shortname_scan.md) |
| 10 | `step10_smbclient_enum.sh` | smbclient — comparte SMB (139/445) abiertos | [▶ paso 10](host/step10_smbclient_enum.md) |
| 11 | `step11_ldap_enum.sh` | ldapsearch — LDAP/AD (root DSE; creds opt-in; Linux y macOS) | [▶ paso 11](host/step11_ldap_enum.md) |
| 12 | `step12_enum4linux_enum.sh` | enum4linux-ng — enumeración AD anónima (solo Linux; 139/445 abiertos) | [▶ paso 12](host/step12_enum4linux_enum.md) |
---

## 🧭 Conceptos rápidos

- **Script:** un archivo con pasos que la computadora ejecuta sola (una "receta").
- **Terminal/consola:** la ventana donde se ejecutan a mano estos archivos.
- **Pipeline:** el proceso completo de escaneo → análisis → informe (12 pasos).
- **Objetivo (target):** el equipo (IP) de la red que se revisa, **siempre con autorización**.
- **Herramientas:** programas como Nmap, HTTPX, Nuclei, Nikto, Gobuster o SSLyze; los scripts los
  organizan y automatizan.
- **CVE:** código único de una vulnerabilidad conocida (ej. `CVE-2024-6387`).

## ▶️ Cómo se ejecuta un script a mano

````bash
# Un script de scripts/ se ejecuta desde la raíz del proyecto, por ejemplo:
bash scripts/check_gobuster_urls.sh --target 10.155.10.15

# Un script de scripts/host/:
bash scripts/host/run_target.sh 10.155.10.15
````

> ⚠️ **En general no hay que ejecutarlos a mano**: el pipeline ya los llama en el orden correcto.
> Ejecutarlos sueltos es útil para **probar una parte** o **revisar una URL puntual**.

## ⚠️ Aviso de uso responsable

Estos scripts realizan **reconocimiento de seguridad** y generan tráfico hacia la red. Deben
usarse **solo sobre sistemas autorizados** (propia infraestructura o contrato de pentest firmado).
El proyecto **nunca ejecuta exploits**; solo documenta y reporta. `hydra_audit.sh` realiza
**pruebas de autenticación activas** (fuerza bruta limitada a 25 intentos/servicio): es una
actividad aún más intrusiva y requiere **autorización explícita por target**. Ante la duda,
**no escanees**.