# 📂 Carpeta `scripts/` — Guía de entrada

> **Para quién es esto:** si abriste esta carpeta y ves archivos como `step1_nmap_ports.sh` o
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
| `step1_nmap_ports.sh` | Primer escaneo: qué puertos están abiertos (versión Docker) | [▶ step1_nmap_ports.md](step1_nmap_ports.md) |
| `post_step1_open_ports.sh` | Ordena la lista de puertos abiertos (versión Docker) | [▶ post_step1_open_ports.md](post_step1_open_ports.md) |
| `xml_to_nmap_json.py` | Convierte el XML de Nmap a JSON | [▶ xml_to_nmap_json.md](xml_to_nmap_json.md) |
| `cves_md.py` | Convierte la investigación CVE a un documento legible | [▶ cves_md.md](cves_md.md) |
| `nvd_query.py` | Busca vulnerabilidades conocidas (CVE) por palabra clave | [▶ nvd_query.md](nvd_query.md) |
| `nvd_cve_detail.py` | Trae el detalle de un CVE específico | [▶ nvd_cve_detail.md](nvd_cve_detail.md) |
| `organize_project.py` | Ordena y consolida toda la evidencia en la carpeta del cliente | [▶ organize_project.md](organize_project.md) |
| `make_vuln_report.py` | Genera los informes de vulnerabilidades (Agente 6) — acumula corridas con horario | [▶ make_vuln_report.md](make_vuln_report.md) |
| `cleanup_engagement.sh` | Borra toda la evidencia del cliente y deja el repo listo para el próximo | [▶ cleanup_engagement.md](cleanup_engagement.md) |

### Scripts del pipeline de escaneo (`scripts/host/`)

| Script | Qué hace (resumen) | Documento |
|---|---|---|
| `run_fase1_run3.sh` | Recorre todos los objetivos autorizados y los escanea uno por uno | [▶ run_fase1_run3.md](host/run_fase1_run3.md) |
| `run_target.sh` | Director del escaneo de un solo objetivo (10 pasos) | [▶ run_target.md](host/run_target.md) |
| `make_report.py` | Genera el informe final + informe por objetivo (Agente 5) | [▶ make_report.md](host/make_report.md) |
| `detect_tls_ports.py` | Detecta qué puertos usan cifrado TLS (para SSLyze) | [▶ detect_tls_ports.md](host/detect_tls_ports.md) |
| `step9_iis_shortname_scan.py` | Detecta y enumera IIS Short File Name Disclosure (8.3) — integrado como Step 9, con modo manual `--proyecto CLIENTE` intacto | [▶ step9_iis_shortname_scan.md](host/step9_iis_shortname_scan.md) |
| `step10_smbclient_enum.sh` | Enumeración anónima (null session) de recursos SMB (139/445) — integrado como Step 10, con modo manual `--all` intacto | [▶ step10_smbclient_enum.md](host/step10_smbclient_enum.md) |

**Los 10 pasos del escaneo:**

| Paso | Script | Qué herramienta usa | Documento |
|---|---|---|---|
| 1 | `step1_nmap_ports.sh` | Nmap — puertos abiertos | [▶ paso 1](host/step1_nmap_ports.md) |
| 1 aux | `post_step1_open_ports.sh` | Nmap — ordena puertos abiertos | [▶ paso 1 aux](host/post_step1_open_ports.md) |
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
---

## 🧭 Conceptos rápidos

- **Script:** un archivo con pasos que la computadora ejecuta sola (una "receta").
- **Terminal/consola:** la ventana donde se ejecutan a mano estos archivos.
- **Pipeline:** el proceso completo de escaneo → análisis → informe (10 pasos).
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
El proyecto **nunca ejecuta exploits**; solo documenta y reporta. Ante la duda, **no escanees**.