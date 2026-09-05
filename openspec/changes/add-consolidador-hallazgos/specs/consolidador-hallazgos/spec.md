# Consolidador Hallazgos Specification

## Purpose

Define al Agente 6 (Consolidador de hallazgos), un paso independiente posterior a la consolidación de `organize_project.py` que analiza exclusivamente el directorio `outputs/` de cada target y genera dos resúmenes formales (`.doc` y `.txt`) con trazabilidad a la evidencia fuente y cero invención.

## ADDED Requirements

### Requirement: Análisis exclusivo de outputs/
El Agente 6 SHALL leer únicamente el directorio `outputs/` de cada target consolidado (`<project>/<ip>/outputs/`) y NUNCA las carpetas `data/`, `evidence/` ni otro directorio del workspace. Los archivos de salida se generan en la raíz del directorio del target (`<project>/<ip>/`).

#### Scenario: Target consolidado con outputs/
- **WHEN** el directorio `<project>/<target_ip>/outputs/` existe y contiene archivos de evidencia
- **THEN** el agente analiza solo esos archivos y genera `<target_id>_resumen_vulnerabilidades.doc` y `<target_id>_resumen_breve.txt` en `<project>/<target_ip>/`

#### Scenario: Directorio outputs/ vacío o inexistente
- **WHEN** `outputs/` no existe o está vacío
- **THEN** el agente no genera reportes para ese target y emite el aviso de cero hallazgos

### Requirement: Detección dinámica de evidencia
El Agente 6 SHALL detectar los archivos de `outputs/` presentes en cada corrida mediante un registro de parsers por patrón de nombre (`<target_id>_cves.md`, `nuclei.json`, `nikto_*.json`, `sslyze_*.json`, `gobuster_*.txt`, `nmap_detailed.*`, `httpx.json`, `evidencia.md`) más un parser genérico de respaldo para archivos no reconocidos. Si el usuario agrega un archivo de evidencia nuevo a `outputs/`, el próximo reporte SHALL incluirlo sin modificar el script.

#### Scenario: Nueva evidencia agregada a outputs/
- **WHEN** el usuario copia un nuevo archivo con hallazgos a `<project>/<target_ip>/outputs/`
- **THEN** la siguiente ejecución del agente lo parsea (por patrón conocido o fallback genérico) y lo incluye en los reportes con su ruta fuente y ubicación

#### Scenario: Archivo sin hallazgos reconocibles
- **WHEN** un archivo de `outputs/` no contiene hallazgos explícitos (vacío, corrupto o sin campos reconocibles)
- **THEN** el archivo se omite y no se fabrican entradas en el reporte

### Requirement: Cero invención en hallazgos
El Agente 6 SHALL extraer únicamente hallazgos, vulnerabilidades, CVEs, warnings o errores de configuración explícitamente reportados en los archivos fuente. PROHIBIDO inventar, deducir, inferir, recomendar o parafrasear libremente. La severidad SHALL registrarse solo si está declarada literalmente en la fuente; si no lo está, el reporte SHALL escribir `Severidad: No declarada en fuente`.

#### Scenario: CVE sin severidad en la fuente
- **WHEN** una fuente reporta un CVE sin severidad/CVSS
- **THEN** el reporte muestra el título literal y `Severidad: No declarada en fuente`

#### Scenario: Hallazgo con severidad declarada
- **WHEN** la fuente escribe explícitamente `severity: high`, `CVSS 9.8 (Critical)`, `Severity: MEDIUM` u otro formato aceptado
- **THEN** la severidad se registra tal cual aparece en la fuente

#### Scenario: Intento de inventar contenido
- **WHEN** el agente no puede señalar el archivo fuente, sección/línea de un ítem candidato
- **THEN** el ítem no se incluye en el reporte

#### Scenario: Condición insegura explícita en hostscript de nmap
- **WHEN** `outputs/nmap_detailed.*` contiene un script NSE de `hostscript` cuyo output textual expresa una condición insegura explícita (ej. `smb2-security-mode` → `Message signing enabled but not required`, `smb-security-mode` → `Message signing disabled`)
- **THEN** el agente registra el hallazgo con el id del script como título literal, el output como descripción extraída y `Severidad: No declarada en fuente`

#### Scenario: Estado técnico del escáner no es hallazgo
- **WHEN** `outputs/sslyze_*.json` tiene un `scan_status` distinto de `COMPLETED` (ej. `ERROR_NO_CONNECTIVITY`), o `outputs/nikto_*.json` contiene entradas de estado técnico (id `FAIL`, mensajes `Unable to connect` / `failed to connect` / `connection timed out`)
- **THEN** el agente omite esas entradas (limitación de la herramienta, no debilidad) y no las incluye en el reporte

#### Scenario: Mensajes de ruido de Nikto omitidos
- **WHEN** `outputs/nikto_*.json` contiene mensajes `* may be outdated` / `appears to be outdated`, `junk HTTP methods ... false positives` o `IP address found in the ... cookie`
- **THEN** el agente los omite (no son verificaciones remotas reales o son artefactos del plugin, no hallazgos)

#### Scenario: Cookies sin HttpOnly consolidadas
- **WHEN** `outputs/nikto_*.json` reporta N cookies creadas sin el flag httponly
- **THEN** el agente genera UN hallazgo `Cookies creadas sin flag HttpOnly (N)` con las primeras cookies como detalle, en vez de una VULN por cookie

#### Scenario: Rutas de gobuster consolidadas
- **WHEN** `outputs/gobuster_*.txt` contiene N líneas de rutas descubiertas
- **THEN** el agente genera UN hallazgo `Rutas descubiertas en <archivo> (N)` cuyo detalle lista las líneas literales, en vez de una vulnerabilidad por línea

### Requirement: Trazabilidad de cada hallazgo
Cada hallazgo del reporte SHALL incluir el ID literal `VULN-00X` (sin numeración automática: el analista asigna el número final a mano al agregar o quitar hallazgos), título exacto como aparece en el archivo fuente, severidad declarada (o `No declarada en fuente`), descripción (extracto literal o parafraseo mínimo de 2-3 líneas, o `Sin descripción en fuente.`), ruta relativa del archivo fuente y ubicación dentro del archivo (sección, línea, JSON path o template ID).

#### Scenario: Reporte .doc completo
- **WHEN** se genera el `.doc` para un target con N hallazgos
- **THEN** el documento contiene: encabezado `REPORTE DE VULNERABILIDADES – <target>`, fecha de generación, total de hallazgos, una sección por vulnerabilidad separada por línea horizontal con espacio en blanco para evidencia, y una tabla resumen con columnas ID/Título/Severidad/Fuente/Ubicación

#### Scenario: Reporte .txt de una línea por hallazgo
- **WHEN** se genera el `.txt` para un target con N hallazgos
- **THEN** el archivo contiene estrictamente una línea por hallazgo con formato `VULN-00X | <título> (Severidad: <valor|No declarada>) | <archivo fuente> → <ubicación>`

### Requirement: Deduplicación entre fuentes
Si dos archivos reportan el mismo hallazgo (mismo CVE o hallazgo en el mismo puerto), el Agente 6 SHALL contarlo una sola vez, usar como fuente principal la de más detalle textual y anotar en la ubicación las fuentes adicionales (por ejemplo `(también en outputs/nikto_80.json → línea X)`).

#### Scenario: Mismo CVE en nuclei.json y nikto
- **WHEN** nuclei y nikto reportan el mismo CVE en el mismo puerto con distinto detalle
- **THEN** el hallazgo aparece UNA vez con la fuente de mayor detalle y la referencia secundaria en la ubicación, y el total no lo duplica

#### Scenario: Header sugerido faltante repetido entre puertos
- **WHEN** Nikto reporta el mismo `Suggested security header missing` en varios puertos web distintos (ej. `nikto_80.json` y `nikto_5985.json`)
- **THEN** el agente lo cuenta UNA sola vez (fuente principal + referencias secundarias en la ubicación) y el total no lo duplica

#### Scenario: Fingerprinting repetido entre puertos
- **WHEN** Nikto reporta el mismo mensaje de fingerprinting (ej. `Retrieved x-aspnet-version header`, `Retrieved x-powered-by header`) en varios puertos web
- **THEN** el agente lo cuenta UNA sola vez con las referencias secundarias anotadas, y el total no lo duplica

#### Scenario: OPTIONS Allowed y Public con los mismos métodos
- **WHEN** `outputs/nikto_*.json` reporta `OPTIONS: Allowed HTTP Methods` y `OPTIONS: Public HTTP Methods` con el mismo set de métodos en el mismo puerto
- **THEN** el agente los fusiona en UN hallazgo y el total no los duplica

#### Scenario: Detección de SMB signing duplicada entre nuclei y nmap
- **WHEN** `outputs/nuclei.json` reporta `SMB Signing Not Required` y `outputs/nmap_detailed.*` reporta `smb2-security-mode` en el mismo target
- **THEN** el agente los fusiona en UN hallazgo (gana la fuente con severidad declarada o mas detalle)y el total no lo duplica

### Requirement: Ofuscación de datos sensibles
### Requirement: Ofuscación de datos sensibles
El Agente 6 SHALL redactar con `***` cualquier password, passwd, default password, token, API key, secret, credencial Basic o Bearer antes de escribirlo en los reportes. Los archivos fuente en `outputs/` NO se modifican.

#### Scenario: Credencial en texto del hallazgo
- **WHEN** la descripción de un hallazgo contiene un password o token en claro
- **THEN** el reporte muestra el valor redactado como `***` y el archivo fuente queda intacto

### Requirement: Confirmación de entrega
Al terminar por target, el Agente 6 SHALL informar: `✅ <target> analizado. N hallazgos extraídos de los archivos fuente.` con el conteo de severidades declaradas y los dos archivos generados; si N = 0, SHALL informar `⚠️ <target>: No se encontraron hallazgos explícitos en ninguno de los archivos fuente. No se generaron reportes.`

#### Scenario: Con hallazgos
- **WHEN** el análisis extrae ≥1 hallazgo
- **THEN** se imprime la confirmación `✅` con N, severidades declaradas y las rutas de los dos archivos generados

#### Scenario: Sin hallazgos
- **WHEN** ninguna fuente contiene hallazgos explícitos
- **THEN** se imprime el aviso `⚠️` y no se generan archivos de reporte
- **AND** si existían `_resumen_vulnerabilidades.doc` / `_resumen_breve.txt` previos de un análisis anterior, se eliminan (salvo `--dry-run`) para no entregar información obsoleta

### Requirement: Modos de ejecución
El Agente 6 SHALL exponer, al menos, los mismos flags de convención que el resto de scripts: `--project` (nombre del directorio destino, default `CLIENTE`), `--target IP` (repetible), `--dry-run` (no crea archivos) y `--no-clobber` (no sobrescribe existentes).

#### Scenario: Ejecución normal
- **WHEN** se ejecuta `python3 scripts/make_vuln_report.py --project CLIENTE`
- **THEN** se procesan todos los targets con `outputs/` bajo `CLIENTE/` y se generan los reportes por target

#### Scenario: Dry-run
- **WHEN** se usa `--dry-run`
- **THEN** se imprime la estructura prevista sin crear ni sobrescribir archivos
- **THEN** el ítem no se incluye en el reporte