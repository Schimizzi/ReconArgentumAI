# step9_iis_shortname_scan — IIS Short File Name Disclosure (8.3)

Detección y enumeración de **IIS Short File Name Disclosure** (divulgación de
nombres cortos 8.3 de Windows, también llamada *IIS tilde enumeration*,
CVE-2007-5418) sobre las URLs identificadas como Microsoft-IIS en los outputs
de Gobuster del repositorio.

## Vulnerabilidad

IIS genera nombres cortos 8.3 (`AAAAAA~1.EXT`) para archivos/directorios
largos. Haciendo requests con comodines y el literal `~1` es posible:

- confirmar que el servidor está expuesto (detección), y
- listar parcialmente los nombres de archivos/directorios sin listado de
  directorio (`Options Indexes`), porque las respuestas HTTP difieren según el
  prefijo coincida o no con un nombre corto real.

Mitigación en IIS: `Fsutil behavior set disable8dot3 1` (o/aureo de la unidad)
y/o quitar la opción `Enable 8.3 name creation` en la config del sitio.

## Técnica implementada

Basada en el scanner de referencia público `lijiejie/IIS_shortname_Scanner`
con adaptación para IIS 8/10 (request filtering y soft-404):

### 1. Detección (`is_vulnerable`)

Por cada directorio `<dir>` se comparan las sondas clásicas:

| Request | Significado | Status esperado |
|---|---|---|
| `<dir>/*~1*/a.aspx` | comodín nulo (existe cualquier shortname) | **404** |
| `<dir>/l1j1e*~1*/a.aspx` | prefijo aleatorio inexistente | **≠ 404** |

En **AUTO** (default) el flujo es:

1. Probar con **GET**: si diferencia (404 vs otro) ⇒ vulnerable y se enumera con GET.
2. Si GET **no diferencia** (en IIS 8/10 suele devolver `400` por *request filtering* sobre el comodín `*`, o el sitio responde soft-404 global), se prueba con **OPTIONS**, que sí permite el comodín y diferencia `404` vs resto. Si OPTIONS diferencia ⇒ vulnerable y se enumera con OPTIONS.

Se puede forzar el método con `--method GET` u `--method OPTIONS`.

### 1bis. Sonda de confirmación (evita falsos positivos)

Antes de lanzar el BFS se hace una sonda real de enumeración con el método
elegido:

| Sonda | Esperado si hay shortnames |
|---|---|
| `<dir>/a*~1.*/1.aspx` | **404** (existe un nombre 8.3 que empieza por `a…`) |
| `<dir>/zz*~1.*/1.aspx` | **≠ 404** (prefijo aleatorio sin match) |

Si ambas devuelven lo mismo ⇒ la enumeración no es fiable y el directorio se
marca **INCONCLUSO** (posible falso positivo o shortname con caracteres fuera
del set alfanumérico) en lugar de lanzar miles de requests. Puede omitirse con
`--no-confirm`.

### 2. Enumeración (BFS)

Con el método elegido (`--method`/AUTO) se piden
`<dir><prefijo>*~1<ext>/1.aspx`:

- status **404** ⇒ existe un nombre corto cuyo prefijo es `<prefijo>`;
- se expande carácter a carácter de `abcdefghijklmnopqrstuvwxyz0123456789_-`
  (máx. 6 caracteres de base, más la extensión).

Por directorio hay un **corte de seguridad** `--max-reqs` (default 1000) para
acotar casos de soft-404 (donde todo responde 404 y el BFS explotaría).

El resultado son nombres cortos 8.3 parciales (p. ej. `/applic~1`), que luego
el analista puede validar manualmente.

## Descubrimiento de URLs objetivo

El script **lee los `gobuster_evidence.txt` de los targets** y toma solo las
URLs cuyo servidor es IIS:

1. `CLIENTE/<IP>_*/outputs/gobuster_evidence.txt` — líneas
   `VERSIONS<TAB>URL<TAB>Server: Microsoft-IIS/...` ⇒ sitios base IIS.
2. `CLIENTE/<IP>_*/outputs/gobuster_<port>.txt` del mismo puerto — paths con
   `(Status: 301|302|307|308|403)` ⇒ directorios de cada sitio a escanear.

Targets sin evidencia IIS (Apache/Express/nginx…) se **omiten** y se reportan.
Ejemplo con los 5 targets solicitados (10.155.10.14, 10.155.10.15,
10.156.244.42, 10.156.244.50, 10.156.244.51): solo **10.155.10.15**,
**10.156.244.42** (puertos 80 y 81) y **10.156.244.50** (solo :80; el :8080 es
Tomcat) presentan `Microsoft-IIS`.

## Uso

Hoy vive en `scripts/host/` y tiene dos modos:

- **Modo manual** (bajo demanda sobre `CLIENTE/`): descubre IIS desde
  `outputs/gobuster_evidence.txt`, tal como siempre.
- **Modo pipeline** (`--ev-dir`): lo invoca `run_target.sh` en el **Step 9**, apuntando directo
  a `evidence/<IP>/`. En el pipeline **no existe** `gobuster_evidence.txt` todavía (eso lo
  genera `check_gobuster_urls.sh` a mano); por eso el descubrimiento IIS usa el campo
  `webserver` de `httpx.json` (el Step 2) y los directorios de `gobuster_<port>.txt` (Step 7).

### Modo manual (bajo demanda, como siempre)

```bash
# todos los targets con IIS del CLIENTE/
python3 scripts/host/step9_iis_shortname_scan.py

# un target concreto
python3 scripts/host/step9_iis_shortname_scan.py --target 10.155.10.15

# solo el puerto 81 de un target
python3 scripts/host/step9_iis_shortname_scan.py --target 10.156.244.42 --port 81

# sin enumerar, solo confirmar vulnerabilidad
python3 scripts/host/step9_iis_shortname_scan.py --isvuln

# URLs manuales (una por línea)
python3 scripts/host/step9_iis_shortname_scan.py --urls mis_urls.txt

# ver qué URLs se escanearían, sin tráfico
python3 scripts/host/step9_iis_shortname_scan.py --dry-run
```

### Modo pipeline (lo llama el Step 9 de `run_target.sh`)

```bash
# Apunta directo a un dir de evidencia del pipeline (evidence/<IP>). Descubre las
# URLs IIS desde httpx.json y escribe las salidas en el mismo <DIR>.
python3 scripts/host/step9_iis_shortname_scan.py --ev-dir evidence/10.155.10.15 --dry-run
python3 scripts/host/step9_iis_shortname_scan.py --ev-dir evidence/10.155.10.15 --target 10.155.10.15
```

> En modo `--ev-dir` el resumen global (`iis_shortname_summary.txt`) queda **dentro** del
> mismo `<DIR>` de evidencia (self-contained en `evidence/<IP>/`), no en `CLIENTE/`.

### Flags

| Flag | Descripción |
|---|---|
| `-p, --proyecto DIR` | raíz con `CLIENTE/<IP>_*/outputs` (default `CLIENTE`) |
| `--ev-dir DIR` | MODO PIPELINE: dir de evidencia directo (ej. `evidence/<IP>`); descubre IIS desde `httpx.json` |
| `-o, --out DIR` | resumen global y salidas de targets sin carpeta en CLIENTE (default `CLIENTE/iis_shortname_checks`) |
| `-t, --target IP` | solo ese target |
| `--port N` | solo ese puerto del sitio IIS |
| `-u, --urls FILE` | URLs manuales en vez del descubrimiento |
| `--only-root` | solo la raíz, sin directorios de gobuster |
| `--isvuln` / `--no-enum` | solo detección, sin enumerar |
| `--method M` | método HTTP para detección/enumeración: `GET`, `OPTIONS` o `AUTO` (default AUTO) |
| `--no-confirm` | omitir la sonda `a*` vs `zz*` antes de enumerar |
| `--force` | sobrescribir evidencia aunque la corrida sea SIN CONEXIÓN total |
| `-c, --threads N` | hilos de enumeración (default 20) |
| `--max-reqs N` | corte de requests de enumeración por directorio (default 1000) |
| `-T, --timeout N` | timeout por request en segundos (default 8) |
| `-d, --delay S` | espera entre directorios (default 0.2) |
| `--dry-run` | listar URLs sin enviar requests |
| `-v, --verbose` | verboso |

## Salidas

Por target, dentro de la carpeta `outputs/` de cada target de CLIENTE
(`CLIENTE/<IP>_<sufijo>/outputs/`, junto a los outputs de gobuster):

| Archivo | Contenido |
|---|---|
| `iis_shortname_evidence.txt` | hallazgos `IIS_SHORTNAME<TAB>URL<TAB>ESTADO+DETALLE` |
| `iis_shortname_evidence.json` | idem en JSON (formato estándar del repo) |
| `iis_shortname_commands_outputs.txt` | evidencia humana por request (auditoría) |
| `iis_scan_urls.txt` | URLs/directorios escaneados |
| `iis_shortname_skipped_corridas.txt` | registro de corridas SIN CONEXIÓN que no sobrescribieron evidencia previa |

### Estados posibles en un hallazgo

El `evidence.txt` marca explícitamente el resultado por URL:

| Estado | Qué significa | Acción sugerida |
|---|---|---|
| `VULNERABLE CONFIRMADO` | Se detectó la diferencia **y** se enumeró al menos un shortname 8.3 (`~1`) | Reportar como hallazgo confirmado |
| `DETECCION POSITIVA - ENUMERACION INCONCLUSA` | La sonda clásica diferencia, pero `a*` vs `zz*` no (falso positivo probable o caracteres fuera del set) | Validar manualmente; no reportar como explotado |
| `DETECCION POSITIVA - ENUMERACION INCOMPLETA` | Hay hits pero el BFS se cortó por `--max-reqs` (`CUT`) | Re-escanear con `--max-reqs` mayor o validar manualmente |
| `DETECCION POSITIVA` | Solo con `--isvuln` (no se enumeró) | Ejecutar sin `--isvuln` para confirmar |
| — (no aparece en evidence) | `NO_VULNERABLE` o `SIN_CONEXION` | Ver `commands_outputs.txt` |

El resumen global conserva **todas las corridas** (no las pisa) y muestra por
target: `detect / confirm / inconcl / incompl / no_vuln / sin_conn / shortnames`.

### Protección anti-sobrescritura

Si una corrida es **SIN CONEXIÓN total** (todos los hosts no respondieron) y ya
existía evidencia previa con datos, el script **NO la sobrescribe**: escribe una
nota en `iis_shortname_skipped_corridas.txt` y muestra `[SKIP]`. Para forzar el
re-escaneo usar `--force`.

Resumen global: `iis_shortname_checks/iis_shortname_summary.txt` (targets,
URLs, sitios vulnerables y shortnames encontrados). Si se usa `--urls` (URLs
manuales) o un proyecto sin carpetas de target, las salidas por target van en
`--out <DIR>/<IP>/`.

Ejemplo de hallazgo:

```
IIS_SHORTNAME	http://10.155.10.15:8082/	Server vulnerable a IIS Short File Name Disclosure (8.3/~1): difiere por OPTIONS; metodo de enumeracion: OPTIONS
IIS_SHORTNAME	http://10.155.10.15:8082/	Posible nombre corto 8.3 (directorio): /applic~1
```

Si la sonda de confirmación no diferencia, en `iis_shortname_commands_outputs.txt`
quedará una línea `INCONCLUSO| ...` advirtiendo del posible falso positivo en
lugar de lanzar el BFS.

> **Nota**: la severidad la decide el analista (el script solo marca el tipo de
> hallazgo, igual que `check_gobuster_urls`).

## Limitaciones

- Requiere conectividad con los puertos (VPN/LAN de la campaña).
- La enumeración cubre los **primeros 6 caracteres** del nombre 8.3 (base) y la
  extensión; los 2 caracteres finales + `~1` se infieren.
- El **request filtering** de IIS puede devolver `400` a los `GET` con comodín
  `*`; por eso el modo AUTO hace *fallback a OPTIONS*. Si aún así no hay
  diferencia en la sonda de confirmación, el directorio se marca `INCONCLUSO`
  (posible falso positivo).
- Pueden existir **falsos positivos/negativos** según la página de error
  personalizada de IIS; conviene validar manualmente cada shortname hallado
  (p. ej. con `curl -I` contra `<URL><shortname>`).
- Targets cuyo `gobuster_evidence.txt` no reporta `Server: Microsoft-IIS` se
  omiten automáticamente.

## Referencias

- `lijiejie/IIS_shortname_Scanner` (técnica de detección/enumeración).
- `bitquark/shortscan` (enumeración con checksums, Go).
- Soroush Dalili — “IIS Short Name Scanner”, investigación original del 8.3.