# `check_gobuster_urls.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es un script que **visita automáticamente las direcciones web descubiertas** por Gobuster (el
escaneo de carpetas/páginas de un sitio) y busca **pistas de vulnerabilidades o información
sensible** para después reportar.

Trabaja **por objetivo (target)**: revisa las URLs de **un equipo a la vez** y deja los
resultados en la carpeta de ese equipo, listos para que el generador de informes los incorpore.

---

## 🎯 Cómo se usa (modo recomendado: por target)

```bash
# Revisar UN equipo (IP)
bash scripts/check_gobuster_urls.sh --target 10.155.10.15

# Revisar TODOS los equipos que tengan escaneo de Gobuster
bash scripts/check_gobuster_urls.sh --all

# Re-escanear un equipo aunque ya tenga resultados (pisa los anteriores)
bash scripts/check_gobuster_urls.sh --target 10.156.244.42 --force

# Probar sin ejecutar nada (enseña qué URLs revisaría)
bash scripts/check_gobuster_urls.sh --target 10.155.10.15 --dry-run
```

### Lo que hace por cada equipo, en orden
1. **Ubica la carpeta** del target (busca `CLIENTE/<IP>_vuln/outputs/`).
2. **Verifica si ya fue escaneado**: si existe `gobuster_evidence.*`, lo **salta** (SKIP) para no
   pisar el trabajo ya hecho. `--force` lo re-escanza.
3. **Arma la lista de URLs** de ese equipo desde sus resultados de Gobuster.
4. **Chequea conectividad** antes de tocar nada:
   - **Si el equipo NO responde** (por ejemplo porque la VPN de ese rango está apagada) →
     **NO genera hallazgos**. Solo deja una constancia en `CLIENTE/gobuster_checks/`
     (`gobuster_checks_RAW.txt` + `gobuster_checks_unreachable.txt`) y pasa al siguiente.
   - **Si responde** → visita todas sus URLs aplicando los chequeos.
5. **Deja la evidencia en la carpeta del equipo** (`CLIENTE/<IP>_vuln/outputs/`).

---

## 📥 Entrada / 📤 Salida por target

### Entrada
- Un escaneo de Gobuster previo: `CLIENTE/<IP>_vuln/outputs/gobuster_<puerto>.txt`
  (y, si existe, `httpx.json` para saber si usar HTTP o HTTPS).

### Salida — en `CLIENTE/<IP>_vuln/outputs/`

| Archivo | Para quién | Qué contiene |
|---|---|---|
| `gobuster_evidence.txt` | **El Agente 6 / generador de informes** | Los hallazgos en texto (una línea por hallazgo). Se incorpora automáticamente al informe del equipo. |
| `gobuster_evidence.json` | **El Agente 6 / generador de informes** | Lo mismo en formato JSON (el consolidador lo detecta solo). |
| `gobuster_commands_outputs.txt` | **Auditoría humana (vos)** | **Cada comando `curl` ejecutado + su salida completa** (headers y body) por cada URL. Es la evidencia de lo que se hizo; **NO lo lee el Agente 6**. |

> **Sin duplicados "de sitio":** los chequeos que dependen del **servidor** (headers de
> seguridad, versión del software) se reportan **una sola vez por sitio** (`host:puerto`), no por
> cada página. En cambio, lo que depende del **path** (redirects, títulos, métodos HTTP) se
> reporta por cada ruta descubierta, ya que es información real de esa URL.

### Salida — global de cada corrida (en `CLIENTE/gobuster_checks/`)

| Archivo | Qué contiene |
|---|---|
| `gobuster_checks_RAW.txt` | Registro crudo de la corrida (qué se revisó y si hubo URLs sin conexión). |
| `gobuster_checks_unreachable.txt` | Targets/URLs que **no respondieron** en esta corrida (posible VPN apagada). |

> Estos dos archivos son la **evidencia de la corrida actual**: si en una corrida un target no
> responde, queda anotado ahí para que sepas con qué VPN reintentar.

---

## 🔍 ¿Qué chequea por cada página?

| Revisión | Qué detecta |
|---|---|
| **Identificación** | Redirecciones, título de la página, respuestas de error, "página 404 falsa" |
| **Headers de seguridad** | Si faltan protecciones web estándar (CSP, HSTS, X-Frame-Options…) |
| **Versiones de software** | Qué programa y versión corre (ej. IIS 10.0, Tomcat 9.0) → sirve para buscar CVEs |
| **Métodos HTTP** | Si el servidor permite métodos peligrosos (PUT/DELETE/WebDAV…) |
| **TRACE** | Si el servidor "devuelve" la petición tal cual (posible ataque XST) |
| **Listado de directorios** | Si una carpeta muestra su contenido público ("Index of…") |
| **Errores reveladores** | Mensajes de error que filtran datos internos (errores SQL, stack traces) |
| **Credenciales / secretos** | Si una página expone contraseñas, claves o tokens |
| **CORS** *(opcional)* | Si otras webs podrían leer los datos del sitio con credenciales |
| **WebDAV** *(opcional)* | Si el servidor permite editar archivos por web |

---

## 🔑 El tema de las VPN (varias redes en el mismo cliente)

La red tiene **varias VPN**: no todas las direcciones están visibles al mismo tiempo. El flujo
pensado es:

```bash
# 1) Con la VPN-1 activa: revisa todos los targets (los de la VPN-2/3 quedan "sin conexión")
bash scripts/check_gobuster_urls.sh --all

# 2) Cambio a la VPN-2 y vuelvo a correr: los ya escaneados se saltan (SKIP),
#    y se revisan los que antes no respondieron.
bash scripts/check_gobuster_urls.sh --all

# (lo mismo con la VPN-3)
```

Como el script **no pisa lo ya escaneado** (SKIP) y **no inventa resultados** cuando un equipo
está inalcanzable, podés correrlo las veces que haga falta hasta cubrir todos los rangos.

---

## ⭐ El archivo `gobuster_commands_outputs.txt` (la evidencia para vos)

Es la **evidencia de auditoría**: por cada URL visitada guarda:

1. El **comando `curl` exacto** que se ejecutó.
2. Los **headers** de la respuesta.
3. El **cuerpo (body)** de la respuesta.

Sirve para que un humano pueda verificar *qué se hizo y qué respondió cada página*,
independientemente del resumen que consume el generador de informes.

---

## 🧩 Modo avanzado / legado (una sola lista de URLs)

El script también conserva el modo anterior (procesar una lista de URLs en un solo directorio):

```bash
bash scripts/check_gobuster_urls.sh -u CLIENTE/gobuster_urls_curl.txt -o CLIENTE/gobuster_checks
```

No es el modo recomendado (no documenta por target), pero sigue funcionando para casos puntuales.

---

## ⚠️ Notas

- Los chequeos son **pasivos** (solo leen, no modifican nada) y **no siguen enlaces**.
- El script **no asigna severidad** a los hallazgos de `gobuster_evidence.*`: eso lo decide el
  analista al momento de reportar. El informe del Agente 6 los mostrará como
  **"Severidad: No declarada en fuente"**, y ahí se le asigna la gravedad final a mano.
- El script trabaja los targets que tienen carpeta consolidada en `CLIENTE/` con evidencia de un
  escaneo ya autorizado (respeta el `config/scope.json`).
- Solo debe usarse sobre IPs con **autorización** (pentest firmado / infraestructura propia).
- Requiere que el target esté **consolidado** en `CLIENTE/` con su carpeta `outputs/` (generada
  por `scripts/organize_project.py`).