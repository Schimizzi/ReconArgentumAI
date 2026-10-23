## Why

El `Dockerfile` instalaba httpx y nuclei de ProjectDiscovery descargando los binarios oficiales de GitHub (`curl` + `unzip`), con versiones pineadas (`HTTPX_VERSION`/`NUCLEI_VERSION`). En Kali Linux estos tools ya se distribuyen como paquetes nativos (`httpx-toolkit` y `nuclei`), más simples de mantener y alineados con el entorno estándar de Kali. Instalarlos vía apt elimina la descarga manual de binarios, las variables de versión y el symlink `httpx-pd` construido a mano, y deja el contenedor idéntico a una VM Kali real.

## What Changes

- **`Dockerfile`**: se agregan `httpx-toolkit` y `nuclei` al `apt-get install` de la Sección 1 (paquetes de Kali). Se eliminan las secciones de descarga de los binarios oficiales de GitHub (httpx y nuclei), las variables de entorno `HTTPX_VERSION` / `NUCLEI_VERSION`, y el symlink `httpx-pd → httpx`.
- **Sanity check del build**: ahora verifica `command -v httpx-toolkit` (antes aceptaba `httpx-pd || httpx-toolkit`) y mantiene `command -v nuclei`.
- **`run_docker.sh`**: el sanity del contenedor chequea `httpx-toolkit` (antes `httpx-pd`) y resuelve el probe con `httpx-toolkit` directamente.
- **Docs**: `README.md` y `specs/agent_recon_pipeline.md` actualizados: el contenedor Docker instala `httpx-toolkit` vía apt (igual que la VM Kali), ya no existe el symlink `httpx-pd`.
- **Versión resultante**: httpx pasa de 1.10.0 (pinned, binario) a 1.9.0-0kali2 (paquete apt). nuclei queda en la misma versión que trae el paquete apt: 3.11.1-0kali1 (idéntica a la pineada anterior).

No hay cambios de script: `step2_httpx.sh` ya resolvía el binario con prioridad `httpx-toolkit` → `httpx-pd` → `httpx`, y lo que ahora instala el paquete apt es exactamente `httpx-toolkit`.

## Capabilities

### New Capabilities

- Ninguna (no se introduce una capability nueva).

### Modified Capabilities

- Ninguna a nivel de spec: el cambio es de tooling/infraestructura de la imagen. El comportamiento observable del pipeline (DAG de 10 steps, inputs/outputs, manifests, Service-Based Routing) no cambia; los steps invocan las mismas herramientas con los mismos flags y salidas. Por eso el change usa `skip_specs: true` (no se inventa un requerimiento solo para validar).

## Impact

- **Docker** (modificado): `Dockerfile` (apt `httpx-toolkit` + `nuclei`, se eliminan descargas y symlink); `run_docker.sh` (sanity del contenedor con `httpx-toolkit`).
- **Docs** (modificados): `README.md` (Prerrequisitos — nota de `httpx-toolkit` en contenedor); `specs/agent_recon_pipeline.md` (Step 2 — nota de binario en Kali/Docker).
- **Scripts**: ninguno. `step2_httpx.sh` ya priorizaba `httpx-toolkit`; `preflight_run.sh` acepta ambos binarios.
- **Dependencias**: se reduce una dependencia de red en el build (ya no se descargan zip de GitHub para httpx/nuclei); los paquetes apt se resuelven desde los repos de Kali. La imagen sigue instalando SecLists por git (sin cambios).
- **Compatibilidad**: no rompe contratos: la resolución de binario del probe sigue siendo `httpx-toolkit` → `httpx-pd` → `httpx` (el contenedor usa el primero). El `httpx` del PATH (cliente Python) sigue prohibido para probe en todos los scripts.