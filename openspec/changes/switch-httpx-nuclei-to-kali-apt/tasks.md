## 1. Dockerfile

- [x] 1.1 Agregar `httpx-toolkit` y `nuclei` al `apt-get install` de la Sección 1 (paquetes de Kali).
- [x] 1.2 Eliminar del `ENV` las variables `HTTPX_VERSION` y `NUCLEI_VERSION`.
- [x] 1.3 Eliminar las secciones de descarga de binarios oficiales de GitHub (httpx y nuclei), incluido el symlink `httpx-pd → httpx`.
- [x] 1.4 Actualizar el sanity check del build: `command -v httpx-toolkit` (antes `httpx-pd || httpx-toolkit`) y mantener `command -v nuclei`.

## 2. Lanzador y docs

- [x] 2.1 Actualizar el sanity de `run_docker.sh`: lista de tools con `httpx-toolkit` (antes `httpx-pd`) y resolución del probe con `httpx-toolkit` directo.
- [x] 2.2 Actualizar `README.md` (Prerrequisitos — nota del contenedor: `httpx-toolkit` vía apt, ya no symlink `httpx-pd`).
- [x] 2.3 Actualizar `specs/agent_recon_pipeline.md` (Step 2 — nota de binario en Kali/Docker: `httpx-toolkit` vía apt).

## 3. Validación

- [x] 3.1 `docker compose build --progress=plain`: sanity del build OK con las 10 tools (incluye `/usr/bin/httpx-toolkit` y `/usr/bin/nuclei`).
- [x] 3.2 `docker compose run --rm -T pentest bash -c '…'`: sanity 10/10 OK dentro del contenedor; `httpx-toolkit → /usr/bin/httpx-toolkit`, `nuclei → /usr/bin/nuclei` (v3.11.1-0kali1), `httpx-pd` ausente (correcto).
- [x] 3.3 Confirmar versiones de los paquetes apt instalados: `httpx-toolkit 1.9.0-0kali2`, `nuclei 3.11.1-0kali1`.
- [x] 3.4 Verificar que `step2_httpx.sh` resuelve `httpx-toolkit` (prioridad 1) dentro del contenedor (no requiere cambios: la resolución ya lo priorizaba).