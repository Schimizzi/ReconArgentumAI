## Context

El `Dockerfile` de la imagen `recon-argento-stepai:latest` (base `kalilinux/kali-rolling`) instalaba httpx y nuclei de ProjectDiscovery descargando los binarios oficiales desde GitHub con `curl` + `unzip`, pineando versiones vía `ENV HTTPX_VERSION` / `NUCLEI_VERSION`, y creando un symlink `httpx-pd → httpx`. En Kali Linux ambos tools se distribuyen como paquetes nativos (`httpx-toolkit`, `nuclei`) que el pipeline ya contempla como PRIMERA prioridad de resolución del binario de probe. Ver `proposal.md` — Why.

## Goals / Non-Goals

**Goals:**
- Instalar httpx y nuclei en el contenedor desde los paquetes de Kali (`apt-get install httpx-toolkit nuclei`), igual que en la VM Kali.
- Eliminar del `Dockerfile` las descargas de GitHub, las variables de versión y el symlink `httpx-pd`.
- Mantener el sanity check del build y el sanity de `run_docker.sh` coherentes con el binario real instalado (`httpx-toolkit`).
- Documentar la nueva instalación en `README.md` y `specs/agent_recon_pipeline.md`.

**Non-Goals:**
- No cambiar el comportamiento del pipeline ni los specs (los 10 steps, inputs/outputs, manifests quedan idénticos).
- No modificar la resolución de binario de los scripts (`httpx-toolkit → httpx-pd → httpx` ya existía).
- No versionar los paquetes apt (Kali rolling trae la última; el pin de versiones deja de aplicarse a estos tools).

## Decisions

- **Usar los paquetes apt de Kali (`httpx-toolkit`, `nuclei`) en lugar de los binarios oficiales de GitHub**: el paquete `httpx-toolkit` instala el binario `/usr/bin/httpx-toolkit` (Kali lo renombra para no chocar con `python3-httpx`), que es exactamente lo que `step2_httpx.sh` prioriza. Nuclei instala `/usr/bin/nuclei` con la misma versión que ya usaba el pipeline (3.11.1). Alternativa considerada: mantener los binarios GitHub → descartada por pedido explícito del usuario de alinear el contenedor con el Kali estándar (`sudo apt install httpx-toolkit` / `sudo apt install nuclei`).
- **Eliminar el symlink `httpx-pd → httpx`**: el contenedor ahora resuelve `httpx-toolkit` directamente; mantener el symlink sería un residuo del binario descargado. La resolución de `step2_httpx.sh` cae en `httpx-toolkit` sin necesidad del symlink.
- **`skip_specs: true` en el change**: este cambio es de infraestructura/tooling; no altera ningún requirement de `openspec/specs/recon-pipeline/spec.md` (el comportamiento observable es el mismo). No se inventa un requerimiento solo para satisfacer la validación.

## Risks / Trade-offs

- [El contenedor deja de pinear la versión de httpx/nuclei (Kali rolling puede actualizarlas en futuros rebuilds)] → Mitigación: alineación con la VM Kali (mismo origen apt); si se necesita una versión exacta, se documenta en el Dockerfile y se puede revertir a binarios GitHub.
- [httpx baja de 1.10.0 (pinned) a 1.9.0-0kali2 (apt Kali)] → Impacto: el pipeline usa flags estándar de httpx (`-l`, `-o`, `-json`, `-timeout`, `-retries`, `-t`) presentes en 1.9.0; validado en el sanity y en `httpx-toolkit -version`.
- [El sanity del build falla si el paquete `httpx-toolkit`/`nuclei` no existe en los repos de Kali] → Mitigación: son paquetes oficiales de Kali (verificados en kali.org/tools); el build lo detecta de inmediato y da error claro.

## Migration Plan

1. Los cambios ya están implementados en el working tree (`Dockerfile`, `run_docker.sh`, `README.md`, `specs/agent_recon_pipeline.md`).
2. Rebuild de la imagen cuando se requiera: `docker compose build` (ya ejecutado y validado en esta sesión: sanity build OK, `httpx-toolkit` y `nuclei` en `/usr/bin`).
3. Rollback: revertir los archivos modificados y el change de OpenSpec correspondiente; volver a agregar los `ENV HTTPX_VERSION`/`NUCLEI_VERSION`, las descargas GitHub y el symlink `httpx-pd`.

## Open Questions

Ninguna: no hay preguntas que puedan cambiar los specs, el approach o el desglose de tareas.