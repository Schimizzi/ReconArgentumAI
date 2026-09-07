## 1. Unificación de scripts del Agente 1

- [x] 1.1 Hacer el scan type de Nmap autodetectado por privilegios en `scripts/host/step1_nmap_ports.sh` y `step3_nmap_detailed.sh`: `EUID == 0` → `-sS`; si no → `-sT`.Mutable: los demas flags (retries, rtt, -Pn, -n, -sC -sV) siguen igual..




- [x] 1.2 Implementar resolución portable de wordlists (`resolve_wordlist`) en `scripts/host/step7_gobuster.sh` (`/opt/SecLists` → `$HOME/Documents/SecLists` → `tools/seclists_common.txt`) y aplicarla en los modos `dir`, `dns` y `tftp`.


- [x] 1.3 Actualizar `scripts/host/preflight_run.sh` con la misma resolución portable, verificar `smbclient` y `ping` (Agente 1 completo) y emitir mensaje accionable cuando una wordlist falte.



## 2. Imagen Docker y lanzador automático

- [x] 2.1 Agregar `samba-client` e `iputils-ping` al `Dockerfile` y extender el sanity check del build a las 9 tools + `jq`.
- [x] 2.2 Agregar los modos `--auto` y `--auto-target <IP>` en `run_docker.sh`: mismo runner `scripts/host/run_fase1_run3.sh` (o `run_target.sh`) dentro del contenedor con `WORKSPACE=/workspace`, soporte `--dry-run`, sanity con rebuild automático UNA vez si la imagen es vieja.


- [x] 2.3 Mantener el modo default de `run_docker.sh` (instrucciones del Orchestrator / LLM)) intacto y documentado en el propio script.





## 3. Documentación

- [x] 3.1 Actualizar `README.md`: tabla de modos (scripts unificados, scan type autodetectado, wordlists portables) + Quick Start con el Agente  1 automático sin LLM en ambos modos.
- [x] 3.2 Actualizar `run_host.sh` con instrucciones del modo sin LLM (`preflight_run.sh` + `run_fase1_run3.sh`).


- [x] 3.3 Actualizar `scripts/host/step1_nmap_ports.md` con la autodetección del scan type por privilegios.
- [x] 3.4 Actualizar `specs/agent_recon_pipeline.md`(§0bis: runner unificado, wordlists portables, scan type autodetectado).

.





## 4. Validación

- [x] 4.1 `bash -n` en todos los scripts modificados (`run_docker.sh`, `run_host.sh`, `step1_nmap_ports.sh`, `step3_nmap_detailed.sh`, `step7_gobuster.sh`, `preflight_run.sh`).
- [x] 4.2 Correr `scripts/host/preflight_run.sh` en el host real: verificar las 9 tools + jq y las wordlists resueltas (y su fallback al cache del repo cuando no hay `~/Documents/SecLists`).
- [x] 4.3 Correr `bash scripts/host/run_fase1_run3.sh --dry-run`: recorre los targets de `scope.json` sin ejecutar scans ni crear evidencia.
.
- [x] 4.4 Con Docker activo: `./run_docker.sh --auto --dry-run` y sanity check de las 9 tools + jq dentro de la imagen(y rebuild automático UNA vez si la imagen es vieja).
- [x] 4.5 Verificar que `scripts/host/step3_nmap_detailed.md` quedó intacto (los cambios de unificación no tocan docs ajenos).