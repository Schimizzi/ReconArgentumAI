# AUDIT_REPORT.md — Auditoría de mantenimiento (MODO B)

> **Proyecto:** ReconArgentumAI — pipeline de pentest multi-agente (academia/lab).
> **Rama:** `chore/cleanup-audit` · **Fecha:** 2026-10-22 · **Modo:** B (auditoría + limpieza segura por lotes).
> **Baseline QA del inventario:** `python3 scripts/qa_check.py` → **107/107 PASS | 0/107 FAIL**
> (al momento de la auditoría). La línea base **actual** es **102/102** tras retirar CK-08 (ver **§9**).
> **Regla de oro aplicada:** sólo es elegible para borrado lo que tenga **0 referencias** en código, docs,
> specs, `.clinerules`, SOULs, master_prompt, YAML, Dockerfile y entrypoints de shell. Todo lo demás = propuesta.

---

## 1. Executive summary — Top 10 hallazgos por impacto

| # | Hallazgo | Evidencia | Veredicto | Acción | Riesgo | Cómo se verifica |
|---|---|---|---|---|---|---|
| 1 | `tools/httpx-pd` (51 MiB) trackeado en git, **0 referencias por ruta** | `git cat-file -s HEAD:tools/httpx-pd` = 53490930; `grep -rn 'tools/httpx'` sólo docs; resolución por `command -v httpx-pd` | HUÉRFANO-de-ruta | **Lote 3:** `git rm --cached` + `.gitignore` + doc | Medio | tree sin binario; QA 107/107 |
| 2 | `__pycache__` + `.DS_Store` | `find . -name '*.pyc'` | Basura no ambigua | **Lote 1:** borrar | Bajo | `find` vacío; QA 107/107 |
| 3 | README con badge y QA-count obsoletos | `README.md:5` (10 steps/9 tools) y `:44` ("8 comprobaciones") vs `:7,53,69,344` (12 steps/11 tools, 10 checks) | Doc drift | **Lote 2:** corregir texto | Bajo | `grep` |
| 4 | Link OpenSpec roto en spec recon | `specs/agent_recon_pipeline.md:4` apunta a change **archivado** | Doc drift | **Lote 2:** repuntar a `openspec/specs/recon-pipeline/spec.md` | Bajo | `ls` del path |
| 5 | `cves_md.py` y `gobuster_urls.sh` fuera del pipeline | 0 imports/llamadas; citados sólo en docs | MANUAL | **Lote 2:** documentar como manual | Bajo | `grep -c` invocaciones |
| 6 | `post_step1_open_ports.sh` sin invocaciones | 0 refs de código; `run_target.sh:112-113` hace el jq **inline** | HUÉRFANO | **Lote 2:** nota "obsoleto/huérfano" en su `.md` | Bajo | `grep` |
| 7 | `install_souls.sh` sin `.md` hermano ni fila en índice | `grep install_souls scripts/README.md` = 0 | Convención | **Lote 2:** crear `install_souls.md` + fila | Bajo | `grep` |
| 8 | Duplicación Python (7 funciones + 4 parsers Nmap) | `load_json`×3, `load_jsonl`×2, `warn`×2, `ofuscar`×2, `get_target_id`×2, `descubrir_targets`×2, `procesar_target`×2 | Deuda técnica | **Propuesta MODO C** (no en B) | Medio | QA por script |
| 9 | OpenSpec: 3 changes 100% + 4 sólo-sync pendiente | `tasks.md` counts | Listos | **Lote 4:** archivar | Bajo | paridad spec↔scenario |
| 10 | Sin `tests/` ni linters; test Agente 4 en `/tmp` | `ls tests/`; `command -v ruff` | Deuda | **Lote 4:** promover `/tmp/test_agente4_field_evidence.py` | Bajo | `pytest`/`unittest` local |

### 1.1 Métricas before/after

| Métrica | Before | After Lote 1 | After Lote 2 | After Lote 3 | After Lote 4 |
|---|---|---|---|---|---|
| Archivos basura (`*.pyc`, `.DS_Store`) | 3 | 0 | 0 | 0 | 0 |
| `tools/httpx-pd` en tree git | Sí (53 490 930 B) | Sí | Sí | **No** | No |
| `.git` (tamaño) | 47 M | 47 M | 47 M | 47 M* | 47 M* |
| Docs con drift (badge/count/link) | 3 | 3 | 0 | 0 | 0 |
| Changes OpenSpec activos | 7 | 7 | 7 | 7 | **4 (+4 arch.)** |
| Tests en repo | 0 | 0 | 0 | 0 | **1** |
| QA | 107/107 | 107/107 | 107/107 | 107/107 | 107/107 |

\* `git rm --cached` no reduce `.git`: el blob permanece en la historia. Reducir el historial exige
`git filter-repo`/rewrite (**prohibido** por guardrails). Impacto real: el árbol/clon de trabajo deja de
descargar 51 MiB.

---

## 2. Fase A — Grafo real de invocación (entrypoints → helpers)

```
run_docker.sh --auto ─► docker compose run … scripts/host/run_fase1_run3.sh        [run_docker.sh:83,85]
run_docker.sh --auto-target IP ─► run_target.sh IP                                 [run_docker.sh:90]
run_host.sh            ─► NO ejecuta pipeline: verifica tools e imprime comandos   [run_host.sh:77-82]
run_fase1_run3.sh      ─► run_target.sh <IP> por cada authorized_targets[]          [run_fase1_run3.sh:21,47]
preflight_run.sh       ─► verificación de tools/wordlists/scope (no invoca steps)  [preflight_run.sh]
install_host_tools.sh  ─► instalación manual (no invoca steps)
run_target.sh          ─► DAG 12 steps + helpers                                   [run_target.sh:103-437]
```

| Script | ¿Invocado por quién? (ruta:línea) | Artefactos que produce | Consume | Documentado en | Veredicto |
|---|---|---|---|---|---|
| `host/step1_nmap_ports.sh` | `run_target.sh:105` | `nmap_ports.{xml,txt,gnmap}` | `scope.json` | `step1_nmap_ports.md` | VIVO |
| `xml_to_nmap_json.py` | `run_target.sh:110` | `nmap_ports.json` | XML | `xml_to_nmap_json.md` | VIVO |
| `host/step2_httpx.sh` | `run_target.sh:150` | `httpx.json` | `open_ports.txt` | `step2_httpx.md` | VIVO |
| `host/step3_nmap_detailed.sh` | `run_target.sh:164` | `nmap_detailed.*` | `open_ports.txt` | `step3_nmap_detailed.md` | VIVO |
| `host/step4_nuclei.sh` | `run_target.sh:177` | `nuclei.json` | `open_ports.txt` | `step4_nuclei.md` | VIVO |
| `host/step5_nikto.sh` | `run_target.sh:206` | `nikto_<port>.json` | `web_endpoints.txt` | `step5_nikto.md` | VIVO |
| `host/step6_whatweb.sh` | `run_target.sh:218` | `whatweb.json` | web | `step6_whatweb.md` | VIVO |
| `host/step7_gobuster.sh` | `run_target.sh:242,258,285` | `gobuster_*.txt` | web/udp | `step7_gobuster.md` | VIVO |
| `host/step7_udp_probe.sh` | `run_target.sh:256` | `udp_69.gnmap` | `stealth.yaml` | `step7_udp_probe.md` | VIVO |
| `host/detect_tls_ports.py` | `run_target.sh:302` | stdout (puertos TLS) | `nmap_detailed.*` | `detect_tls_ports.md` | VIVO |
| `host/step8_sslyze.sh` | `run_target.sh:308` | `sslyze_<port>.json` | TLS lines | `step8_sslyze.md` | VIVO |
| `host/step9_iis_shortname_scan.py` | `run_target.sh:339` | `iis_shortname_*` | `httpx.json` | `step9_iis_shortname_scan.md` | VIVO |
| `host/step10_smbclient_enum.sh` | `run_target.sh:385` | `smbclient_*.txt` | `nmap_detailed` | `step10_smbclient_enum.md` | VIVO |
| `host/step11_ldap_enum.sh` | `run_target.sh:418` | `ldapsearch*.txt` | `open_ports` | `step11_ldap_enum.md` | VIVO |
| `host/step12_enum4linux_enum.sh` | `run_target.sh:432` | `enum4linux.*` | SMB | `step12_enum4linux_enum.md` | VIVO |
| `cve_research_vulnx.py` | LLM / RUNBOOK §F2a | `cve_research/*_cves.json` | nmap/whatweb/nuclei/advisories | `specs/agent_4_cve_research.md` | VIVO |
| `resumen_exploit.py` | LLM / RUNBOOK §F2b | resumen Agente 3 | evidence | `resumen_exploit.md` | VIVO |
| `organize_project.py` | RUNBOOK §F4 | `CLIENTE/<ip>/{data,outputs}` | evidence/plans/cve_research | `organize_project.md` | VIVO |
| ~~`make_vuln_report.py`~~ | — | — | — | — | **REMOVIDO (§9)** |
| `qa_check.py` | RUNBOOK §F5 | stdout `[PASS]/[FAIL]` (CK-01..CK-10) | todos los artefactos | `qa_check.md` | VIVO |
| `php2shell_audit.py` | CK-10 / RUNBOOK | `plans/php2shell_<fecha>.md` | evidence | `php2shell_audit.md` | VIVO |
| `check_gobuster_urls.sh` | manual (flujo IIS histórico) | `gobuster_evidence.txt` + findings | `CLIENTE/` | `check_gobuster_urls.md` | MANUAL |
| `hydra_audit.sh` | manual | log de credenciales débiles | `scope` | `hydra_audit.md` | MANUAL |
| `cleanup_engagement.sh` | manual | limpia repo | — | `cleanup_engagement.md` | MANUAL |
| `install_souls.sh` | manual (Hermes) | `~/.hermes/profiles/*` | `SOULs/` | README/SOULs | MANUAL |
| `install_host_tools.sh` | manual | instala tools | — | `install_host_tools.md` | MANUAL |
| `cves_md.py` | manual (API) | `<id>_cves.md` | `cve_research/*.json` | `cves_md.md` | MANUAL |
| `gobuster_urls.sh` | manual | `gobuster_urls_curl.txt` | `CLIENTE/` | `gobuster_urls.md` | MANUAL |
| `host/post_step1_open_ports.sh` | **nadie** | `open_ports.txt` | `nmap_ports.json` | `post_step1_open_ports.md` | HUÉRFANO (doc-cited) |

**Contrato de artefactos (intacto):** `run_target.sh` produce `evidence/<ip>/{nmap_ports.*,open_ports.txt,
httpx.json,web_endpoints.txt,nmap_detailed.*,nuclei.json,nikto_*.json,whatweb.json,gobuster_*.txt,
udp_69.gnmap,sslyze_*.json,iis_shortname_*,smbclient_*.txt,ldapsearch*.txt,enum4linux.*}` + `manifest.json`
(12 entradas). `qa_check.py` CK-09 valida las 12; CK-02 valida los globs de output.


---

## 3. Fase B — Prueba de muerte (por ítem del inventario)

Comando base: `grep -rn --exclude-dir=.git --exclude-dir=CLIENTE --exclude-dir=evidence --exclude-dir=cve_research --exclude-dir=tools "<nombre>" .`

| Elemento | Refs código | Refs docs | Veredicto |
|---|---|---|---|
| `scripts/cves_md.py` | 0 (`build_cves_md` sólo su def:154) | `README.md:291,523`, `scripts/README.md:38`, `cves_md.md` | MANUAL |
| `scripts/gobuster_urls.sh` | 0 | `gobuster_urls.md`, `scripts/README.md:35` | MANUAL |
| `scripts/host/post_step1_open_ports.sh` | 0 | `scripts/README.md:67`, su `.md` | HUÉRFANO |
| `scripts/host/detect_tls_ports.py` | `run_target.sh:302` | `scripts/README.md:54` | VIVO |
| `scripts/host/step7_udp_probe.sh` | `run_target.sh:256` | `scripts/README.md:74` | VIVO |
| `scripts/hydra_audit.sh` | 0 | `README.md:472-485`, `scripts/README.md:44` | MANUAL |
| `scripts/cleanup_engagement.sh` | 0 | `README.md:522`, `scripts/README.md:45` | MANUAL |
| `scripts/install_souls.sh` | 0 | `README.md:366,521`, `SOULs/README.md`, `.gitignore:53` | MANUAL |
| `scripts/check_gobuster_urls.sh` | 0 (pipeline) | `specs/agent_recon_pipeline.md:285`, `step9_*.md/.py` | MANUAL |

**Resultado:** ningún archivo fuente trackeado calificó como MUERTO bajo la regla estricta de MODO B (todos
tienen ≥1 cita en documentación). Elegible para borrado en B sólo la basura no ambigua (Lote 1).

---

## 4. Fase C — Duplicación y optimización (propuesta MODO C)

> ⚠️ **Actualizado 2026-10-22:** `make_vuln_report.py` fue **removido** (§9); las copias que se le
> atribuían en esta tabla ya no existen → la duplicación efectiva bajó. El resto sigue vigente (ahora
> sólo `organize_project.py` y `resumen_exploit.py` comparten esas helpers/parsers).

| Función | Copias | Evidencia |
|---|---|---|
| `load_json` | 3 | `host/detect_tls_ports.py:39`, `organize_project.py:97`, `make_vuln_report.py:147` |
| `load_jsonl` | 2 | `organize_project.py:109`, `make_vuln_report.py:158` |
| `warn` | 2 | `organize_project.py:69`, `make_vuln_report.py:126` |
| `ofuscar` | 2 | `organize_project.py:74`, `make_vuln_report.py:131` |
| `get_target_id` | 2 (firmas distintas) | `organize_project.py:149`, `make_vuln_report.py:801` |
| `descubrir_targets` | 2 | `organize_project.py:158`, `make_vuln_report.py:1047` |
| `procesar_target` | 2 | `organize_project.py:377`, `make_vuln_report.py:1067` |
| Parsers Nmap | 4 | `resumen_exploit.py:120`, `cve_research_vulnx.py:786`, `make_vuln_report.py:465`, `organize_project.py:270` |
| `main()` | 8 | normal en CLIs (no es defecto) |

Scripts gigantes: `cve_research_vulnx.py` (1144+/53 KB),
`check_gobuster_urls.sh` (857/38 KB), `php2shell_audit.py` (32 KB), `step9_iis_shortname_scan.py` (33 KB).
Sintaxis: `bash -n` **OK** en todos los `.sh`; `python3 -m compileall -q scripts` **OK**.

---

## 5. Fase D — Higiene de repo y datos

| Elemento | Evidencia | Veredicto | Acción |
|---|---|---|---|
| `tools/httpx-pd` (53 490 930 B) | `git ls-files tools/httpx-pd`; 0 refs por ruta | HUÉRFANO-de-ruta | Lote 3 (MODO D) |
| `tools/WhatWeb/.git` (~40 M) | gitignored (`git check-ignore` → `.gitignore:65`) | basura local | Propuesta (MODO D, local) |
| `CLIENTE/gobuster_checks_old` (1.0 M) vs `gobuster_checks` (2.1 M) | gitignored | DUDA (datos) | Propuesta (MODO D) |
| `cve_research/.backup_pre_php2shell`, `plans/.backup_pre_rerun` | gitignored; fechados 2026-10-22 | **NO TOCAR** (directiva del usuario) | — |
| `reports/` (vacío) | protegido por guardrail #2 | DUDA | No borrar |
| 80 dirs `CLIENTE/*/data` vacíos | **los crea** `organize_project.py:386,391` | no basura | No borrar |
| `CLIENTE/iis_shortname_checks` (vacío) | default de `step9_iis_shortname_scan.py:561` | no basura | No borrar |
| `.gitignore` | — | sin reglas huérfanas | — |

---

## 6. Fase E — Documentación (DRY sin perder información)

- **Dueño único propuesto** para los 12 steps: `specs/agent_recon_pipeline.md` (spec de implementación);
  `README.md` (usuario) y `scripts/host/stepN.md` (por-script) linkean a él. `openspec/specs/recon-pipeline/spec.md`
  = contrato formal.
- **Contradicciones reales corregidas (Lote 2):**
  - `README.md:5` badge `10 Steps · 9 Tools` → `12 Steps · 11 Tools`.
  - `README.md:44` "8 comprobaciones" → "10 checks".
  - `specs/agent_recon_pipeline.md:4` link a change archivado → `openspec/specs/recon-pipeline/spec.md`.
- **Docs marcadas como MANUAL/obsoletas (Lote 2):** `cves_md.md`, `gobuster_urls.md`,
  `post_step1_open_ports.md` (obsoleto/huérfano).

---

## 7. Fase F — OpenSpec

| Change | Tasks | Estado |
|---|---|---|
| `add-consolidador-hallazgos` | 16/16 | 100% → archivar (Lote 4) |
| `switch-httpx-nuclei-to-kali-apt` | 11/11 | 100% → archivar (Lote 4) |
| `unify-fase1-sin-llm` | 19/19 | 100% → archivar (Lote 4) |
| `add-php2shell-watchlist-and-qa-hardening` | 51/53 | sólo falta VM + archive |
| `add-step11-enum4linux` | 64/65 | sólo falta sync (6.2) |
| `integrate-vulnx-cve-research` | 15/16 | sólo falta sync (6.3) |
| `refine-cve-research-precision` | 18/19 | sólo falta sync (6.4) |

CLI `openspec` **no instalado** → archivado = mover a `openspec/changes/archive/<fecha>-<nombre>/`.
Test Agente 4 en `/tmp/test_agente4_field_evidence.py` (3537 B) → promover a `tests/` (Lote 4).

---

## 8. Riesgos residuales y propuestas (fuera de MODO B)

1. `host/detect_tls_ports.py` invocado con `2>/dev/null || true` (`run_target.sh:302`) → fallo silencioso
   que degrada Step 8 a `skipped_no_tls` sin traza. *Propuesta: loggear a `_errors.log`.*
2. `.cline/master_prompt.md` (local, gitignored) cita `specs/agent_5_reporter.md` (inexistente) y "Fase 3".
   *Propuesta: sanear la plantilla versionada.*
3. Duplicación Python (§4) → librería compartida `scripts/lib/` (MODO C).
4. `tools/WhatWeb/.git`, `gobuster_checks_old`, OpenSpec archive restante (MODO D).

---

## 9. Cambio posterior ejecutado — Remoción del Agente 6 (`make_vuln_report.py`) — 2026-10-22

> **Aprobado aparte por el usuario** (limpieza técnica, no refactor). Motivo declarado: el reporte
> `.doc`/`.txt` no aportaba valor antes de completar las comprobaciones manuales.

**Eliminado (rama `chore/cleanup-audit`):**
- `scripts/make_vuln_report.py` (Agente 6, 1180 líneas) + `scripts/make_vuln_report.md`
- `specs/agent_6_consolidador_hallazgos.md`
- `openspec/specs/consolidador-hallazgos/` (capability) → OpenSpec pasa de 7 a **6 capacidades**
- Requisito **CK-08** (`openspec/specs/qa-validation/spec.md`) y su check en `scripts/qa_check.py`
- **V-08a/V-08b** + flags `--project`/`--v08a-only` en `scripts/host/validate_step11_12.sh` (+ `.md`)
- Bloque del Agente 6 en `scripts/organize_project.py`
- Datos: **100** archivos `*_resumen_*` en `CLIENTE/` — backup en
  `plans/.backup_cleanup_2026-10-22/resumen_vulnerabilidades_2026-10-22.tar.gz` (205 KB)

**Commits:** `c0f1114` (archivos), `784ef4c` (código), `201f4d6` (docs), `5637d81` (openspec)
+ Lote 5 (datos `CLIENTE/`, sin commit por estar gitignored).

**Impacto:**
| Área | Antes | Después |
|---|---|---|
| QA (`qa_check.py`) | 107/107 | **102/102** (CK-08 retirado) |
| Agentes vigentes | 1, 3, 4, 6, 7 (+Orchestrator) | **1, 3, 4, 7** (+Orchestrator) |
| Capacidades OpenSpec | 7 | **6** |
| Validador Steps 11/12 | V-01..V-08 | **V-01..V-07** |

**Verificación:** `qa_check.py` **102/102** · `tests/test_agente4_field_evidence.py` **16 PASS** ·
`bash -n` de todos los `.sh` **OK** · `compileall` **OK** · **0** referencias a "Agente 6" fuera de
`openspec/changes/**` (histórico/propuestas) y `plans/`.

**Residual no bloqueante:** `openspec/changes/**` y `plans/php2shell_2026-10-22_cierre.md` conservan
menciones históricas (registro/dato). `README.md:59` menciona la retirada a propósito. Las secciones
§1–§8 de este documento son el **snapshot previo** a la remoción.

