# CLEANUP_PLAN.md — Plan de limpieza por lotes (MODO B, aprobado)

> **Rama:** `chore/cleanup-audit` · **Fecha:** 2026-10-22.
> **Invariantes por lote:** un lote = un commit atómico `chore(cleanup): <lote>` · después de CADA lote
> `python3 scripts/qa_check.py` debe dar **107/107 PASS** · backup previo (git o `plans/.backup_cleanup_2026-10-22/`) ·
> sin `push`, sin `reset --hard`, sin reescribir historia · si el QA baja o algo se rompe → `git revert` del commit
> y re-clasificar el ítem como DUDA.

---

## Lote 1 — Basura no ambigua (riesgo BAJO)

| Campo | Detalle |
|---|---|
| **Archivos** | `scripts/__pycache__/` (2 `.pyc`: `cves_md.*`, `cve_research_vulnx.*`), `.DS_Store` |
| **Comando** | `rm -rf scripts/__pycache__ .DS_Store` |
| **Verificación** | `python3 scripts/qa_check.py` == 107/107 · `find . -name '*.pyc' -not -path './tools/WhatWeb/*'` vacío |
| **Rollback** | Regenerable (`.pyc`); `.DS_Store` trivial |
| **Commit** | `chore(cleanup): remove pycache and DS_Store` |

## Lote 2 — Doc fixes / convención (riesgo BAJO)

| Campo | Detalle |
|---|---|
| **Archivos** | `README.md` (badge L5; conteo QA L44) · `specs/agent_recon_pipeline.md` (link L4) · `scripts/cves_md.md` (nota MANUAL) · `scripts/gobuster_urls.md` (nota MANUAL) · `scripts/host/post_step1_open_ports.md` (nota obsoleto/huérfano) · **nuevo** `scripts/install_souls.md` · `scripts/README.md` (fila `install_souls.sh`) |
| **Comando** | Edición puntual de texto + alta del `.md` y la fila |
| **Verificación** | `grep -n '8 comprobaciones' README.md`→0 · `grep -n '10%20Steps' README.md`→0 · `test -f scripts/install_souls.md` · `grep -n install_souls scripts/README.md`≥1 · QA 107/107 |
| **Rollback** | `git revert` |
| **Commit** | `chore(cleanup): fix doc drift and document manual/huerfano scripts` |

## Lote 3 — `tools/httpx-pd` fuera del tree git (riesgo MEDIO)

| Campo | Detalle |
|---|---|
| **Archivos** | `tools/httpx-pd` (`git rm --cached`) · `.gitignore` (alta) · `README.md`/`RUNBOOK.md`/`scripts/install_host_tools.md` (doc instalación por PATH) |
| **Comando** | `git rm --cached tools/httpx-pd` + regla `tools/httpx-pd` en `.gitignore` + nota "se resuelve por `PATH` (`command -v httpx-pd`); instalar vía `go install`/vendor" |
| **Verificación** | `git ls-files tools/httpx-pd`→vacío · binario sigue en disco (`test -x tools/httpx-pd`) · scripts siguen usando `command -v httpx-pd` (sin cambios) · QA 107/107 |
| **Rollback** | `git revert` |
| **Commit** | `chore(cleanup): untrack tools/httpx-pd binary (resolved via PATH)` |
| **Nota** | NO reduce `.git` (blob persiste en historia). Reducirlo exige rewrite (prohibido). |

## Lote 4 — OpenSpec archive + tests (riesgo BAJO)

| Campo | Detalle |
|---|---|
| **Archivos** | Mover a `openspec/changes/archive/2026-10-22-<nombre>/`: `add-consolidador-hallazgos`, `switch-httpx-nuclei-to-kali-apt`, `unify-fase1-sin-llm` · **nuevo** `tests/test_agente4_field_evidence.py` (promovido de `/tmp`) · opcional `tests/README.md` |
| **Comando** | `mkdir -p openspec/changes/archive && git mv openspec/changes/<n> openspec/changes/archive/2026-10-22-<n>` (×3) · `mkdir -p tests && cp /tmp/test_agente4_field_evidence.py tests/` |
| **Verificación** | `ls openspec/changes/` sin los 3 movidos · `ls openspec/changes/archive/` incluye los 3 con fecha · `python3 -m pytest tests/ -q` o `python3 tests/test_agente4_field_evidence.py` (si es standalone) · QA 107/107 |
| **Rollback** | `git revert` (o `git mv` inverso) |
| **Commit** | `chore(cleanup): archive completed openspec changes and add agente4 test` |

---

## Fuera de alcance (propuesta, requiere MODO C o D)

- **MODO C:** `scripts/lib/evidencia.py` (load_json/jsonl, warn, ofuscar, get_target_id, parsers nmap) +
  modularizar `make_vuln_report.py` / `check_gobuster_urls.sh`. Migración script por script con QA verde.
- **MODO D (datos):** `CLIENTE/gobuster_checks_old`, `tools/WhatWeb/.git`, archivar los 4 changes restantes
  al 100% de tareas no-sync. **Backups `.backup_pre_*`: NO TOCAR** (decisión del usuario).
- **MODO D (código citado, no borrado en B):** `cves_md.py`, `gobuster_urls.sh`, `post_step1_open_ports.sh`
  (documentados como MANUAL/HUÉRFANO en Lote 2).
