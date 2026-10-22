# `validate_step11_12.sh` — Qué hace (guía sin saber de código)

## 🧩 ¿Qué es?

Es el **validador asistido** de los dos steps de AD: **Step 11 (LDAP con `ldapsearch`)** y **Step 12
(Enum4linux)**. Corre una batería de checks (V-01..V-08), imprime `[PASS]`/`[FAIL]` por cada uno y cierra
con `>>> VALIDATE_STEP11_12_OK` o `>>> VALIDATE_STEP11_12_FAIL`.

## ⏱️ ¿Cuándo se usa?

- Antes de dar por bueno un cambio en los Steps 11/12 (localmente o en la VM Debian con VPN).
- Como paso previo al QA de la Fase 5 cuando se tocó la parte AD/Windows.

## ▶️ Cómo se usa

```bash
# 1) Incremental sobre la evidencia existente (no re-escanea nada)
bash scripts/host/validate_step11_12.sh <IP> --ev-dir evidence/<IP>

# 2) Con credenciales (solo si la Fase 0 lo aprobó) + verificación anti-fuga del password
bash scripts/host/validate_step11_12.sh <IP> --creds usuario@dominio:password

# 3) Corrida completa de UN target + contrato del manifest (12 entradas)
bash scripts/host/validate_step11_12.sh <IP> --full

# 4) Consolidador + QA final
bash scripts/host/validate_step11_12.sh <IP> --project CLIENTE

# 5) Ver qué haría, sin ejecutar nada
bash scripts/host/validate_step11_12.sh <IP> --dry-run

# 6) SOLO V-08a (Agente 6 aislado; sin tráfico: no corre V-01..V-08b)
#    Útil tras tocar make_vuln_report.py o los Steps 10/12
bash scripts/host/validate_step11_12.sh <IP> --v08a-only
bash scripts/host/validate_step11_12.sh <IP> --ev-dir /tmp/evidencia_sintetica --v08a-only

# 7) Corrida completa SIN backup automático de la evidencia previa
bash scripts/host/validate_step11_12.sh <IP> --full --no-backup
```

## 📥 Qué verifica

| Check | Qué valida |
|---|---|
| V-01 | `ldapsearch` y `enum4linux-ng`/`enum4linux` presentes en el PATH |
| V-02 | Existe `evidence/<IP>/nmap_detailed.xml` |
| V-03 | Deriva del XML la expectativa (puertos LDAP 389/636/3268/3269, SMB 139/445 y workgroup) — el test se autoadapta al target |
| V-04 | Step 11: `STEP_LDAP_DONE` + `ldapsearch.txt` (1ª línea = comando) **o** skip correcto (`skipped_no_ldap` sin archivos nuevos, `skipped_no_ping`, `skipped`) |
| V-05 | Step 12: `STEP_ENUM4LINUX_DONE` con el workgroup del XML **o** skip correcto (`skipped_no_smb` / `skipped_unsupported_os` en macOS) |
| V-06 | (con `--creds`) el password **no** queda en la evidencia ni en `/tmp`, y se generan `ldapsearch_users.txt`/`ldapsearch_spn.txt` |
| V-07 | (con `--full`) manifest con **12 entradas**, step 11 = `ldap_enum`, step 12 = `enum4linux` y `_step.log` con 12 líneas `Step N/12` |
| V-08a | **Agente 6 aislado** (corre siempre): staging temporal con symlinks -> `make_vuln_report.py` y verifica que el reporte incluya los hallazgos que la evidencia **puede** producir (*expectation-aware*, fix 2026-10-22): hallazgo de dominio LDAP **sólo si hay `ldapsearch*.txt`**; hallazgos de enum4linux **sólo si hay `enum4linux.*`**, o el hallazgo de **sesión SMB anónima rechazada** si lo que hay es la nota `*_sin_sesion.txt`; y **dedupe de usuarios** (<=1 entrada) cuando hay evidencia AD. Si no hay evidencia AD informa `[SKIP]` (antes daba 2 falsos positivos por target). **No toca `CLIENTE/`** |
| V-08b | (con `--project`) cadena de produccion: `organize_project.py --target --no-clobber` + `make_vuln_report.py` + `qa_check.py` con `SCOPE_FILTER_IP` (CK-02/CK-09 solo de ese target). **Escribe en el proyecto** |

## ⚠️ Notas

- No escribe fuera del directorio de evidencia del target. Con `--full` dispara `run_target.sh`, que
  **regenera** la evidencia del target (hacé backup si la querés conservar) y respeta **R1** (si el target
  no está en `config/scope.json`, no corre nada).
- **Independencia de `organize_project`:** V-01..V-06 y V-08a **no** lo necesitan (solo leen/escriben `evidence/<IP>/` y un staging en `/tmp`); V-08b es opt-in porque es el unico que valida el tramo `evidencia -> CLIENTE -> reporte`.
- **Nunca imprime el password**: se lo pasa al Step 11, que lo usa por archivo temporal `0600` y lo
  redacta como `<REDACTED>` en la evidencia.
- V-06/V-07/V-08b se muestran como `[SKIP]` si no pasás `--creds`/`--full`/`--project`.
- **`--v08a-only`** corre únicamente V-08a: **no genera tráfico** (no ejecuta V-01..V-08b). Es el modo para re-verificar Agente 6 tras tocar `make_vuln_report.py` o los Steps 10/12, incluso con una carpeta de evidencia sintética en `/tmp`.
- **`--full` hace backup automático** de la evidencia previa en `/tmp/backup_<IP>_<timestamp>` (`--no-backup` lo omite). Motivo: el `manifest.json` declara sus `output` con **globs** sobre el dir de evidencia, así que tras un re-run un step `failed` puede quedar “cubierto” por archivos de corridas anteriores y `CK-02` no lo detectaría (los archivos existen, pero son viejos). Con el backup se puede comparar `ls -la` por fecha antes/después.
- Exit code: `0` si no hay ningún FAIL, `1` si hay alguno.
- En **macOS** el Step 12 da `skipped_unsupported_os` y el check lo considera correcto; el Step 11 sí corre.
