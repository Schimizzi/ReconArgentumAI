# SOULs — Perfiles Hermes Agent para ReconArgentumAI

> 📦 **Perfiles de comportamiento para Hermes Agent.** Cada `SOUL.md` define la identidad, reglas e instrucciones de un bot especializado en el pipeline. Vive en el repo para que cualquiera que clone el proyecto pueda instalar los **perfiles Hermes** correspondientes en su máquina.

## 🤖 ¿Qué es un SOUL en Hermes?

En **Hermes Agent** (framework de agentes CLI), un `SOUL.md` es el **system prompt de un perfil**. Cada perfil es una instancia aislada de Hermes con su propio config, skills y SOUL.md. Al ejecutar `hermes -p <nombre>`, Hermes carga ese SOUL.md automáticamente y el bot adopta esa identidad.

## 📁 Estructura

```
SOULs/
├── orchestrator/    Perfil: orchestrator  — coordina las 6 fases del pipeline
│   └── SOUL.md
├── recon/           Perfil: recon         — Fase 1 (escaneo)
│   └── SOUL.md
├── analyst/         Perfil: analyst       — F2a (CVE research) + F2b (plan explotación)
│   └── SOUL.md
└── reporter/        Perfil: reporter      — F4 (consolidación) + F5 (QA)
    └── SOUL.md
```

## 🚀 Instalación (automática, recomendada)

```bash
# Desde la raíz del proyecto clonado
bash scripts/install_souls.sh
```

El script:
1. **Crea 4 perfiles Hermes** ejecutando `hermes profile create <agente> --clone --no-alias`
2. **Copia el SOUL.md** correspondiente a `~/.hermes/profiles/<agente>/SOUL.md`
3. **Reemplaza automáticamente** la ruta del workspace original por tu ruta local
4. **Verifica** la instalación

> ⚠️ Los SOULs del repo **no se modifican**. El script solo instala copias sanitizadas.

## ▶️ Cómo se usa

Cada bot se invoca con el flag `-p <perfil>`:

```bash
# Prueba rápida
hermes -p recon -z 'IDIOMA: ESPAÑOL. ¿Cuál es tu rol?' chat

# Delegación desde el Orchestrator (Fase 1)
hermes -p recon -z "WORKSPACE=/ruta/local/ReconArgentumAI ..." chat

# Delegación de análisis (Fase 2)
hermes -p analyst -z "WORKSPACE=/ruta/local/ReconArgentumAI ..." chat

# Delegación de consolidación + QA (Fases 4-5)
hermes -p reporter -z "WORKSPACE=/ruta/local/ReconArgentumAI ..." chat
```
## 🎬 Ejemplos de ejecución del pipeline

Los siguientes ejemplos muestran cómo el **OrchestratorBot** delega cada fase usando los perfiles Hermes. `WS` es la ruta absoluta de tu proyecto.

### ▶️ Cómo arrancar el pipeline

El OrchestratorBot es tu único punto de entrada. Según tengas o no los comandos ya aprobados, usá uno de estos métodos:

#### 🧑‍💻 Opción 1 — Interactivo (con calibración Fase 0)

Abrís una **sesión interactiva** con el Orchestrator. Él lee `scope.json`, te muestra los targets, y te guía herramienta por herramienta (APROBAR / MODIFICAR / SALTAR). Al finalizar la calibración, ejecuta las Fases 1→5 automáticamente.

```bash
# Sesión interactiva (recomendado para primera ejecución)
hermes -p orchestrator chat

# Dentro del chat, el Orchestrator arranca la Fase 0 automáticamente.
# Vos solo tenés que responder APROBAR / MODIFICAR / SALTAR a cada herramienta.
```

También podés usar one-shot con la instrucción inicial ya lista:

```bash
hermes -p orchestrator -z "IDIOMA: ESPAÑOL. Los authorized_targets están en config/scope.json. Iniciá la Fase 0 de calibración del pipeline y guíame herramienta por herramienta." chat
```

#### ⚡ Opción 2 — Semi-automático (sin calibración)

Si **ya calibraste antes** y tenés `config/approved_commands.md` con los comandos aprobados, pedile al Orchestrator que salte la Fase 0 y ejecute todo el pipeline directo:

```bash
hermes -p orchestrator -z "IDIOMA: ESPAÑOL. Los targets ya están en config/scope.json y los comandos aprobados en config/approved_commands.md. Saltá la Fase 0 (calibración ya hecha). Ejecutá las Fases 1, 2a, 2b, 4 y 5 en secuencia. Informame cada resultado." chat
```

#### 🤖 Opción 3 — Automático total (Fase 1 sin LLM)

Si solo querés la **evidencia del escaneo** (Fase 1) sin usar LLM en absoluto, ejecutá directamente el script maestro:

```bash
cd /ruta/a/tu/workspace && bash scripts/host/preflight_run.sh && zsh -i -c "cd /ruta/a/tu/workspace && bash scripts/host/run_fase1_run3.sh"
```

Esto recorre todos los `authorized_targets` de `scope.json` de forma 100% automática, aplicando delays, service-based routing y generando `manifest.json`. Después podés invocar al Orchestrator solo para las Fases 2→5:

```bash
hermes -p orchestrator -z "IDIOMA: ESPAÑOL. La Fase 1 ya está completa (evidencia en evidence/). Ejecutá las Fases 2a, 2b, 4 y 5 desde ese punto." chat
```

---

### Pipeline completo (Fase 0 → Fase 5)

**FASE 0 — Calibración interactiva**
El Orchestrator lee el scope y calibra cada herramienta con el usuario:
```bash
cat /ruta/a/tu/workspace/config/scope.json
cat /ruta/a/tu/workspace/config/stealth.yaml
```

**FASE 1 — Reconocimiento** (delegar a ReconBot)
```bash
hermes -p recon -z "IDIOMA: ESPAÑOL ESTRICTO.
WORKSPACE=/ruta/a/tu/workspace
SCOPE=\$WORKSPACE/config/scope.json
1. cat \$WORKSPACE/config/scope.json
2. Extrae target_id e IP del primer authorized_target.
3. zsh -i -c 'cd \$WORKSPACE && bash scripts/host/run_fase1_run3.sh'
4. cat \$WORKSPACE/evidence/[IP]/manifest.json
5. Responde: >>> FASE1_OK | TARGET:[id] | IP:[IP] | MANIFEST:\$WORKSPACE/evidence/[IP]/manifest.json
" chat
```

**FASE 2a — CVE Research** (delegar a AnalystBot)
```bash
hermes -p analyst -z "IDIOMA: ESPAÑOL ESTRICTO.
WORKSPACE=/ruta/a/tu/workspace
TARGET_ID=[id] TARGET_IP=[IP]
1. python3 \$WORKSPACE/scripts/cve_research_vulnx.py --target-id [ID] --target-ip [IP] --nmap \$WORKSPACE/evidence/[IP]/nmap_detailed.json --whatweb \$WORKSPACE/evidence/[IP]/whatweb.json --nuclei \$WORKSPACE/evidence/[IP]/nuclei.json
2. cat \$WORKSPACE/cve_research/[ID]_cves.json | head -50
3. >>> FASE2a_OK | TARGET:[ID] | CVES:\$WORKSPACE/cve_research/[ID]_cves.json
" chat
```

**FASE 2b — Plan de Explotación** (delegar a AnalystBot)
```bash
hermes -p analyst -z "IDIOMA: ESPAÑOL ESTRICTO.
WORKSPACE=/ruta/a/tu/workspace
TARGET_ID=[id] TARGET_IP=[IP]
EVID=\$WORKSPACE/evidence/[IP]
CVES_JSON=\$WORKSPACE/cve_research/[ID]_cves.json
PLAN_OUT=\$WORKSPACE/plans/[ID]_exploitation_plan.md
REGLAS: PROHIBIDO inventar CVEs/versiones. Lee archivos con cat/jq/wc.
1. wc -l \$EVID/nuclei.json; wc -l \$EVID/nmap_detailed.json
2. cat \$EVID/manifest.json | jq '{target, tools}'
3. cat \$EVID/nmap_detailed.json | jq '.scan | to_entries[] | {ip, tcp}'
4. cat \$EVID/nikto_*.json 2>/dev/null | jq '.|{port,items[:20]}'
5. cat \$CVES_JSON | jq '{summary, services}'
6. cat > \$PLAN_OUT << 'EOF' [plan markdown] EOF
7. >>> FASE2b_OK | TARGET:[ID] | PLAN:\$PLAN_OUT
" chat
```

**FASE 4 — Consolidación** (delegar a ReporterBot)
```bash
hermes -p reporter -z "IDIOMA: ESPAÑOL ESTRICTO.
WORKSPACE=/ruta/a/tu/workspace
CLIENTE=\$(jq -r '.engagement_id' \$WORKSPACE/config/scope.json)
1. cd \$WORKSPACE && python3 scripts/organize_project.py
2. python3 \$WORKSPACE/scripts/make_vuln_report.py --project \$CLIENTE
3. >>> FASE4_OK | CLIENTE:\$CLIENTE | DIR:\$WORKSPACE/\$CLIENTE
" chat
```

**FASE 5 — QA Final** (delegar a ReporterBot)
```bash
hermes -p reporter -z "IDIOMA: ESPAÑOL ESTRICTO.
WORKSPACE=/ruta/a/tu/workspace
1. cd \$WORKSPACE && python3 scripts/qa_check.py
2. Si hay FAIL en CK-04/05/07: DETENER.
3. >>> QA_OK | CHECKS_PASS:[N]
" chat
```

### Ejemplo simplificado para un solo target

```bash
ENGAGEMENT="Test-CORP-2026"; TARGET_IP="192.168.1.100"; TARGET_ID="S-$TARGET_IP"
WS="/Users/tuusuario/ReconArgentumAI"

cd "$WS" && bash scripts/host/preflight_run.sh           # preflight
hermes -p recon -z "WORKSPACE=\$WS ... run_fase1 ..." chat             # F1
hermes -p analyst -z "WORKSPACE=\$WS ... cve_research..." chat         # F2a
hermes -p analyst -z "WORKSPACE=\$WS ... exploitation_plan..." chat    # F2b

hermes -p reporter -z "WORKSPACE=\$WS ... organize..." chat            # F4
hermes -p reporter -z "WORKSPACE=\$WS ... qa_check..." chat            # F5
```

### Verificación de perfiles

```bash
for p in recon analyst reporter orchestrator; do
  echo "--- $p ---"
  hermes -p "$p" -z 'IDIOMA: ESPAÑOL. ¿Cuál es tu rol?' chat | head -2
done
```

> 📖 Para criterios de éxito/bloqueo detallados, consultá el [`RUNBOOK.md`](../RUNBOOK.md).

## 📋 Perfiles instalados

| Perfil | Comando | Responsabilidad |
|---|---|---|
| `orchestrator` | `hermes -p orchestrator` | Coordina las 6 fases del pipeline |
| `recon` | `hermes -p recon` | Fase 1: escaneo automatizado |
| `analyst` | `hermes -p analyst` | Fase 2a (CVEs) + Fase 2b (plan de explotación) |
| `reporter` | `hermes -p reporter` | Fases 4-5 (consolidación, QA) |

## 🔄 Actualización

Si modificás un SOUL.md en el repo, volvé a ejecutar el script para actualizar los perfiles:

```bash
bash scripts/install_souls.sh
```

El script detecta que los perfiles ya existen y solo actualiza el SOUL.md de cada uno.

## 🧹 Eliminar perfiles

```bash
hermes profile delete orchestrator
hermes profile delete recon
hermes profile delete analyst
hermes profile delete reporter
```

## 🔗 Referencias

- **Manual operativo (RUNBOOK):** [`RUNBOOK.md`](../RUNBOOK.md)
- **Orquestación del pipeline:** [`SOULs/orchestrator/SOUL.md`](orchestrator/SOUL.md)
- **Specs operativas:** [`specs/`](../specs/)
- **Especificaciones OpenSpec:** [`openspec/specs/qa-validation/spec.md`](../openspec/specs/qa-validation/spec.md)