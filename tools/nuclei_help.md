# NUCLEI — Reference Help
## Versión: v3.11.1 (verificada localmente: `nuclei -version`, 2025-08-30)
## Config dir: `/Users/claudio/Library/Application Support/nuclei`
## Fuente: `nuclei -h`

## FLAGS DE TARGET
- `-u, -target <url>` Target único.
- `-l, -list <file>` Lista de targets (uno por línea). ← Step 4 usa `web_endpoints.txt`
- `-eh, -exclude-hosts` Excluir hosts (ip, cidr, hostname).

## FLAGS DE TEMPLATES
- `-t, -templates <dir|archivo>` Templates a usar (comma-separated). Ej: `-t http/`, `-t cves/`.
- `-tags <tags>` Filtrar por tags (ej: `-tags cve,wordpress`).
- `-etags, -exclude-tags` Excluir por tags.
- `-nt, -new-templates` Correr solo templates nuevos del último release.
- `-w, -workflows` Workflows (secuencias de templates).
- `-validate` Validar templates sin correr.
- `-tl` Listar templates que matchean filtros actuales.

## FLAGS DE FILTRADO POR SEVERIDAD  ← CLAVE para protección de contexto
- `-s, -severity <vals>` Correr solo templates de esas severidades: `info, low, medium, high, critical, unknown`.
- `-es, -exclude-severity <vals>` Excluir severidades. ← Step 4 recomienda `-es info` (evitar ruido)
- `-id, -template-id` Correr por template ID específico.
- `-eid, -exclude-id` Excluir template IDs.

## FLAGS DE OUTPUT
- `-o, -output <file>` Escribir hallazgos al archivo.
- `-j, -jsonl` Salida JSONL(ines) (una línea JSON por finding). ← evidencia estructurada
- `-je, -json-export <file>` Exportar a JSON.
- `-jle, -jsonl-export <file>` Exportar a JSONL.
- `-silent` Solo findings, sin banner.
- `-nc, -no-color` Sin ANSI.
- `-me, -markdown-export <dir>` Exportar MD (útil para review humano).
- `-se, -sarif-export <file>` Exportar SARIF.
- `-rd, -redact <keys>` Redactar keys sensibles del output.

## FLAGS DE RATE-LIMIT / STEALTH
- `-rl, -rate-limit <int>` Máximo de requests/segundo (default 150). ← resolver de `{{nuclei_rate_limit}}`
- `-per-host-rate-limit` Rate-limit por host (el global pasa a ilimitado).
- `-bs, -bulk-size <int>` Hosts analizados en paralelo por template (default 25). Bajar para stealth.
- `-timeout <int>` Timeout por request en segundos (default 10). ← resolver de `{{nuclei_timeout_seconds}}`
- `-mt, -max-time <dur>` Tiempo máximo total de corrida (ej. `30m`, `1h`).
- `-dc, -disable-clustering` Desactivar clustering (aumenta requests; no recomendado en stealth).
- `-fr, -follow-redirects`/`-dr, -disable-redirects` Control de redirects.

## EJEMPLO ÚTIL (Step 4 — escaneo de vulnerabilidades web)
```bash
nuclei -l /workspace/evidence/<target>/web_endpoints.txt \
  -o /workspace/evidence/<target>/nuclei.json \
  -jsonl \
  -rl {{nuclei_rate_limit}} \
  -timeout {{nuclei_timeout_seconds}} \
  -es info \
  -t <TEMPLATES_DIR_O_CATEGORIAS>
```

## NOTAS PARA EL AGENTE
- Guardar SIEMPRE el output completo en `nuclei.json` (formato JSONL: válido por línea).
- `-es info` reduce drásticamente el ruido y protege la ventana de contexto del Agente 3.
- Con WAF/tarpits: bajar `nuclei_rate_limit` (3-5) y subir `nuclei_timeout_seconds` a 15-20.
- El Agente 3 filtra este archivo con `jq` antes de ingerirlo (ver `specs/agent_3_exploitation_plan.md`).
- Cada finding incluye `template-id`, `severity`, `info`, `matcher-name` y `matched-at`.