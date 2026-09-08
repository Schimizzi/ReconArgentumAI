# HTTPX (ProjectDiscovery) — Reference Help
## Versión: verificada localmente con `httpx-pd -h` (2025-08-30)
## ⚠️ IMPORTANTE EN ESTE HOST:
##   - El pipeline resuelve el binario de probe con **prioridad**: `httpx-toolkit` → `httpx-pd` → `httpx` (los 3 de ProjectDiscovery).
##   - **Kali Linux:** el binario PD se llama **`httpx-toolkit`** (Kali renombra los binarios PD que chocan con paquetes Python). Es el PRINCIPAL.
##   - **macOS / contenedor Docker:** se usa **`httpx-pd`** (`/Users/claudio/go/bin/httpx-pd`).
##   - El `httpx` del PATH (cliente HTTP de Python, ej. `pip install httpx`) NUNCA sirve para probe: solo se acepta
##     como fallback si realmente soporta `-l` (o sea, es el PD real). La resolución prioriza `httpx-toolkit`/`httpx-pd`
##     justamente para no caer en él. No confundir.
##   - PD httpx es una "toolkit HTTP multi-purpose": probea host:puerto, detecta
##     web services, extrae títulos/tech y emite JSONL.

## FLAGS DE INPUT
- `-l, -list <file>` Archivo con lista de hosts a procesar (uno por línea). ← Step 2 usa `open_ports.txt`
- `-u, -target <host>` Target directo (puede repetirse).
- `-irr, -input-mode <mode>` Modo de input (list, burp).

## FLAGS DE PROBES (qué mostrar/capturar por host)
- `-sc, -status-code` Mostrar status code HTTP.
- `-title` Mostrar título de página.
- `-td, -tech-detect` Detección de tecnología (dataset wappalyzer).
- `-server, -web-server` Mostrar header Server.
- `-ip` Mostrar IP del host.
- `-cl, -content-length` Mostrar content-length.
- `-ct, -content-type` Mostrar content-type.
- `-location` Mostrar redirect location.
- `-rt, -response-time` Mostrar tiempo de respuesta.
- `-cdn` Mostrar CDN/WAF en uso (default true).
- `-probe` Mostrar estado del probe.
- `-favicon` Hash mmh3 del favicon.
- `-jarm` Fingerprint JARM.

## FLAGS DE FILTRADO/MATCH
- `-mc, -match-code <codes>` Solo hosts con esos status codes.
- `-fc, -filter-code <codes>` Excluir esos status codes.
- `-ml, -match-length`, `-fl, -filter-length` Filtrar por content-length.
- `-ms, -match-string`, `-fe, -filter-regex` Filtrar por contenido.

## FLAGS DE OUTPUT
- `-o, -output <file>` Archivo de salida. ← pipeline guarda `httpx.json`
- `-j, -json` Salida en formato JSONL(ines). ← se combina con `-o` para evidencia estructurada
- `-csv` Salida CSV.
- `-md` Salida Markdown.
- `-silent` Modo silencioso (solo resultados).
- `-nc, -no-color` Sin ANSI colors.
- `-irh/-irr` Incluir headers / request+response en el JSON.

## FLAGS DE OPTIMIZACIÓN / STEALTH
- `-timeout <int>` Timeout en segundos (default 10). ← se resuelve de `{{httpx_timeout_seconds}}`
- `-retries <int>` Número de reintentos. ← `{{httpx_retries}}`
- `-t, -threads <int>` Threads (default 50). Bajar para stealth (ej. 5-10).
- `-delay <dur>` Delay entre requests (ej. `200ms`, `1s`).
- `-e, -exclude <filtro>` Excluir hosts (cdn, private-ips, cidr...).
- `-nf, -no-fallback` No probear ambos esquemas protocol.
- `-fr, -follow-redirects` Seguir redirects (cuidado con loops).
- `-maxr, -max-redirects <int>` Máx redirects a seguir (default 10).
- `-rsts/-rstr` Límite de tamaño de respuesta leída/guardada.

## EJEMPLO ÚTIL (Step 2 — probe sobre puertos abiertos)
```bash
httpx-pd -l /workspace/evidence/<target>/open_ports.txt \
  -o /workspace/evidence/<target>/httpx.json \
  -json \
  -timeout {{httpx_timeout_seconds}} \
  -retries {{httpx_retries}} \
  -t 10
```

## NOTAS PARA EL AGENTE
- Guardar SIEMPRE el output completo (`-json`), incluyendo los resultados no-web
  (el manifiesto y el Agente 3 los interpretan).
- Post-proceso Step 2: extraer SOLO líneas con `http://` o `https://` a
  `web_endpoints.txt` (`grep -E '^https?://'` sobre el JSONL o el output).
- Con WAF/tarpits: subir `httpx_timeout_seconds` a 15-20 y reducir threads,
  los timeouts internos del tarpit matan los probes rápidos (falsos negativos).
- Nunca usar el binario `httpx` (cliente Python) para el probe del pipeline.