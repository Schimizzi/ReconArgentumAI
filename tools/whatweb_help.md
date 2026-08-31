# WHATWEB - Reference Help
> VERIFICADO: WhatWeb **0.6.4** instalado en el contenedor Docker del Paso 2
> (`whatweb --help`, 2026-08-30). **NO existe `--json-output`** (usar
> `--log-json=<file>`) y **NO existe `--timeout`** (usar `--open-timeout` +
> `--read-timeout`). Agresion aprobada en Fase 0: `-a 2`. Threads: `-t`.

## QUE ES
WhatWeb detecta tecnologias web (CMS, frameworks, servidores, librerias JS) mediante
fingerprinting. Es intensivo en requests (nivel de agresion -a 1 a 4).
En stealth, usar -a 2 como maximo (aprobado en Fase 0) y timeouts acotados.

## FLAGS PRINCIPALES (v0.6.4)
- '-i <archivo>'     : archivo con lista de URLs (una por linea). Step 6 usa web_endpoints.txt
- '-u <url>'         : URL unica (tambien acepta URL directa sin flag).
- '-a, --aggression <1-4>' : nivel de agresion
  - 1 Stealthy (default). ← aprobado en Fase 0 (MODO HOST)
  - ⚠️ **2 NO EXISTE en v0.6.4** (valores validos: 1, 3 o 4)
  - 3 Agressive: revisa paths especificos de plugins.
  - 4 Heavy: MUY ruidoso. Evitar con WAF/IDS.
- '--log-json=<file>'   : output JSON estructurado COMPLETO. VERIFICADO en 0.6.4. ← Step 6 usa whatweb.json
- '--log-verbose=<file>' / '--log-brief=<file>' : logs alternativos (verboso / one-line).
- '-o <archivo>'        : output a archivo en modo texto.
- '--no-errors'         : no mostrar errores HTTP.
- '--open-timeout <s>'  : timeout de conexion (default 15). Resolver de {{whatweb_timeout_seconds}}
- '--read-timeout <s>'  : timeout de lectura (default 30). Resolver de {{whatweb_read_timeout_seconds}}
- '--max-threads, -t <n>': threads (default 25). Resolver de {{whatweb_threads}} (Fase 0: 5)
- '--follow-redirects' / '--max-redirects <n>' : control de redirects.
- '-q, --quiet'     : reducir verbosidad.
- '--color=never'   : output sin ANSI colors (limpio para evidencia .txt).
- '-v'              : verbose.

## EJEMPLO UTIL (Step 6 - fingerprinting tech) — VERIFICADO en 0.6.4
```bash
whatweb -i /workspace/evidence/<target>/web_endpoints.txt \
  --log-json=/workspace/evidence/<target>/whatweb.json \
  -a 2 \
  --open-timeout {{whatweb_timeout_seconds}} \
  --read-timeout {{whatweb_read_timeout_seconds}} \
  --max-threads {{whatweb_threads}}

# Fallback texto (si --log-json fallara):
whatweb -i /workspace/evidence/<target>/web_endpoints.txt \
  -o /workspace/evidence/<target>/whatweb.txt \
  -a 2 \
  --open-timeout {{whatweb_timeout_seconds}} \
  --read-timeout {{whatweb_read_timeout_seconds}} \
  --max-threads {{whatweb_threads}} \
  --color=never
```

## NOTAS PARA EL AGENTE
- Guardar SIEMPRE output COMPLETO (--log-json o .txt integro).
- El output alimenta la correlacion tecnologica del Agente 3 y la busqueda de
  CVEs de tecnologias web del Agente 4.
- Con WAF/tarpits: bajar -a a 1 y subir timeouts (open/read) a 15-20s.