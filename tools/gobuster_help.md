# GOBUSTER - Reference Help
> VERIFICADO: Gobuster instalado en el contenedor Docker del Paso 2
> (`gobuster dir --help`, 2026-08-30). Gobuster NO tiene output JSON nativo:
> la evidencia se guarda como .txt COMPLETO (registrar formato en el manifest).
> Wordlist aprobada en Fase 0: `/opt/SecLists/Discovery/Web-Content/common.txt`.

## QUE ES
Gobuster es un brute-forcer de directorios/archivos sobre HTTP(S).
Subcomandos: 'gobuster dir' (directorios), 'dns' (subdominios), 'vhost'.
El pipeline usa 'gobuster dir'.

## FLAGS VERIFICADOS DE 'gobuster dir' (v3.x)
- '-u <URL>'        : URL objetivo con esquema y puerto. Ej: http://IP:8080
- '-w <wordlist>'   : path de la wordlist de paths ('-' = STDIN). Step 7 (HOST): <WORKSPACE>/tools/seclists_common.txt
- '-o <file>'       : archivo de output (.txt). Pipeline: gobuster_<port>.txt
- '-t <threads>'    : threads concurrentes (default 10). Resolver de {{gobuster_threads}} (Fase 0: 3)
- '--timeout <dur>' : timeout por request (default 10s). Resolver de {{gobuster_timeout_seconds}}
- '--retry' / '--retry-attempts <n>' : reintentar requests con timeout (default 3).
- '-x <ext>'        : extensiones a probar (ej. -x txt,bak,old,zip) ← aprobado en Fase 0
- '-s <codes>'      : status codes positivos (soporta rangos 200,300-400). Fase 0 (HOST v3.8.2):
  200,204,301,307,403 (401 quitado por wildcard en algunos servers)
- ⚠️ '-b <codes>'    : status codes blacklist (default "404"). En 3.8.2, si -s está set → CONFLICTO.
  En MODO HOST se usa '-b \'\'' (lo desactiva) para evitar el warning.
- '--force'         : continuar incluso si los prechecks fallan (servers con wildcard 401). ← HOST
- '-k'              : skip TLS certificate verification
- '-r' / '-n'       : follow redirects / no follow redirects
- '-c <cookies>'    : enviar cookies
- '-H <header>'     : headers custom (repetible)
- '-a <useragent>'  : User-Agent custom (hay --random-agent).
- '-d <dur>'        : delay entre requests.
- '-q'              : quiet (solo hallazgos)
- '--no-error'      : no imprimir errores
- '-z'              : sin progress bar

## EJEMPLO UTIL (Step 7 - MODO HOST, uno por endpoint web, secuencial) — VERIFICADO en 3.8.2
```bash
gobuster dir \
  -u <URL> \
  -w <WORKSPACE>/tools/seclists_common.txt \
  -o <WORKSPACE>/evidence/<target>/gobuster_<port>.txt \
  -t {{gobuster_threads}} \
  --timeout {{gobuster_timeout_seconds}}s \
  -s 200,204,301,307,403 \
  -b '' \
  --force \
  -x txt,bak,old,zip
```

## NOTAS PARA EL AGENTE
- Ejecutar de forma SECUENCIAL por cada URL de web_endpoints.txt (archivo por puerto).
- Sin JSON nativo: guardar .txt COMPLETO y registrar el formato en el manifest.
- Wordlist (HOST): se descarga a tools/seclists_common.txt en el primer uso (SecLists common.txt ~4.7k).
- Si el server responde wildcard 401/200 a rutas inexistentes → usar --force y quitar ese code de -s.
- Los paths sensibles descubiertos alimentan el plan de explotacion del Agente 3.