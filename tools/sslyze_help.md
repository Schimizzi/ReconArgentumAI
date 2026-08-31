# SSLYZE - Reference Help
> VERIFICADO: SSLyze **6.3.1** instalado en el contenedor Docker del Paso 2 del
> proyecto (`docker compose run --rm pentest sslyze --help`, 2026-08-30).
> El flag de JSON output es **`--json_out`** (reemplaza al viejo `--json_outfile`).
> En 6.x NO existe `--regular` ni flag CLI de timeout.

## QUE ES
SSLyze analiza la configuracion TLS/SSL de un endpoint: protocolos habilitados,
suites de cifrado, certificados (validez, cadena), renegociacion, heartbleed, etc.
Se ejecuta UNA vez por cada endpoint https de web_endpoints.txt (secuencial).

## INPUT / OUTPUT
- '<IP:PORT>'           : endpoint objetivo (ej. 10.156.226.156:443).
- '--json_out <file>'   : escribe el resultado como JSON en <file>. Si <file> es
  '-', el JSON se imprime a stdout. (flag VERIFICADA en v6.3.1)
- '--quiet'             : no imprime nada a stdout (util con --json_out).
- '--targets_in <file>' : lee targets desde archivo (uno 'host:port' por linea).

## SCAN COMMANDS (v6.3.1)
- '--certinfo'               : obtener y validar el/los certificados del server.
- '--mozilla_config {modern,intermediate,old,disable}' : valida contra las
  configs recomendadas por Mozilla. Default: intermediate.
- '--tlsv1' / '--tlsv1_1' / '--tlsv1_2' / '--tlsv1_3' : probar soporte por version.
- '--sslv2' / '--sslv3'      : probar soporte SSL 2.0 / 3.0 (debilidades).
- '--reneg'                  : renegociacion insegura / client-initiated.
- '--compression'            : TLS compression (CRIME).
- '--heartbleed'             : OpenSSL Heartbleed (CVE-2014-0160).
- '--robot'                  : ROBOT vulnerability.
- '--early_data'             : TLS 1.3 early data support.
- '--openssl_ccs'            : CCS Injection (CVE-2014-0224).
- '--fallback'               : TLS_FALLBACK_SCSV (downgrade prevention).
- '--resum'                  : session resumption IDs / tickets.
- '--ems'                    : Extended Master Secret support.
- '--elliptic_curves'        : curvas elipticas soportadas.
- '--http_headers'           : security headers HTTP.
- '--certinfo_ca_file <f>'   : con --certinfo; roots en PEM para validar.

## CONECTIVIDAD / STEALTH
- '--slow_connection'        : reduce concurrencia; mas fiable en redes lentas o
  con muchos timeouts. USAR si Fase 0 indica WAF/tarpits o si hay timeouts.
- '--https_tunnel PROXY_URL' : tunel via proxy HTTP CONNECT
  (ej. 'http://USER:PW@HOST:PORT').
- '--sni HOSTNAME'           : Server Name Indication.
- '--starttls PROTOCOL'      : StartTLS (auto, smtp, pop3, imap, ftp, ldap,
  xmpp, postgres, rdp). 'auto' deduce del puerto.
- NOTA: en v6.x NO existe flag CLI de timeout (antes --connect_timeout). La
  variable 'sslyze_connect_timeout' de config/stealth.yaml es el UMBRAL del
  Orchestrator (espera antes de declarar fallo y decision de --slow_connection).
  NUNCA hardcodear un timeout en el comando.

## EJEMPLO UTIL (Step 8 - por cada puerto https)
```bash
sslyze <IP:PORT> \
  --json_out /workspace/evidence/<target>/sslyze_<port>.json \
  --quiet \
  --certinfo

# Con red lenta / tarpits / timeouts (aprobado en Fase 0):
sslyze <IP:PORT> \
  --json_out /workspace/evidence/<target>/sslyze_<port>.json \
  --quiet --certinfo --slow_connection

# Fallback sin JSON:
sslyze <IP:PORT> --certinfo > /workspace/evidence/<target>/sslyze_<port>.txt
```

## NOTAS PARA EL AGENTE
- Ejecutar SOLO sobre puertos con esquema 'https://' confirmados en web_endpoints.txt.
- Un archivo por puerto: sslyze_<port>.json (o .txt).
- Anomalias clave a reportar: TLS 1.0/1.1 habilitados, certs expirados/auto-firmados,
  suites con cifrado debil (RC4, 3DES), renegociacion insegura, heartbleed.
- Con tarpits/endpoints lentos: usar --slow_connection para evitar falsos negativos.