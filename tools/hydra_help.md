# HYDRA — Reference Help
> VERIFICADO: **hydra 9.7** instalado en el host macOS (`/opt/homebrew/bin/hydra`, fórmula brew
> `hydra`). En Docker/Kali viene con el paquete apt `hydra`. `scripts/hydra_audit.sh` lo usa
> para **auditoría manual de credenciales** (fuera del pipeline de Fase 1).

## QUÉ ES
Hydra es un "cracker" de logins por red que prueba combinaciones usuario/contraseña contra
muchos protocolos. En este proyecto se usa **solo para evidenciar credenciales débiles** con
**límite de 25 intentos por servicio** (ver `config/stealth.yaml` → `hydra_max_attempts`),
nunca como fuerza bruta masiva ni como paso automático.

## FLAGS PRINCIPALES (v9.7)
- `-l LOGIN` / `-L FILE` — un usuario o una lista de usuarios.
- `-p PASS` / `-P FILE` — una contraseña o una lista de contraseñas.
- `-C FILE` — archivo `login:pass` por línea (en vez de `-L`/`-P`).
- `-t TASKS` — conexiones en paralelo (default 16). Bajo = sigiloso. ← `hydra_threads`.
- `-w TIME` — timeout de espera de respuesta (default 32). ← `hydra_wait_seconds`.
- `-f` — cortar tras el **primer** login encontrado (solo evidencia).
- `-v` — verbose (imprime cada intento; es lo que queda en `logs/hydra.log`).
- `-o FILE` — escribe los pares **encontrados** a un archivo (determinístico para detectar VULNERABLE).
- `-s PORT` — puerto si no es el default del servicio.
- `-m OPTIONS` — opciones específicas de módulo (forms, SNMP, headers HTTP).
- `-S` — conexión SSL (para módulos que no la traen implícita).
- `-U <servicio>` — ayuda del módulo concreto.

## TABLA puerto → módulo (la que usa `hydra_audit.sh` en modo automático)
| Puerto | Módulo | Puerto | Módulo |
|---|---|---|---|
| 21 → `ftp` | 22 → `ssh` | 23 → `telnet` | 25 → `smtp` |
| 80 → `http-get` | 110 → `pop3` | 139/445 → `smb` | 143 → `imap` |
| 161 → `snmp` | 389/636 → `ldap3` | 443/8443 → `https-get` | 465 → `smtps` |
| 587 → `smtp` | 990 → `ftps` | 993 → `imaps` | 995 → `pop3s` |
| 1433 → `mssql` | 1521 → `oracle-listener` | 3306 → `mysql` | 3389 → `rdp` |
| 5060 → `sip` | 5432 → `postgres` | 5900 → `vnc` | 6379 → `redis` |
| 8080/8081 → `http-get` | | | |

> Otros módulos disponibles en esta build (verificados con `hydra -U`): `asterisk, cisco,
> cisco-enable, cvs, firebird, http-post-form, https-post-form, http-proxy, icq, irc,
> mongodb (no en esta build), nntp, oracle, oracle-sid, pcanywhere, postgres, radmin2, rexec,
> rlogin, rsh, rtsp, s7-300, sapr3, smtp-enum, socks5, sshkey, svn, teamspeak, vmauthd,
> xmpp`. Lista completa: `hydra -U` o `hydra -h`.

## EJEMPLOS (con los límites que aplica `hydra_audit.sh`)
```bash
# FTP / SSH / Redis — los módulos más simples:
hydra -l admin -P tools/seclists_common.txt 10.150.40.50 ftp
hydra -l root -P tools/seclists_common.txt 10.150.40.50 ssh
hydra -P tools/seclists_common.txt redis://10.150.40.50:6379   # redis NO usa usuario

# SNMP (UDP): community strings, también sin usuario:
hydra -P tools/seclists_common.txt snmp://10.150.40.50:161

# Puerto no-default (todos los módulos):
hydra -l admin -P words.txt -s 8123 10.150.40.50 ssh

# HTTP Basic (80) / HTTPS Basic (443):
hydra -l admin -P words.txt http-get://10.150.40.50/
hydra -l admin -P words.txt https-get://10.150.40.50:8443/

# Formulario de login web (necesita -m con la URL, datos y marcador de fallo):
hydra -l admin -P words.txt -m "/login.php:user=^USER^&pass=^PASS^:F=incorrecto" 10.150.40.50 http-post-form

# RDP — siempre con -t 1 (conexión-oriented):
hydra -t 1 -l admin -P words.txt rdp://10.150.40.50:3389

# SQL Server / MySQL / PostgreSQL:
hydra -l sa -P words.txt 10.150.40.50 mssql
hydra -l root -P words.txt 10.150.40.50 mysql
hydra -l postgres -P words.txt 10.150.40.50 postgres
```

## CÓMO LEE LOS RESULTADOS `hydra_audit.sh` (3 estados)
- **VULNERABLE** = el archivo `-o found.txt` NO está vacío (hydra escribe ahí los pares
  encontrados). Además hydra imprime líneas `[21][ftp] host: IP login: X password: Y` y el
  resumen `N valid password found`.
- **NO_VULNERABLE** = hydra terminó la lista (`finished at` / `successfully completed`),
  rc=0, sin pares encontrados y sin `[ERROR]`/timeouts → lista completa probada sin login válido.
- **INCONCLUSO** = rc≠0, mensajes `[ERROR]`, `timed out`, `Too many bad logins`, `not bruteable`,
  conexión rechazada, o el **watchdog** del script lo cortó (`hydra_service_cutoff_seconds`) →
  no se puede concluir "no vulnerable".

## NOTAS PARA EL AGENTE/OPERADOR
- **Nunca** usar hydra sin autorización expresa por target: es una prueba de autenticación
  activa (más intrusiva que el recon pasivo del pipeline).
- No usar `-x` (generación de passwords) ni listas enormes: `hydra_audit.sh` ya topa en 25
  intentos por servicio para **evidenciar**, no para romper.
- `-f` corta el ataque en el primer hallazgo; el resto de intentos no se ejecutan.
- El **verbose completo** de cada corrida está en `logs/hydra.log` (append, nunca se borra);
  solo los hallazgos generan evidencia en `evidence/<IP>/hydra_*.txt`.
- Los timeouts/threads/límites salen de `config/stealth.yaml` (`hydra_*`) — nada hardcodeado (R5).
- `hydra -U <módulo>` es la referencia autoritativa por módulo; `hydra` sin argumentos lista
  los módulos compilados.