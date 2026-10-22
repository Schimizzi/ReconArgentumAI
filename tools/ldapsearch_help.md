# LDAPSEARCH — Reference Help
> VERIFICADO: **OpenLDAP ldapsearch** presente en macOS (`/usr/bin/ldapsearch`) y en Linux (paquete
> `ldap-utils`). Flags verificados localmente: `-x`, `-H`, `-b`, `-s`, `-l`, `-o nettimeout`, `-o ldif-wrap`.

## QUÉ ES
ldapsearch es el cliente LDAP de OpenLDAP. En este proyecto es el **Step 11** del pipeline: hace el
**root DSE anónimo** (la consulta más barata y silenciosa del engagement) y, si hay modo
credencializado aprobado, enumera **usuarios y SPN** (candidatos a Kerberoasting). **Solo lectura** (R2).

## FLAGS PRINCIPALES
- `-x` — Autenticación simple (sin SASL). Obligatorio para el bind anónimo.
- `-H URI` — URI del servidor: `ldap://IP:389`, `ldaps://IP:636`, `ldap://IP:3268` (Global Catalog), `ldaps://IP:3269`.
- `-b BASEDN` — Base de la búsqueda. `-b ""` = root DSE (el que usa el Step 11 por defecto).
- `-s base|sub` — Alcance: `base` (solo el objeto raíz) o `sub` (subárbol; usado en usuarios/SPN).
- `-o nettimeout=N` — Timeout de red en segundos. ← `{{ldapsearch_timeout_seconds}}` de `stealth.yaml`.
- `-o ldif-wrap=no` — No cortar las líneas largas del LDIF (facilita el parseo).
- `-l N` — Time limit del servidor (segundos). ← mismo `{{ldapsearch_timeout_seconds}}`.
- `-D USER` — Bind DN explícito (modo credencializado: `usuario@dominio` o `DOMINIO\\\\usuario`).
- `-y PWFILE` — Password desde archivo (el Step 11 lo usa con archivo temporal 0600 y `-y` para NO
  dejar el password en la línea de comando ni en la evidencia).
- `-W` — Prompt interactivo de password (no se usa en el pipeline).
- `-ZZ` / `-Z` — Exigir / solicitar StartTLS (no usado por defecto; el Step usa LDAPS si 389 no está abierto).

## EJEMPLOS ÚTILES
```bash
# 1) Root DSE anónimo (lo que corre el Step 11):
ldapsearch -x -H ldap://<IP>:389 -b "" -s base -o nettimeout={{ldapsearch_timeout_seconds}} -o ldif-wrap=no

# 2) Objeto raíz del dominio (base DN tomado del root DSE):
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s base "(objectClass=*)"

# 3) Usuarios y SPN (SOLO con credenciales aprobadas en Fase 0; password por archivo):
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s sub "(objectCategory=person)" sAMAccountName cn
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s sub "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```
# LDAPSEARCH — Reference Help
> VERIFICADO: **OpenLDAP ldapsearch** en macOS (`/usr/bin/ldapsearch`) y en Linux (paquete `ldap-utils`).
> Flags verificados localmente: `-x`, `-H`, `-b`, `-s`, `-l`, `-o nettimeout`, `-o ldif-wrap`.

## QUÉ ES
Cliente LDAP de OpenLDAP. En este proyecto es el **Step 11**: hace el **root DSE anónimo** (la consulta
más barata y silenciosa del engagement) y, si el modo credencializado fue aprobado, enumera **usuarios
y SPN** (candidatos a Kerberoasting). **Solo lectura** (R2).

## FLAGS PRINCIPALES
- `-x` — Autenticación simple (sin SASL). Obligatorio para el bind anónimo.
- `-H URI` — `ldap://IP:389`, `ldaps://IP:636`, `ldap://IP:3268` (Global Catalog), `ldaps://IP:3269`.
- `-b BASEDN` — Base de búsqueda. `-b ""` = root DSE (default del Step 11).
- `-s base|sub` — Alcance: `base` (objeto raíz) o `sub` (subárbol: usuarios/SPN).
- `-o nettimeout=N` — Timeout de red (s). Es `{{ldapsearch_timeout_seconds}}` de `stealth.yaml`.
- `-o ldif-wrap=no` — No cortar líneas largas del LDIF (facilita el parseo).
- `-l N` — Time limit del servidor (s). Mismo `{{ldapsearch_timeout_seconds}}`.
- `-D USER` — Bind DN (modo credencializado: `usuario@dominio` o `DOMINIO\\usuario`).
- `-y PWFILE` — Password desde archivo. El Step 11 lo usa con archivo temporal 0600 para que el
  password NO quede en la línea de comando ni en la evidencia.
- `-W` — Prompt interactivo (no se usa en el pipeline).
- `-Z` / `-ZZ` — StartTLS opcional/obligatorio (el Step usa LDAPS si 389 no está abierto).

## EJEMPLOS ÚTILES
```bash
# 1) Root DSE anónimo (lo que corre el Step 11):
ldapsearch -x -H ldap://<IP>:389 -b "" -s base -o nettimeout={{ldapsearch_timeout_seconds}} -o ldif-wrap=no
# 2) Objeto raíz del dominio (base DN tomado del root DSE):
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s base "(objectClass=*)"
# 3) Usuarios y SPN (SOLO con credenciales aprobadas en Fase 0; password por archivo):
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s sub "(objectCategory=person)" sAMAccountName cn
ldapsearch -x -H ldap://<IP>:389 -b "DC=dominio,DC=local" -s sub "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

## NOTAS PARA EL AGENTE (Step 11 - LDAP Enum)

- **Gate Service-Based:** solo si TCP **389, 636, 3268 o 3269** está abierto (de `nmap_detailed.xml`).
  Sin esos puertos -> `skipped_no_ldap` y **no se genera tráfico**.
- **Plataforma:** corre en **Linux Y macOS** (a diferencia de Enum4linux/Step 12, que es solo Linux).
- **Endpoint:** 389 -> `ldap://`; 3268 (GC) -> `ldap://`; 636/3269 -> `ldaps://` con `LDAPTLS_REQCERT=never`
  (certificados autofirmados de DC). `--tls` fuerza LDAPS.
- **Modo anónimo (default):** root DSE + objeto raíz del dominio; bajo ruido, sin credenciales.
- **Modo credencializado (OPT-IN):** `--ldap-user` + `--ldap-pass`, aprobado en Fase 0. El password va por
  archivo temporal 0600 (`-y`) y se redacta `<REDACTED>` en la línea de comando guardada; se borra al terminar.
- **R2 (solo lectura):** jamás `ldapmodify`/`ldapadd`/`ldappasswd`; solo búsquedas.
- **R5:** timeout desde `{{ldapsearch_timeout_seconds}}` (`config/stealth.yaml`).
- **Evidencia:** `ldapsearch.txt` (root DSE) + `ldapsearch_domain.txt`; con credenciales, `ldapsearch_users.txt`
  y `ldapsearch_spn.txt`. Primera línea = comando ejecutado. Se conservan solo si trajeron datos.
- El Agente 6 tiene `parse_ldapsearch()` (LDIF) y **deduplica** los usuarios listados por LDAP y por Enum4linux.
- **Riesgo de detección:** MEDIO en anónimo; **ALTO** con credenciales (AD audita binds anómalos).
