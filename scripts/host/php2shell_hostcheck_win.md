# `php2shell_hostcheck_win.ps1` — Cómo confirmar la versión de PHP en un host Windows/IIS

## 🧩 ¿Qué es?

Script **PowerShell, solo lectura** que se ejecuta **en el servidor IIS** y responde la pregunta que
no se puede responder desde Internet: **¿qué versión de PHP corre detrás de IIS?** (el `X-Powered-By`
está oculto y `/CHANGELOG.txt` de Drupal devuelve un *soft-404*, así que la versión de PHP **no** es
determinable remotamente).

Recoge la versión desde fuentes **confiables** — binario (`FileVersion`), registro de Windows y
**handler mappings de IIS** (`applicationHost.config`) — y emite una línea canónica
`PHP-Version: x.y.z` que el auditor toma como **evidencia verificable** (archivo + línea).

> ⚠️ **Regla de oro:** la versión de PHP **nunca** se infiere del **cuerpo** de una página web.
> El único falso positivo de este engagement salió justamente de ahí (`/INSTALL.txt` de Drupal dice
> *“PHP 5.3.0 or higher”*). Binario/registro/handler sí; HTML no.

## ▶️ Uso en el host IIS (como administrador)

```powershell
# 1) Copiar el script al servidor y ejecutarlo:
powershell -ExecutionPolicy Bypass -File php2shell_hostcheck_win.ps1 `
     -Out "C:\Windows\Temp\php2shell_hostcheck_win.txt"

# 2) Copiar ese archivo a la evidencia del target (en el workspace compartido):
#    evidence/<IP>/php2shell_hostcheck_win.txt
```

Salida (resumen canónico al final del archivo):

```
PHP-Versions-Detected: 7.4.33
PHP-Version: 7.4.33
PHP-Version-Source: binario C:\Program Files\PHP\v7.4\php-cgi.exe
PHP-SAPI: fastcgi/php-fpm (IIS)
```

## 🧭 Métodos de confirmación por nivel de acceso

| # | Si tenés… | Método | Qué te da |
|---|---|---|---|
| 1 | **Cuenta en el Drupal** (por bajo privilegio que sea) | `https://<host>/admin/reports/status` | Versión de **PHP**, SAPI, `memory_limit`, base de datos (Drupal lo muestra en *Status report*) |
| 2 | **Sesión en el servidor Windows/IIS** | `php2shell_hostcheck_win.ps1` (este script) | Versión exacta + SAPI + path del handler |
| 2b | Sesión, a mano | `php -v` · `where php` · `Get-ItemProperty 'HKLM:\SOFTWARE\PHP\*' \| select InstallDir,Version` | Versión exacta |
| 2c | Sesión / IIS Manager | *Handler Mappings* → el `scriptProcessor` apunta a `…\PHP\v7.4\php-cgi.exe` (la carpeta **es** la versión) | Versión (rama) |
| 3 | **Credenciales de dominio con admin share** (desde la VM Debian, sin RDP) | `smbclient //<IP>/C$ -U 'DOMINIO\usuario%pass' -c 'ls "Program Files/PHP"'` | Versión por nombre de carpeta (`v7.4`) |
| 3b | ídem, más preciso | `smbclient //<IP>/C$ -U 'DOMINIO\usuario%pass' -c 'get "Windows/System32/inetsrv/config/applicationHost.config" /tmp/ahc.xml'` y luego `grep -oE 'PHP\\\\v?[0-9.]+' /tmp/ahc.xml` | Path del binario PHP del handler |
| 3c | **Credenciales con WinRM** (5985 abierto) | `Enter-PSSession -ComputerName <IP> -Credential <user>` y correr este mismo `.ps1`, o `Invoke-Command -ComputerName <IP> -Credential <user> -FilePath .\php2shell_hostcheck_win.ps1` | Igual que el método 2, sin RDP ni SMB |
| 4 | **Contacto con Sistemas/IT** | Pedir la salida de `php -v` o el inventario de software (SCCM/GLPI/Lansweeper) | Versión exacta (documental) |
| 5 | Nada de lo anterior | Registrar *“versión de PHP no determinable remotamente”* + tratar como **afectado** (Drupal 7 ⇒ PHP 5.x–7.x; PHP2Shell cubre 5.4–8.5) | Trazabilidad honesta |

## 📥 Cómo se integra con el pipeline

```bash
# 1) El host-check queda como evidencia del target:
#    evidence/<IP>/php2shell_hostcheck_win.txt
# 2) Re-auditar (offline, sin tráfico): la versión del host pasa a ser la principal
python3 scripts/php2shell_audit.py --target-ip <IP>
#    → si queda affected/eol_sin_parche, el JSON cita el hallazgo (archivo + línea)
# 3) Si queda afectado, registrar los CVE del advisory en su *_cves.json (CK-10 lo exige):
python3 scripts/cve_research_vulnx.py --target-id <IP> --target-ip <IP> \
    --nmap evidence/<IP>/nmap_detailed.json --whatweb evidence/<IP>/whatweb.json \
    --nuclei evidence/<IP>/nuclei.json --evidence-dir evidence/<IP> \
    --cliente-dir CLIENTE/<IP>/outputs --advisories config/advisories
python3 scripts/qa_check.py            # CK-10 debe quedar en PASS
```

## ⚠️ Notas

- **No instala, no modifica, no reinicia** nada: lee binarios/registro/config y escribe un solo archivo.
- Si el host tiene **varias instalaciones/pools** de PHP, el script lista todas
  (`PHP-Versions-Detected`) y el `PHP-Version:` es la primera ordenada — hay que revisar cuál usa el
  sitio (paso 2c).
- Equivalente en Linux: `bash scripts/host/php2shell_check.sh --host-check` (emite las mismas líneas
  canónicas `PHP-Version:` / `PHP-SAPI:`).
- Recordá el **parche** del advisory: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**; ramas 5.x/7.x/8.0/8.1
  están **EOL** (sin fix upstream).
