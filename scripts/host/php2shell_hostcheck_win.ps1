# php2shell_hostcheck_win.ps1 — Verificación LOCAL de PHP en un host Windows/IIS (PHP2Shell)
# =========================================================================================
# SOLO LECTURA: no instala, no modifica nada. Escribe un único archivo de salida.
#
# Uso (en el host IIS, como administrador):
#   powershell -ExecutionPolicy Bypass -File php2shell_hostcheck_win.ps1 `
#              -Out "C:\Windows\Temp\php2shell_hostcheck_win.txt"
# Luego copiar ese archivo a:  evidence/<IP>/php2shell_hostcheck_win.txt
#
# Emite una línea CANÓNICA `PHP-Version: x.y.z` (y `PHP-Version-Source:`) para que
# `scripts/php2shell_audit.py` la tome como evidencia VERIFICABLE (archivo + línea).
# La versión se extrae de binarios/registro/handlers de IIS — NUNCA del cuerpo de
# páginas web (ese camino fue la fuente del falso positivo "PHP 5.3.0" de /INSTALL.txt).

param([string]$Out = "$env:TEMP\php2shell_hostcheck_win.txt")

$L = New-Object System.Collections.ArrayList
function Add-Line([string]$s) { [void]$L.Add($s) }
$script:vers = @()
$script:iis  = $false
$script:src  = ""

function Safe([scriptblock]$sb) {
  try { & $sb } catch { Add-Line "ERROR: $($_.Exception.Message)" }
}

Add-Line "# php2shell_hostcheck_win - $(Get-Date -Format o) - host: $env:COMPUTERNAME"

# 1) php -v (si el CLI está en PATH)
Add-Line "## php -v"
Safe {
  $o = (& php -v 2>&1 | Select-Object -First 2) -join ' / '
  if ($o) {
    Add-Line "PHP-CLI: $o"
    if ($o -match 'PHP\s+(\d+\.\d+\.\d+)') {
      $script:vers += $Matches[1]; if (-not $script:src) { $script:src = "php -v" }
      Add-Line "PHP-CLI-VER: $($Matches[1])"
    }
  } else { Add-Line "PHP-CLI: (sin salida)" }
}

# 2) Registro (instalaciones MSI/zip de PHP)
Add-Line "## Registro de instalaciones PHP"
foreach ($k in @('HKLM:\SOFTWARE\PHP', 'HKLM:\SOFTWARE\WOW6432Node\PHP')) {
  Safe {
    if (Test-Path $k) {
      Get-ChildItem $k | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.Version) {
          Add-Line "PHP-REG: $($p.InstallDir) v$($p.Version)"
          $script:vers += $p.Version
          if (-not $script:src) { $script:src = "registro $($p.InstallDir)" }
        }
      }
    }
  }
}

# 3) Binarios php*.exe (el FileVersion trae la versión exacta)
Add-Line "## Binarios PHP encontrados"
$roots = @(
  "$env:ProgramFiles\PHP", "${env:ProgramFiles(x86)}\PHP",
  "$env:SystemDrive\PHP", "$env:SystemDrive\php",
  "$env:ProgramFiles\iis express\PHP"
)
foreach ($root in $roots) {
  Safe {
    if ($root -and (Test-Path $root)) {
      Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue -Include php.exe, php-cgi.exe, php-fpm.exe |
        ForEach-Object {
          $fv = $_.VersionInfo.FileVersion
          Add-Line "PHP-BIN: $($_.FullName) (FileVersion=$fv)"
          if ($fv -and ($fv -match '^(\d+\.\d+\.\d+)')) {
            $script:vers += $Matches[1]
            if (-not $script:src) { $script:src = "binario $($_.FullName)" }
          }
        }
    }
  }
}

# 4) Handlers de IIS (el path del scriptProcessor revela la versión instalada)
Add-Line "## IIS: handler mappings de PHP"
Safe {
  $cfg = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
  if (Test-Path $cfg) {
    Select-String -Path $cfg -Pattern 'php(-cgi)?\.exe' -ErrorAction SilentlyContinue |
      Select-Object -First 10 | ForEach-Object {
        $script:iis = $true
        Add-Line ("IIS-FastCGI: " + $_.Line.Trim())
        # La carpeta del handler (ej. ...\PHP\v7.4\php-cgi.exe) indica la RAMA; el patch
        # exacto sale del binario/registro. NUNCA se inventa el patch (no "7.4.0").
        if ($_.Line -match 'PHP\\v?(\d+\.\d+)') {
          Add-Line ("PHP-Branch-Hint: " + $Matches[1] + " (rama del handler de IIS; el patch exacto sale del binario/registro)")
        }
      }
  } else { Add-Line "IIS-FastCGI: (no se pudo leer applicationHost.config)" }
}
Safe {
  $ac = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
  if (Test-Path $ac) {
    (& $ac list config /section:handlers 2>&1 | Select-String -Pattern 'php' | Select-Object -First 10) |
      ForEach-Object { $script:iis = $true; Add-Line ("IIS-HANDLER: " + $_.Line.Trim()) }
  }
}

# 5) web.config de los sitios (scriptProcessor + php.ini)
Add-Line "## web.config de los sitios (handler / php.ini)"
Safe {
  Get-ChildItem "$env:SystemDrive\inetpub\wwwroot" -Recurse -Filter web.config -ErrorAction SilentlyContinue |
    Select-Object -First 20 | ForEach-Object {
      Select-String -Path $_.FullName -Pattern 'php(-cgi)?\.exe|scriptProcessor' -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Line ("WEB.CONFIG[$($_.Filename)]: " + $_.Line.Trim()) }
    }
}

# 6) Resumen canónico
$vers = @($script:vers | Where-Object { $_ } | Sort-Object -Unique)
Add-Line "## Resumen"
Add-Line ("PHP-Versions-Detected: " + ($vers -join ' '))
if (@($vers).Count -gt 0) {
  Add-Line ("PHP-Version: " + $vers[0])
  Add-Line ("PHP-Version-Source: " + $script:src)
} else {
  Add-Line "PHP-Version: "
  Add-Line "PHP-Version-Source: (no determinada — revisar los paths listados arriba)"
}
if ($script:iis) { Add-Line "PHP-SAPI: fastcgi/php-fpm (IIS)" } else { Add-Line "PHP-SAPI: desconocido" }
Add-Line "# Si hay VARIAS versiones, revisar los binarios listados (puede haber más de un pool/instalación)."
Add-Line "# Revisar cves_research con: config/advisories/php2shell-2026-10-21.json (parches 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)"

$L | Set-Content -Path $Out -Encoding UTF8
Write-Host "OK -> $Out"
$L
