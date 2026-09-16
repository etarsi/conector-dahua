<#
.SYNOPSIS
    Instala el panel Monitoreo Sebigus como servicio de Windows (NSSM).

.DESCRIPTION
    Se corre UNA vez, como administrador. Deja el panel:
      - arrancando solo con la PC (automatico retrasado),
      - reiniciandose solo si el proceso se cae,
      - sin depender de que haya una sesion de Claude Code ni una consola abierta.

    Ademas abre el puerto 8090 en el firewall para que se pueda entrar desde
    otras PC de la red (hoy la red esta como "Publica" y Windows lo bloquea).

.USAGE
    Boton derecho sobre PowerShell -> "Ejecutar como administrador", y:
        cd "C:\proyectos\conector-dahua\monitoreo Sebigus"
        powershell -ExecutionPolicy Bypass -File .\instalacion\instalar_servicio.ps1

.NOTES
    Si NSSM no esta, el script lo baja de nssm.cc. Si esta PC no tiene internet,
    bajar nssm.exe a mano y dejarlo en <panel>\instalacion\nssm.exe, y correr de nuevo.
#>
param(
    [string]$Servicio = "monitoreo_sebigus",
    [string]$Python   = "",
    [string]$Nssm     = "",
    [int]$Puerto      = 8090,
    [switch]$SinFirewall
)

$ErrorActionPreference = "Stop"

# --- Debe correr como administrador ---
$soyAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $soyAdmin) {
    throw "Hay que correr esto como ADMINISTRADOR. Abri PowerShell con boton derecho -> Ejecutar como administrador."
}

# El panel es la carpeta que contiene a este script (una arriba de instalacion\).
$AppDir = Split-Path -Parent $PSScriptRoot
$script = Join-Path $AppDir "servidor.py"
if (-not (Test-Path $script)) { throw "No encuentro servidor.py en $AppDir" }
Write-Host "Panel  = $AppDir"

# --- Ubicar pythonw.exe (sin consola) ---
if (-not $Python) {
    $candidatos = @(
        "$env:LOCALAPPDATA\Programs\Python\Python311\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\pythonw.exe"
    )
    $g = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    if ($g) { $candidatos = @($g.Source) + $candidatos }
    $Python = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Python -or -not (Test-Path $Python)) {
    throw "No encuentro pythonw.exe. Pasalo con -Python 'C:\ruta\pythonw.exe'."
}
Write-Host "Python = $Python"

# --- Ubicar o BAJAR nssm.exe ---
# Ojo (aprendido con el conector viejo): el ejecutable del servicio ES nssm.exe.
# Si despues se mueve o se borra, el servicio deja de arrancar aunque figure
# instalado. Por eso se deja una copia FIJA dentro del panel y se apunta ahi.
$nssmFijo = Join-Path $AppDir "instalacion\nssm.exe"
if (-not $Nssm) {
    $candidatos = @($nssmFijo, "C:\nssm\nssm.exe",
                    "C:\Program Files\nssm\nssm.exe", "C:\Program Files (x86)\nssm\nssm.exe")
    $g = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($g) { $candidatos = @($g.Source) + $candidatos }
    $Nssm = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Nssm) {
    Write-Host "NSSM no esta. Bajandolo de nssm.cc ..." -ForegroundColor Yellow
    $zip = Join-Path $env:TEMP "nssm-2.24.zip"
    $tmp = Join-Path $env:TEMP "nssm-2.24"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip -UseBasicParsing
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
        Expand-Archive $zip -DestinationPath $tmp -Force
        $exe = Join-Path $tmp "nssm-2.24\win64\nssm.exe"
        Copy-Item $exe $nssmFijo -Force
        $Nssm = $nssmFijo
    } catch {
        throw "No se pudo bajar NSSM ($($_.Exception.Message)). Bajalo a mano de https://nssm.cc, y deja win64\nssm.exe en $nssmFijo"
    }
}
# Si el nssm hallado no es la copia fija del panel, copiarla ahi y usar esa.
if ($Nssm -ne $nssmFijo) { Copy-Item $Nssm $nssmFijo -Force; $Nssm = $nssmFijo }
Write-Host "NSSM   = $Nssm"

# --- Frenar cualquier panel/gateway suelto (ocupan el puerto, y conviene que el
#     servicio arranque su propio go2rtc como hijo, asi tambien queda persistente) ---
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like "*servidor.py*" } |
    ForEach-Object { Write-Host "Frenando panel suelto PID $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force }
Get-Process go2rtc -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "Frenando go2rtc suelto PID $($_.Id)"; Stop-Process -Id $_.Id -Force }

# --- Instalar o reconfigurar el servicio ---
$existe = Get-Service -Name $Servicio -ErrorAction SilentlyContinue
if ($existe) {
    Write-Host "El servicio $Servicio ya existe: se reconfigura." -ForegroundColor Yellow
    if ($existe.Status -eq "Running") { & $Nssm stop $Servicio | Out-Null }
    # Corregir el binario del servicio si el nssm anterior se movio.
    $actual = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Servicio" -ErrorAction SilentlyContinue).ImagePath -replace '^"|"$',''
    if ($actual -and $actual -ne $Nssm) {
        & sc.exe config $Servicio binPath= "`"$Nssm`"" | Out-Null
    }
} else {
    & $Nssm install $Servicio $Python "servidor.py" | Out-Null
}

$logsDir = Join-Path $AppDir "logs"
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

# El panel corre con cwd = carpeta del panel: las rutas relativas (config.json,
# data\, gateway\, logs\) dependen de esto.
& $Nssm set $Servicio Application       $Python           | Out-Null
& $Nssm set $Servicio AppParameters     "servidor.py"     | Out-Null
& $Nssm set $Servicio AppDirectory      $AppDir           | Out-Null
& $Nssm set $Servicio DisplayName       "Monitoreo Sebigus (control de accesos)" | Out-Null
& $Nssm set $Servicio Description        "Panel web de control de accesos Dahua (Lavalle + Deposito)." | Out-Null
& $Nssm set $Servicio Start             SERVICE_DELAYED_AUTO_START | Out-Null
& $Nssm set $Servicio AppStdout         (Join-Path $logsDir "servicio.out.log") | Out-Null
& $Nssm set $Servicio AppStderr         (Join-Path $logsDir "servicio.err.log") | Out-Null
& $Nssm set $Servicio AppRotateFiles    1                 | Out-Null
& $Nssm set $Servicio AppRotateBytes    5242880           | Out-Null
# Reiniciar solo si se cae, con throttle para no entrar en bucle.
& $Nssm set $Servicio AppExit Default   Restart           | Out-Null
& $Nssm set $Servicio AppThrottle       5000              | Out-Null
& $Nssm set $Servicio AppRestartDelay   3000              | Out-Null

# --- Firewall: abrir el puerto para el resto de la red ---
if (-not $SinFirewall) {
    $regla = "Monitoreo Sebigus $Puerto"
    if (-not (Get-NetFirewallRule -DisplayName $regla -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $regla -Direction Inbound -Protocol TCP `
            -LocalPort $Puerto -Action Allow -Profile Any | Out-Null
        Write-Host "Firewall: puerto $Puerto abierto (entrante)."
    } else {
        Write-Host "Firewall: la regla del puerto $Puerto ya existia."
    }
}

# --- Arrancar y verificar ---
& $Nssm start $Servicio | Out-Null
Start-Sleep -Seconds 8
$estado = (Get-Service -Name $Servicio).Status
Write-Host "`nServicio '$Servicio': $estado" -ForegroundColor Cyan
try {
    $r = Invoke-WebRequest "http://127.0.0.1:$Puerto/api/sesion" -TimeoutSec 6 -UseBasicParsing
    Write-Host "El panel responde en http://127.0.0.1:$Puerto  (HTTP $($r.StatusCode))" -ForegroundColor Green
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' -and $_.InterfaceAlias -notlike '*VirtualBox*' -and $_.InterfaceAlias -notlike '*vEthernet*' } |
        Select-Object -First 1).IPAddress
    if ($ip) { Write-Host "Desde otra PC de la red:  http://${ip}:$Puerto" -ForegroundColor Green }
} catch {
    Write-Host "El servicio arranco pero el panel todavia no responde. Mira $logsDir\servicio.err.log" -ForegroundColor Yellow
}

Write-Host "`nComandos utiles:"
Write-Host "  Estado:   Get-Service $Servicio"
Write-Host "  Reiniciar: Restart-Service $Servicio"
Write-Host "  Frenar:   Stop-Service $Servicio"
Write-Host "  Quitar:   & '$Nssm' remove $Servicio confirm"
