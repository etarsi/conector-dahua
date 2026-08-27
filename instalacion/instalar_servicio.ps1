<#
    Instala o reconfigura el servicio de Windows del conector Dahua.
    Ejecutar como Administrador:
        powershell -ExecutionPolicy Bypass -File .\instalacion\instalar_servicio.ps1

    Deja el servicio con: arranque automatico retrasado, reinicio ante cualquier
    salida o falla, rotacion de logs y parada limpia (Ctrl+C).
#>
param(
    [string]$Servicio = "script_lector_sdk_v2",
    [string]$AppDir   = "C:\proyectos\conector-dahua",
    [string]$Python   = "C:\Python313\python.exe",
    [string]$Nssm     = "",
    [switch]$NoArrancar
)

$ErrorActionPreference = "Stop"
$script  = Join-Path $AppDir "script_lector_sdk.py"
$logs    = Join-Path $AppDir "logs"
$config  = Join-Path $AppDir "config.json"

# --- Ubicar nssm.exe ---
# Ojo: si nssm.exe se mueve o se borra, el servicio deja de arrancar aunque
# figure instalado, porque el ejecutable del servicio ES nssm.exe.
if (-not $Nssm) {
    $candidatos = @(
        (Join-Path $AppDir "instalacion\nssm.exe"),
        "C:\nssm\nssm.exe",
        "C:\Program Files\nssm\nssm.exe",
        "C:\Program Files (x86)\nssm\nssm.exe"
    )
    $cmd = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($cmd) { $candidatos += $cmd.Source }
    $Nssm = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Nssm) {
    throw "No se encontro nssm.exe. Descargarlo de https://nssm.cc y dejarlo en $AppDir\instalacion\nssm.exe"
}
Write-Host "NSSM   = $Nssm"
Write-Host "PYTHON = $Python"
Write-Host "SCRIPT = $script`n"

# --- Comprobaciones ---
foreach ($p in @($Nssm, $Python, $script)) {
    if (-not (Test-Path $p)) { throw "No existe: $p" }
}
if (-not (Test-Path $config)) {
    throw "Falta $config. Copiar config.example.json a config.json y completar las claves."
}
New-Item -ItemType Directory -Force -Path $logs | Out-Null

$existe = Get-Service -Name $Servicio -ErrorAction SilentlyContinue
if ($existe) {
    Write-Host "El servicio $Servicio ya existe: se reconfigura." -ForegroundColor Yellow
    if ($existe.Status -eq "Running") { & $Nssm stop $Servicio | Out-Null }

    # Si nssm.exe se movio de lugar, el servicio quedo apuntando a una ruta que
    # ya no existe y falla al arrancar. Se corrige el binario del servicio.
    $actual = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Servicio").ImagePath -replace '^"|"$', ''
    if ($actual -ne $Nssm) {
        Write-Host "Corrigiendo el ejecutable del servicio:" -ForegroundColor Yellow
        Write-Host "  antes:  $actual"
        Write-Host "  ahora:  $Nssm"
        & sc.exe config $Servicio binPath= "`"$Nssm`"" | Out-Null
    }
} else {
    Write-Host "Instalando el servicio $Servicio..." -ForegroundColor Cyan
    & $Nssm install $Servicio $Python "-u `"$script`""
}

# --- Ejecucion ---
& $Nssm set $Servicio Application    $Python
& $Nssm set $Servicio AppParameters  "-u `"$script`""
& $Nssm set $Servicio AppDirectory   $AppDir
& $Nssm set $Servicio DisplayName    "Conector Dahua - Lector de asistencias"
& $Nssm set $Servicio Description    "Escucha los lectores Dahua, guarda las marcas en SQLite y las envia a Odoo"

# --- Logs con rotacion (antes crecian sin limite) ---
& $Nssm set $Servicio AppStdout      "$logs\listener.out.log"
& $Nssm set $Servicio AppStderr      "$logs\listener.err.log"
& $Nssm set $Servicio AppStdoutCreationDisposition 4
& $Nssm set $Servicio AppStderrCreationDisposition 4
& $Nssm set $Servicio AppRotateFiles  1
& $Nssm set $Servicio AppRotateOnline 1
& $Nssm set $Servicio AppRotateBytes  10485760

# --- Reinicio automatico ante cualquier salida (incluye el watchdog) ---
& $Nssm set $Servicio AppExit Default Restart
& $Nssm set $Servicio AppRestartDelay 5000
& $Nssm set $Servicio AppThrottle     10000

# --- Parada limpia: primero Ctrl+C para que cierre bien la base ---
& $Nssm set $Servicio AppStopMethodSkip    0
& $Nssm set $Servicio AppStopMethodConsole 15000
& $Nssm set $Servicio AppStopMethodWindow  5000
& $Nssm set $Servicio AppStopMethodThreads 5000

# --- Arranque automatico retrasado + acciones de recuperacion de Windows ---
& sc.exe config $Servicio start= delayed-auto | Out-Null
& sc.exe failure $Servicio reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null

if ($NoArrancar) {
    Write-Host "`nConfiguracion aplicada. NO se arranco (parametro -NoArrancar)." -ForegroundColor Yellow
    Get-Service $Servicio | Select-Object Name, Status, StartType | Format-Table -AutoSize
    return
}

Write-Host "`nConfiguracion aplicada. Arrancando..." -ForegroundColor Cyan
Start-Service $Servicio
Start-Sleep -Seconds 8
Get-Service $Servicio | Select-Object Name, Status, StartType | Format-Table -AutoSize

Write-Host "Ultimas lineas del log:" -ForegroundColor Cyan
Get-Content (Join-Path $logs "dahua_sdk.log") -Tail 20
