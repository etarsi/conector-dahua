<#
    Vigilancia externa del conector Dahua.

    El script Python escribe logs\estado.json cada 30 segundos. Si ese archivo
    queda viejo (proceso congelado) o el servicio no esta corriendo, aca se
    reinicia el servicio. Es la ultima red de seguridad: cubre el caso en que el
    proceso se cuelga tan feo que ni su propio watchdog reacciona.

    Uso manual:
        powershell -ExecutionPolicy Bypass -File .\instalacion\vigilar_servicio.ps1

    Instalar como tarea programada cada 5 minutos (como Administrador):
        powershell -ExecutionPolicy Bypass -File .\instalacion\vigilar_servicio.ps1 -Instalar
#>
param(
    [string]$Servicio       = "script_lector_sdk_v2",
    [string]$AppDir         = "C:\proyectos\conector-dahua",
    [int]   $MaxMinutosSinSenal = 5,
    [switch]$Instalar
)

$ErrorActionPreference = "Stop"
$estadoPath = Join-Path $AppDir "logs\estado.json"
$logPath    = Join-Path $AppDir "logs\vigilancia.log"

function Escribir($msg) {
    $linea = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $linea
    Add-Content -Path $logPath -Value $linea -Encoding utf8
}

if ($Instalar) {
    $accion  = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$AppDir\instalacion\vigilar_servicio.ps1`" -Servicio $Servicio -AppDir `"$AppDir`""
    $disparo = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5)
    $opciones = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName "Vigilar_$Servicio" -Action $accion -Trigger $disparo `
        -Settings $opciones -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Escribir "Tarea programada 'Vigilar_$Servicio' registrada (cada 5 minutos)."
    return
}

$svc = Get-Service -Name $Servicio -ErrorAction SilentlyContinue
if (-not $svc) { Escribir "ERROR: el servicio $Servicio no existe."; exit 1 }

$reiniciar = $false
$motivo    = ""

if ($svc.Status -ne "Running") {
    $reiniciar = $true
    $motivo    = "el servicio estaba en estado $($svc.Status)"
}
elseif (-not (Test-Path $estadoPath)) {
    Escribir "Aviso: todavia no existe estado.json (servicio recien arrancado?)."
}
else {
    $edad = (New-TimeSpan -Start (Get-Item $estadoPath).LastWriteTime -End (Get-Date)).TotalMinutes
    if ($edad -gt $MaxMinutosSinSenal) {
        $reiniciar = $true
        $motivo    = "estado.json sin actualizar hace {0:N1} minutos (proceso colgado)" -f $edad
    }
    else {
        $estado = Get-Content $estadoPath -Raw | ConvertFrom-Json
        $msg = "OK | equipos {0}/{1} | cola {2} | pendientes Odoo {3}" -f `
            $estado.conectados, $estado.total_equipos, $estado.cola, $estado.pendientes_odoo
        if ($estado.conectados -eq 0 -and $estado.total_equipos -gt 0) {
            Escribir "$msg | AVISO: ningun lector conectado"
        }
    }
}

if ($reiniciar) {
    Escribir "REINICIANDO $Servicio : $motivo"
    try {
        Restart-Service -Name $Servicio -Force -ErrorAction Stop
        Start-Sleep -Seconds 10
        $svc2 = Get-Service -Name $Servicio
        Escribir "Estado despues del reinicio: $($svc2.Status)"
    } catch {
        Escribir "ERROR al reiniciar: $($_.Exception.Message)"
        exit 1
    }
}
