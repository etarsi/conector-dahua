<#
    Deja corriendo en ESTE servidor las dos piezas de RRHH:

        1. el panel de personas          -> http://panel.control.rrhh
        2. el conector de Lavalle        -> manda las marcas del ZKTeco a Odoo

    y publica el nombre en el servidor DNS de esta misma maquina.

    Ejecutar EN EL SERVIDOR, como Administrador:
        powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel.ps1

    Que hace, en orden:
      1. comprueba Python, pyzk y que los scripts compilen
      2. comprueba que el puerto 80 este libre (ojo con IIS)
      3. abre el 80 en el firewall, solo para la red interna
      4. registra las dos tareas al arranque, corriendo como SYSTEM
      5. crea la zona DNS control.rrhh apuntando a este mismo servidor
      6. las arranca y verifica

    No reinicia el servidor ni toca PostgreSQL, Veeam ni IIS.
    Para volver atras todo:  .\instalar_panel.ps1 -Desinstalar

    Se verifico que el panel y el conector pueden hablarle al mismo lector
    ZKTeco al mismo tiempo sin pisarse, asi que conviven bien en esta maquina.
#>
param(
    [string]$AppDir      = "C:\proyectos\conector-dahua",
    [string]$TareaPanel  = "Panel RRHH",
    [string]$TareaLav    = "Conector Lavalle",
    [string]$Zona        = "control.rrhh",
    [string]$Nombre      = "panel",          # ojo: $Host es variable reservada de PowerShell
    [string]$Ip          = "",           # vacio = se detecta la IP de este servidor
    [int]$Puerto         = 80,
    [switch]$SinDns,
    [switch]$SinLavalle,
    [switch]$Desinstalar
)

$ErrorActionPreference = "Stop"

function Titulo($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Ok($t)     { Write-Host "  OK    $t" -ForegroundColor Green }
function Aviso($t)  { Write-Host "  AVISO $t" -ForegroundColor Yellow }
function Malo($t)   { Write-Host "  FALLA $t" -ForegroundColor Red }

# --- tiene que correr elevado: sin esto no se puede bindear el 80 ni tocar DNS ---
$yo = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $yo.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Hay que ejecutarlo como Administrador (boton derecho sobre PowerShell > Ejecutar como administrador)."
}

# --- IP de este servidor ---
# Se toma la de la interfaz que sale a la red, no una de loopback ni de un
# adaptador virtual. Si la maquina tiene varias, conviene pasar -Ip a mano.
if (-not $Ip) {
    $candidatas = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notmatch "^(127\.|169\.254\.)" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -ExpandProperty IPAddress
    if (-not $candidatas) { throw "No pude detectar la IP de este servidor. Pasala con -Ip 192.168.x.x" }
    $Ip = @($candidatas)[0]
    if (@($candidatas).Count -gt 1) {
        Write-Host ("  AVISO este servidor tiene varias IPs ({0}); uso {1}. " -f ($candidatas -join ", "), $Ip) -ForegroundColor Yellow
        Write-Host "        Si no es la correcta, cancelar y correr con -Ip <la que corresponda>" -ForegroundColor Yellow
    }
}

$scriptPanel = Join-Path $AppDir "panel_personas.py"
$scriptLav   = Join-Path $AppDir "script_lector_lavalle.py"
$fqdn        = "$Nombre.$Zona"
$regla       = "Panel RRHH (TCP $Puerto)"

# =====================================================================
# DESINSTALAR
# =====================================================================
if ($Desinstalar) {
    Titulo "Desinstalando"
    foreach ($t in @($TareaPanel, $TareaLav)) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $t -Confirm:$false
            Ok "tarea '$t' eliminada"
        } else { Aviso "la tarea '$t' no existia" }
    }
    if (Get-NetFirewallRule -DisplayName $regla -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $regla
        Ok "regla de firewall eliminada"
    }
    if (Get-DnsServerZone -Name $Zona -ErrorAction SilentlyContinue) {
        Remove-DnsServerZone -Name $Zona -Force
        Ok "zona DNS $Zona eliminada"
    }
    Write-Host "`nListo, quedo como antes.`n" -ForegroundColor Green
    return
}

# =====================================================================
# 1. COMPROBACIONES
# =====================================================================
Titulo "1. Comprobaciones"

# pythonw.exe y no python.exe: corre sin ventana de consola.
$candidatos = @(
    "C:\Program Files\Python313\pythonw.exe",
    "C:\Python313\pythonw.exe",
    "C:\Program Files\Python312\pythonw.exe"
)
$cmd = Get-Command pythonw.exe -ErrorAction SilentlyContinue
if ($cmd) { $candidatos += $cmd.Source }
$Python = $candidatos | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Python) { throw "No encontre pythonw.exe. Instalar Python 3.13 o pasar la ruta a mano." }
$pyExe = $Python -replace "pythonw\.exe$", "python.exe"
Ok "python: $Python"

foreach ($s in @($scriptPanel, $scriptLav)) {
    if (-not (Test-Path $s)) { throw "No existe $s" }
}
Ok "estan los dos scripts"

# pyzk hace falta para Lavalle, en las dos piezas
if ((& $pyExe -c "import zk; print('si')" 2>$null) -eq "si") { Ok "pyzk instalado" }
else {
    Aviso "falta pyzk; lo instalo"
    & $pyExe -m pip install --quiet pyzk
    if ($LASTEXITCODE -ne 0) { throw "No se pudo instalar pyzk" }
    Ok "pyzk instalado"
}

# que compilen antes de dejarlos como tarea
foreach ($s in @($scriptPanel, $scriptLav)) {
    & $pyExe -m py_compile $s
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($s)) no compila" }
}
Ok "los dos scripts compilan"

# --- alcance al lector de Lavalle ---
# Hoy esta maquina no llega al ZKTeco. Se avisa pero no se corta: cuando le
# cambien la IP al lector y se actualice config.json, el conector arranca solo.
$config = Join-Path $AppDir "config.json"
$cfg = Get-Content $config -Raw -Encoding UTF8 | ConvertFrom-Json
$ipLector = $cfg.lavalle.devices[0].ip
$puertoLector = $cfg.lavalle.devices[0].puerto
$alcanza = Test-NetConnection -ComputerName $ipLector -Port $puertoLector -WarningAction SilentlyContinue
if ($alcanza.TcpTestSucceeded) {
    Ok "llego al lector de Lavalle en $ipLector`:$puertoLector"
} else {
    Aviso "NO llego al lector de Lavalle en $ipLector`:$puertoLector"
    Aviso "el conector va a quedar reintentando cada 15s hasta que la red lo permita"
    Aviso "si le cambian la IP al lector, actualizar 'lavalle.devices[0].ip' y 'zkteco' en config.json"
}

# =====================================================================
# 2. PUERTO 80
# =====================================================================
Titulo "2. Puerto $Puerto"
$enUso = Get-NetTCPConnection -LocalPort $Puerto -State Listen -ErrorAction SilentlyContinue
if ($enUso) {
    $duenios = $enUso | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($p) { "$($p.ProcessName) (PID $($p.Id))" } else { "PID $($_.OwningProcess)" }
    } | Sort-Object -Unique
    Malo "el puerto $Puerto ya lo tiene: $($duenios -join ', ')"
    Write-Host ""
    Write-Host "  Si es IIS y no lo usan, se libera con:" -ForegroundColor Yellow
    Write-Host "      Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled" -ForegroundColor Yellow
    Write-Host "  Si IIS SI se usa, correr este script con otro puerto:" -ForegroundColor Yellow
    Write-Host "      .\instalar_panel.ps1 -Puerto 8080" -ForegroundColor Yellow
    Write-Host "  (con otro puerto la URL queda http://$fqdn`:8080)" -ForegroundColor Yellow
    throw "Puerto $Puerto ocupado. Nada fue modificado."
}
Ok "el puerto $Puerto esta libre"

# el panel lee el puerto de config.json, asi que tienen que coincidir
if ([int]$cfg.panel.port -ne $Puerto) {
    Aviso "config.json decia puerto $($cfg.panel.port); lo dejo en $Puerto"
    $cfg.panel.port = $Puerto
    $cfg | ConvertTo-Json -Depth 20 | Set-Content $config -Encoding UTF8
}
Ok "config.json: host $($cfg.panel.host), puerto $Puerto"

# =====================================================================
# 3. FIREWALL
# =====================================================================
Titulo "3. Firewall"
# Se abre solo para 192.168.0.0/16, que es toda la red interna de la empresa.
# Asi el panel NO queda accesible desde internet aunque el router reenvie
# algo por error.
if (Get-NetFirewallRule -DisplayName $regla -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName $regla
}
New-NetFirewallRule -DisplayName $regla -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Puerto -RemoteAddress "192.168.0.0/16" `
    -Profile Any -Description "Panel de personas de RRHH. Solo red interna." | Out-Null
Ok "puerto $Puerto abierto solo para 192.168.0.0/16"

# =====================================================================
# 4. TAREAS AL ARRANQUE
# =====================================================================
Titulo "4. Arranque automatico"
# Se usan tareas programadas y no servicios porque python.exe no es un binario
# de servicio: haria falta nssm, que en esta maquina no esta. Corren como
# SYSTEM, asi no hay que guardar la contrasena de nadie.
function Registrar-Tarea($nombreTarea, $scriptPy, $descripcion) {
    if (Get-ScheduledTask -TaskName $nombreTarea -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $nombreTarea -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $nombreTarea -Confirm:$false
        Aviso "habia una tarea '$nombreTarea' previa, la reemplazo"
    }
    $accion    = New-ScheduledTaskAction -Execute $Python -Argument "`"$scriptPy`"" -WorkingDirectory $AppDir
    $disparo   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $opciones  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $nombreTarea -Action $accion -Trigger $disparo `
        -Principal $principal -Settings $opciones -Description $descripcion | Out-Null
    Ok "tarea '$nombreTarea' registrada"
}

Registrar-Tarea $TareaPanel $scriptPanel `
    "Panel de alta de personas en los lectores de Deposito y Lavalle. Se levanta solo al arrancar el servidor."

if (-not $SinLavalle) {
    Registrar-Tarea $TareaLav $scriptLav `
        "Toma las marcas del lector ZKTeco de Lavalle y las manda a Odoo. Se levanta solo al arrancar el servidor."
}
Ok "las tareas se reintentan cada minuto si se caen"

# =====================================================================
# 5. DNS
# =====================================================================
if (-not $SinDns) {
    Titulo "5. DNS"
    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        Aviso "este servidor no tiene los cmdlets de DNS; salteo el paso"
        Aviso "se puede resolver igual con el archivo hosts de cada PC"
    } else {
        if (-not (Get-DnsServerZone -Name $Zona -ErrorAction SilentlyContinue)) {
            Add-DnsServerPrimaryZone -Name $Zona -ZoneFile "$Zona.dns" -DynamicUpdate None
            Ok "zona '$Zona' creada"
        } else { Aviso "la zona '$Zona' ya existia" }

        if (Get-DnsServerResourceRecord -ZoneName $Zona -Name $Nombre -RRType A -ErrorAction SilentlyContinue) {
            Remove-DnsServerResourceRecord -ZoneName $Zona -Name $Nombre -RRType A -Force
            Aviso "habia un registro previo, lo reemplazo"
        }
        Add-DnsServerResourceRecordA -ZoneName $Zona -Name $Nombre -IPv4Address $Ip -TimeToLive 01:00:00
        Ok "$fqdn -> $Ip"
    }
}

# =====================================================================
# 6. ARRANCAR Y VERIFICAR
# =====================================================================
Titulo "6. Arranque y verificacion"
Start-ScheduledTask -TaskName $TareaPanel
if (-not $SinLavalle) { Start-ScheduledTask -TaskName $TareaLav }
Ok "tareas lanzadas, espero a que levanten"

$arriba = $false
for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Seconds 2
    $t = Test-NetConnection -ComputerName "127.0.0.1" -Port $Puerto -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) { $arriba = $true; Ok "el panel responde en el puerto $Puerto (a los $($i*2)s)"; break }
}

if (-not $arriba) {
    Malo "el panel no llego a responder en 40 segundos"
    $log = Join-Path $AppDir "logs\panel_personas.log"
    if (Test-Path $log) {
        Write-Host "`n  ultimas lineas de $log :" -ForegroundColor Yellow
        Get-Content $log -Tail 15 | ForEach-Object { Write-Host "    $_" }
    }
    throw "El panel no arranco. Revisar el log de arriba."
}

if (-not $SinLavalle) {
    $logLav = Join-Path $AppDir "logs\lavalle.log"
    if (Test-Path $logLav) {
        Write-Host "`n  ultimas lineas del conector de Lavalle:" -ForegroundColor Gray
        Get-Content $logLav -Tail 6 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
}

if (-not $SinDns) {
    try {
        $r = Resolve-DnsName -Name $fqdn -Server $Ip -Type A -ErrorAction Stop | Select-Object -First 1
        Ok "el DNS de este servidor resuelve $fqdn -> $($r.IPAddress)"
    } catch { Aviso "no pude verificar el DNS: $($_.Exception.Message)" }
}

$url = if ($Puerto -eq 80) { "http://$fqdn/" } else { "http://$fqdn`:$Puerto/" }
Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "  Panel andando:  $url" -ForegroundColor Green
Write-Host "  Por IP directa: http://$Ip$(if ($Puerto -ne 80) {":$Puerto"})/" -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Para ver como van:" -ForegroundColor Gray
Write-Host "      Get-ScheduledTask '$TareaPanel','$TareaLav' | Get-ScheduledTaskInfo" -ForegroundColor Gray
Write-Host "      Get-Content $AppDir\logs\panel_personas.log -Tail 20 -Wait" -ForegroundColor Gray
Write-Host "      Get-Content $AppDir\logs\lavalle.log -Tail 20 -Wait" -ForegroundColor Gray
Write-Host ""
Write-Host "  FALTA UN PASO para que el nombre ande en las PCs de RRHH:" -ForegroundColor Yellow
Write-Host "  esas maquinas tienen que preguntarle el DNS a este servidor." -ForegroundColor Yellow
Write-Host "  Ver el instructivo que acompana a este script." -ForegroundColor Yellow
Write-Host ""
