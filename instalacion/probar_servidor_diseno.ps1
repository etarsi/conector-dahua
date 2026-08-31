<#
    Correr ESTO EN LA MAQUINA 192.168.1.100 (servidor de diseno).

    Sirve para decidir que se instala ahi: solo la parte de Lavalle, o todo el
    sistema. La diferencia es si esa maquina alcanza a los lectores del Deposito.

        powershell -ExecutionPolicy Bypass -File .\probar_servidor_diseno.ps1
#>

$ErrorActionPreference = "Continue"

function Probar($etiqueta, $ip, $puerto) {
    $r = Test-NetConnection -ComputerName $ip -Port $puerto -WarningAction SilentlyContinue
    $estado = if ($r.TcpTestSucceeded) { "SI" } else { "NO" }
    "{0,-34} {1,-18} {2}" -f $etiqueta, "$ip`:$puerto", $estado
}

Write-Host "`n=== Quien soy ===" -ForegroundColor Cyan
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254*" }
$ips | Select-Object IPAddress, PrefixLength, InterfaceAlias | Format-Table -AutoSize
"Gateway: " + (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty NextHop)

Write-Host "`n=== Lector de LAVALLE (ZKTeco) ===" -ForegroundColor Cyan
Probar "Horus por su IP real" "192.168.1.201" 4370
Probar "Horus por la redireccion" "192.168.0.80" 4370

Write-Host "`n=== Lectores del DEPOSITO (Dahua) ===" -ForegroundColor Cyan
Probar "Fijos - lector .245" "192.168.88.245" 37777
Probar "Fijos - lector .252" "192.168.88.252" 37777
Probar "Fijos - lector .253" "192.168.88.253" 37777
Probar "Eventuales - lector .254" "192.168.88.254" 37777

Write-Host "`n=== Otros ===" -ForegroundColor Cyan
Probar "Odoo" "one.sebigus.com.ar" 443
Probar "Servidor actual (N009)" "192.168.30.88" 8082

Write-Host "`n=== Python instalado? ===" -ForegroundColor Cyan
$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) { "python: $($py.Source)"; & python --version } else { "python: NO esta instalado" }

Write-Host "`n=== Que significa el resultado ===" -ForegroundColor Yellow
@"
  Si los 4 lectores del Deposito dan SI  -> se puede mover TODO el sistema aca,
                                            y queda un solo lugar para todo.

  Si dan NO                              -> aca va solo el servidor ADMS (Lavalle)
                                            y el resto se queda en N009.

  El lector Horus por su IP real (192.168.1.201) DEBE dar SI: esa es la razon
  por la que el sistema se muda a esta maquina.
"@
