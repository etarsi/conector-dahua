# Panel de RRHH y conector de Lavalle en el servidor

Cómo se montan las dos piezas en un Windows Server y qué hace falta para que las
PCs de RRHH entren por `http://panel.control.rrhh`.

**Servidor elegido: `192.168.88.240`.**

---

## 1. Instalación (una sola vez, en el servidor)

Entrar por RDP, abrir **PowerShell como Administrador** y correr:

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel.ps1
```

Deja instalado:

| Qué | Cómo queda |
|---|---|
| Panel de personas | tarea `Panel RRHH`, arranca sola al bootear |
| Conector de Lavalle | tarea `Conector Lavalle`, arranca sola al bootear |
| Puerto 80 | abierto en el firewall **solo** para `192.168.0.0/16` |
| DNS | zona `control.rrhh` con `panel` → la IP del servidor |

Las dos tareas corren como **SYSTEM**, así que no hay que guardar la contraseña de
nadie, y se reintentan solas cada minuto si se caen.

No reinicia el servidor. La IP se detecta sola; si la máquina tiene varias, avisa
cuál eligió y se le puede pasar `-Ip 192.168.88.240` a mano.

Para deshacer todo:

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel.ps1 -Desinstalar
```

Eso saca las dos tareas, la regla de firewall y la zona DNS. Los archivos del
proyecto quedan; si además hay que borrarlos, es a mano.

### El puerto 80 en la .88.240 está ocupado por IIS

Esa máquina responde en el 80 con la página por defecto de IIS. El script corta y
avisa antes de tocar nada. Dos salidas:

**Si IIS no se usa** (parece ser el caso: sirve la página de bienvenida):

```
Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled
```

**Si IIS sí se usa**, dejarlo y correr el panel en otro puerto — la URL pasa a ser
`http://panel.control.rrhh:8080`:

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel.ps1 -Puerto 8080
```

Antes de desactivar IIS conviene mirar si tiene sitios propios:

```
Import-Module WebAdministration; Get-Website | Select-Object Name,State,Bindings
```

---

## 2. Que las PCs de RRHH resuelvan el nombre

Acá la `.88.240` juega a favor: **ya es el servidor DNS de la red**. Las máquinas
que la usan van a resolver `panel.control.rrhh` apenas se cree la zona, sin tocarles
nada.

Para comprobarlo desde una PC:

```
Resolve-DnsName panel.control.rrhh
```

Tiene que devolver `192.168.88.240`. Si dice que el nombre no existe, esa PC está
usando otro DNS. Ahí hay tres caminos:

**A — apuntar el DNS de esa PC al servidor** *(recomendado)*, como Administrador:

```
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.88.240,8.8.8.8
```

Mejor todavía: cargarlo en el DHCP del router y lo toman todas solas.

**B — archivo hosts**, si es una sola máquina suelta:

```
Add-Content C:\Windows\System32\drivers\etc\hosts "`n192.168.88.240`tpanel.control.rrhh"
```

**C — reenvío condicional en el router**, si el modelo lo permite: mandar
`control.rrhh` al `192.168.88.240`.

---

## 3. Antes de dar por cerrado

### Verificar que el servidor alcanza los dos lectores

Los Dahua del Depósito están en la misma subred que este servidor, así que no
deberían dar problema. El ZKTeco de Lavalle hay que probarlo **desde el servidor**:

```
Test-NetConnection 192.168.88.245 -Port 37777    # Deposito
Test-NetConnection 192.168.0.80  -Port 4370      # Lavalle
```

Si Lavalle no responde, el panel anda igual (Depósito funciona normal) pero esa
sede aparece desconectada, y el conector queda reintentando cada 15 segundos hasta
que la red lo permita.

Cuando se le cambie la IP al lector, hay que actualizar **dos** lugares de
`C:\proyectos\conector-dahua\config.json`:

```
"lavalle": { "devices": [ { "ip": "LA NUEVA IP", ... } ] }
"zkteco":  { "devices": [ { "ip": "LA NUEVA IP", ... } ] }
```

y reiniciar las tareas. No hace falta reinstalar nada.

### La clave del panel tiene 3 caracteres

Está en `config.json`, en `panel.password`. Alcanza mientras el panel viva solo en
la red interna. **Si en algún momento se lo expone hacia afuera, hay que cambiarla
antes** — y ahí conviene VPN o Cloudflare Tunnel, no abrir el puerto en el router.

---

## 4. Operación del día a día

```
Get-ScheduledTask "Panel RRHH","Conector Lavalle" | Get-ScheduledTaskInfo
Get-Content C:\proyectos\conector-dahua\logs\panel_personas.log -Tail 20 -Wait
Get-Content C:\proyectos\conector-dahua\logs\lavalle.log -Tail 20 -Wait
Get-Content C:\proyectos\conector-dahua\logs\estado_lavalle.json
Restart-ScheduledTask "Panel RRHH"
```

`estado_lavalle.json` es el más rápido para ver si el conector está bien: dice si
está conectado, cuál fue la última marca y cuántas quedan pendientes de Odoo.

---

## 5. Al actualizar el código

Desde la máquina de desarrollo:

```
Copy-Item C:\proyectos\conector-dahua\panel_personas.py \\192.168.88.240\c$\proyectos\conector-dahua\ -Force
```

y después, en el servidor, reiniciar la tarea que corresponda. **No hace falta
volver a correr el instalador**, salvo que cambie el puerto o el nombre DNS.
