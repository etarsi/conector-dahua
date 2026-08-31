# Panel de RRHH en el servidor 192.168.1.100

Cómo queda montado el panel y el conector de Lavalle en la `.100`, y qué hace falta
para que las PCs de RRHH entren por `http://panel.control.rrhh`.

---

## 1. Instalación (una sola vez, en la .100)

Entrar por RDP o AnyDesk a `192.168.1.100`, abrir **PowerShell como Administrador** y correr:

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel_en_100.ps1
```

Deja instalado:

| Qué | Cómo queda |
|---|---|
| Panel de personas | tarea `Panel RRHH`, arranca sola al bootear |
| Conector de Lavalle | tarea `Conector Lavalle`, arranca sola al bootear |
| Puerto 80 | abierto en el firewall **solo** para `192.168.0.0/16` |
| DNS | zona `control.rrhh` con `panel` → `192.168.1.100` |

Las dos tareas corren como **SYSTEM**, así que no hay que guardar la contraseña de
nadie, y se reintentan solas cada minuto si se caen.

No reinicia el servidor, y no toca PostgreSQL, Veeam ni IIS.

**Si algo sale mal**, el script corta antes de modificar nada y dice por qué. Para
deshacer todo lo que sí llegó a hacer:

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel_en_100.ps1 -Desinstalar
```

### Si el puerto 80 está ocupado

En la `.100` hay IIS instalado. Si está usando el 80, el script se detiene y avisa.
Dos salidas:

```
Stop-Service W3SVC; Set-Service W3SVC -StartupType Disabled
```

o dejar IIS en paz y usar otro puerto (la URL pasa a ser `http://panel.control.rrhh:8080`):

```
powershell -ExecutionPolicy Bypass -File C:\proyectos\conector-dahua\instalacion\instalar_panel_en_100.ps1 -Puerto 8080
```

---

## 2. Que las PCs de RRHH resuelvan el nombre

Este es el paso que **no** se puede hacer desde el servidor. El registro DNS vive en
la `.100`, así que cada PC tiene que preguntarle a ella. Hay tres formas; elegir una.

### Opción A — apuntar el DNS de las PCs a la .100 *(recomendada)*

Es la más limpia: se configura una vez y después cualquier nombre nuevo que se
publique en la `.100` funciona solo, sin volver a tocar las PCs.

La `.100` ya resuelve internet correctamente, así que puede ser el DNS de esas
máquinas sin romperles la navegación.

En cada PC de RRHH, PowerShell **como Administrador**:

```
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.1.100,8.8.8.8
```

El `8.8.8.8` queda de respaldo: si la `.100` se apaga, la PC sigue navegando
(aunque deje de resolver `panel.control.rrhh`).

Para ver cómo se llama la placa de red de esa PC:

```
Get-NetAdapter | Where-Object Status -eq Up | Select-Object Name,InterfaceAlias
```

**Mejor todavía:** si el DHCP lo maneja el router, cargar ahí `192.168.1.100` como
DNS primario. Así todas las PCs lo toman solas y no hay que ir una por una.

### Opción B — archivo hosts en cada PC

Funciona siempre, no depende de nada, pero hay que repetirlo en cada máquina y
volver a hacerlo si el panel cambia de IP.

PowerShell **como Administrador**:

```
Add-Content C:\Windows\System32\drivers\etc\hosts "`n192.168.1.100`tpanel.control.rrhh"
```

### Opción C — reenvío condicional en el router

Si el router permite reenviar un dominio a un DNS interno, apuntar `control.rrhh`
a `192.168.1.100`. Es lo mejor de las dos anteriores, pero depende del modelo.

### Comprobar que funcionó

Desde la PC:

```
Resolve-DnsName panel.control.rrhh
```

Tiene que devolver `192.168.1.100`. Si dice que el nombre no existe, esa PC todavía
no está usando el DNS de la `.100`.

---

## 3. Lo que falta resolver

### El lector de Lavalle todavía no se alcanza desde la .100

Hoy la `.100` **no llega** al ZKTeco, ni por `192.168.1.201` ni por `192.168.0.80`.
Mientras siga así:

- el **panel** anda, pero la sede Lavalle aparece desconectada (Depósito funciona normal);
- el **conector de Lavalle** arranca igual y queda reintentando cada 15 segundos.

Cuando se le cambie la IP al lector, hay que actualizar dos lugares de
`C:\proyectos\conector-dahua\config.json`:

```
"lavalle": { "devices": [ { "ip": "LA NUEVA IP", ... } ] }
"zkteco":  { "devices": [ { "ip": "LA NUEVA IP", ... } ] }
```

y reiniciar las dos tareas:

```
Restart-ScheduledTask "Panel RRHH"; Restart-ScheduledTask "Conector Lavalle"
```

No hace falta reinstalar nada ni reiniciar el servidor.

### La clave del panel tiene 3 caracteres

Está en `config.json`, en `panel.password`. Alcanza mientras el panel viva solo en la
red interna, que es como queda ahora. **Si en algún momento se lo expone hacia
afuera, hay que cambiarla antes** — y ahí conviene VPN o Cloudflare Tunnel, no abrir
el puerto en el router.

---

## 4. Operación del día a día

Ver si están corriendo:

```
Get-ScheduledTask "Panel RRHH","Conector Lavalle" | Get-ScheduledTaskInfo
```

Mirar los logs en vivo:

```
Get-Content C:\proyectos\conector-dahua\logs\panel_personas.log -Tail 20 -Wait
Get-Content C:\proyectos\conector-dahua\logs\lavalle.log -Tail 20 -Wait
```

Reiniciar una:

```
Restart-ScheduledTask "Panel RRHH"
```

Estado del conector de Lavalle en JSON (conectado, última marca, pendientes de Odoo):

```
Get-Content C:\proyectos\conector-dahua\logs\estado_lavalle.json
```

---

## 5. Al actualizar el código

Los archivos se copian desde la máquina de desarrollo por SMB:

```
Copy-Item C:\proyectos\conector-dahua\panel_personas.py \\192.168.1.100\c$\proyectos\conector-dahua\ -Force
```

y después, en la `.100`, reiniciar la tarea que corresponda. **No hace falta volver a
correr el instalador**, salvo que cambie el puerto o el nombre DNS.
