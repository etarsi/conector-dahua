# Monitoreo Sebigus

Panel web de control de accesos para los 7 lectores Dahua del edificio: quién
puede pasar por cada puerta, alta y baja de gente, marcas en vivo y apertura
remota. Es el reemplazo del SmartPSS Lite, pero como sitio web: se abre desde
cualquier PC de la red, sin instalar nada en la máquina del que lo usa.

**No tiene nada que ver con el panel de personal ni con Odoo.** Esto es solo
control de puertas. El padrón de este edificio es independiente del Depósito.

## Arrancar

```bash
cd "monitoreo Sebigus"
copy config.example.json config.json    # y poner las claves
python servidor.py
```

Después se abre `http://<ip-del-servidor>:8090`. No hace falta instalar nada:
usa solo la biblioteca estándar de Python 3.

La máquina donde corra tiene que llegar por red a la 192.168.0.x, porque le
habla directo a cada lector.

## Los lectores

| Puerta | IP | Modelo |
|---|---|---|
| Entrada Depósito Rack 1 (1er piso) | 192.168.0.73 | DHI-ASI3213A-W |
| Puerta Entrada Vidrio (1er piso) | 192.168.0.74 | DHI-ASI3213A-W |
| Fichador 2do Piso | 192.168.0.240 | DHI-ASI3214A-W |
| Fichador 3er Piso | 192.168.0.75 | DHI-ASI3213A-W |
| Fichador 4to Piso | 192.168.0.76 | DHI-ASI3213A-W |
| Fichador 5to Piso A | 192.168.0.78 | DHI-ASI3213A-W |
| Fichador 5to Piso B | 192.168.0.79 | DHI-ASI3213A-W |

Los siete con firmware `3.000.0000000.2.R` (build 2023-08-01).

> En la planilla original los de .78 y .79 figuran los dos como "Fichador 5to
> Piso". Acá se llaman A y B para poder distinguirlos; conviene confirmar cuál
> es cuál en el edificio y renombrarlos en `config.json`.

## Cómo está armado

```
servidor.py   servidor web + API (http.server, sin framework)
nucleo.py     hilos: eventos en vivo, vigilancia de puertas, sincronización
lector.py     cliente de un lector Dahua (HTTP/CGI + RPC2)
base.py       SQLite: personas, accesos, perfiles, eventos
web/          la pagina (html + css + js, sin dependencias)
```

**La base es la fuente de verdad, no los lectores.** Se da de alta a la persona
una vez, se eligen las puertas, y un worker empuja eso a cada equipo. Si un
lector está caído, la fila queda `pendiente` y se sincroniza sola cuando vuelve.
Es la misma idea que ya funciona en `panel_personas.py`, pero acá sin el NetSDK.

### Por qué no usa el NetSDK

El panel del Depósito depende de las DLL del NetSDK de Dahua. Este no: habla la
API HTTP del equipo, así que corre en cualquier máquina y no hay DLL que se
rompa al actualizar. Además el binding de Python del NetSDK **no expone forma de
listar usuarios** (solo GET de a uno), y por HTTP sí se puede.

### Las tres APIs del lector

| Para qué | Cómo | Estado |
|---|---|---|
| Padrón, estado de puerta, abrir | CGI (`/cgi-bin/...`, digest) | verificado |
| Alta, modificación, baja | RPC2 `AccessUser.insertMulti` / `updateMulti` / `removeMulti` | verificado el 11/09 |
| Historial de marcas | RPC2 (`RecordFinder`, JSON) | verificado |
| Eventos en vivo | CGI `eventManager.cgi?action=attach` | stream verificado |

El historial va por RPC2 y no por CGI por un motivo concreto: **el `find` del
CGI ignora el `offset` y corta en 1024 registros**, así que siempre devuelve los
1024 más viejos y no hay manera de llegar al final. El buscador con estado de
RPC2 sí avanza: pagina de a 1024 y recorre los ~16.800 registros de un equipo en
unos 13 segundos.

## Puesta en marcha

En **Ajustes → Importar padrón de los lectores**: lee las personas que ya tienen
cargadas los 7 equipos y arma la base con eso. Los venían cargando desde el
SmartPSS, así que la base arranca reflejando la realidad y no vacía.

La importación es **solo lectura**: marca cada acceso como `ok` (ya está en ese
equipo) o `ausente` (no corresponde), y no encola ninguna escritura. Verificado:
después de importar, 0 pendientes.

Con eso quedaron 92 personas y 432 permisos en los 7 equipos.

## Lo que hay que saber

### Hay 7 personas cargadas dos veces

Cada una tiene dos IDs distintos: uno con acceso a casi todo el edificio y otro
suelto, con una sola puerta.

| Persona | ID principal | ID duplicado |
|---|---|---|
| Brian Michat | 37 (6 puertas) | 238 (1) |
| Cintia Ibañez | 5 (7 puertas) | 206 (1) |
| Exequiel Sayago | 6 (7 puertas) | 207 (1) |
| Juan Angel Rodriguez | 18 (6 puertas) | 219 (1) |
| Kenny Osorio | 21 (7 puertas) | 222 (1) |
| Lautaro Stella | 1 (2 puertas) | 2 (1) |
| Santiago Waimblum | 33 (6 puertas) | 234 (1) |

Pasa cuando se vuelve a cargar a alguien en un equipo en vez de darle permiso al
ID que ya tenía. **Importa para la seguridad**: si a esa persona le dan de baja,
se le saca un ID y el otro sigue entrando. El botón "Revisar duplicados" en
Personas los lista cuando haga falta.

### El acceso es por piso, no parejo

De las 92 personas, 38 comparten el mismo conjunto de puertas y 17 otro. Por eso
el panel tiene **perfiles de acceso**: un conjunto de puertas con nombre, en vez
de tildar puerta por puerta para cada persona. Se arman en Ajustes.

### La foto todavía no llega al lector

La foto se carga y se guarda en la base del panel, pero **empujarla al equipo
todavía no está hecho ni verificado**.

> Corrección: el primer día este README decía que no había API de rostro por
> HTTP. Estaba mal: se había probado `AccessFace.cgi?action=find`, que no existe.
> `AccessFace` sí responde con `startFind` y `list`, pero `list` devuelve rasgos
> (`FaceData`), no la foto. Lo que falta verificar es la carga
> (`AccessFace.insertMulti` con la imagen), y probarla requiere una foto real.

Mientras tanto la cara se sigue tomando desde el equipo o desde el SmartPSS.

### Los dos lectores del 5to piso tienen 6 veces mas trafico

Al importar el historial quedo a la vista: `.78` (96.254 marcas) y `.79`
(112.156) contra 7.000-21.000 de los demas, con la misma cantidad de gente
cargada (73). O son la entrada principal del edificio y no fichadores de piso, o
estan mal rotulados en la planilla. Vale confirmarlo antes de tomarlos como
"5to piso".

### El historial arranca cuando arranca el panel

Las marcas en vivo se guardan a medida que pasan. El historial viejo se trae con
"Importar historial completo" (~1 min los 7 equipos). Además hay una pasada
automática cada 30 minutos como red de seguridad, por si el stream en vivo se
cortó y se perdió algo.


## Cámaras (NVR)

El NVR es un **DH-NVR804-32-HDS3/I** en `192.168.5.2` (otra subred que los
fichadores; la máquina donde corra el panel tiene que llegar a las dos). Habla
la misma API CGI que los lectores, así que `camaras.py` es primo hermano de
`lector.py`. Se conecta con el usuario `glicht`.

Tiene **32 canales, todos con nombre por piso**, y los nombres coinciden con los
pisos de las puertas — eso es lo que después permite atar cada marca a su cámara.

### Cómo se ve el video

| Modo | Cómo | Rendimiento |
|---|---|---|
| Miniatura del mosaico | `snapshot.cgi` (JPEG suelto) | ~1s por cámara |
| Cámara ampliada | `mjpg/video.cgi` en un `<img>` | **~12 fps**, medido |
| Calidad máxima | RTSP `:554` | necesita gateway aparte |

El navegador **nunca habla con el NVR**: el panel hace de intermediario, así las
claves no salen del servidor.

MJPEG solo anda en el sub-stream (`subtype=1`). El principal es H.265 y el
equipo no lo transcodifica: la petición se queda colgada hasta el timeout.

### El mosaico va de a una cámara por vez

El NVR entrega **un snapshot por segundo**. Pedirle las 32 juntas no lo acelera:
lo satura y empieza a devolver HTTP 500. Por eso las miniaturas se cargan en
fila (~35s la vuelta completa) y se refrescan cada 90s.

Ese fue un error real durante el desarrollo: cada vez que se entraba a la vista
arrancaba otra vuelta sin matar la anterior, se apilaban y tumbaban al NVR (310
peticiones en pocos minutos). Se resolvió con un contador de generación en vez
de un flag: la vuelta nueva invalida a las viejas. Si se toca ese código,
mantener esa propiedad.

Para ver muchas cámaras en vivo a la vez el camino es un gateway RTSP
(go2rtc o MediaMTX) que convierta a WebRTC. Eso sí agrega una dependencia
binaria al proyecto, que hoy no tiene ninguna.

### La cámara del canal 1 está fallando

`CH1 · 3° Piso Entrada` devuelve **HTTP 500 desde el propio NVR**, no desde el
panel. Las otras 31 responden bien (verificado de a una, 31/31). Conviene
revisar esa cámara.


## Los códigos de evento de los lectores

`AccessControl` y `NewFaceRecognition` **no existen** en estos equipos: si se
preguntan con `eventManager.cgi?action=getEventIndexes`, el lector contesta
"No Events". Suscribirse a ellos abre el stream y llegan los heartbeats, pero no
entra nunca una marca — que fue exactamente el síntoma que tuvimos.

Los códigos reales, capturados escuchando `codes=[All]` mientras la gente fichaba:

| Código | Qué trae |
|---|---|
| `_DoorFace_` | La marca: `UserID`, `Similarity`, `OpenDoorMethod`, `Door` |
| `DoorStatus` | La puerta: `Status: Open` / `Close` |
| `_NewFile_` | La foto del rostro capturado, con su ruta en el equipo |

Los guiones bajos son parte del nombre.

`_DoorFace_` **no trae el nombre de la persona ni si le abrieron**. El nombre
sale de la base local por `UserID`. El veredicto es más delicado:

> Primero se intentó deducirlo del `DoorStatus` que llega alrededor. No sirve:
> el `DoorStatus` a veces llega **antes** que el `_DoorFace_`, y si la puerta ya
> estaba abierta porque alguien entró justo antes, no se manda una apertura
> nueva. Medido contra los equipos reales: **2 de cada 3 marcas legítimas
> figuraban como rechazadas**.
>
> Lo que se hace ahora: la marca en vivo entra como concedida y **provisoria**,
> y la importación del historial —que sí trae el `ErrorCode` del equipo— la
> corrige si de verdad fue un rechazo (`base.corregir_desde_historial`).

El `_NewFile_` abre una puerta interesante que todavía no está hecha: el nombre
del archivo es `{UserID}_{similitud}_{vivacidad}_{timestamp}.jpg`, así que se
podría mostrar la cara capturada junto a cada marca, como hace el SmartPSS.


## El gateway de video (go2rtc)

El navegador no reproduce RTSP, y el NVR solo entrega el 1080p por ahi. go2rtc
se queda en el medio.

**Instalado:** `gateway/go2rtc.exe`, v1.9.14, 19 MB, licencia MIT, bajado de
`github.com/AlexxIT/go2rtc`. Es un ejecutable suelto: no hay instalador ni
runtime. `gateway/go2rtc.yaml` lo genera `gateway.py` desde `config.json` en
cada arranque — no editarlo a mano.

```
navegador --:8090 + cookie--> panel Python --127.0.0.1:1984--> go2rtc --:554--> NVR
```

Se ata a **127.0.0.1 solamente** (verificado: no responde desde 192.168.30.93).
El navegador nunca lo ve; le pide al panel, que valida la sesion y relaya. La
clave del NVR sigue sin salir del servidor.

Dos streams por camara, on-demand (go2rtc se conecta al NVR recien cuando
alguien mira):

| Stream | Fuente | Para que |
|---|---|---|
| `camN_sub` | subtype=1, MJPEG 704x576 | el mosaico |
| `camN_hd` | subtype=0, H.265 1080p | la camara ampliada |

**El HD se entrega como H.264, no como H.265.** go2rtc negocia con cada
navegador: si la PC decodifica HEVC por hardware le manda el original, y si no
lo transcodifica. Es a proposito: Chrome y Edge no traen decodificador HEVC por
software, y cuando falta el modo de falla es **pantalla negra sin ningun error**,
imposible de diagnosticar desde soporte.

Verificado punta a punta: `/api/camaras/10/hd` entrega **1920x1088 a ~1,4 Mbps**
a traves del panel.

### Lo que NO se puede, y conviene tenerlo claro

**Las 32 camaras en 1080p al mismo tiempo no se pueden ver en un navegador.**
Son ~1.600 megapixeles por segundo de decodificacion en una sola pestana. No es
un problema de este panel ni del gateway: no hay PC de oficina que lo aguante.
El SmartPSS lo logra porque es una app nativa que decodifica H.265 por hardware.

Y no haria falta igual: con 32 recuadros en un monitor 1080p, cada celda mide
~240x135 px. El sub-stream ya entrega 704x576, **7 veces mas pixeles de los que
la celda puede mostrar**. Lo que se percibe como "mala calidad" en el mosaico no
es resolucion: es que la miniatura se refresca cada 90 segundos.

### Pendiente: la prueba escalonada de la grilla

Para que el mosaico pase de 90s a movimiento real hay que sostener varios
streams abiertos contra el NVR, y **el limite de sesiones del equipo se
desconoce** (no se puede consultar: `configManager.cgi` da 403 con `glicht`).
Este panel ya lo saturo una vez con 310 peticiones apiladas.

Por eso la prueba va **escalonada y fuera de horario**: 4 -> 8 -> 16 -> 32
camaras, midiendo en cada paso, y verificando que la grabacion no se resienta.
El NVR esta grabando 32 canales en produccion y ese es su trabajo principal;
cualquier prueba compite con eso. Un NVR saturado puede perder grabacion, y eso
no se recupera.

`frame.jpeg` del gateway tarda 1,2s igual que `snapshot.cgi` mientras el stream
esta on-demand: la ventaja aparece recien cuando el stream se sostiene abierto.


## Dos sedes (Lavalle + Deposito)

El panel maneja **dos sedes** con un selector arriba a la izquierda y una sola
clave: **Lavalle** (7 lectores 192.168.0.x + NVR) y **Deposito** (5 lectores de
puertas de oficina 192.168.88.x, sin camaras). Administrar una sede nunca puede
tocar una puerta de la otra: cada IP se valida contra la sede de la URL.

La diferencia de fondo entre las dos:

- **Lavalle: IDs compartidos.** El mismo UserID es la misma persona en las 7
  puertas. La ficha pide un ID.
- **Deposito: IDs por lector.** Cada equipo numera por su cuenta y el mismo
  UserID es OTRA persona en cada puerta. El panel identifica a la persona por su
  nombre y guarda que ID tiene en cada puerta; la ficha no pide un ID, muestra el
  de cada lector ("ID 3600 en Administracion, ID 116716928 en la Reja").

Modelo de datos v2 (`docs/diseno-multisede.md`): la persona es un `pid` interno,
y `accesos` separa lo DESEADO (que puertas quiere el operador) de lo OBSERVADO
(que ID tiene en cada equipo y como salio la ultima escritura). El worker adopta
por nombre, elige IDs nuevos desde 9000 (para no chocar con SmartPSS) y **nunca
escribe sobre un registro cuyo nombre no coincide con quien el panel cree que es**
(la "regla de oro": comparacion por igualdad exacta, no por parecido, asi
Mario != Maria).

La escritura va por RPC2 `AccessUser` (el `recordUpdater.cgi` daba HTTP 400 y el
alta del panel de una sede nunca habia funcionado). Verificado en los dos
firmwares del Deposito.

**Migracion:** el panel v2 esta listo pero migrar la base corta Lavalle unos
minutos, asi que se hace fuera de horario. Ver `docs/migracion.md`.

## Seguridad

- `config.json` tiene las claves de los lectores y la del panel: **no va al
  repositorio** (está en `.gitignore`).
- La base tampoco se versiona. En este proyecto ya pasó que un `git pull` vació
  una base SQLite de producción que estaba trackeada.
- El panel **abre puertas reales**. Poné `clave_panel` sí o sí; si queda vacía,
  cualquiera en la red puede abrir. Cada apertura remota queda en
  `logs/monitoreo.log` con la IP de quien la pidió.
- Dos personas tienen clave de teclado `1234` y `2222`. Conviene cambiarlas.
- El NVR tiene 6 usuarios cargados. El panel usa `glicht`; conviene que sea uno
  dedicado y con permisos de solo lectura de video, no un usuario de persona.

## Estado

Verificado contra los equipos reales:

- [x] Conexión y credenciales de los 7 lectores
- [x] Leer el padrón (92 personas, 432 permisos)
- [x] Importar el historial (277.749 marcas de los 7 equipos)
- [x] Estado de puerta de los 7
- [x] Abrir el stream de eventos en vivo de los 7
- [x] NVR: 32 canales, snapshot y MJPEG a 12 fps por el proxy del panel
- [x] go2rtc instalado y atado a loopback; HD 1920x1088 verificado por el panel
- [ ] Prueba escalonada de la grilla (4→8→16→32) **fuera de horario**
- [x] **Alta / modificación / baja contra el equipo: verificadas el 11/09** con RPC2
      `AccessUser` en los dos firmwares, con un usuario de prueba sin puertas ni
      credenciales y vencido. El camino que tenía el panel (`recordUpdater.cgi insert`)
      **devolvía HTTP 400: el alta nunca había funcionado.** El panel pasa a usar el
      camino nuevo con la reestructuración en dos sedes.
- [x] **Eventos en vivo: funcionando.** Ver "Los códigos de evento" más abajo.
- [ ] Apertura remota (no se disparó: abre una puerta de verdad)
- [ ] Empujar la foto al lector (necesita NetSDK)
