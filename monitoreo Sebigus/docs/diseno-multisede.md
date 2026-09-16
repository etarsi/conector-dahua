# Diseño corregido: panel de dos sedes (Lavalle + Depósito)

## 0. Lo que salió de leer el código y cambia la base del diseño

Esto no estaba en la propuesta y condiciona los puntos 4 y 6:

- **La escritura ya no va por `recordUpdater.cgi`.** `recordUpdater insert` devuelve HTTP 400 en los dos firmwares (lector.py, docstring y README "Estado"). Lo que se verificó el 11/09 es RPC2 `AccessUser.insertMulti/updateMulti/removeMulti` (`Lector.crear/actualizar/quitar`, lector.py:406-471), **y esas operaciones van por UserID, no por RecNo**.
- **`nucleo.aplicar()` (nucleo.py:347-364) sigue llamando a `alta()/baja()` del CGI.** El alta del v1 nunca funcionó. Toda fila v1 con `permitido=1` en `pendiente` o `error` es un alta que nunca llegó al equipo.
- **`Lector._conflicto` (lector.py:425) ya implementa la "regla de oro" con dos agujeros:** compara con `_mismo_nombre` (tolerancia de 0,85) y **no compara nada si `nombre_esperado` viene vacío**.
- **`_llamar_rpc` (lector.py:331) reintenta cualquier método ante un error de red, `insertMulti` incluido.** Un alta que entró pero cuya respuesta se perdió vuelve como "alta rechazada: ya existe".
- **Hay dos padrones posibles:** `recordFinder.cgi AccessControlCard` (con `CardName`, tabla de tarjetas, `find` topeado en 1024 y sin offset) y `AccessUser.startFind/doFind` (con `UserName`, uno por UserID, paginado con token de a 50). Hoy la importación usa el primero y las escrituras comparan contra el segundo.

**Decisión transversal [CAMBIO]:** todo lo que decide una escritura o una vinculación usa **un único padrón: `AccessUser` por RPC2**, con `UserID` como clave y `UserName` como nombre. Motivo: es la misma API que escribe y la misma que `_conflicto` compara. Con eso desaparecen el RecNo y los "varios registros por UserID". El CGI queda solo como control cruzado informativo.

---

## 1. Config

```json
"sedes": {
  "lavalle":  { "nombre": "Lavalle",  "ids": "compartidos", "usuario": "...", "clave": "...",
                "escritura": true,  "nvr": { ... }, "lectores": [ {ip, nombre, sector, modelo}, ... ] },
  "deposito": { "nombre": "Depósito", "ids": "por_lector",  "usuario": "...", "clave": "...",
                "escritura": false, "rango_ids_nuevos": 9000,
                "lectores": [ {ip, nombre, ..., "eventos_en_vivo": false, "historial": false, "escritura": false} ] }
}
```

- **[CAMBIO] Solo se acepta `sedes`.** Si falta, el panel sale con `SystemExit` y explica cómo convertir el archivo. Motivo: hay un solo config en una sola PC, y leer el formato viejo mantiene la herencia de credenciales de la raíz.
- **[CAMBIO] Credenciales:** primero las del lector, después las de la sede, **nunca las de la raíz**. Si faltan, ese lector no arranca y figura como "sin credenciales". Motivo: probar la clave de una sede en la otra bloquea la cuenta admin del .246, que también usa SmartPSS.
- **[CAMBIO] Validación al cargar (aborta con mensaje):**
  - una IP repetida en cualquier lugar del archivo;
  - una clave de sede que no cumpla `^[a-z0-9_]+$`;
  - nombres de lector repetidos dentro de una sede;
  - `ids` fuera de `compartidos|por_lector`;
  - `nvr` en una sede `por_lector` sin cámaras declaradas.
  
  Motivo: `LECTORES` es un dict por IP y hoy un duplicado pisa al otro en silencio.
- **[CAMBIO] Banderas por lector (heredan de la sede, con estos valores por defecto):**
  - `escritura`: `true` en Lavalle y `false` en el Depósito hasta pasar el punto 12;
  - `eventos_en_vivo` y `historial`: `true`, salvo el .246, que arranca en `false` hasta verificarlo.
  
  Motivo: el Depósito se puede importar y mirar en solo lectura antes de habilitar escrituras, y el .246 (fw 2.000) no tiene nada verificado.
- **[CAMBIO] `rango_ids_nuevos`** (solo en `por_lector`, 9000 por defecto): los IDs que crea el panel salen de ese rango. Motivo: no chocar con la secuencia propia de SmartPSS ni con lo que se carga por la web del equipo.
- En memoria: `SEDE_DE_IP = {ip: sede}`, `LECTORES_DE[sede] = [ip...]` y `GRABADORES[sede]` (NVR o None).

## 2. Esquema v2

```sql
CREATE TABLE personas (
  pid          INTEGER PRIMARY KEY AUTOINCREMENT,
  sede         TEXT NOT NULL,
  id_preferido TEXT,                -- compartidos: obligatorio (el UserID en toda la sede). por_lector: NULL
  nombre       TEXT NOT NULL,
  documento TEXT DEFAULT '', sector TEXT DEFAULT '', perfil TEXT DEFAULT '',
  desde TEXT DEFAULT '', hasta TEXT DEFAULT '',   -- '' = el panel no administra la vigencia
  foto BLOB, activo INTEGER NOT NULL DEFAULT 1, notas TEXT DEFAULT '',
  creado TEXT NOT NULL, actualizado TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_personas_id ON personas(sede, id_preferido) WHERE id_preferido IS NOT NULL;
INSERT INTO sqlite_sequence(name, seq) VALUES ('personas', 999999);

CREATE TABLE accesos (
  pid              INTEGER NOT NULL REFERENCES personas(pid) ON DELETE RESTRICT,
  lector           TEXT NOT NULL,              -- ip
  -- lo DESEADO (solo lo cambia una acción del operador)
  permitido        INTEGER NOT NULL,
  version          INTEGER NOT NULL DEFAULT 0, -- +1 en cada cambio de deseo
  forzar_nuevo     INTEGER NOT NULL DEFAULT 0,
  -- lo OBSERVADO / estado de sincronización (lo escriben worker e importación)
  user_id          TEXT NOT NULL DEFAULT '',
  confirmado       INTEGER NOT NULL DEFAULT 0, -- 0 = reserva (elegido, sin confirmar en el equipo)
  nombre_en_lector TEXT NOT NULL DEFAULT '',   -- texto crudo leído del equipo
  estado           TEXT NOT NULL,              -- pendiente|ok|error|ausente
  error            TEXT NOT NULL DEFAULT '',   -- por qué no avanza
  aviso            TEXT NOT NULL DEFAULT '',   -- informativo, no bloquea
  cara             TEXT NOT NULL DEFAULT '?',  -- '?' | 'vista'
  intentos         INTEGER NOT NULL DEFAULT 0,
  visto            TEXT DEFAULT '',            -- última lectura del padrón que lo encontró
  actualizado      TEXT NOT NULL,
  PRIMARY KEY (pid, lector),
  CHECK (estado IN ('pendiente','ok','error','ausente')),
  CHECK (NOT (estado='ausente' AND user_id!='')),
  CHECK (NOT (estado='ok' AND (permitido=0 OR user_id='' OR confirmado=0))),
  CHECK (NOT (user_id='' AND confirmado=1))
);
CREATE UNIQUE INDEX ux_accesos_uid ON accesos(lector, user_id) WHERE user_id != '';

CREATE TABLE perfiles (sede TEXT NOT NULL, nombre TEXT NOT NULL, lectores TEXT NOT NULL DEFAULT '[]',
                       creado TEXT NOT NULL, PRIMARY KEY (sede, nombre));

ALTER TABLE eventos ADD COLUMN sede TEXT NOT NULL DEFAULT '<sede_v1>';
ALTER TABLE eventos ADD COLUMN pid INTEGER;          -- sin FK: NULL = no atribuida
CREATE INDEX ix_evento_sede ON eventos(sede, ts DESC);
CREATE INDEX ix_evento_pid  ON eventos(pid, ts DESC);

ALTER TABLE estado_lector ADD COLUMN proximo_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE estado_lector ADD COLUMN serie TEXT DEFAULT '';
```

Cambios respecto de la propuesta:

- **[CAMBIO] Se separa lo deseado (`permitido`, `version`, `forzar_nuevo`) de lo observado.** Motivo: la importación pisaba `permitido`, lo que cancelaba bajas y autorizaba re-altas externas.
- **[CAMBIO] `confirmado`:** una reserva escrita antes del insert. Motivo: si se pierde la respuesta del insert, el reintento no debe duplicar el registro ni dar un falso "ID ocupado".
- **[CAMBIO] Invariantes como CHECK:** nunca `permitido=0` con `ok`, nunca `ausente` con `user_id`. Motivo: la carrera worker/operador dejaba `0/ok`, un estado que nadie vuelve a mirar.
- **[CAMBIO] `aviso` separado de `error`.** Motivo: "sigue figurando con otro ID" o "falta la cara" no deben bloquear ni verse como una escritura fallida.
- **[CAMBIO] `cara` es informativo, no un estado.** Motivo: la cara no se carga por HTTP y no puede frenar la sincronización.
- **[CAMBIO] Se saca `clave` de personas y el panel no administra la clave de teclado.** Motivo: `actualizar()` excluye `Password` a propósito, y guardar claves en la base sin poder empujarlas no suma.
- **[CAMBIO] `ON DELETE RESTRICT`.** Motivo: CASCADE borraba el mapeo de registros que siguen en el equipo.
- **[CAMBIO] Los pid arrancan en 1.000.000.** Motivo: un UserID confundido con un pid da 404 en vez de abrir a otra persona.
- **[CAMBIO] `UNIQUE(sede, id_preferido)`.** Motivo: en compartidos, sin la PK del v1, el mismo ID podía quedar en dos personas.
- **[CAMBIO] `eventos.sede` y `eventos.pid`.** Motivo: el historial por persona vía (lector, user_id) mezcla a los sucesivos dueños de un ID, y filtrar por `lector IN (ips)` esconde los lectores que salen del config. `ADD COLUMN` con DEFAULT constante no reescribe filas (medido en 1,3 ms).
- **[CAMBIO] Ya no hay filas `ausente` para todos los lectores: si no hay fila, la persona no está.** Motivo: unir personas chocaba contra la PK en cualquier lector. Solo existe una fila `ausente` si carga un aviso o si el panel acaba de sacar a esa persona.
- **[CAMBIO] `estado_lector.proximo_id`** es un contador monotónico por lector, que nunca baja. Motivo: un ID liberado no se reutiliza (cara heredada, marcas ambiguas) y no hace falta una tabla `ids_usados`.

**Invariante de sede (en la aplicación, sin FK compuestas):** todo acceso de un pid tiene `SEDE_DE_IP[lector] == personas.sede`. Se hace cumplir en tres lugares: la importación, `guardar_persona` y el worker (punto 6, paso 0). Al arrancar, una consulta cuenta las violaciones y las muestra en `/api/<sede>/estado`, sin borrar nada.

**Funciones de identidad únicas** (módulo nuevo `identidad.py`, que usan importación, worker y servidor):

- `normalizar(t)`: NFKD sin diacríticos, minúsculas, espacios colapsados (es el `_normalizar_nombre` actual).
- `mismo_registro(nombre_equipo, nombre_en_lector)`: `normalizar(a) == normalizar(b) and normalizar(a) != ''`. **Igualdad exacta; un nombre vacío nunca coincide.**
- `parecido(a, b)`: el `SequenceMatcher.ratio()` de hoy. **Solo sirve para sugerir** (duplicados, avisos) y para el guardián de choques de compartidos. **Nunca decide una escritura ni una vinculación.**
- `es_generico(t)`: menos de 2 palabras de 3 letras o más, contiene dígitos, o alguna palabra está en {visita, visitante, temporal, prueba, test, usuario, invitado, proveedor, limpieza, seguridad, guardia, admin}.

## 3. Arranque y migración v1 → v2

**[CAMBIO] La migración no copia personas ni accesos: los reconstruye la primera importación.** Motivo: todo sale de los lectores (0 perfiles, 0 fotos, 0 datos manuales), y las reglas de mapeo eran la parte peligrosa (bajas en curso sin user_id, `nombre_en_lector` inventado).

Orden en `main()`:

1. **Instancia única, antes de tocar la base [CAMBIO].** Se bindea el socket HTTP con `allow_reuse_address=False` y `SO_EXCLUSIVEADDRUSE`, y se toma `data/panel.lock` con `msvcrt.locking`. Si falla cualquiera de los dos, sale con "ya hay un panel corriendo (PID si se conoce)". Motivo: en Windows, con `SO_REUSEADDR`, dos `ThreadingHTTPServer` escuchan el 8090 a la vez.
2. **Config** (punto 1). Si falta `sedes`, sale sin abrir la base.
3. **Se decide según el esquema real, antes de cualquier DDL [CAMBIO].** Motivo: con `CREATE IF NOT EXISTS` más un índice sobre `user_id`, el panel no arranca sobre una base v1.
   - Sin tabla `personas`: se crea el esquema v2 y se pone `user_version=2`.
   - `personas` con columna `id` (v1): se migra.
   - `user_version=2`: se sigue.
   - `user_version>2`: no arranca.
4. **Controles previos a migrar.** Si alguno falla, aborta **sin escribir** y lista los casos:
   - filas de `accesos` con `estado IN ('pendiente','error')` o `permitido=0 AND estado='ok'`, con id, nombre, lector y error;
   - que las IP de `accesos` del v1 no estén todas dentro de una única sede S del config nuevo.
   
   Los `eventos` y el `estado_lector` con IP fuera del config también van a S, y se loguean. El v1 es de una sola sede por definición.
5. **Respaldo [CAMBIO]:** `PRAGMA wal_checkpoint(TRUNCATE)` con `busy=0` obligatorio; después `sqlite3.Connection.backup()` a `data/respaldos/monitoreo-v1-AAAAMMDD-HHMMSS.sqlite3` y `PRAGMA integrity_check` sobre la copia igual a `ok`. Motivo: copiar el archivo con el `-wal` vivo da una copia inconsistente, y fuera de `data/` el archivo no está ignorado por git.
6. **Una transacción (`BEGIN IMMEDIATE`):**
   - `ALTER TABLE personas RENAME TO personas_v1`, y lo mismo con `accesos_v1` y `perfiles_v1`. **Se conservan, no se borran [CAMBIO].** Motivo: guardan documento, notas, foto y bajas por si existieran, y sirven de consulta en la primera importación.
   - `CREATE` del esquema v2, semilla de `sqlite_sequence`, `ALTER` de `eventos` y `estado_lector`, índices y `PRAGMA user_version=2`. Después `COMMIT`. Ante cualquier excepción, `ROLLBACK` y el panel no arranca.
7. **La sede S queda "sin padrón":** su worker y su conciliación periódica no corren y las marcas en vivo entran con `pid NULL`. Al terminar el arranque se intenta **una** primera importación de S (solo lectura, punto 4).
   - Si pasa, la sede queda lista y se ejecuta la atribución de eventos (punto 8).
   - Si falla, queda para el botón.
8. **go2rtc:** si el yaml generado difiere del que está en disco, o si `GET /api/streams` no tiene las claves esperadas, se mata el go2rtc vivo y se relanza (punto 11).

**Vuelta atrás (procedimiento escrito en el README):**

1. Parar el panel y matar `go2rtc.exe`.
2. Borrar `data/monitoreo.sqlite3-wal` y `-shm`.
3. Copiar el respaldo sobre `monitoreo.sqlite3`.
4. Volver el código a v1.
5. Arrancar y correr "Importar padrón" para reconciliar lo que v2 escribió en los equipos.

## 4. Importar / conciliar el padrón de una sede

### 4.1 Leer un padrón: `Lector.padron()` valida o lanza

**[CAMBIO] La validación vive en `lector.py`, no en quien llama.** Motivo: así quedan protegidos a la vez la importación, el worker, la conciliación y "Duplicados".

`padron()` hace `AccessUser.startFind({})` y `doFind` con `Offset` y `Count=50`, siempre `stopFind` al final, y lanza `PadronInvalido(ErrorLector)` si:

- `startFind` no devuelve `Token`;
- `startFind` devuelve `Total` y la cantidad leída no coincide;
- algún registro no tiene `UserID`;
- hay `UserID` repetidos;
- una página trae `UserID` ya vistos (el offset se ignora);
- se superan 40 páginas.

Los errores de transporte lanzan `ErrorSinRespuesta` y los de credenciales `ErrorCredenciales` (punto 10). **Se elimina `usuarios()` con el bucle de offset del CGI [CAMBIO]**, porque ese bucle se cuelga cuando un lector llega a 100 registros.

### 4.2 Qué lectores entran en una corrida

- **Leídos:** `padron()` terminó sin excepción. Un padrón vacío de un lector que tiene filas con `user_id` en la base **cuenta como no leído** ("padrón vacío sospechoso"), salvo que la IP venga en `forzar`.
- **Sin leer:** todos los demás. **Sus filas no se tocan en nada** (estado, user_id, nombre_en_lector, aviso).
- **Primera importación de la sede** (0 personas de esa sede): si hay algún lector sin leer, 409 y no se escribe nada, salvo que venga `forzar_sin: [ip]`.
- **Re-importación:** sale parcial, con 200 y `sin_leer: [{ip, nombre, motivo}]`. [CAMBIO] Motivo: abortar trabaría el Depósito cada vez que la Reja no conteste.
- Si no se pudo leer ningún lector, 409.

### 4.3 Concurrencia

La importación toma el `CANDADO[ip]` (punto 10) de **todos** los lectores de la sede, en orden de IP, **antes de leer el primer padrón**, y los suelta después del COMMIT. [CAMBIO] Motivo: si no, un insert del worker entre la lectura y el COMMIT queda desmapeado. Toda la escritura va en una sola transacción.

### 4.4 Paso 1: filas ya vinculadas

Aplica a toda fila con `lector ∈ leídos` y `user_id != ''`. **Se procesan todas antes del paso 2**, porque el índice único obliga a liberar antes de asignar. `reg = padron[ip].get(user_id)`.

| Fila | Equipo | Resultado |
|---|---|---|
| cualquiera | `reg` y `mismo_registro(reg.UserName, nombre_en_lector)` | Se observa: `nombre_en_lector=reg.UserName` (texto crudo), `visto=ahora`; el registro queda consumido. `permitido` y `estado` no se tocan, salvo `confirmado=0`, que pasa a `confirmado=1`. |
| `1/ok` | `reg` con otro nombre | **Se libera:** `permitido=0, ausente, user_id='', confirmado=0`, `aviso="El ID N ahora es 'X' (cambio fuera del panel, fecha)"`. Va a `cambios_fuera`. El registro no queda consumido. |
| `1/pendiente` o `1/error`, `confirmado=1` | `reg` con otro nombre | `estado=error`, `user_id=''`, `error="El ID N en <lector> ahora es 'X'"`. No se reencola solo. |
| `0/pendiente` o `0/error` | `reg` con otro nombre | `ausente`, `user_id=''`, con aviso (a ese ID ya no está). |
| `confirmado=0` (reserva) | `reg` con otro nombre | `por_lector`: `user_id=''` y sigue `pendiente` (el worker vuelve a elegir). `compartidos`: `error="el ID N en <lector> es 'X'"`, `user_id=''`. |
| `1/ok` | sin `reg` | Se adopta como baja externa: `permitido=0, ausente, user_id=''`, `aviso="desapareció del equipo"`. Va a `cambios_fuera`. |
| `1/pendiente` o `1/error` | sin `reg` | No se toca (el worker inserta con ese ID). |
| `0/pendiente` o `0/error` | sin `reg` | `ausente, user_id=''` (la baja pedida ya está cumplida). |

**[CAMBIO]** Motivo: el paso 1 original volvía a atar (lector, user_id) aunque ahora fuera otra persona. Eso reescribía la referencia contra la que compara la regla de oro, y la baja siguiente borraba a un tercero.

### 4.5 Paso 2: registros no consumidos

Se recorren por lector en orden y por `UserID` numérico, para que el resultado sea determinista.

**`compartidos`:**

1. Se agrupan los registros por `UserID` entre todos los lectores leídos.
2. **Guardián:** se juntan los nombres del grupo con los `nombre_en_lector` de filas vinculadas con ese `user_id` en lectores de la sede (leídos o no). Si dos nombres dan `parecido < 0,85`, **se aborta toda la importación con 409 sin escribir nada** (el `choques_de_id` actual, ampliado con la base). Si difieren pero dan 0,85 o más, se sigue y va a `nombres_distintos_mismo_id`.
3. `P = persona(sede, id_preferido=UserID)`:
   - **P no existe:** se crea con el nombre más frecuente del grupo. `desde`/`hasta` se copian solo si son iguales en todos los lectores; si no, quedan en `''`.
   - **P tiene alguna fila vinculada** (confirmada) después del paso 1: se vincula.
   - **P no tiene filas vinculadas y en esta corrida se le liberó alguna:** es otro dueño del ID. `P.id_preferido=NULL`, con aviso "su ID N pasó a 'X'", y se crea Q con ese ID.
   - **P no tiene filas vinculadas ni liberadas en esta corrida:** se vincula solo si `normalizar(P.nombre) == normalizar(nombre del grupo)`. Si no, va a `sin_importar` ("el ID N es 'X' en el equipo y 'P' en el panel") y no se escribe.

**`por_lector`,** registro por registro (lector, UserID, UserName):

1. Si `es_generico(UserName)`, o el nombre normalizado aparece 2 o más veces en ese mismo lector: persona nueva sola, marcada `no_se_une`.
2. **Nombre ambiguo en la sede:** ya hay 2 o más pids de la sede con ese nombre normalizado. Persona nueva, a Duplicados.
3. **Candidatos:** pids de la sede con `normalizar(nombre)` igual, o con alguna fila vinculada cuyo `nombre_en_lector` normalizado sea igual, **y** sin fila con `user_id != ''` en este lector, **y** sin fila liberada en este lector en esta corrida.
   - **Exactamente 1:** se vincula (4.6).
   - **0 o 2 o más:** persona nueva (`nombre=UserName`, vigencia del registro).
4. Al final, toda persona nueva con `parecido >= 0,85` contra otra de la sede, sin ser igual y sin ser genérica, va a `posibles_duplicados`. Las uniones de pids con IDs distintos entre lectores van a `unidos_por_nombre`, con opción de separar (punto 5).

### 4.6 Vincular un registro a un pid

Se hace un upsert de la fila (pid, lector) con `user_id=UserID, confirmado=1, nombre_en_lector=UserName, visto=ahora`:

- **No había fila, o había una `0/ausente`:**
  - con `activo=1`: `permitido=1, ok`. Va a `accesos_fuera` ("cargado fuera del panel").
  - con `activo=0`: `permitido=0, estado=error, error="dado de baja y sigue cargado en <lector>"`. **Nunca `permitido=1`.** Va a `bajas_con_registro` (alerta roja).
- **Fila `1/pendiente` o `1/error` con `user_id=''`:** se vincula y queda `pendiente`, sin tocar `permitido`. El worker compara diferencias (es la adopción del alta).
- **Primera importación en compartidos:** si existe `personas_v1` con `id == UserID` y el mismo nombre normalizado, se copian documento, sector, notas y foto. Si `activo=0` en v1, la persona se crea con `activo=0` y la fila cae en el caso anterior.

### 4.7 Después del COMMIT

- **Atribución de eventos** (punto 8).
- **Control cruzado informativo:** `recordFinder.cgi find name=AccessControlCard count=1024` una sola vez por lector leído. Se informan los `UserID` de tarjetas que no están en `AccessUser` (`tarjetas_huerfanas`) y las diferencias `CardName` contra `UserName`. Si el resultado trae 1024 registros, se marca "no verificable". No decide nada.
- **Respuesta:** `{leidos, sin_leer, nuevas, vinculadas, cambios_fuera, accesos_fuera, bajas_con_registro, posibles_duplicados, unidos_por_nombre, nombres_distintos_mismo_id, sin_importar, tarjetas_huerfanas}`.
- **La importación nunca escribe en los equipos y nunca cambia `personas.nombre` de un pid que ya existía [CAMBIO].** Motivo: el `UPDATE personas SET nombre` actual pega la ficha de alguien a quien heredó su número.

### 4.8 Conciliación periódica

**[CAMBIO]** Es la misma función en modo automático, cada `padron_minutos` (30 por defecto), por sede y solo con la sede lista. En este modo nunca hay `forzar` y nunca es primera importación. Motivo: las alertas de "dado de baja y sigue cargado", "ID reasignado" y "registro duplicado de SmartPSS" no pueden depender de que alguien apriete un botón. Leer 102 registros cada 30 minutos no es carga.

## 5. Guardar persona, baja y acciones de resolución

**`guardar_persona(sede, pid|None, datos, lectores, confirmar_quitar)`,** dentro de `_LOCK`:

1. **Sede:**
   - `pid` dado: `SELECT ... WHERE pid=? AND sede=?`, y 404 si no hay fila.
   - Persona nueva: toma la sede de la URL.
   - Cualquier IP de `lectores` con `SEDE_DE_IP != sede` da **400 y no se filtra nunca** [CAMBIO]. Motivo: con el filtro, una lista de otra sede se convertía en `[]` y le quitaba todas las puertas.
2. **Perfil:** se busca por `(sede, nombre)`.
3. **Compartidos:** `id_preferido` es obligatorio y alfanumérico.
   - 409 si otro pid de la sede lo tiene como `id_preferido`, o como `user_id` en cualquier lector de la sede.
   - Solo se puede cambiar si la persona no tiene filas con `user_id != ''`.
   - **Aviso no bloqueante [CAMBIO]:** si `eventos` tiene marcas de ese `persona_id` en la sede con un nombre que no coincide, se muestra "el ID 38 tuvo marcas de 'A.J.' hasta el 04/06/2025". Motivo: en Lavalle ya hay al menos 15 IDs reutilizados.
4. **Por lector:** `id_preferido` siempre es NULL y no se muestra en la ficha [CAMBIO]. Motivo: un ID ocupado por la misma persona caía igual en max+1, así que no evitaba el duplicado. La adopción por nombre del worker lo reemplaza.
5. **`confirmar_quitar`:** se calcula `quita = {ip : fila permitido=1} − deseados`. Si `quita != set(confirmar_quitar)`, se responde 409 "la ficha quedó vieja, reabrila" [CAMBIO]. Motivo: casillas repintadas, respuestas de otra sede o una importación intermedia. Cubre también las bajas parciales.
6. **Filas, solo sobre lectores de `sede`** (los de otra sede no se leen ni se tocan):
   - **Deseado, sin fila:** se inserta `permitido=1, pendiente, version=1`. En compartidos, además `user_id=id_preferido, confirmado=0, nombre_en_lector=nombre`; si choca el índice único, 409 "el ID N en <lector> está asignado a <persona>".
   - **Deseado, con fila `permitido=0`:** `permitido=1, pendiente, version+1, error='', forzar_nuevo=0`. En compartidos, `user_id=id_preferido, confirmado=0` si estaba vacío.
   - **Deseado, con fila `permitido=1` en `ok` o `pendiente`,** y cambió nombre, desde, hasta o documento: `pendiente, version+1` [CAMBIO]. Motivo: hoy un cambio de vigencia o de nombre no llega nunca al equipo.
   - **Deseado, con fila `permitido=1` en `error`:** no se toca. [CAMBIO] Motivo: reencolar solo recrea a quien SmartPSS sacó. Se destraba con los botones.
   - **No deseado, con fila `permitido=1`:** `permitido=0, pendiente, version+1, error=''` (también si estaba en error).
   - **Con `activo=False`:** toda fila con `user_id != ''` o `estado != 'ausente'` pasa a `permitido=0, pendiente, version+1`.

**`dar_de_baja(sede, pid, incluir_pids=[])`:** `activo=0` y toda fila con `user_id != ''` o `estado != 'ausente'` pasa a `permitido=0, pendiente, version+1`, **incluidas las que están en error** [CAMBIO]. Motivo: hoy se saltean las `ausente` y el worker nunca reintenta `error`. `incluir_pids` (posibles duplicados tildados en la UI) tienen que ser de la misma sede, y si no, 409.

**Acciones por acceso** (`POST /api/<sede>/personas/<pid>/accesos/<ip>/<accion>`). Todas validan sede y pid, hacen `version+1` cuando cambian el deseo y se loguean:

- **`reintentar`:** `estado=pendiente, error='', intentos=0`. En compartidos pone `user_id=id_preferido, confirmado=0` si estaba vacío.
- **`adoptar_nombre`** ("es la misma persona, cambió el nombre"): bajo `CANDADO[ip]` hace `buscar_persona(user_id)`; si existe, `nombre_en_lector=UserName` y pasa a `pendiente`.
- **`desvincular`** ("es otra persona"): `user_id='', confirmado=0`.
  - con `permitido=0`: pasa a `ausente`.
  - con `permitido=1`: pasa a `error` "desvinculado; reintentá para crear un registro nuevo".
- **`vincular {user_id}`:** solo si ese `user_id` no está asignado en ese lector y existe en el último padrón. Pone `confirmado=1, nombre_en_lector=UserName` y pasa a `pendiente`.
- **`crear_nuevo`:** `forzar_nuevo=1` y `pendiente`.
- **`sacar`** (dado de baja y sigue cargado): `pendiente` con `permitido=0`.
- **`reactivar`:** `activo=1, permitido=1, pendiente`.

**Unir y separar (por sede):**

- **`unir(destino, origen)`:** 409 si las sedes difieren o si los dos tienen `user_id != ''` en un mismo lector ("sacá el registro sobrante de <lector>"). Si no, en cada lector: las filas de `origen` sin fila en `destino` se mueven; si hay fila en ambos, se conserva la que tenga `user_id` (o la de `destino`). Se borra `origen`.
- **`separar(pid, lectores)`:** crea un pid nuevo con el mismo nombre y mueve esas filas.

**Borrar persona:** solo si todas sus filas tienen `user_id=''` y ninguna está en `pendiente` o `error`. Si no, 409.

## 6. Worker

**[CAMBIO] Un hilo por sede. Dentro de la sede se procesa por lector.** Motivo: un lector caído del Depósito demoraba las bajas de Lavalle entre 20 y 25 minutos.

```
por cada vuelta (sede):
  tareas = accesos pendiente de lectores de la sede, JOIN personas,
           ORDER BY permitido ASC, actualizado        # bajas primero
  agrupar por lector
  por cada lector (saltear si: escritura=false | espera vigente | credenciales rechazadas):
    con CANDADO[ip]:
      padron = lector.padron()          # una lectura por lector por vuelta
        ErrorSinRespuesta/PadronInvalido -> espera(ip); a sus filas solo
            error="sin respuesta desde HH:MM" (sin tocar estado ni version); siguiente lector
        ErrorCredenciales -> punto 10; siguiente lector
      por cada tarea (bajas primero): decidir, ejecutar, grabar
      pausa de 300 ms entre escrituras
```

**Paso 0 (toda tarea):** si `SEDE_DE_IP[lector] != persona.sede`, pasa a `error="acceso de otra sede"` y no se escribe.

**`permitido=1`:**

- **A. `user_id=''`** (solo `por_lector`; en compartidos la reserva ya viene desde el guardado):
  1. `sueltos` = registros del padrón cuyo `UserID` no está en `accesos` para ese lector.
  2. Si `forzar_nuevo=0` y `persona.nombre` no es genérico:
     - **Exactamente un suelto con nombre normalizado igual:** se **adopta** con `user_id` y `confirmado=1`; el nombre del equipo va a `nombre_en_lector`, sin renombrar el registro. Sigue en C. Aviso "se tomó el registro que ya existía (ID N)".
     - **Hay algún suelto con `parecido >= 0,85`, dos o más iguales, o uno igual asignado a otro pid:** `error="Ya figura 'X' con ID N en <lector>: vincular o crear nuevo"` y no se escribe.
     
     [CAMBIO] Motivo: la cara se carga en el equipo o en SmartPSS, así que es normal que la persona ya exista, y un segundo registro sin cara sobrevive a la baja.
  3. **ID nuevo:** `cand = max(rango_ids_nuevos, proximo_id, max(UserID numéricos del padrón >= rango)+1, max(user_id numéricos de accesos del lector >= rango)+1)`.
  4. **Reserva, en una transacción y con COMMIT:** `user_id=cand, confirmado=0, nombre_en_lector=persona.nombre` (el texto exacto que se va a mandar) y `proximo_id=cand+1`. Si falla el índice único, se elige de nuevo. Sigue en B.
  
  [CAMBIO] Motivo: con el insert antes de la reserva, una respuesta perdida duplicaba el registro, y el max+1 sin contador reutilizaba IDs.
- **B. `user_id != ''` y `confirmado=0` (reserva):**
  - **No está en el padrón:** `crear(user_id, nombre, desde|None, hasta|None, plantilla(padron))`.
    - OK: `buscar_persona(user_id)`, `nombre_en_lector=UserName`, `confirmado=1`, `ok`, `cara='?'`.
    - `ResultadoIncierto` o `ErrorSinRespuesta`: sigue `pendiente` con la reserva puesta, `intentos+1`, espera del lector y se cortan las demás tareas de ese lector.
    - Rechazo "ya existe": sigue `pendiente` y lo decide la vuelta siguiente con un padrón nuevo.
  - **Está y coincide `mismo_registro`:** se confirma sin escribir (es la escritura propia que no se llegó a confirmar) y sigue en C.
  - **Está con otro nombre:**
    - `por_lector`: `user_id=''`, sigue `pendiente` y se vuelve a elegir, con aviso "SmartPSS o la web tomaron el ID N".
    - `compartidos`: `error="el ID N en <lector> es 'X'"`; se conserva `user_id` como reserva (botones `adoptar_nombre` o `desvincular`).
- **C. `user_id != ''` y `confirmado=1`:**
  - **No está en el padrón:** `crear` con ese mismo ID, con `aviso="el registro había desaparecido; se volvió a crear sin cara"`.
  - **Está con `mismo_registro(UserName, nombre_en_lector)`:** se calcula `cambios`:
    - `nombre` si `UserName != persona.nombre`;
    - `desde` y `hasta` solo si la persona los tiene no vacíos y son distintos a los del equipo;
    - `documento` si no está vacío y es distinto;
    - `puertas` solo si el registro tiene `Doors` vacío.
    
    Sin cambios pasa a `ok` sin escribir. Con cambios: `actualizar(user_id, nombre_esperado=nombre_en_lector, **cambios)`, que conserva `TimeSections` y lo demás del equipo, después `buscar_persona` y `ok`.
    
    [CAMBIO] Motivo: no pisar vigencias puestas por SmartPSS ni horarios restringidos, y no extender vencimientos que el panel no administra.
  - **Está con otro nombre:** `error="conflicto: el ID N en <lector> es 'X', no 'Y'"`. **No se escribe.**

**`permitido=0`:**

- **`user_id=''`:** pasa a `ausente`, con el control de restos.
- **`user_id != ''`:**
  - **No está en el padrón:** `ausente, user_id='', confirmado=0`, con el control de restos.
  - **Está con `mismo_registro`:** `quitar(user_id, nombre_esperado=nombre_en_lector)`; se verifica que `buscar_persona(user_id)` devuelva None y queda `ausente, user_id=''`, con el control de restos. `removeMulti` es idempotente y admite reintento.
  - **Está con otro nombre:**
    - `confirmado=1`: `error` de conflicto y **no se borra**.
    - `confirmado=0`: la reserva nunca aterrizó; `ausente, user_id=''`.
- **Control de restos [CAMBIO]:** si en el padrón hay sueltos con `parecido(UserName, persona.nombre) >= 0,85`, se deja `aviso="en <lector> sigue 'X' con ID N sin vincular: sigue entrando"` y la fila igual queda `ausente`. Motivo: el duplicado que crean SmartPSS o la web deja entrar a alguien dado de baja, y una escritura que salió bien no puede figurar como error.

**Grabar el resultado [CAMBIO]:**

- **Observación, siempre:** `user_id`, `confirmado`, `nombre_en_lector`, `aviso`, `cara`, `visto`.
- **Estado:** `UPDATE ... SET estado=?, error=?, intentos=? WHERE pid=? AND lector=? AND version=?` con la versión leída con la tarea. Si no toca ninguna fila, queda `pendiente` y lo decide la vuelta siguiente contra el deseo nuevo.
- Motivo: un operador que destilda durante un insert dejaba `0/ok`. La observación va sin condición porque `guardar_persona` nunca escribe esas columnas.

**`lector.py` como cliente fino [CAMBIO]:**

- Métodos: `padron()`, `buscar_persona(uid)`, `plantilla(padron)`, `crear(...)`, `actualizar(uid, nombre_esperado, **cambios)`, `quitar(uid, nombre_esperado)`.
- **`_conflicto` compara con `identidad.mismo_registro` y lanza error si `nombre_esperado` está vacío.**
- Se eliminan `usuarios()`, `buscar_usuario()`, `alta()`, `modificar()` y `baja()`.
- `_llamar_rpc(metodo, reintentar)`: `insertMulti` va con `reintentar=False` y ante un error de transporte lanza `ResultadoIncierto(ErrorSinRespuesta)`.

**Quiénes pueden cambiar `nombre_en_lector`:** el worker después de leer tras escribir (o al adoptar o confirmar), la importación en el caso `mismo_registro` o al vincular, y la acción `adoptar_nombre`. Nadie más.

## 7. API

- **`GET /api/sedes`** (global): `[{clave, nombre, ids, tiene_nvr, lista, lectores:[{ip,nombre}]}]`.
- **Todo lo demás cuelga de `/api/<sede>/...`.** `<sede>` tiene que cumplir el regex y existir; si no, 404. **Toda IP recibida** (en el cuerpo, la query o la ruta) con `SEDE_DE_IP != sede` da **400**.
- **Persona:** `GET/POST/DELETE /api/<sede>/personas/<pid>`, `POST .../baja`, `GET/POST .../foto` y `POST .../accesos/<ip>/<accion>`. Todas pasan antes por `persona_de(sede, pid)`, que devuelve 404 si no coincide. [CAMBIO] Motivo: la baja, la foto y el DELETE no llevan IP y cruzaban de sede.
- **`GET /api/<sede>/personas/<pid>`** devuelve la persona y `puertas`: **cada lector de la sede** con `{ip, nombre, user_id, confirmado, nombre_en_lector, permitido, estado, error, aviso, cara, version}` (o `null` si no hay fila).
- **La API no devuelve `id`:** usa `pid` e `id_preferido` [CAMBIO]. Motivo: cualquier `p.id` que quede en app.js da `undefined` a la vista, en vez de abrir a otra persona.
- **Colecciones:** `GET /api/<sede>/personas`, `/eventos?pid=&lector=&user_id=&...`, `/duplicados`, `/perfiles`, `DELETE /api/<sede>/perfiles/<nombre>`, `POST /api/<sede>/personas/unir`, `.../<pid>/separar`.
- **`POST /api/<sede>/importar/personas {forzar, forzar_sin}`:** 200 con el resultado del 4.7, o 409 (primera importación incompleta, choque en compartidos o ningún lector leído).
- **`POST /api/<sede>/importar/historial {lectores?}`:** asincrónico. Por defecto, los lectores de la sede con `historial=true`.
- **`POST /api/<sede>/sincronizar`:** borra las esperas de los lectores de la sede, despierta el worker de esa sede y devuelve los pendientes de esa sede.
- **`POST /api/<sede>/abrir {lector}`** y **`/api/<sede>/camaras/...`:** usan `GRABADORES[sede]`, y 404 "sede sin NVR" si es None, **incluido `/hd`**.
- **`GET /api/stream`** es uno solo. **`difundir(tipo, datos, sede)` lanza `ValueError` si `sede` es None.**
  - `estado`: un mensaje por sede, solo con sus lectores.
  - `resumen` y `sincronizado` (`{aplicadas, reintentando, fallidas}`): por cada sede tocada en la vuelta.
  - `evento` y `apertura`: con la sede del lector.
  - [CAMBIO] Motivo: los mensajes que juntaban sedes no tienen una sede sola.
- **`resumen(sede)`:** personas, bajas, pendientes, reintentando (`pendiente` con `error != ''`), `con_error`, `bajas_incompletas` (`activo=0` con filas `pendiente`/`error` o `user_id != ''`), `bajas_con_registro`, `sin_cara`, `avisos`, eventos de hoy y rechazos de hoy.

## 8. Eventos en vivo e historial

- **Marca en vivo (`_DoorFace_`):** `fila = accesos WHERE lector=ip AND user_id=UserID AND confirmado=1 AND estado != 'error'`, más la persona.
  - Si hay fila: `evento.pid`, `evento.nombre=persona.nombre`, y `cara='vista'` si el método es Rostro.
  - Si no hay fila, o está en conflicto: `pid NULL` y `nombre=''` (la UI muestra "ID N sin identificar").
  - `evento.sede=SEDE_DE_IP[ip]`.
- **`corregir_desde_historial` [CAMBIO]:** también pone `nombre=CardName` en las marcas vivas que corrige. Si el `CardName` normalizado de una marca posterior a `visto` no coincide con el `nombre_en_lector` de la fila, pone `pid=NULL` en esas marcas, deja `aviso="las marcas del ID N salen como 'X'"` y despierta la conciliación de ese lector. Motivo: cubre la ventana en la que las marcas de Rosa salen como Pedro.
- **Atribución después de cada importación exitosa:** `UPDATE eventos SET pid=? WHERE sede=? AND lector=? AND persona_id=? AND pid IS NULL AND normalizar(nombre)=normalizar(nombre_en_lector)`, por cada fila vinculada, con `normalizar` registrada vía `create_function`. Las marcas con nombre vacío o distinto quedan en NULL y se muestran con el nombre guardado. Se hace una vez por fila vinculada nueva. Si hubo marcas del método Rostro, pone `cara='vista'`.
- **La ficha muestra el historial `WHERE pid=?`.** La vista general usa `WHERE sede=?`.
- **Lectura del stream:** `respuesta.read1(4096)` en vez de `read(1024)` [CAMBIO]. Motivo: hoy las marcas llegan en tandas de hasta un minuto y el emparejado con DoorStatus trabaja sobre la hora de llegada. `ts` sale de `RealUTC`, `UTC` o `CreateTime`, y si ninguno viene, de la hora de la PC.
- **Historial:**
  - Guarda la sede.
  - Toma `CANDADO_HISTORIAL[ip]`, compartido entre la pasada automática y el botón.
  - Loguea los errores con `log.warning`.
  - **Si `max(RecNo)` del equipo es menor que `ultimo_recno`, o cambió `serie` (leída con `getSystemInfo` al arrancar), vuelve a 0 y lo loguea** [CAMBIO]. Motivo: con un equipo reemplazado en la misma IP la pasada queda muda.

## 9. UI

- **Selector de sede** en la barra lateral. La sede vive **en memoria por pestaña**: `localStorage` se lee solo al arrancar (se valida contra `/api/sedes` y, si no existe, se usa la primera) y se escribe al cambiar [CAMBIO]. Motivo: otra pestaña no puede redirigir las acciones de esta.
- **`generacion`:** un contador que sube al cambiar de sede. `cargarPersonas`, `abrirFicha`, `cargarHistorial`, `refrescarEstado` y `cargarDuplicados` descartan la respuesta si cambió, o si `respuesta.sede != sedeActual`.
- **Al cambiar de sede:**
  1. `cerrarCajon()` y `estado.editando=null`.
  2. `cerrarVisor()`, `pararMosaico()` y `estado.camaras=[]`.
  3. Si la vista activa es Cámaras y la sede no tiene NVR, se pasa a "En vivo".
  4. Se recarga estado, personas y perfiles. **El EventSource no se toca.**
  5. Se piden las últimas 50 marcas de la sede con `/api/<sede>/eventos?limite=50`, sin repetir por (lector, ts, persona_id, metodo).
- **Salir de Cámaras** por el menú llama a `cerrarVisor()` además de `pararMosaico()`.
- **`estado.marcas[sede]`:** un buffer de 200 por sede. Todo evento SSE entra al buffer de su sede, se esté mirando o no. `pintarFeed` pinta el de la sede actual.
- **La ficha arma sus propias casillas [CAMBIO]:** `abrirFicha` y "Nueva persona" construyen `#p-lectores` a partir de `puertas` de `GET /api/<sede>/personas/<pid>` (o de `/api/sedes` para una persona nueva). `pintarSelectores()` deja de tocar `#p-lectores` y `#p-perfil`. Guardar va a `/api/<persona.sede>/personas/<pid>`, con la sede tomada de esa respuesta. Motivo: `refrescarEstado` y el reingreso después de un 401 repintaban las casillas vacías y el guardado mandaba `[]`.
- **Guardar:** el cliente calcula `quita = permitidas al abrir − tildadas`. Si no está vacío, confirma nombrando las puertas y manda `confirmar_quitar`. Si vuelve 409, muestra "la ficha quedó vieja, reabrila".
- **Ficha, por puerta:**
  - `compartidos`: "ID 37" con el estado.
  - `por_lector`: "ID 12", "ID 9001 (reservado)" o "sin cargar".
  - Siempre: `estado`, `error` y `aviso` con fecha; "Falta la cara: editá el ID N en <lector> y cargale la cara, no crees una persona nueva" si `cara='?'` y `ok`.
  - Botones según el caso: Reintentar, Es la misma persona, Es otra persona, Vincular ID N, Crear registro nuevo, Sacar, Reactivar.
- **`id_preferido`:** obligatorio en compartidos; no aparece en `por_lector`.
- **Dar de baja:** muestra el grupo de posibles duplicados de la sede (nombre igual o `parecido >= 0,85`, sin genéricos) con casillas para incluirlos en `incluir_pids`. El botón dice "Se está sacando de N puertas" hasta que `resumen` lo confirme.
- **Lista de personas:**
  - "Solo activos" también muestra a los inactivos con baja incompleta, con la etiqueta roja "baja incompleta".
  - Etiqueta "dado de baja y sigue cargado".
  - Marca "posible duplicado sin resolver".
  - Las métricas "con error", "bajas incompletas", "sin cara" y "avisos" se pueden cliquear y filtran la lista.
- **Importar:** si vuelve `sin_leer`, se muestra un aviso con clase `mal`: "Importación parcial: no se leyó <lector> (<motivo>). Sus accesos no se tocaron". Si no, "Listo", con listas desplegables de `cambios_fuera`, `bajas_con_registro` (en rojo), `posibles_duplicados` y `sin_importar`.
- **Duplicados por sede:** coincidencias exactas, parecidos por tipeo y `unidos_por_nombre` con botón Separar. En `por_lector`, el texto aclara que un ID distinto por puerta es lo normal.
- **Textos de conteo:** "N lectores" sale de la sede. `entrarAlPanel` va con try/catch y muestra el error.
- **`sincronizado`** en rojo, nombrando persona y puerta, si hay `fallidas` o bajas `reintentando`.

## 10. Hilos, candados, transporte y credenciales (nuevo)

- **Hilos por sede:** `sincronizacion(sede)`, `vigilancia(sede)` (difunde el estado de cada lector apenas lo conoce) y `padron_historial(sede)` (conciliación del 4.8 más el historial). Además, un `eventos(ip)` por lector con `eventos_en_vivo=true`. [CAMBIO] Motivo: una sede caída no puede atrasar a la otra.
- **`CANDADO[ip]`** (`threading.Lock`): lo toman el worker (por la tanda de ese lector), la importación y la conciliación (todos los de la sede, en orden de IP) y la acción `adoptar_nombre`. **No lo toman** la vigilancia, los eventos ni abrir la puerta.
- **Esperas por lector, en memoria:** 20 s, 60 s y tope de 120 s. Se borran cuando la vigilancia ve al lector en línea (y en ese momento llama a `avisar_trabajo(sede)`) o con `/sincronizar`.
- **Tipos de error en `lector.py`:**
  - `ErrorSinRespuesta`: URLError, timeout, OSError, HTTP 5xx, RPC2 sin respuesta.
  - `ResultadoIncierto`: subclase del anterior, para `insertMulti` sin respuesta.
  - `ErrorCredenciales`: HTTP 401 después del digest, o RPC2 "usuario o clave rechazados".
  - `PadronInvalido`.
  - `ErrorLector`: los rechazos del equipo.
  - **`error` como estado queda solo para lo lógico:** conflictos, rechazos e ID ocupado en compartidos. [CAMBIO] Motivo: hoy un corte de 10 segundos del .74 deja una baja muerta para siempre.
- **Credenciales [CAMBIO]:**
  - Al arrancar, un solo `getSystemInfo` por lector (también guarda `serie`).
  - Ante `ErrorCredenciales`: `ESTADO[ip].credenciales=True` y **ningún hilo vuelve a pedirle nada a ese lector** hasta el botón "Reintentar credenciales" en Puertas o un reinicio con el config cambiado.
  - Motivo: con ~5 intentos fallidos por minuto se bloquea la cuenta admin, también para SmartPSS y para la web del equipo.
- **Abrir la puerta:** usa un opener propio por llamada, timeout de 8 s y **sin `_lock`** [CAMBIO]. Motivo: quedaba en cola detrás de la lectura del padrón. El `_lock` del digest queda solo para vigilancia y stream. Cada llamada con opener propio no comparte nonce.
- **Al cerrar el servidor:** `PARAR.set()` y `join` del hilo de sincronización con 20 s de timeout. La protección real ante un kill es la reserva del punto 6.

## 11. Cámaras y go2rtc (nuevo)

- **[CAMBIO] Los streams no se renombran:** siguen siendo `camN_sub` y `camN_hd`. Motivo: hay un solo NVR, los nombres son internos (go2rtc escucha en loopback) y renombrar rompe el HD con el go2rtc viejo vivo.
- **Rutas y lecturas del NVR:** las rutas usan `GRABADORES[sede]`, y `servidor.py:234/262` y `gateway.py:54` leen el NVR de la sede.
- **Si `GRABADORES` llegara a tener dos NVR,** recién ahí se prefijan los streams con la sede, incluida la línea `ffmpeg:` (gateway.py:83).
- **Reinicio de go2rtc:** al arrancar, si el yaml generado difiere del que está en disco o si `GET /api/streams` no contiene las claves esperadas, se mata el go2rtc vivo (PID guardado en `gateway/go2rtc.pid`, o por nombre si falta) y se relanza. Vale también para un cambio de clave del NVR.

## 12. Verificaciones previas en los equipos (nuevo)

Las hace el operador, en solo lectura o con el usuario de prueba vencido y sin puertas del 11/09. Hasta completarlas, `escritura=false` en el Depósito y `eventos_en_vivo=false` y `historial=false` en el .246:

1. **`AccessUser.startFind/doFind` en .78 (73 usuarios, más de 50, así que pagina) y en .246:** ¿devuelve `Total`? ¿`Offset` avanza de verdad? `padron()` tiene que dar la misma cantidad que los `UserID` distintos del CGI.
2. **`UserName` (AccessUser) contra `CardName` (AccessControlCard)** en los 12 lectores: listar las diferencias.
3. **En un equipo de prueba o con el usuario de prueba:** después de `removeMulti`, ¿desaparecen su tarjeta de `AccessControlCard` y su cara de `AccessFace`?
4. **.246:** ¿acepta `insertMulti` con UserID 9000 o más (usuario de prueba vencido y sin puertas, que se borra enseguida)?
5. **.246 con `codes=[All]`** mientras alguien pasa por la Reja: ¿qué código emite, y trae `RealUTC`? ¿Funciona `RecordFinder` por RPC2?
6. **Política de bloqueo de cuenta** en la web de cada equipo del Depósito, y **si SmartPSS usa `admin`**. Se recomienda un usuario propio del panel en cada equipo. Crearlo es un cambio en los equipos y lo decide el operador.
7. **Procedimiento documentado para Libertador:** la cara se carga editando el ID que ya existe; en SmartPSS nunca se usa "agregar persona" para alguien que administra el panel; y el panel usa IDs de 9000 en adelante.

---

## Descartado

| Hallazgo o arreglo | Por qué no se incorpora |
|---|---|
| Exigir el mismo RecNo para vincular o escribir | La escritura va por `AccessUser`, con UserID como clave y sin RecNo. Un renombre en el lugar lo detecta el nombre. No está verificado cómo edita SmartPSS en fw 2.000: si recrea los registros, se desarmaría el equipo entero. |
| Estado nuevo "cambio externo" o bandeja nueva | Se cubre con `ausente` o `error` más `aviso` y los botones por acceso. Un estado nuevo con `permitido=1` volvía a `pendiente` al guardar y recreaba a quien SmartPSS sacó. |
| Tolerancia de 0,85 en el worker o al re-vincular; tres franjas de parecido | Mario/Maria (0,909) y Daniel/Daniela (0,963) pasan. Se usa igualdad exacta contra un `nombre_en_lector` que siempre sale del equipo. Un tipeo corregido afuera se resuelve con "Es la misma persona" o uniendo desde Duplicados. |
| Tomar como "misma persona" un nombre de una palabra que se completó (0,71) | Cae en conflicto o en una persona nueva, y se resuelve a mano. Automatizarlo exige heurísticas que no se pueden verificar. |
| Paginar por RecNo, `recordUpdater action=get&recno`, `count=1024` en un solo find del CGI | Quedan sin efecto con `AccessUser`. El CGI queda solo como control cruzado informativo. |
| Leer un registro puntual justo antes de cada escritura como condición | Con `CANDADO[ip]` y el padrón leído al empezar con ese lector alcanza. `actualizar` y `quitar` ya releen por UserID dentro de `lector.py`. |
| Tabla `lectores` y FK compuestas (pid, sede) | Las IP son únicas entre sedes. Alcanza con `SEDE_DE_IP` y los tres controles del punto 2, más el conteo de violaciones al arrancar. |
| Tabla `ids_usados` | La reemplaza `estado_lector.proximo_id`, que es monotónico. |
| Rango de IDs acordado con Libertador | Se usa un rango propio desde 9000, sin depender de otro equipo. Se informa en el procedimiento del punto 12.7. |
| "Falta cara" como estado de sincronización | Es informativo (`cara`). Bloquearía el `ok` de toda alta del Depósito sin que el panel pueda resolverlo. |
| Dejar "a confirmar" toda unión por nombre entre lectores con IDs distintos | Son 17 de las 24 personas multi-lector del Depósito. Partirlas todas deja 17 bajas que no sacan a la persona de todas sus puertas, que es el riesgo real. Se unen por nombre exacto no genérico y se ofrece Separar. |
| Vigencia por acceso | Queda por persona, con `''` como "no administrada". El update solo manda campos no vacíos y distintos, así no se pisan vigencias por lector. |
| Sacar automáticamente a un dado de baja que SmartPSS volvió a cargar | Pelearía con SmartPSS. Queda como alerta roja con botón "Sacar". |
| Abortar toda re-importación si falla un lector | Trabaría el Depósito cada vez que la Reja no conteste. Solo se aborta en la primera importación y en choques de compartidos. |
| Migración que copia personas y accesos con reglas de mapeo y `foreign_keys OFF` | Se reemplaza por renombrar a `_v1` y re-importar. La refutación de las trampas de sqlite3 se acepta y además deja de aplicar. |
| Backfill de `eventos.pid` durante la migración | Se hace después de la primera importación, cuando existen pids y `nombre_en_lector` reales. |
| Leer el formato viejo del config | Solo `sedes` (punto 1). |
| Renombrar los streams de go2rtc | Un solo NVR (punto 11). |
| `puertas_mostradas` y `confirmar_sin_puertas` | Los reemplazan las casillas armadas desde la ficha y `confirmar_quitar`, que cubre también las bajas parciales. |
| Estado en línea sacado del stream en vez de sondear; saltear en el historial los lectores sin `_DoorFace_`; pasada completa de noche | Son optimizaciones de carga, no de identidad. El stream no trae las marcas de tarjeta del .246 (ASI3213G-MW, Mifare). Se incorporan solo la vigilancia por sede, el candado del historial y el log de errores. |
| Clave de teclado administrada desde el panel | `actualizar` excluye `Password` a propósito. Se saca de la base v2. |
| Varios RecNo por UserID en la baja | Deja de aplicar con el padrón `AccessUser`, uno por UserID. Las tarjetas huérfanas se informan (4.7) y el borrado de tarjeta y cara queda en la verificación 12.3. |

---

## Casos de prueba obligatorios

Se corren con un `Lector` falso en memoria (padrón como dict `UserID -> registro`, contadores de llamadas por método, errores y demoras inyectables) y con bases SQLite temporales. Ninguno toca la red.

### Identidad: importación y conciliación

- **T01 · ID reutilizado afuera (Pedro → Rosa).**
  - Dado: `.246` en la base con `pid P, user_id='7', nombre_en_lector='Pedro Acosta', 1/ok`; en el equipo, `7='Rosa Benitez'`.
  - Al re-importar el Depósito: la fila de P en `.246` queda `permitido=0, ausente, user_id=''`, con un `aviso` que contiene "Rosa Benitez". Se crea el pid R con `(.246,'7') 1/ok, nombre_en_lector='Rosa Benitez'`. `cambios_fuera` tiene 1 elemento.
  - Un `_DoorFace_ UserID=7` en `.246` guarda un evento con `pid=R` y `nombre='Rosa Benitez'`.
  - `dar_de_baja(P)`: el worker hace 0 llamadas a `removeMulti` sobre `.246`.
- **T02 · Import con lector sin respuesta.**
  - Dado: el Depósito con 10 filas vinculadas en `.246`, y `.246.padron()` lanza `ErrorSinRespuesta`.
  - Al re-importar: las 10 filas de `.246` quedan byte a byte iguales; `sin_leer=[.246]`; los otros 4 lectores se concilian; HTTP 200.
- **T03 · Padrón vacío sospechoso.**
  - Dado: `.250.padron()` devuelve `[]` y la base tiene 8 filas con `user_id` en `.250`.
  - Al importar: `.250` queda en `sin_leer` con motivo "padrón vacío" y sus 8 filas no cambian.
  - Con `forzar=['192.168.88.250']`, las 8 pasan a `ausente` con `user_id=''`.
- **T04 · Offset ignorado.**
  - Dado: un `doFind` falso que devuelve siempre los mismos 50 registros en un lector de 73.
  - `padron()` lanza `PadronInvalido` en la segunda página. Hay 3 llamadas `doFind` o menos, y el worker hace 0 escrituras en ese lector.
- **T05 · Total que no cierra.** `startFind` devuelve `Total=73` y llegan 50 registros: `PadronInvalido`.
- **T06 · Una baja pendiente no se cancela con un import.**
  - Dado: `0/pendiente, user_id='15', nombre_en_lector='Juan Perez'` y en el equipo `15='Juan Perez'`.
  - Al importar, la fila sigue `0/pendiente`. La vuelta siguiente del worker llama a `removeMulti(['15'])` y la fila queda `ausente, user_id=''`.
- **T07 · Baja cumplida afuera.** `0/error, user_id='15'` y el equipo sin el 15: al importar queda `ausente, user_id=''`.
- **T08 · Dado de baja que vuelven a cargar.**
  - Dado: la persona `activo=0` sin fila en `.246`, y en el equipo `30='Juan Perez'` suelto.
  - Al importar: `(pid,.246)` queda `permitido=0, estado=error, user_id='30'`, con "dado de baja y sigue cargado"; `resumen.bajas_con_registro=1`; 0 llamadas `removeMulti`; en ningún momento hay `permitido=1`.
- **T09 · Primera importación incompleta.**
  - El Depósito sin personas y `.246` caído: 409 y `SELECT COUNT(*) FROM personas WHERE sede='deposito'` da 0.
  - Con `forzar_sin=['192.168.88.246']`: se importan los otros 4.
- **T10 · Tipeos entre lectores.** `.251 3='Roiner Rios'` y `.246 8='Roinel Rios'`: 2 pids, y `posibles_duplicados` contiene el par.
- **T11 · Mismo nombre con 2 IDs en un lector.**
  - `.251 5='Ana Gomez'`, `.251 9='Ana Gomez'` y `.250 4='Ana Gomez'`: 3 pids, todos marcados.
  - Cambio en el equipo: se saca el 9 y se agrega `12='Ana Gomez'` en `.251`. Después de dos importaciones seguidas, el mapeo (lector, user_id) → pid es idéntico entre la 1ª y la 2ª, y el 5 sigue con su pid original.
- **T12 · Genéricos y vacíos.** `'Visita'` en `.246` y `.250`, y `''` en `.249` y `.248`: 4 pids distintos.
- **T13 · Unir por nombre y separar.**
  - `.251 4='Carlos Gonzalez'` y `.248 20='Carlos Gonzalez'`: 1 pid, listado en `unidos_por_nombre`.
  - `separar(pid,['192.168.88.248'])` crea un pid nuevo con `(.248,'20')`. Al re-importar se mantienen 2 pids.
- **T14 · Choque en compartidos.** Lavalle con `38='A J'` en `.73` y `38='R M'` en `.74`: 409 y 0 filas modificadas (checksum de las tablas igual).
- **T15 · ID reutilizado en todos los lectores (compartidos).**
  - Dado: P con `id_preferido='38'` y 7 filas vinculadas `'A J'`; los 7 equipos tienen `38='R M'`.
  - Al importar: las 7 filas de P quedan liberadas, `P.id_preferido=NULL` con aviso; Q tiene `id_preferido='38'` y 7 filas `1/ok`; las marcas previas de P conservan `pid=P`.
- **T16 · Tipeo en compartidos.** El ID 5 como `'Cintia Ibañez'` en `.73` y `'Cintia Ibañes'` en `.74`: un solo pid; cada fila con su propio `nombre_en_lector`; el caso aparece en `nombres_distintos_mismo_id`.
- **T17 · La importación no renombra.** Un pid existente con `nombre='Juan Perez'`, vinculado y con coincidencia exacta: después de importar, `personas.nombre` no cambió.

### Identidad: worker

- **T20 · Mario → Maria en la baja.**
  - Dado: `(.248,'12', nombre_en_lector='Mario Gomez') 1/ok` y en el equipo `12='Maria Gomez'`.
  - `dar_de_baja`: 0 llamadas `removeMulti`, `estado=error`, `user_id='12'` conservado y el error contiene "Maria Gomez".
- **T21 · Juan → Juana en un update.** Se cambia `hasta`; en el equipo `12='Juana Perez'`: 0 `updateMulti` y `error`.
- **T22 · Nombre vacío.** `nombre_en_lector=''` o `UserName=''`: 0 `updateMulti` y 0 `removeMulti`. `Lector.quitar(uid, nombre_esperado='')` lanza `ErrorLector`.
- **T23 · Respuesta perdida en el insert (por_lector).**
  - Dado: el `insertMulti` falso aplica y lanza timeout.
  - La fila queda `pendiente, user_id='9001', confirmado=0`. En la vuelta siguiente, el equipo tiene `9001` con el nombre exacto: queda `confirmado=1, ok`. En total hubo 1 llamada `insertMulti` y la persona figura una sola vez en el equipo.
  - Además, `_llamar_rpc('AccessUser.insertMulti')` no reintenta: hay 1 POST ante el timeout.
- **T24 · Reserva tomada por SmartPSS.** Una reserva de `9002` sin aterrizar, y el equipo con `9002='Sergio'`: se libera; en la vuelta siguiente inserta `9003`; el registro de Sergio no recibe ninguna llamada; `proximo_id` queda en 9004 o más.
- **T25 · Compartidos, la misma persona ya cargada.** Brian con `(.75,'37') confirmado=0` y el equipo con `37='Brian Michat'`: `ok` sin `insertMulti`.
- **T26 · Compartidos, ID de otro.** El equipo con `37='Otro Nombre'`: `error` y 0 escrituras.
- **T27 · Adopción en el Depósito.**
  - Nueva persona `'Juan Perez'` con `.246`; el equipo tiene `115='Juan Pérez'` suelto.
  - Resultado: `user_id='115', confirmado=1`; 0 `insertMulti`; ningún `updateMulti` que cambie `UserName` o `ValidTo` (la persona tiene `hasta=''`).
- **T28 · Adopción ambigua.**
  - El equipo tiene `115='Juan Peres'`: `error` que lista "ID 115" y 0 escrituras.
  - Después de `crear_nuevo`: `insertMulti` con `UserID >= 9000`.
- **T29 · Sin reutilizar IDs.** Baja de `9010` (el más alto) y alta de Lucía en la misma vuelta: Lucía recibe `9011`, no `9010`.
- **T30 · Carrera operador/worker.**
  - Dado: el `insertMulti` falso bloquea con un `Event`, y mientras tanto `guardar_persona` destilda ese lector.
  - Al liberar el insert: la fila tiene `user_id='9005', confirmado=1, permitido=0, estado=pendiente`. La vuelta siguiente llama a `removeMulti(['9005'])` y termina en `ausente`.
  - En ningún `SELECT` intermedio hay `permitido=0 AND estado='ok'` (además lo impide el CHECK).
- **T31 · Carrera importación/worker.**
  - La importación toma los candados del Depósito y lee; el worker intenta insertar en `.250`.
  - El worker espera: su `insertMulti` ocurre después del COMMIT de la importación, y la fila termina `ok` con `user_id` no vacío.
- **T32 · Vigencia que llega al equipo.** Se cambia `hasta` a `2026-09-11` en una persona `1/ok`: pasa a `pendiente`; hay 1 `updateMulti` con `ValidTo` nuevo y `TimeSections` igual al del equipo (`[255]`); termina `ok`.
- **T33 · Registro suelto después de la baja.** Remove de `9001` OK, y el padrón tiene `115='Juan Pérez'` suelto: la fila queda `ausente` con un `aviso` que contiene "115", y `resumen.avisos` sube en 1.
- **T34 · Transporte no es error.** `removeMulti` lanza `ErrorSinRespuesta`: la fila queda `pendiente`, con `error` no vacío e `intentos=1`. Las otras tareas de ese lector no se intentan en esa vuelta. Cuando el lector vuelve, se aplica.
- **T35 · Una sede no frena a la otra.** `.246` duerme 15 s en cada llamada, hay 40 pendientes del Depósito y 1 baja de Lavalle: la baja de Lavalle se aplica en menos de 25 s desde `avisar_trabajo`, y `.246` recibe 1 lectura de padrón por vuelta.
- **T36 · Credenciales.** `.246` devuelve 401: después del primero, 0 pedidos a `.246` en 5 minutos simulados (vigilancia, eventos, worker, historial) y `ESTADO['.246'].credenciales=True`.
- **T37 · Acceso de otra sede.** Una fila insertada a mano `(pid de Lavalle, '192.168.88.251')`: el worker hace 0 llamadas, deja `error='acceso de otra sede'` y `/api/lavalle/estado` informa 1 violación.

### Migración y arranque

- **T40 · v1 limpia.**
  - Dado: una copia de la base real (92 personas, 644 accesos, 279.626 eventos).
  - Resultado: `user_version=2`, `personas_v1=92`, `personas=0`, `eventos=279.626` con `sede='lavalle'` en todos, el respaldo existe con `integrity_check=ok`, y `seq` de personas en 999999.
  - La primera importación en falso da pids desde 1.000.000.
- **T41 · v1 con baja en curso.** Se agrega una fila `permitido=0, estado='error'`: el arranque aborta con un mensaje que nombra id y lector, `user_version=0` y el archivo queda con el mismo hash.
- **T42 · Falla a mitad de la migración.** Se inyecta una excepción después de los CREATE: rollback; `personas` tiene la columna `id` y 92 filas, y `user_version=0`.
- **T43 · Otra instancia.** Con un proceso escuchando en 8090, el segundo `main()` sale antes de llamar a `base.iniciar()` (mock que lo verifica).
- **T44 · Base nueva.** Sin archivo: se crea v2 con `user_version=2`, sin tablas `_v1` y sin error.
- **T45 · Versión futura.** `user_version=3`: no arranca.
- **T46 · Config vieja.** Sin `sedes`: `SystemExit` y la base no se abre.
- **T47 · IP del v1 fuera de una sede única.** Accesos v1 con IPs repartidas en dos sedes del config: aborta y las lista.
- **T48 · Datos del v1 conservados.**
  - `personas_v1` con `id='37', nombre='Brian Michat', notas='x', activo=1`: después de la primera importación, el pid con `id_preferido='37'` tiene `notas='x'`.
  - Con `activo=0` en v1 y todavía cargado: `activo=0` y la fila en `error` "dado de baja y sigue cargado".
- **T49 · Vuelta atrás.** Después de correr v2 con `-wal` presente, siguiendo el procedimiento (borrar `-wal`/`-shm` y restaurar), el v1 abre y `personas` tiene la columna `id`.
- **T50 · Atribución de eventos.** Marcas `(.73,'38')` con `nombre='A J'` y el mapeo vigente `'R M'`: quedan `pid NULL`; las marcas con `nombre='R M'` quedan con el pid de R M.
- **T51 · Equipo reemplazado.** `ultimo_recno=96733` y el máximo RecNo del equipo es 500: `ultimo_recno` vuelve a 0 y se loguea; también si `serie` cambió.

### Alcance, API y UI

- **T60 · pid de otra sede.** `POST /api/deposito/personas/<pid de Lavalle>` con `lectores=[]`: 404 y 0 cambios. Lo mismo con `/baja`, `/foto` y `DELETE`.
- **T61 · IP ajena.** `POST /api/lavalle/personas/<pid>` con `lectores=['192.168.88.251']`: 400 y 0 cambios.
- **T62 · Ficha vieja.** Con `confirmar_quitar=['192.168.0.73']` cuando lo que se quitaría es `{.73, .74}`: 409 y 0 cambios.
- **T63 · ID repetido en compartidos.** Nueva persona en Lavalle con `id_preferido='37'`, ya usado: 409.
- **T64 · Unir entre sedes.** `unir` de pids de sedes distintas: 409. `unir` con `user_id` en el mismo lector en ambos: 409.
- **T65 · Borrar con mapeo.** `DELETE` de una persona con una fila `user_id != ''`: 409 y la fila sigue.
- **T66 · Perfiles por sede.** `'Oficina'` en las dos sedes y `DELETE /api/deposito/perfiles/Oficina`: el de Lavalle sigue.
- **T67 · SSE con sede.** `difundir('resumen', {...})` sin sede lanza `ValueError`. Una vuelta del worker con tareas de las dos sedes emite dos `resumen`, cada uno con su sede y sus números.
- **T68 · Casillas de la ficha (navegador).** Con la ficha abierta, disparar `tarea()` "Importar historial" y esperar a que termine: las casillas de `#p-lectores` siguen iguales, y al Guardar sin tocar nada el cuerpo lleva el mismo conjunto de IPs y ningún `confirmar_quitar`.
- **T69 · Respuesta tardía (navegador).** Demorar `/api/lavalle/estado` 3 s y cambiar a Depósito en el medio: no se pinta ningún lector de Lavalle y `estado.lectores` tiene solo IPs `192.168.88.x`.
- **T70 · Cámaras al cambiar de sede (navegador).** Con el visor HD del CH10 abierto, cambiar a Depósito: el `<video>` queda sin `src`, no hay `setInterval` de miniaturas activo y en los 3 minutos siguientes no hay pedidos a `/camaras`.
- **T71 · Feed por sede (navegador).** 300 marcas de `.78` y 5 de `.246`: al cambiar a Depósito se ven las 5 del Depósito.