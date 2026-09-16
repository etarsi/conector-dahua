# Plan de mejoras — Monitoreo Sebigus (revisión 15/09/2026)

Revisión del panel en producción. Performance sale de una revisión automática con
mediciones sobre una copia de la base real; seguridad / UX / operación las revisé
a mano sobre el código (la parte automática de esas dimensiones falló y se rehízo).
Nada de esto está aplicado todavía: es el menú para decidir qué hacer.

## 1) Arreglar ya — alto impacto, bajo/medio esfuerzo

### Seguridad (abre puertas físicas)
- **HTTPS en el panel** *(medio)*. Hoy entra por HTTP plano: al iniciar sesión, usuario
  y contraseña (incluida la del admin) viajan **en texto claro por la red**. Cualquiera
  con acceso a la LAN los ve. Servir con TLS (stdlib `ssl`, certificado propio; el panel
  viejo `panel_personas` ya tenía este patrón con `certs/`). Es lo primero para un sistema
  que abre puertas.
- **Límite de intentos de login** *(bajo)*. `/api/entrar` no tiene freno: se puede probar
  claves sin límite. Agregar retardo/bloqueo por IP y usuario tras N fallos. Cuidado extra:
  no reintentar contra los lectores, que sí bloquean la cuenta.

### UX / operación (problemas reales vistos hoy)
- **Avisar cuando la sede está en solo lectura** *(bajo)*. Hoy alguien dio de alta a
  "96430726" en las 5 puertas del Depósito y quedó en `pendiente` para siempre, en silencio,
  porque el Depósito tiene `escritura=false`. El panel debe mostrar un cartel "esta sede no
  aplica cambios (solo lectura)" al editar, y no dejar que parezca que se guardó.
- **Hacer visibles los pendientes y errores trabados** *(bajo)*. Ya hay una métrica, pero
  5 accesos quedaron pendientes sin que nadie lo note. Un aviso destacado + filtro rápido
  "mostrar pendientes/errores" para que el operador los resuelva.
- **Lector caído / stream rechazado** *(medio)*. El `.74` (Puerta Vidrio) está sano por HTTP
  pero **rechaza el stream de eventos** (probable: el SmartPSS de Libertadores ya tiene tomado
  el cupo de conexiones de eventos), y el panel reconecta en bucle. Las marcas igual entran por
  historial, pero: (a) bajar el ruido con más backoff cuando el rechazo es persistente; (b) que
  el panel marque "sin eventos en vivo" esa puerta en vez de solo loguear.

### Performance (crece sola con el tamaño de la base)
- **Índices que faltan en `eventos`** *(bajo)*. La atribución de marcas cada 30 min hace un
  UPDATE que escanea toda la partición de la sede (~282k filas): medido **83,7 ms → 1,1 ms por
  UPDATE (75×)** con `ix_evento_atrib ON eventos(lector, persona_id) WHERE pid IS NULL`. Y el
  filtro por puerta del historial necesita `ix_evento_sede_lector ON eventos(sede, lector, ts DESC)`.
  Van dentro de `_ESQUEMA` en `base.py` y se crean solos al reiniciar (sin migración).
- **Sacar los `COUNT(*)` del camino de cada fichada** *(bajo)*. `base.resumen()` calcula
  `eventos_total` (COUNT sobre toda la tabla) en **cada marca en vivo**, y ese campo ni siquiera
  se muestra en la UI. Quitarlo (o moverlo a `/estado`), y no difundir `resumen` si no hay nadie mirando.
- **Higiene de sesiones y vigilancia** *(bajo)*. Las sesiones vencidas no se limpian solas
  (fuga lenta con el proceso días arriba): un barrido periódico. Y bajar el timeout de la
  ronda de puertas de 15 s a ~6 s para que un lector colgado no frene el tablero.

## 2) Mejoras que valen la pena — esfuerzo medio

- **Backup automático de la base** *(medio)*. Hoy solo hay respaldos manuales (antes de migrar).
  La base es la fuente de verdad (94+67 personas, permisos, 433k eventos, 113 MB). Un respaldo
  programado (`Connection.backup()` diario a `data/respaldos/`, rotando los últimos N).
- **Retención de eventos + VACUUM** *(medio)*. La tabla suma marcas sin límite y todo lo demás
  se degrada con su tamaño. Archivar/borrar marcas más viejas que N meses, `wal_checkpoint(TRUNCATE)`
  y `PRAGMA optimize` periódicos. El índice único evita duplicados si se reimporta.
- **Worker: no releer lo que ya sabe** *(medio)*. `_procesar_lector` ya lee el padrón completo
  del equipo por vuelta, pero `crear/actualizar/quitar` vuelven a hacer `buscar_persona` (3
  round-trips RPC2 por tarea, con `sleep(0.3)`). Pasar el registro ya conocido y subir la
  paginación de 50 a ~200. **Sin tocar la regla de oro (no pisar a otra persona por nombre).**
- **Auditoría consultable** *(medio)*. Quién abrió cada puerta y quién dio de alta/baja hoy va
  al log de texto pero no se puede consultar desde el panel. Una vista de auditoría (o registrar
  esas acciones en una tabla) ayuda a investigar después.
- **Conexión SQLite por hilo** *(medio)*. `base.conectar()` abre conexión nueva + PRAGMAs +
  `create_function` en cada llamada (una por marca en vivo, una por difusión). Reusar una por
  hilo (`threading.local`).

## 3) Más adelante / opcional

- **Depósito: habilitar escritura** *(decisión + verificación)*. Hoy es solo lectura. Para
  activarlo faltan las verificaciones del diseño (baja de prueba en la Reja, usuario propio del
  panel en cada equipo en vez de compartir `admin` con SmartPSS). Es lo que desbloquea los
  pendientes trabados.
- **`RecordFinder` con rango de tiempo** *(alto — requiere equipo de prueba)*. El historial
  cada 30 min baja ~180k registros de los 11 lectores para quedarse con unas pocas marcas nuevas.
  Pasar `StartTime` a `startFind` lo haría incremental, pero algunos firmwares ignoran el filtro:
  probar en un equipo de prueba antes. Alternativa segura: mirar `getQuerySize` y releer solo si creció.
- **Grilla de cámaras en vivo (varias a la vez)** *(alto)*. Lo charlado: para muchas cámaras
  fluidas hace falta el gateway RTSP→WebRTC. Pendiente la prueba escalonada fuera de horario.
- **`AccessControl` en vivo para la Reja** *(medio)*. La Reja usa tarjeta y no emite `_DoorFace_`;
  sus marcas hoy entran solo por historial. Manejar `AccessControl` en el stream le daría en vivo.

## Nota de riesgo
Todo lo de la sección 1 es aditivo y de bajo riesgo (índices, quitar COUNT, avisos de UI,
límite de login). HTTPS y backup son medios pero seguros. Lo de la sección 3 toca equipos o
la transacción central: con cuidado y pruebas. Aplicar sobre producción implica reiniciar el
servicio (`Restart-Service monitoreo_sebigus`, como admin).

---

## Implementado (15/09/2026) — pendiente de activar con Restart-Service

Tanda de mejoras aplicadas al código y probadas offline. **Nada está vivo hasta reiniciar el
servicio** (`Restart-Service monitoreo_sebigus`, como admin). Los cambios de web se sirven del
disco, pero dependen de cambios del servidor, así que igual necesitan el reinicio.

- **Índices en `eventos`** (`ix_evento_atrib`, `ix_evento_sede_lector`): se crean solos al arrancar (75× la atribución).
- **`resumen()` sin `eventos_total`** (COUNT de toda la tabla, no se mostraba) y **no se difunde si no hay nadie mirando**.
- **Purga de sesiones vencidas** al crear una sesión; **vigilancia con timeout 6s**.
- **Límite de login**: 5 fallos por IP → bloqueo 5 min (ON por defecto).
- **Aviso de sede en solo lectura** en la UI (banner ámbar cuando `escritura=false`).
- **Backup automático diario** de la base a `data/respaldos/auto-*.sqlite3`, rotando `backups_conservar` (14) — ON por defecto.
- **Retención de eventos**: `retencion_meses` en config (0 = no borrar; poner p.ej. 12 para limpiar). `mantenimiento()` hace checkpoint+optimize.
- **HTTPS opcional**: cert autofirmado generado en `certs/`. Apagado por defecto (`https.enabled=false`). Al activarlo, el acceso pasa a `https://…:8090` (aviso de cert la primera vez) y la cookie suma `Secure`.

Config nueva: `backup_automatico`, `backups_conservar`, `retencion_meses`, `https.{enabled,cert,key}`.

---

## Implementado (15/09/2026, tanda 2) — pendiente de activar con Restart-Service

Unificación de las dos vistas (monitoreo + registro de asistencias) en un solo panel,
con permisos por **secciones + presets** y diseño **adaptable a móvil/tablet**. Todo
probado offline y con un servidor de prueba aislado (base temporal, sin tocar los
lectores). **Nada vivo hasta `Restart-Service monitoreo_sebigus` (como admin).**

- **Permisos por sección** (además del rol, que sigue mandando el nivel de escritura).
  Secciones: `en_vivo`, `puertas`, `asistencias`, `camaras`, `personas`, `usuarios`.
  Cada usuario ve solo las secciones habilitadas; el servidor gatea GET/POST por sección
  (no alcanza con ocultar el botón). Presets en el alta: **RRHH** (solo asistencias),
  **Portero** (solo puertas), Operador, Supervisor, Admin. Columna `secciones` en
  `usuarios` (`[]` = las del rol; los usuarios viejos siguen igual).
- **Vista Asistencias** (la de RRHH): log de fichadas **con la foto que saca el lector
  al marcar** (evento `_NewFile_`). Filtros por texto, puerta, fecha y solo-rechazos;
  la foto se abre en grande (lightbox). Reemplaza y amplía el viejo "Historial".
- **Foto de captura**: al llegar un `_NewFile_`, un hilo aparte baja el JPEG del equipo
  (`RPC_Loadfile`, con caché del endpoint) y lo asocia a la marca por `(sede, lector,
  user_id, ts)`. Se guarda **en disco** (`data/capturas/AAAA-MM-DD/…`, no en la base) y
  se purga sola por `capturas_dias` (60). Nueva columna `eventos.foto` (ruta relativa),
  migración por `ALTER` (probada sobre copia de la base real, 433k eventos, sin pérdida).
- **Vista Puertas = control remoto**: tarjetas grandes con botón "Abrir", pensadas para
  el portero en el celular. Cada uno solo ve el botón en las puertas que tiene asignadas.
- **Responsive**: en móvil/tablet (≤900px) el menú lateral pasa a ser un cajón que se
  abre con un botón; el contenido va a pantalla completa. Grillas a una columna.

Config nueva: `guardar_fotos` (true), `capturas_dias` (60).

Pendiente de confirmar en producción: que `RPC_Loadfile` baje la foto del `_NewFile_`
en estos equipos (no se pudo probar sin una marca real; el descargador ya reintenta
endpoints y cachea el que ande). Se confirma con la primera fichada real tras reiniciar.
