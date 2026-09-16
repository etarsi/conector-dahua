# Migración a dos sedes — procedimiento

El panel v2 (dos sedes: Lavalle + Depósito) ya está en el código y verificado
offline. Falta un único paso que **corta Lavalle unos minutos**: la migración de
la base. Por eso se hace fuera de horario.

Todo el código v2 se probó sin tocar los equipos: identidad, esquema, migración
(sobre una copia real), el importador y el worker (17/17 casos de identidad), la
API por sede (13/13) y la UI. La escritura contra los lectores está verificada
contra los equipos reales con un usuario de prueba inofensivo.

## Antes de migrar

1. Que nadie esté usando el panel viejo.
2. Confirmar que `config.json` tiene la sección `sedes` y `sede_v1: "lavalle"`
   (ya quedó así). Las claves de los equipos, del panel y del NVR ya están puestas.

## Migrar

```bash
cd "monitoreo Sebigus"
# 1) parar el panel viejo (tarea programada, servicio, o el proceso python)
# 2) arrancar el panel v2:
python servidor.py
```

Al arrancar, `servidor.py`:

- toma el candado de instancia única (no arranca si ya hay otro panel en el puerto);
- detecta que la base es v1 y **migra**: renombra `personas`/`accesos`/`perfiles`
  a `*_v1` (se conservan), crea el esquema v2, marca todos los eventos como sede
  `lavalle`, y **hace un respaldo automático** en `data/respaldos/monitoreo-v1-*.sqlite3`
  (con `integrity_check`); si algo falla, no arranca y no toca la base;
- deja las dos sedes "sin padrón" y corre una **primera importación** de cada una
  (solo lectura de los equipos): reconstruye personas y accesos desde lo que
  tienen cargado los lectores.

La migración de la base tarda ~1s. La primera importación del Depósito lee los 5
equipos; la de Lavalle, los 7. El historial (277k+ eventos) se conserva intacto.

## Después de migrar

1. Abrir el panel, entrar, y revisar cada sede:
   - **Lavalle**: 92 personas, todas al día.
   - **Depósito**: ~66 personas. Revisar "Duplicados": ahí aparecen los nombres
     repetidos (los 6 "Daniel Sitzer", etc.) y los 5 tipeos, para unir a mano con
     el botón correspondiente. Unir NO escribe en los equipos.
2. El Depósito arranca en **solo lectura** (`escritura: false` en config.json).
   Cuando quieras habilitar altas/bajas desde el panel en el Depósito, poné
   `escritura: true` en la sede `deposito` y reiniciá. La Reja (.246) además
   arranca con `eventos_en_vivo` e `historial` en false hasta verificarla.

## Volver atrás

Si algo sale mal:

```bash
# 1) parar el panel v2 y matar go2rtc.exe
# 2) borrar el WAL:
del data\monitoreo.sqlite3-wal data\monitoreo.sqlite3-shm
# 3) restaurar el respaldo:
copy data\respaldos\monitoreo-v1-AAAAMMDD-HHMMSS.sqlite3 data\monitoreo.sqlite3
# 4) volver el código a v1 (el zip data/respaldos/codigo-v1-*.zip)
# 5) arrancar el panel viejo y correr "Importar padrón" para reconciliar
```

Verificado: después de correr v2 y restaurar el respaldo, la base v1 vuelve a
abrir con su estructura original.

## Verificaciones que quedan pendientes en los equipos (punto 12 del diseño)

Antes de habilitar `escritura: true` en el Depósito conviene, con el usuario de
prueba vencido y sin puertas del 11/09:

- confirmar que en `.78` (73 usuarios, pagina) `padron()` da la misma cantidad
  que el CGI;
- una baja de prueba en la Reja `.246` (fw 2021) borra tarjeta y cara;
- crear un usuario propio del panel en cada equipo del Depósito, en vez de usar
  `admin` (que también usa SmartPSS), para no arriesgar la cuenta.
