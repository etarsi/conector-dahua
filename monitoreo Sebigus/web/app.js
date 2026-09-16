/* Monitoreo Sebigus — panel de dos sedes.
   Sin frameworks: abre rapido en cualquier PC y se queda dias abierto.

   Todo lo de datos cuelga de la SEDE activa (/api/<sede>/...). Al cambiar de
   sede sube `generacion`: las respuestas que llegan tarde de la sede anterior
   se descartan, asi una demora no pinta datos de la sede equivocada. */

const $  = (sel, raiz = document) => raiz.querySelector(sel);
const $$ = (sel, raiz = document) => [...raiz.querySelectorAll(sel)];

const estado = {
  sede: null,          // clave de la sede activa
  sedes: [],           // [{clave, nombre, ids, tiene_nvr, lectores}]
  generacion: 0,       // sube al cambiar de sede
  lectores: [],
  perfiles: [],
  personas: [],
  marcas: {},          // sede -> [marcas] (buffer por sede)
  camaras: [],
  gateway: { vivo: false },
  editando: null,
  fotoNueva: null,
  fuente: null,
  secciones: [],       // secciones habilitadas para este usuario
};
const TOPE_FEED = 200;

// Secciones de la app (mismas claves que base.py) y presets para el alta de
// usuarios. El rol sigue mandando el nivel de escritura; las secciones deciden
// qué ve cada uno (un RRHH solo asistencias, un portero solo puertas).
const SECCIONES = [
  { id: "en_vivo", texto: "En vivo" },
  { id: "puertas", texto: "Puertas (abrir)" },
  { id: "asistencias", texto: "Asistencias (log)" },
  { id: "registro", texto: "Registrar asistencia" },
  { id: "camaras", texto: "Cámaras" },
  { id: "personas", texto: "Personas (accesos)" },
  { id: "usuarios", texto: "Usuarios" },
];
const PRESETS = {
  "RRHH": ["asistencias", "registro"],
  "Portero": ["puertas"],
  "Operador": ["en_vivo", "camaras"],
  "Supervisor": ["en_vivo", "puertas", "asistencias", "registro", "camaras", "personas"],
  "Admin": ["en_vivo", "puertas", "asistencias", "registro", "camaras", "personas", "usuarios"],
};
const tiene = (sec) => estado.secciones.includes(sec);

const sedeActual = () => estado.sedes.find((s) => s.clave === estado.sede) || {};
const esCompartidos = () => sedeActual().ids === "compartidos";

// ---------------------------------------------------------------- red
async function api(ruta, opciones = {}) {
  const r = await fetch(ruta, { headers: { "Content-Type": "application/json" }, ...opciones });
  if (r.status === 401) { mostrarLogin(); throw new Error("sesion vencida"); }
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(datos.error || `error ${r.status}`);
  return datos;
}
const apiSede = (ruta, opciones) => api(`/api/${estado.sede}${ruta}`, opciones);

function avisar(texto, clase = "") {
  const nodo = document.createElement("div");
  nodo.className = `aviso ${clase}`;
  nodo.textContent = texto;
  $("#avisos").append(nodo);
  setTimeout(() => { nodo.style.opacity = "0"; setTimeout(() => nodo.remove(), 300); }, 4200);
}

// Cartel de confirmacion centrado, con el estilo del panel. Reemplaza al
// confirm() del navegador (que aparece descolgado y sin estilo). Devuelve una
// promesa que resuelve true/false. Enter confirma, Escape / fondo cancelan.
function confirmar(texto, { titulo = "Confirmar", ok = "Confirmar", cancelar = "Cancelar",
                            peligro = false } = {}) {
  return new Promise((resolver) => {
    const fondo = document.createElement("div");
    fondo.className = "modal";
    fondo.innerHTML = `
      <div class="modal-caja" role="dialog" aria-modal="true">
        <h3><span class="modal-icono ${peligro ? "peligro" : ""}"></span>${escapar(titulo)}</h3>
        <p>${escapar(texto)}</p>
        <div class="modal-pie">
          <button class="boton" data-no>${escapar(cancelar)}</button>
          <button class="boton ${peligro ? "peligro" : "primario"}" data-si>${escapar(ok)}</button>
        </div>
      </div>`;
    const cerrar = (valor) => {
      document.removeEventListener("keydown", tecla);
      fondo.remove();
      resolver(valor);
    };
    const tecla = (e) => {
      if (e.key === "Escape") cerrar(false);
      if (e.key === "Enter") cerrar(true);
    };
    fondo.addEventListener("click", (e) => {
      if (e.target === fondo) cerrar(false);           // clic en el fondo = cancelar
      if (e.target.closest("[data-no]")) cerrar(false);
      if (e.target.closest("[data-si]")) cerrar(true);
    });
    document.addEventListener("keydown", tecla);
    document.body.append(fondo);
    fondo.querySelector("[data-si]").focus();
  });
}

const escapar = (t) => String(t ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const iniciales = (n) => (n || "?").trim().split(/\s+/).slice(0, 2).map((p) => p[0]).join("").toUpperCase() || "?";

// ---------------------------------------------------------------- entrada
function mostrarLogin() {
  $("#login").classList.remove("oculto");
  $("#panel").classList.add("oculto");
  if (estado.fuente) { estado.fuente.close(); estado.fuente = null; }
}

// Jerarquia de roles (igual que en base.py). puede("supervisor") = "soy sup o admin".
const ROLES = { operador: 1, supervisor: 2, admin: 3 };
const puede = (min) => (ROLES[estado.rol] || 0) >= (ROLES[min] || 99);

// Puede abrir esa puerta: supervisor/admin (todas) u operador con esa puerta asignada.
const puedeAbrir = (ip) => puede("supervisor") || (estado.puertasAbrir || []).includes(ip);

async function arrancar() {
  const s = await fetch("/api/sesion").then((r) => r.json());
  if (s.abierta) {
    estado.usuario = s.usuario; estado.rol = s.rol; estado.nombre = s.nombre;
    estado.puertasAbrir = s.puertas || [];
    estado.secciones = s.secciones || [];
    entrarAlPanel();
  } else mostrarLogin();
}

$("#form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#login-error").textContent = "";
  try {
    const r = await api("/api/entrar", { method: "POST",
      body: JSON.stringify({ usuario: $("#usuario").value.trim(), clave: $("#clave").value }) });
    estado.usuario = r.usuario; estado.rol = r.rol; estado.nombre = r.nombre;
    estado.puertasAbrir = r.puertas || [];
    estado.secciones = r.secciones || [];
    $("#clave").value = "";
    entrarAlPanel();
  } catch (e) { $("#login-error").textContent = e.message; }
});

$("#salir").addEventListener("click", async () => {
  await api("/api/salir", { method: "POST" }).catch(() => {});
  mostrarLogin();
});

function aplicarRol() {
  // Marca el rol y las secciones en el body: el CSS oculta las acciones que no
  // corresponden (operador no edita; sin sección "personas" no ve ese botón…).
  document.body.dataset.rol = estado.rol || "";
  SECCIONES.forEach((s) => document.body.classList.toggle(`sec-${s.id}`, tiene(s.id)));
  const chip = `<span class="rol-chip ${estado.rol}">${estado.rol || ""}</span>`;
  $("#usuario-actual").innerHTML =
    `<b>${escapar(estado.nombre || estado.usuario || "")}</b> ${chip}`;
  // Cada ítem del menú se muestra si el usuario tiene esa sección (data-seccion)
  // y alcanza el rol mínimo pedido (data-rol: Ajustes=supervisor, Usuarios=admin).
  $$(".nav-item").forEach((b) => {
    const okSec = !b.dataset.seccion || tiene(b.dataset.seccion);
    const okRol = !b.dataset.rol || puede(b.dataset.rol);
    b.hidden = !(okSec && okRol);
  });
}

// Primera vista visible según las secciones del usuario (para no caer en una
// vista oculta al entrar: p.ej. un RRHH arranca directo en Asistencias).
function primeraVista() {
  const visible = $$(".nav-item").find((b) => !b.hidden);
  return visible ? visible.dataset.vista : "monitoreo";
}

async function entrarAlPanel() {
  $("#login").classList.add("oculto");
  $("#panel").classList.remove("oculto");
  aplicarRol();
  estado.sedes = await api("/api/sedes");
  let guardada = null;
  try { guardada = localStorage.getItem("sede"); } catch (e) {}
  estado.sede = estado.sedes.some((s) => s.clave === guardada) ? guardada
                : (estado.sedes[0] && estado.sedes[0].clave);
  pintarSelectorSede();
  conectarStream();
  await cambiarSede(estado.sede, true);
  irA(primeraVista());
}

// ---------------------------------------------------------------- selector de sede
function pintarSelectorSede() {
  const cont = $("#selector-sede");
  if (estado.sedes.length <= 1) { cont.innerHTML = ""; return; }
  cont.innerHTML = estado.sedes.map((s) =>
    `<button class="sede-btn ${s.clave === estado.sede ? "activa" : ""}" data-sede="${escapar(s.clave)}">
       ${escapar(s.nombre)}</button>`).join("");
}

$("#selector-sede").addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-sede]");
  if (b && b.dataset.sede !== estado.sede) cambiarSede(b.dataset.sede);
});

async function cambiarSede(sede, inicial = false) {
  estado.sede = sede;
  estado.generacion++;
  try { localStorage.setItem("sede", sede); } catch (e) {}
  // limpiar todo lo de la sede anterior
  cerrarCajon(); estado.editando = null;
  cerrarVisor(); pararMosaico(); estado.camaras = [];
  pintarSelectorSede();
  // Cámaras: solo si la sede tiene NVR y el usuario tiene esa sección.
  const conNvr = sedeActual().tiene_nvr;
  $('.nav-item[data-vista="camaras"]').hidden = !(conNvr && tiene("camaras"));
  if (!conNvr && vistaActiva() === "camaras") irA(primeraVista());
  // aviso de sede en solo lectura: lo que se cargue no se envía a las puertas
  const banner = $("#banner-solo-lectura");
  if (banner) banner.hidden = !sedeActual().solo_lectura;
  await refrescarEstado();
  if (tiene("personas")) await cargarPersonas();
  pintarFeed();
  if (vistaActiva() === "asistencias") cargarAsistencias();
  if (vistaActiva() === "historial") cargarHistorial();
  if (vistaActiva() === "camaras") cargarCamaras();
}

// ---------------------------------------------------------------- navegación
const vistaActiva = () => ($(".vista.activa") || {}).id?.replace("vista-", "");
function irA(vista) {
  // No entrar a una vista cuya sección no tiene (por si se invoca a mano).
  const item = $(`.nav-item[data-vista="${vista}"]`);
  if (item && item.hidden) vista = primeraVista();
  $$(".nav-item").forEach((b) => b.classList.toggle("activo", b.dataset.vista === vista));
  $$(".vista").forEach((v) => v.classList.toggle("activa", v.id === `vista-${vista}`));
  cerrarMenu();
  if (vista === "personas") cargarPersonas();
  if (vista === "asistencias") cargarAsistencias();
  autoRefrescoAsistencias(vista === "asistencias");
  if (vista === "historial") cargarHistorial();
  if (vista === "registro") {
    // El registro reusa el panel de personas (backend probado), embebido. Vive en
    // el :80 del mismo server. Se carga una sola vez, al entrar.
    const fr = $("#registro-frame");
    if (fr && !fr.getAttribute("src")) fr.src = `http://${location.hostname}/`;
  }
  if (vista === "puertas") pintarRemoto();
  if (vista === "usuarios") cargarUsuarios();
  if (vista === "camaras") cargarCamaras(); else pararMosaico();
}
$$(".nav-item").forEach((b) => b.addEventListener("click", () => irA(b.dataset.vista)));

// ---- menú lateral en móvil/tablet ----
const abrirMenu = () => { document.body.classList.add("menu-abierto"); };
const cerrarMenu = () => { document.body.classList.remove("menu-abierto"); };
$("#menu-boton")?.addEventListener("click", abrirMenu);
$("#lateral-fondo")?.addEventListener("click", cerrarMenu);

// ---------------------------------------------------------------- estado general
async function refrescarEstado() {
  const gen = estado.generacion;
  const datos = await apiSede("/estado");
  if (gen !== estado.generacion) return;    // llego tarde: cambio la sede
  estado.lectores = datos.lectores;
  estado.perfiles = datos.perfiles;
  pintarMetricas(datos.resumen);
  pintarPuertas();
  pintarRemoto();
  pintarPerfilChips();
  pintarPerfiles();
}

function pintarMetricas(r) {
  $("#metricas").innerHTML = `
    <div class="metrica"><b>${r.personas}</b><span>personas</span></div>
    <div class="metrica"><b>${r.eventos_hoy}</b><span>marcas hoy</span></div>
    <div class="metrica ${r.rechazos_hoy ? "ojo" : ""}"><b>${r.rechazos_hoy}</b><span>rechazos hoy</span></div>
    <div class="metrica ${r.pendientes ? "ojo" : ""}"><b>${r.pendientes}</b><span>a sincronizar</span></div>
    ${r.con_error ? `<div class="metrica malo"><b>${r.con_error}</b><span>con error</span></div>` : ""}
    ${r.bajas_incompletas ? `<div class="metrica malo"><b>${r.bajas_incompletas}</b><span>bajas a medias</span></div>` : ""}`;
}

function pintarPuertas() {
  $("#grilla-puertas").innerHTML = estado.lectores.map((l) => {
    const abierta = (l.puerta || "").toLowerCase().includes("open");
    const clase = !l.credenciales_ok ? "muerta" : l.en_linea ? (abierta ? "viva abierta" : "viva") : "muerta";
    const pastilla = !l.credenciales_ok
      ? '<span class="estado-puerta offline">clave rechazada</span>'
      : !l.en_linea ? '<span class="estado-puerta offline">sin conexión</span>'
      : `<span class="estado-puerta ${abierta ? "abierta" : ""}">${abierta ? "abierta" : "cerrada"}</span>`;
    const boton = puedeAbrir(l.ip)
      ? `<button class="abrir" data-abrir="${escapar(l.ip)}" ${l.en_linea ? "" : "disabled"}>Abrir</button>`
      : "";
    return `<div class="puerta ${clase}">
      <h4>${escapar(l.nombre)}</h4>
      <div class="sector">${escapar(l.sector || "")}</div>
      <div class="ip">${escapar(l.ip)}</div>
      <div class="puerta-pie">${pastilla}${boton}</div></div>`;
  }).join("");
}

// Vista Puertas: control remoto con botones grandes (sirve para el portero en el
// celular y para el supervisor en la PC). Cada puerta muestra su estado y, si el
// usuario puede abrirla, un botón grande.
function pintarRemoto() {
  const cont = $("#grilla-remoto");
  if (!cont) return;
  if (!estado.lectores.length) {
    cont.innerHTML = '<p class="vacio">No hay puertas en esta sede.</p>';
    return;
  }
  cont.innerHTML = estado.lectores.map((l) => {
    const abierta = (l.puerta || "").toLowerCase().includes("open");
    const sana = l.credenciales_ok && l.en_linea;
    const clase = !sana ? "caida" : abierta ? "abierta" : "ok";
    const estadoTxt = !l.credenciales_ok ? "clave rechazada"
      : !l.en_linea ? "sin conexión" : abierta ? "abierta" : "cerrada";
    const puedo = puedeAbrir(l.ip);
    let accion;
    if (!l.credenciales_ok && puede("supervisor")) {
      accion = `<button class="remoto-btn secundario" data-cred="${escapar(l.ip)}">Reintentar clave</button>`;
    } else if (puedo) {
      accion = `<button class="remoto-btn" data-abrir="${escapar(l.ip)}" ${sana ? "" : "disabled"}>
        <svg viewBox="0 0 24 24"><path d="M7 11V7a5 5 0 0 1 9.9-1M5 11h14v10H5z"/></svg>
        Abrir</button>`;
    } else {
      accion = '<span class="remoto-nota">Sin permiso para abrir</span>';
    }
    return `<div class="remoto-card ${clase}">
      <div class="remoto-cab">
        <h3>${escapar(l.nombre)}</h3>
        <span class="estado-puerta ${abierta ? "abierta" : sana ? "" : "offline"}">${estadoTxt}</span>
      </div>
      <div class="remoto-sector">${escapar(l.sector || l.ip)}</div>
      ${accion}
    </div>`;
  }).join("");
}

document.addEventListener("click", async (ev) => {
  const abrir = ev.target.closest("[data-abrir]");
  if (abrir) {
    const ip = abrir.dataset.abrir;
    const l = estado.lectores.find((x) => x.ip === ip);
    if (!await confirmar(`Es una puerta real: se destraba ahora.`,
        { titulo: `¿Abrir "${l?.nombre || ip}"?`, ok: "Abrir puerta" })) return;
    abrir.disabled = true;
    try { await apiSede("/abrir", { method: "POST", body: JSON.stringify({ lector: ip }) });
      avisar(`Puerta "${l?.nombre || ip}" abierta`, "ok"); }
    catch (e) { avisar(`No se pudo abrir: ${e.message}`, "mal"); }
    finally { abrir.disabled = false; }
    return;
  }
  const cred = ev.target.closest("[data-cred]");
  if (cred) {
    await apiSede("/reintentar_credenciales", { method: "POST", body: JSON.stringify({ lector: cred.dataset.cred }) }).catch(() => {});
    avisar("Reintentando credenciales…"); refrescarEstado();
  }
});

// ---------------------------------------------------------------- eventos en vivo (SSE)
function conectarStream() {
  if (estado.fuente) estado.fuente.close();
  const fuente = new EventSource("/api/stream");
  estado.fuente = fuente;
  fuente.onopen = () => { $("#conexion").className = "conexion viva";
    $("#conexion").innerHTML = '<span class="latido"></span> en vivo'; };
  fuente.onerror = () => { $("#conexion").className = "conexion caida";
    $("#conexion").innerHTML = '<span class="latido"></span> reconectando…'; };
  fuente.onmessage = (msg) => {
    let p; try { p = JSON.parse(msg.data); } catch { return; }
    const suSede = p.sede;
    if (p.tipo === "evento") {
      (estado.marcas[suSede] = estado.marcas[suSede] || []).unshift(p.datos);
      if (estado.marcas[suSede].length > TOPE_FEED) estado.marcas[suSede].length = TOPE_FEED;
      if (suSede === estado.sede) { pintarFeed(); if (vistaActiva() === "asistencias") programarAsis(); }
    } else if (suSede === estado.sede && p.tipo === "estado") {
      estado.lectores = p.datos; pintarPuertas(); pintarRemoto();
    } else if (suSede === estado.sede && p.tipo === "resumen") {
      pintarMetricas(p.datos);
    } else if (suSede === estado.sede && p.tipo === "apertura") {
      avisar(`Apertura remota: ${p.datos.lector}`);
    } else if (suSede === estado.sede && p.tipo === "foto") {
      // llegó la foto de una fichada: si estoy mirando Asistencias, refresco
      if (vistaActiva() === "asistencias") programarAsis();
    }
  };
}

function pintarFeed() {
  const lista0 = estado.marcas[estado.sede] || [];
  const lista = $("#solo-rechazos").checked ? lista0.filter((m) => !m.concedido) : lista0;
  $("#contador-feed").textContent = lista.length;
  $("#feed").innerHTML = lista.length
    ? lista.map(filaMarca).join("")
    : '<p class="vacio">Esperando movimiento en las puertas…</p>';
}
function filaMarca(m) {
  const hora = (m.momento || "").split(" ")[1] || "";
  const quien = m.nombre || (m.id ? `ID ${m.id} sin identificar` : "Desconocido");
  return `<div class="marca-item ${m.concedido ? "si" : "no"}">
    <div class="avatar">${escapar(iniciales(m.nombre))}</div>
    <div class="marca-datos"><b>${escapar(quien)}</b>
      <span>${escapar(m.lector || "")} · ${escapar(m.metodo || "")}</span></div>
    <div class="marca-hora">${escapar(hora)}<em>${m.concedido ? "" : escapar(m.motivo || "rechazado")}</em></div>
  </div>`;
}
$("#solo-rechazos").addEventListener("change", pintarFeed);

// ---------------------------------------------------------------- personas
async function cargarPersonas() {
  const gen = estado.generacion;
  const params = new URLSearchParams();
  if ($("#buscar").value) params.set("q", $("#buscar").value);
  if ($("#filtro-lector").value) params.set("lector", $("#filtro-lector").value);
  if ($("#filtro-activos").checked) params.set("activos", "1");
  const datos = await apiSede(`/personas?${params}`);
  if (gen !== estado.generacion) return;
  estado.personas = datos;
  $("#contador-personas").textContent = `${datos.length} personas`;
  pintarPersonas();
  pintarFiltroLector();
}

function pintarFiltroLector() {
  const val = $("#filtro-lector").value;
  const ops = estado.lectores.map((l) => `<option value="${escapar(l.ip)}">${escapar(l.nombre)}</option>`).join("");
  $("#filtro-lector").innerHTML = `<option value="">Todas las puertas</option>${ops}`;
  $("#filtro-lector").value = val;
}

function pintarPersonas() {
  if (!estado.personas.length) {
    $("#tabla-personas").innerHTML =
      '<tbody><tr><td><p class="vacio">No hay personas. Andá a Ajustes → "Importar padrón de los lectores".</p></td></tr></tbody>';
    return;
  }
  const comp = esCompartidos();
  $("#tabla-personas").innerHTML = `
    <thead><tr><th>Nombre</th>${comp ? "<th>ID</th>" : ""}<th>Documento</th><th>Sector</th>
      <th>Puertas</th><th>Sincronización</th></tr></thead>
    <tbody>${estado.personas.map((p) => `
      <tr class="clic ${p.activo ? "" : "baja"}" data-pid="${p.pid}">
        <td><b>${escapar(p.nombre)}</b>${p.admin ? ' <span class="etiqueta">admin</span>' : ""}${
          p.activo ? "" : (p.baja_incompleta ? ' <span class="etiqueta error">baja a medias</span>' : ' <span class="etiqueta">baja</span>')}</td>
        ${comp ? `<td class="num">${escapar(p.id_preferido || "—")}</td>` : ""}
        <td class="num">${escapar(p.documento || "—")}</td><td>${escapar(p.sector || "—")}</td>
        <td><span class="pastilla">${p.puertas}</span></td>
        <td>${p.con_error ? `<span class="etiqueta error">${p.con_error} en conflicto</span>`
          : p.sin_sincronizar ? `<span class="etiqueta pendiente">${p.sin_sincronizar} pendiente(s)</span>`
          : '<span class="etiqueta ok">al día</span>'}</td>
      </tr>`).join("")}</tbody>`;
}

$("#tabla-personas").addEventListener("click", (ev) => {
  const f = ev.target.closest("[data-pid]");
  if (f) abrirFicha(Number(f.dataset.pid));
});
let temporizador;
$("#buscar").addEventListener("input", () => { clearTimeout(temporizador); temporizador = setTimeout(cargarPersonas, 250); });
$("#filtro-lector").addEventListener("change", cargarPersonas);
$("#filtro-activos").addEventListener("change", cargarPersonas);

// ---------------------------------------------------------------- ficha
function pintarPerfilChips() {
  $("#p-perfil").innerHTML = '<option value="">— elegir puertas a mano —</option>' +
    estado.perfiles.map((p) => `<option value="${escapar(p.nombre)}">${escapar(p.nombre)}</option>`).join("");
  $("#perfil-lectores").innerHTML = estado.lectores.map((l) =>
    `<label class="chip"><input type="checkbox" value="${escapar(l.ip)}">${escapar(l.nombre)}</label>`).join("");
}

$("#p-perfil").addEventListener("change", () => {
  const perfil = estado.perfiles.find((p) => p.nombre === $("#p-perfil").value);
  if (perfil) $$("#p-lectores input").forEach((c) => { c.checked = perfil.lectores.includes(c.value); });
});

function casillasFicha(accesosPorIp) {
  // Arma las puertas desde la sede activa, mostrando el estado por puerta.
  return estado.lectores.map((l) => {
    const a = accesosPorIp[l.ip];
    let detalle = "sin cargar", botones = "";
    if (a) {
      const idtxt = a.user_id ? `ID ${a.user_id}${a.confirmado ? "" : " (reservado)"}` : "sin cargar";
      const est = a.estado === "ok" ? "al día" : a.estado === "error" ? "conflicto"
                : a.estado === "pendiente" ? "pendiente" : "—";
      detalle = `${idtxt} · ${est}`;
      if (a.error) detalle += ` — ${escapar(a.error)}`;
      else if (a.aviso) detalle += ` — ${escapar(a.aviso)}`;
      if (a.estado === "error") {
        botones = `<div class="acc-botones">
          <button class="mini" data-acc="reintentar" data-ip="${escapar(l.ip)}">Reintentar</button>
          <button class="mini" data-acc="crear_nuevo" data-ip="${escapar(l.ip)}">Crear registro nuevo</button>
          ${a.nombre_en_lector ? `<button class="mini" data-acc="adoptar_nombre" data-ip="${escapar(l.ip)}" data-nom="${escapar(a.nombre_en_lector)}">Es la misma persona</button>` : ""}
          <button class="mini" data-acc="desvincular" data-ip="${escapar(l.ip)}">Es otra persona</button>
          ${a.permitido ? "" : `<button class="mini" data-acc="sacar" data-ip="${escapar(l.ip)}">Sacar</button>`}
        </div>`;
      }
    }
    return `<label class="puerta-check"><input type="checkbox" value="${escapar(l.ip)}">
      <div><b>${escapar(l.nombre)}</b><span class="acc-detalle">${detalle}</span>${botones}</div></label>`;
  }).join("");
}

async function abrirFicha(pid) {
  const gen = estado.generacion;
  const p = await apiSede(`/personas/${pid}`);
  if (gen !== estado.generacion) return;
  estado.editando = p; estado.fotoNueva = null;
  $("#cajon-titulo").textContent = p.nombre;
  $("#p-nombre").value = p.nombre || "";
  $("#p-documento").value = p.documento || "";
  $("#p-sector").value = p.sector || "";
  $("#p-notas").value = p.notas || "";
  $("#p-perfil").value = p.perfil || "";
  $("#p-activo").checked = !!p.activo;
  configIdFicha(p.id_preferido || "");
  const accesosPorIp = {}; (p.accesos || []).forEach((a) => { accesosPorIp[a.lector] = a; });
  $("#p-lectores").innerHTML = casillasFicha(accesosPorIp);
  (p.accesos || []).forEach((a) => {
    if (a.permitido) { const c = $(`#p-lectores input[value="${a.lector}"]`); if (c) c.checked = true; }
  });
  $("#foto-vista").innerHTML = p.tiene_foto
    ? `<img src="/api/${estado.sede}/personas/${pid}/foto?t=${Date.now()}" alt="">` : "<span>Sin foto</span>";
  $("#btn-baja").classList.toggle("oculto", !p.activo);
  $("#error-persona").textContent = "";
  $("#cajon").classList.remove("oculto");
}

function configIdFicha(valor) {
  const comp = esCompartidos();
  $("#fila-id").hidden = !comp;
  $("#p-id").value = valor;
  $("#p-id").disabled = !!estado.editando && !!valor && comp;  // no cambiar el ID de alguien ya cargado
}

$("#btn-nueva").addEventListener("click", () => {
  estado.editando = null; estado.fotoNueva = null;
  $("#cajon-titulo").textContent = "Nueva persona";
  $("#form-persona").reset();
  configIdFicha("");
  $("#p-id").disabled = false;
  $("#p-activo").checked = true;
  $("#p-lectores").innerHTML = casillasFicha({});
  $("#foto-vista").innerHTML = "<span>Sin foto</span>";
  $("#btn-baja").classList.add("oculto");
  $("#error-persona").textContent = "";
  $("#cajon").classList.remove("oculto");
});

const cerrarCajon = () => $("#cajon").classList.add("oculto");
$("#cajon-cerrar").addEventListener("click", cerrarCajon);
$("#btn-cancelar").addEventListener("click", cerrarCajon);
$(".cajon-fondo").addEventListener("click", cerrarCajon);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { cerrarCajon(); cerrarLightbox(); cerrarMenu(); }
});

// La foto se convierte a JPEG y se achica ACÁ (en el navegador) a lo que pide el
// lector: el server no tiene librerías de imagen. El equipo quiere un JPEG con una
// cara clara; se limita el lado mayor a 720px y se baja la calidad hasta pesar
// menos de ~140 KB.
$("#foto-archivo").addEventListener("change", (ev) => {
  const archivo = ev.target.files[0];
  if (!archivo) return;
  const fr = new FileReader();
  fr.onload = () => {
    const img = new Image();
    img.onload = () => {
      const MAX = 720;
      let { width: w, height: h } = img;
      if (Math.max(w, h) > MAX) {
        const k = MAX / Math.max(w, h);
        w = Math.round(w * k); h = Math.round(h * k);
      }
      const cv = document.createElement("canvas");
      cv.width = w; cv.height = h;
      cv.getContext("2d").drawImage(img, 0, 0, w, h);
      let jpeg, q = 0.92;
      do {
        jpeg = cv.toDataURL("image/jpeg", q);
        q -= 0.08;
      } while (jpeg.length > 140 * 1024 * 1.37 && q > 0.4);   // 1.37 ≈ overhead base64
      estado.fotoNueva = jpeg;
      $("#foto-vista").innerHTML = `<img src="${jpeg}" alt="">`;
    };
    img.onerror = () => avisar("No se pudo leer esa imagen", "mal");
    img.src = fr.result;
  };
  fr.readAsDataURL(archivo);
});

// botones de resolución de conflicto por puerta
$("#p-lectores").addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-acc]");
  if (!b || !estado.editando) return;
  ev.preventDefault();
  const cuerpo = b.dataset.nom ? { nombre: b.dataset.nom } : {};
  try {
    await apiSede(`/personas/${estado.editando.pid}/accesos/${b.dataset.ip}/${b.dataset.acc}`,
                  { method: "POST", body: JSON.stringify(cuerpo) });
    avisar("Listo, se está aplicando", "ok");
    abrirFicha(estado.editando.pid);
  } catch (e) { avisar(e.message, "mal"); }
});

$("#form-persona").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#error-persona").textContent = "";
  const cuerpo = {
    nombre: $("#p-nombre").value.trim(),
    documento: $("#p-documento").value.trim(),
    sector: $("#p-sector").value.trim(),
    perfil: $("#p-perfil").value,
    notas: $("#p-notas").value.trim(),
    activo: $("#p-activo").checked,
    lectores: $$("#p-lectores input[type=checkbox]:checked").map((c) => c.value),
  };
  if (esCompartidos()) cuerpo.id_preferido = $("#p-id").value.trim();
  if (estado.fotoNueva) cuerpo.foto = estado.fotoNueva;
  const url = estado.editando ? `/personas/${estado.editando.pid}` : "/personas";
  try {
    await apiSede(url, { method: "POST", body: JSON.stringify(cuerpo) });
    cerrarCajon();
    avisar(`${cuerpo.nombre} guardado — aplicando a ${cuerpo.lectores.length} puerta(s)`, "ok");
    cargarPersonas();
  } catch (e) { $("#error-persona").textContent = e.message; }
});

$("#btn-baja").addEventListener("click", async () => {
  const p = estado.editando;
  if (!p) return;
  if (!await confirmar("Se lo saca de todas las puertas.",
      { titulo: `¿Dar de baja a ${p.nombre}?`, ok: "Dar de baja", peligro: true })) return;
  await apiSede(`/personas/${p.pid}/baja`, { method: "POST", body: "{}" });
  cerrarCajon(); avisar(`${p.nombre} dado de baja`, "ok"); cargarPersonas();
});

// ---------------------------------------------------------------- duplicados
$("#btn-duplicados").addEventListener("click", async () => {
  const d = await apiSede("/duplicados");
  const grupos = [...(d.exactos || []), ...(d.tipeos || [])];
  if (!grupos.length) { avisar("No hay duplicados ni nombres parecidos", "ok"); $("#aviso-duplicados").innerHTML = ""; return; }
  $("#aviso-duplicados").innerHTML = `<div class="alerta-duplicados">
    <h4>${grupos.length} caso(s) de posible duplicado</h4>
    <p style="margin:0;color:var(--tenue)">Nombres iguales o casi iguales cargados por separado.
      ${esCompartidos() ? "Al dar de baja a uno, el otro sigue entrando." : "En el Depósito un ID distinto por puerta es normal; esto son nombres repetidos o tipeos."}</p>
    <ul>${grupos.map((g) => `<li>${g.map((p) => `<b>${escapar(p.nombre)}</b> (${p.puertas} p.)`).join(" · ")}</li>`).join("")}</ul></div>`;
});

// ---------------------------------------------------------------- asistencias
// Log de fichadas con la foto que saca el lector al marcar (la vista de RRHH).
let asisTimer = null;
const programarAsis = () => { clearTimeout(asisTimer); asisTimer = setTimeout(cargarAsistencias, 500); };

async function cargarAsistencias() {
  const gen = estado.generacion;
  const params = new URLSearchParams({ limite: "300" });
  if ($("#buscar-asis").value) params.set("q", $("#buscar-asis").value);
  if ($("#filtro-lector-asis").value) params.set("lector", $("#filtro-lector-asis").value);
  if ($("#filtro-tipo-asis") && $("#filtro-tipo-asis").value) params.set("tipo", $("#filtro-tipo-asis").value);
  if ($("#filtro-rechazos-asis").checked) params.set("rechazos", "1");
  const f = $("#filtro-fecha-asis").value;
  if (f) params.set("desde", Math.floor(new Date(`${f}T00:00:00`).getTime() / 1000));
  let marcas;
  try { marcas = await apiSede(`/asistencias?${params}`); }
  catch (e) { avisar(e.message, "mal"); return; }
  if (gen !== estado.generacion) return;
  // El filtro de fichador se arma con los fichadores de la sede (no las puertas).
  const val = $("#filtro-lector-asis").value;
  const fich = sedeActual().fichadores || [];
  const ops = fich.map((l) => `<option value="${escapar(l.ip)}">${escapar(l.nombre)}</option>`).join("");
  $("#filtro-lector-asis").innerHTML = `<option value="">Todos los fichadores</option>${ops}`;
  $("#filtro-lector-asis").value = val;
  $("#contador-asis").textContent = `${marcas.length} marca(s)`;
  $("#lista-asistencias").innerHTML = marcas.length
    ? marcas.map(tarjetaAsistencia).join("")
    : '<p class="vacio">No hay fichadas para ese filtro.</p>';
}

// Entrada/Salida: badge según la dirección que reporta el fichador.
function badgeTipo(t) {
  const v = (t || "").toLowerCase();
  if (v === "entry" || v === "entrada") return '<span class="etiqueta ok">entrada</span>';
  if (v === "exit" || v === "salida") return '<span class="etiqueta">salida</span>';
  return "";
}

function tarjetaAsistencia(e) {
  const partes = (e.momento || "").split(" ");
  const fecha = partes[0] || "", hora = partes[1] || "";
  const quien = e.nombre || (e.user_id ? `ID ${e.user_id}` : "Desconocido");
  const foto = e.tiene_foto
    ? `<img class="asis-foto" loading="lazy" data-foto src="/api/${estado.sede}/asistencias/${e.id}/foto" alt="Foto de la fichada">`
    : `<div class="asis-foto sin"><span>${escapar(iniciales(e.nombre))}</span></div>`;
  return `<div class="asis-card ${e.concedido ? "" : "no"}">
    ${foto}
    <div class="asis-datos">
      <b>${escapar(quien)}</b>
      <span class="asis-lector">${escapar(e.lector_nom || e.lector || "")}</span>
      <span class="asis-meta">${escapar(fecha)} · ${escapar(hora)}${e.metodo ? " · " + escapar(e.metodo) : ""}</span>
    </div>
    <div class="asis-resultado">
      ${badgeTipo(e.tipo)}
      ${e.concedido ? "" : `<span class="etiqueta error">${escapar(e.motivo || "rechazado")}</span>`}
    </div>
  </div>`;
}

$("#buscar-asis").addEventListener("input", () => { clearTimeout(temporizador); temporizador = setTimeout(cargarAsistencias, 250); });
$("#filtro-lector-asis").addEventListener("change", cargarAsistencias);
$("#filtro-tipo-asis").addEventListener("change", cargarAsistencias);
$("#filtro-rechazos-asis").addEventListener("change", cargarAsistencias);
$("#filtro-fecha-asis").addEventListener("change", cargarAsistencias);

// Ver la foto de una fichada en grande
$("#lista-asistencias").addEventListener("click", (ev) => {
  const img = ev.target.closest("[data-foto]");
  if (!img) return;
  const nombre = img.closest(".asis-card")?.querySelector("b")?.textContent || "";
  abrirLightbox(img.src, nombre);
});
function abrirLightbox(src, titulo) {
  const lb = $("#lightbox");
  lb.querySelector("img").src = src;
  lb.querySelector("figcaption").textContent = titulo || "";
  lb.classList.remove("oculto");
}
const cerrarLightbox = () => { $("#lightbox").classList.add("oculto"); $("#lightbox img").src = ""; };
$("#lightbox").addEventListener("click", (ev) => {
  if (ev.target.id === "lightbox" || ev.target.closest(".lightbox-cerrar")) cerrarLightbox();
});

$("#btn-traer-marcas").addEventListener("click", async (ev) => {
  ev.target.disabled = true; const t = ev.target.textContent; ev.target.textContent = "Trayendo…";
  try {
    const r = await apiSede("/asistencias/sincronizar", { method: "POST", body: "{}" });
    avisar(`${r.nuevas || 0} marca(s) nuevas`, "ok"); cargarAsistencias();
  } catch (e) { avisar(e.message, "mal"); }
  finally { ev.target.disabled = false; ev.target.textContent = t; }
});

// La asistencia entra por polling (no por SSE): refresco la vista sola mientras se mira.
let refrescoAsis = null;
function autoRefrescoAsistencias(on) {
  if (refrescoAsis) { clearInterval(refrescoAsis); refrescoAsis = null; }
  if (on) refrescoAsis = setInterval(() => { if (vistaActiva() === "asistencias") cargarAsistencias(); }, 60000);
}

// ---------------------------------------------------------------- historial de accesos (puertas, texto, SIN foto)
async function cargarHistorial() {
  const gen = estado.generacion;
  const params = new URLSearchParams({ limite: "300" });
  if ($("#buscar-hist").value) params.set("q", $("#buscar-hist").value);
  if ($("#filtro-lector-hist").value) params.set("lector", $("#filtro-lector-hist").value);
  if ($("#filtro-rechazos-hist").checked) params.set("rechazos", "1");
  const f = $("#filtro-fecha-hist").value;
  if (f) params.set("desde", Math.floor(new Date(`${f}T00:00:00`).getTime() / 1000));
  let ev;
  try { ev = await apiSede(`/eventos?${params}`); }
  catch (e) { avisar(e.message, "mal"); return; }
  if (gen !== estado.generacion) return;
  const val = $("#filtro-lector-hist").value;
  const ops = estado.lectores.map((l) => `<option value="${escapar(l.ip)}">${escapar(l.nombre)}</option>`).join("");
  $("#filtro-lector-hist").innerHTML = `<option value="">Todas las puertas</option>${ops}`;
  $("#filtro-lector-hist").value = val;
  $("#contador-hist").textContent = `${ev.length} marca(s)`;
  $("#tabla-historial").innerHTML = ev.length ? `
    <thead><tr><th>Cuándo</th><th>Persona</th><th>ID</th><th>Puerta</th><th>Método</th><th>Resultado</th></tr></thead>
    <tbody>${ev.map((e) => `<tr>
      <td class="num">${escapar(e.momento)}</td>
      <td>${escapar(e.nombre || "—")}</td><td class="num">${escapar(e.persona_id || "—")}</td>
      <td>${escapar(e.lector_nom || e.lector)}</td><td>${escapar(e.metodo || "—")}</td>
      <td>${e.concedido ? '<span class="etiqueta ok">acceso</span>'
        : `<span class="etiqueta error">${escapar(e.motivo || "rechazado")}</span>`}</td>
    </tr>`).join("")}</tbody>`
    : '<tbody><tr><td><p class="vacio">No hay marcas para ese filtro.</p></td></tr></tbody>';
}
$("#buscar-hist").addEventListener("input", () => { clearTimeout(temporizador); temporizador = setTimeout(cargarHistorial, 250); });
$("#filtro-lector-hist").addEventListener("change", cargarHistorial);
$("#filtro-rechazos-hist").addEventListener("change", cargarHistorial);
$("#filtro-fecha-hist").addEventListener("change", cargarHistorial);

// ---------------------------------------------------------------- perfiles
function pintarPerfiles() {
  $("#lista-perfiles").innerHTML = estado.perfiles.length
    ? estado.perfiles.map((p) => `<div class="perfil"><b>${escapar(p.nombre)}</b>
        <span>${p.lectores.length} puerta(s)</span><span class="crecer"></span>
        <button class="boton chico" data-borrar-perfil="${escapar(p.nombre)}">Borrar</button></div>`).join("")
    : '<p class="ayuda" style="margin:0">Todavía no hay perfiles.</p>';
}
$("#lista-perfiles").addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-borrar-perfil]");
  if (!b) return;
  const d = await apiSede(`/perfiles/${encodeURIComponent(b.dataset.borrarPerfil)}`, { method: "DELETE" });
  estado.perfiles = d.perfiles; pintarPerfiles(); pintarPerfilChips();
});
$("#btn-guardar-perfil").addEventListener("click", async () => {
  const nombre = $("#perfil-nombre").value.trim();
  if (!nombre) return avisar("Poné un nombre para el perfil", "mal");
  const lectores = $$("#perfil-lectores input:checked").map((c) => c.value);
  const d = await apiSede("/perfiles", { method: "POST", body: JSON.stringify({ nombre, lectores }) });
  estado.perfiles = d.perfiles;
  $("#perfil-nombre").value = ""; $$("#perfil-lectores input").forEach((c) => { c.checked = false; });
  pintarPerfiles(); pintarPerfilChips(); avisar(`Perfil "${nombre}" guardado`, "ok");
});

// ---------------------------------------------------------------- ajustes
async function tarea(boton, texto, fn) {
  boton.disabled = true; const original = boton.textContent; boton.textContent = texto;
  $("#salida-ajustes").textContent = "";
  try {
    const r = await fn();
    $("#salida-ajustes").textContent = JSON.stringify(r, null, 2);
    if (r.error) avisar(r.error, "mal"); else avisar("Listo", "ok");
    await refrescarEstado(); await cargarPersonas();
  } catch (e) { $("#salida-ajustes").textContent = e.message; avisar(e.message, "mal"); }
  finally { boton.disabled = false; boton.textContent = original; }
}
$("#btn-importar-personas").addEventListener("click", (ev) =>
  tarea(ev.target, "Leyendo los lectores…", () => apiSede("/importar/personas", { method: "POST", body: "{}" })));
$("#btn-importar-todo").addEventListener("click", async (ev) => {
  if (!await confirmar("Relee el historial completo de la sede. Tarda un rato.",
      { titulo: "Importar historial completo", ok: "Sí, importar" })) return;
  tarea(ev.target, "Importando…", () => apiSede("/importar/historial", { method: "POST", body: JSON.stringify({ completo: true }) }));
});
$("#btn-sincronizar").addEventListener("click", (ev) =>
  tarea(ev.target, "Sincronizando…", () => apiSede("/sincronizar", { method: "POST", body: "{}" })));

/* ---------------------------------------------------------------- camaras */
let relojMosaico = null;
let visorCanal = null;
let vueltaActual = 0;
let calidadVisor = "hd";
const camUrl = (canal, accion) => `/api/${estado.sede}/camaras/${canal}/${accion}`;

async function cargarCamaras() {
  if (!sedeActual().tiene_nvr) return;
  if (!estado.camaras.length) {
    const datos = await apiSede("/camaras");
    estado.camaras = datos.canales || [];
    estado.gateway = datos.gateway || { vivo: false };
    $("#sub-nvr").textContent = datos.nvr
      ? (datos.nvr.en_linea ? `${datos.nvr.nombre} · ${estado.camaras.length} cámaras`
         : `${datos.nvr.nombre} sin conexión`)
      : "Esta sede no tiene NVR";
    const pisos = [...new Set(estado.camaras.map((c) => c.piso))];
    $("#filtro-piso").innerHTML = '<option value="">Todos los pisos</option>' +
      pisos.map((p) => `<option value="${escapar(p)}">${escapar(p)}</option>`).join("");
  }
  pintarMosaico(); arrancarMosaico();
}
function camarasVisibles() {
  const piso = $("#filtro-piso").value;
  return piso ? estado.camaras.filter((c) => c.piso === piso) : estado.camaras;
}
function pintarMosaico() {
  const lista = camarasVisibles();
  if (!lista.length) { $("#mosaico").innerHTML = '<p class="vacio">No hay cámaras.</p>'; return; }
  let html = "", pisoActual = null;
  const agrupar = !$("#filtro-piso").value;
  for (const c of lista) {
    if (agrupar && c.piso !== pisoActual) { pisoActual = c.piso; html += `<h4 class="camara-piso">${escapar(pisoActual)}</h4>`; }
    html += `<div class="camara" data-canal="${c.canal}" title="${escapar(c.nombre)}">
      <img alt="${escapar(c.nombre)}" loading="lazy"><div class="sin-senal oculto">sin señal</div>
      <div class="rotulo"><b>${escapar(c.nombre)}</b><span class="canal">CH${c.canal}</span></div></div>`;
  }
  $("#mosaico").innerHTML = html;
}
// Snapshots de a UNO en fila; `vueltaActual` es un contador de generacion para
// que al reentrar no se apilen vueltas y tumben al NVR (paso por eso en desarrollo).
async function refrescarMiniaturas() {
  const mi = ++vueltaActual;
  for (const img of $$("#mosaico .camara img")) {
    if (mi !== vueltaActual || vistaActiva() !== "camaras") return;
    const t = img.closest(".camara");
    await new Promise((listo) => {
      let cerrado = false; const fin = () => { if (!cerrado) { cerrado = true; listo(); } };
      img.onload = () => { t.querySelector(".sin-senal")?.classList.add("oculto"); fin(); };
      img.onerror = () => { t.querySelector(".sin-senal")?.classList.remove("oculto"); fin(); };
      img.src = camUrl(t.dataset.canal, "foto") + `?t=${Date.now()}`;
      setTimeout(fin, 8000);
    });
  }
}
function arrancarMosaico() {
  pararMosaico(); refrescarMiniaturas();
  if ($("#mosaico-vivo").checked) relojMosaico = setInterval(refrescarMiniaturas, 90000);
}
function pararMosaico() {
  vueltaActual++;
  if (relojMosaico) { clearInterval(relojMosaico); relojMosaico = null; }
}
$("#mosaico-vivo").addEventListener("change", arrancarMosaico);
$("#filtro-piso").addEventListener("change", () => { pintarMosaico(); arrancarMosaico(); });
$("#mosaico").addEventListener("click", (ev) => {
  const t = ev.target.closest("[data-canal]");
  if (t) abrirVisor(Number(t.dataset.canal));
});
function abrirVisor(canal) {
  const c = estado.camaras.find((x) => x.canal === canal);
  if (!c) return;
  visorCanal = canal;
  $("#visor-nombre").textContent = `${c.nombre} · CH${canal}`;
  $("#visor").classList.remove("oculto"); mostrarCalidad();
  $("#visor").scrollIntoView({ behavior: "smooth", block: "start" });
}
function mostrarCalidad() {
  if (!visorCanal) return;
  const video = $("#visor-video"), img = $("#visor-img");
  video.pause(); video.removeAttribute("src"); video.load(); img.src = "";
  $$("#selector-calidad .boton").forEach((b) => b.classList.toggle("activo", b.dataset.calidad === calidadVisor));
  if (calidadVisor === "hd" && estado.gateway?.vivo) {
    img.hidden = true; video.hidden = false;
    $("#visor-estado").textContent = "conectando…";
    $("#visor-nota").textContent = "Stream principal 1080p. Si la PC no decodifica H.265, el gateway lo convierte.";
    video.src = camUrl(visorCanal, "hd");
    video.onplaying = () => { $("#visor-estado").textContent = "en vivo · 1080p"; };
    video.onerror = () => { $("#visor-estado").textContent = "sin señal"; };
  } else {
    video.hidden = true; img.hidden = false;
    $("#visor-estado").textContent = "conectando…";
    $("#visor-nota").textContent = calidadVisor === "hd"
      ? "El gateway no está corriendo: calidad liviana." : "Sub-stream 704x576.";
    img.onload = () => { $("#visor-estado").textContent = "en vivo · 704x576"; };
    img.onerror = () => { $("#visor-estado").textContent = "sin señal"; };
    img.src = camUrl(visorCanal, "vivo");
  }
}
$("#selector-calidad").addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-calidad]");
  if (b) { calidadVisor = b.dataset.calidad; mostrarCalidad(); }
});
function cerrarVisor() {
  const video = $("#visor-video");
  if (video) { video.pause(); video.removeAttribute("src"); video.load(); }
  const img = $("#visor-img"); if (img) img.src = "";
  $("#visor")?.classList.add("oculto"); visorCanal = null;
}
$("#visor-cerrar").addEventListener("click", cerrarVisor);

// ---------------------------------------------------------------- formulario modal
// Cartel con campos, mismo estilo que confirmar(). Devuelve los valores o null.
// campos: [{id, label, tipo:'text'|'password'|'select'|'checkbox', valor, opciones, ayuda, requerido}]
function pedirDatos({ titulo, campos, ok = "Guardar" }) {
  return new Promise((resolver) => {
    const fondo = document.createElement("div");
    fondo.className = "modal";
    const html = campos.map((c) => {
      if (c.tipo === "select") {
        return `<label class="bloque">${escapar(c.label)}
          <select data-campo="${c.id}">${c.opciones.map((o) =>
            `<option value="${escapar(o.valor)}" ${o.valor === c.valor ? "selected" : ""}>${escapar(o.texto)}</option>`).join("")}</select></label>`;
      }
      if (c.tipo === "checkbox") {
        return `<label class="check" style="margin:4px 0 14px"><input type="checkbox" data-campo="${c.id}" ${c.valor ? "checked" : ""}> ${escapar(c.label)}</label>`;
      }
      if (c.tipo === "puertas") {
        const sel = new Set(c.valor || []);
        const grupos = estado.sedes.map((s) => {
          const items = (s.lectores || []).map((l) =>
            `<label class="chip"><input type="checkbox" data-puerta value="${escapar(l.ip)}"
               ${sel.has(l.ip) ? "checked" : ""}>${escapar(l.nombre)}</label>`).join("");
          return `<div class="grupo-puertas"><span class="grupo-titulo">${escapar(s.nombre)}</span>
            <div class="chips">${items}</div></div>`;
        }).join("");
        return `<div class="bloque" data-campo="${c.id}"><span>${escapar(c.label)}</span>
          ${c.ayuda ? `<span class="ayuda" style="margin:0 0 4px">${escapar(c.ayuda)}</span>` : ""}
          ${grupos}</div>`;
      }
      if (c.tipo === "secciones") {
        const sel = new Set(c.valor || []);
        const presets = Object.entries(PRESETS).map(([n, ss]) =>
          `<button type="button" class="chip-preset" data-preset="${escapar(ss.join(","))}">${escapar(n)}</button>`).join("");
        const items = SECCIONES.map((s) =>
          `<label class="chip"><input type="checkbox" data-seccion value="${escapar(s.id)}"
             ${sel.has(s.id) ? "checked" : ""}>${escapar(s.texto)}</label>`).join("");
        return `<div class="bloque" data-campo="${c.id}"><span>${escapar(c.label)}</span>
          ${c.ayuda ? `<span class="ayuda" style="margin:0 0 6px">${escapar(c.ayuda)}</span>` : ""}
          <div class="presets">${presets}</div>
          <div class="chips">${items}</div></div>`;
      }
      return `<label class="bloque">${escapar(c.label)}
        <input type="${c.tipo || "text"}" data-campo="${c.id}" value="${escapar(c.valor || "")}"
          placeholder="${escapar(c.placeholder || "")}" autocomplete="off" ${c.requerido ? "required" : ""}>
        ${c.ayuda ? `<span class="ayuda" style="margin:2px 0 0">${escapar(c.ayuda)}</span>` : ""}</label>`;
    }).join("");
    fondo.innerHTML = `
      <div class="modal-caja" role="dialog" aria-modal="true">
        <h3>${escapar(titulo)}</h3>
        <form>${html}
          <p class="error" data-error></p>
          <div class="modal-pie">
            <button type="button" class="boton" data-no>Cancelar</button>
            <button type="submit" class="boton primario">${escapar(ok)}</button>
          </div>
        </form>
      </div>`;
    const cerrar = (valor) => { document.removeEventListener("keydown", tecla); fondo.remove(); resolver(valor); };
    const tecla = (e) => { if (e.key === "Escape") cerrar(null); };
    fondo.addEventListener("click", (e) => {
      const preset = e.target.closest("[data-preset]");
      if (preset) {   // un preset tilda su combo de secciones
        const quiere = new Set(preset.dataset.preset.split(",").filter(Boolean));
        fondo.querySelectorAll("[data-seccion]").forEach((i) => { i.checked = quiere.has(i.value); });
        return;
      }
      if (e.target === fondo || e.target.closest("[data-no]")) cerrar(null);
    });
    fondo.querySelector("form").addEventListener("submit", (e) => {
      e.preventDefault();
      const datos = {};
      campos.forEach((c) => {
        const el = fondo.querySelector(`[data-campo="${c.id}"]`);
        if (c.tipo === "puertas") {
          datos[c.id] = [...el.querySelectorAll("[data-puerta]:checked")].map((i) => i.value);
        } else if (c.tipo === "secciones") {
          datos[c.id] = [...el.querySelectorAll("[data-seccion]:checked")].map((i) => i.value);
        } else if (c.tipo === "checkbox") {
          datos[c.id] = el.checked;
        } else {
          datos[c.id] = el.value.trim();
        }
      });
      cerrar(datos);
    });
    document.addEventListener("keydown", tecla);
    document.body.append(fondo);
    fondo.querySelector("[data-campo]")?.focus();
  });
}

// ---------------------------------------------------------------- usuarios (admin)
const ROL_OPCIONES = [
  { valor: "operador", texto: "Operador — solo mirar" },
  { valor: "supervisor", texto: "Supervisor — altas/bajas y abrir puertas" },
  { valor: "admin", texto: "Admin — todo + usuarios" },
];

async function cargarUsuarios() {
  let usuarios;
  try { usuarios = await api("/api/usuarios"); }
  catch (e) { avisar(e.message, "mal"); return; }
  const nombreDe = (ip) => {
    for (const s of estado.sedes) {
      const l = (s.lectores || []).find((x) => x.ip === ip);
      if (l) return l.nombre;
    }
    return ip;
  };
  const abre = (u) => {
    if (ROLES[u.rol] >= ROLES.supervisor) return "todas";
    if (!u.puertas || !u.puertas.length) return "—";
    return u.puertas.map(nombreDe).join(", ");
  };
  const ve = (u) => (u.secciones || []).map((s) => (SECCIONES.find((x) => x.id === s) || {}).texto || s).join(" · ");
  $("#tabla-usuarios").innerHTML = `
    <thead><tr><th>Usuario</th><th>Nombre</th><th>Rol</th><th>Secciones</th><th>Abre puertas</th><th>Estado</th>
      <th>Último acceso</th><th></th></tr></thead>
    <tbody>${usuarios.map((u) => `
      <tr class="${u.activo ? "" : "baja"}">
        <td class="num">${escapar(u.usuario)}${u.usuario === estado.usuario ? ' <span class="pastilla">vos</span>' : ""}</td>
        <td>${escapar(u.nombre || "—")}</td>
        <td><span class="rol-chip ${u.rol}">${u.rol}</span></td>
        <td style="font-size:12px;color:var(--tenue)">${escapar(ve(u))}</td>
        <td style="font-size:12.5px;color:var(--tenue)">${escapar(abre(u))}</td>
        <td>${u.activo ? '<span class="etiqueta ok">activo</span>' : '<span class="etiqueta">inactivo</span>'}</td>
        <td class="num">${escapar(u.ultimo_acceso || "—")}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="boton chico" data-editar="${escapar(u.usuario)}">Editar</button>
          ${u.usuario === estado.usuario ? "" :
            `<button class="boton chico peligro" data-borrar-usuario="${escapar(u.usuario)}">Borrar</button>`}
        </td>
      </tr>`).join("")}</tbody>`;
  estado._usuarios = usuarios;
}

$("#btn-nuevo-usuario").addEventListener("click", async () => {
  const d = await pedirDatos({
    titulo: "Nuevo usuario",
    campos: [
      { id: "usuario", label: "Usuario (para entrar)", requerido: true, placeholder: "ej: jperez" },
      { id: "nombre", label: "Nombre visible", placeholder: "ej: Juan Pérez" },
      { id: "rol", label: "Rol (nivel de edición)", tipo: "select", opciones: ROL_OPCIONES, valor: "operador" },
      { id: "clave", label: "Contraseña", tipo: "password", requerido: true, ayuda: "Mínimo 4 caracteres" },
      { id: "secciones", label: "Secciones que ve", tipo: "secciones", valor: [],
        ayuda: "Elegí un preset o tildá a mano. Vacío = las que trae el rol." },
      { id: "puertas", label: "Puertas que puede abrir", tipo: "puertas", valor: [],
        ayuda: "Para el portero/operador. Supervisor y admin ya pueden abrir todas." },
    ],
  });
  if (!d) return;
  try {
    await api("/api/usuarios", { method: "POST", body: JSON.stringify(d) });
    avisar(`Usuario "${d.usuario}" creado`, "ok"); cargarUsuarios();
  } catch (e) { avisar(e.message, "mal"); }
});

$("#tabla-usuarios").addEventListener("click", async (ev) => {
  const editar = ev.target.closest("[data-editar]");
  const borrar = ev.target.closest("[data-borrar-usuario]");
  if (editar) {
    const u = (estado._usuarios || []).find((x) => x.usuario === editar.dataset.editar);
    if (!u) return;
    const d = await pedirDatos({
      titulo: `Editar "${u.usuario}"`,
      campos: [
        { id: "nombre", label: "Nombre visible", valor: u.nombre },
        { id: "rol", label: "Rol (nivel de edición)", tipo: "select", opciones: ROL_OPCIONES, valor: u.rol },
        { id: "activo", label: "Usuario activo (puede entrar)", tipo: "checkbox", valor: u.activo },
        { id: "secciones", label: "Secciones que ve", tipo: "secciones", valor: u.secciones || [],
          ayuda: "Elegí un preset o tildá a mano. Vacío = las que trae el rol." },
        { id: "puertas", label: "Puertas que puede abrir", tipo: "puertas", valor: u.puertas || [],
          ayuda: "Para el portero/operador. Supervisor y admin ya pueden abrir todas." },
        { id: "clave", label: "Nueva contraseña", tipo: "password",
          ayuda: "Dejala en blanco para no cambiarla" },
      ],
    });
    if (!d) return;
    if (!d.clave) delete d.clave;   // sin cambio de clave
    try {
      await api(`/api/usuarios/${encodeURIComponent(u.usuario)}`, { method: "POST", body: JSON.stringify(d) });
      avisar("Usuario actualizado", "ok"); cargarUsuarios();
    } catch (e) { avisar(e.message, "mal"); }
  }
  if (borrar) {
    const usuario = borrar.dataset.borrarUsuario;
    if (!await confirmar(`Se borra el acceso de "${usuario}" al panel.`,
        { titulo: `¿Borrar al usuario ${usuario}?`, ok: "Borrar", peligro: true })) return;
    try {
      await api(`/api/usuarios/${encodeURIComponent(usuario)}`, { method: "DELETE" });
      avisar("Usuario borrado", "ok"); cargarUsuarios();
    } catch (e) { avisar(e.message, "mal"); }
  }
});

// Cambiar la propia clave (cualquier usuario)
$("#mi-clave").addEventListener("click", async () => {
  const d = await pedirDatos({
    titulo: "Cambiar mi contraseña",
    ok: "Cambiar",
    campos: [
      { id: "actual", label: "Contraseña actual", tipo: "password", requerido: true },
      { id: "nueva", label: "Contraseña nueva", tipo: "password", requerido: true, ayuda: "Mínimo 4 caracteres" },
    ],
  });
  if (!d) return;
  try {
    await api("/api/mi-clave", { method: "POST", body: JSON.stringify(d) });
    avisar("Contraseña cambiada", "ok");
  } catch (e) { avisar(e.message, "mal"); }
});

arrancar();
