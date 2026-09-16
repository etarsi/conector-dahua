/* Monitoreo Sebigus — logica del panel.
   Sin frameworks: es una pagina que tiene que abrir rapido en cualquier PC
   de la oficina y quedarse dias abierta sin comerse la memoria. */

const $  = (sel, raiz = document) => raiz.querySelector(sel);
const $$ = (sel, raiz = document) => [...raiz.querySelectorAll(sel)];

const estado = {
  lectores: [],
  perfiles: [],
  personas: [],
  marcas: [],          // feed en vivo (se acota a TOPE_FEED)
  editando: null,
  fotoNueva: null,
  fuente: null,
};
const TOPE_FEED = 200;

// ---------------------------------------------------------------- red
async function api(ruta, opciones = {}) {
  const r = await fetch(ruta, {
    headers: { "Content-Type": "application/json" },
    ...opciones,
  });
  if (r.status === 401) { mostrarLogin(); throw new Error("sesion vencida"); }
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(datos.error || `error ${r.status}`);
  return datos;
}

function avisar(texto, clase = "") {
  const nodo = document.createElement("div");
  nodo.className = `aviso ${clase}`;
  nodo.textContent = texto;
  $("#avisos").append(nodo);
  setTimeout(() => { nodo.style.opacity = "0"; setTimeout(() => nodo.remove(), 300); }, 3800);
}

const escapar = (t) => String(t ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const iniciales = (nombre) => (nombre || "?").trim().split(/\s+/).slice(0, 2)
  .map((p) => p[0]).join("").toUpperCase() || "?";

// ---------------------------------------------------------------- entrada
function mostrarLogin() {
  $("#login").classList.remove("oculto");
  $("#panel").classList.add("oculto");
  if (estado.fuente) { estado.fuente.close(); estado.fuente = null; }
}

async function arrancar() {
  const s = await fetch("/api/sesion").then((r) => r.json());
  if (s.abierta) entrarAlPanel();
  else { mostrarLogin(); if (!s.pide_clave) $("#clave").placeholder = "El panel no tiene clave — entrá"; }
}

$("#form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#login-error").textContent = "";
  try {
    await api("/api/entrar", { method: "POST", body: JSON.stringify({ clave: $("#clave").value }) });
    $("#clave").value = "";
    entrarAlPanel();
  } catch (e) { $("#login-error").textContent = e.message; }
});

$("#salir").addEventListener("click", async () => {
  await api("/api/salir", { method: "POST" }).catch(() => {});
  mostrarLogin();
});

async function entrarAlPanel() {
  $("#login").classList.add("oculto");
  $("#panel").classList.remove("oculto");
  await refrescarEstado();
  await cargarPersonas();
  conectarStream();
}

// ---------------------------------------------------------------- navegación
$$(".nav-item").forEach((boton) => boton.addEventListener("click", () => {
  $$(".nav-item").forEach((b) => b.classList.toggle("activo", b === boton));
  const vista = boton.dataset.vista;
  $$(".vista").forEach((v) => v.classList.toggle("activa", v.id === `vista-${vista}`));
  if (vista === "personas") cargarPersonas();
  if (vista === "historial") cargarHistorial();
  if (vista === "puertas") pintarTablaPuertas();
  if (vista === "camaras") cargarCamaras(); else pararMosaico();
}));

// ---------------------------------------------------------------- estado general
async function refrescarEstado() {
  const datos = await api("/api/estado");
  estado.lectores = datos.lectores;
  estado.perfiles = datos.perfiles;
  pintarMetricas(datos.resumen);
  pintarPuertas();
  pintarTablaPuertas();
  pintarSelectores();
  pintarPerfiles();
}

function pintarMetricas(r) {
  $("#metricas").innerHTML = `
    <div class="metrica"><b>${r.personas}</b><span>personas</span></div>
    <div class="metrica"><b>${r.eventos_hoy}</b><span>marcas hoy</span></div>
    <div class="metrica ${r.rechazos_hoy ? "ojo" : ""}"><b>${r.rechazos_hoy}</b><span>rechazos hoy</span></div>
    <div class="metrica ${r.pendientes ? "ojo" : ""}"><b>${r.pendientes}</b><span>a sincronizar</span></div>
    ${r.errores ? `<div class="metrica malo"><b>${r.errores}</b><span>con error</span></div>` : ""}`;
}

function pintarPuertas() {
  $("#grilla-puertas").innerHTML = estado.lectores.map((l) => {
    const abierta = (l.puerta || "").toLowerCase().includes("open");
    const clase = l.en_linea ? (abierta ? "viva abierta" : "viva") : "muerta";
    const pastilla = !l.en_linea
      ? '<span class="estado-puerta offline">sin conexión</span>'
      : `<span class="estado-puerta ${abierta ? "abierta" : ""}">${abierta ? "abierta" : "cerrada"}</span>`;
    return `<div class="puerta ${clase}">
      <h4>${escapar(l.nombre)}</h4>
      <div class="sector">${escapar(l.sector || "")}</div>
      <div class="ip">${escapar(l.ip)}</div>
      <div class="puerta-pie">
        ${pastilla}
        <button class="abrir" data-abrir="${escapar(l.ip)}" ${l.en_linea ? "" : "disabled"}>Abrir</button>
      </div>
    </div>`;
  }).join("");
}

function pintarTablaPuertas() {
  $("#tabla-puertas").innerHTML = `
    <thead><tr><th>Puerta</th><th>Sector</th><th>IP</th><th>Modelo</th>
      <th>Conexión</th><th>Estado</th><th>Último chequeo</th><th></th></tr></thead>
    <tbody>${estado.lectores.map((l) => {
      const abierta = (l.puerta || "").toLowerCase().includes("open");
      return `<tr>
        <td><b>${escapar(l.nombre)}</b></td>
        <td>${escapar(l.sector || "—")}</td>
        <td class="num">${escapar(l.ip)}</td>
        <td class="num">${escapar(l.modelo || "—")}</td>
        <td><span class="etiqueta ${l.en_linea ? "ok" : "error"}">${l.en_linea ? "en línea" : "caído"}</span></td>
        <td>${l.en_linea ? (abierta ? '<span class="etiqueta ok">abierta</span>' : "cerrada") : "—"}</td>
        <td class="num">${escapar(l.visto || "—")}</td>
        <td><button class="boton chico" data-abrir="${escapar(l.ip)}" ${l.en_linea ? "" : "disabled"}>Abrir</button></td>
      </tr>${l.error ? `<tr><td colspan="8" style="color:var(--error);font-size:12px">${escapar(l.error)}</td></tr>` : ""}`;
    }).join("")}</tbody>`;
}

// Abrir puerta: delegado, porque los botones se repintan seguido.
document.addEventListener("click", async (ev) => {
  const boton = ev.target.closest("[data-abrir]");
  if (!boton) return;
  const ip = boton.dataset.abrir;
  const lector = estado.lectores.find((l) => l.ip === ip);
  if (!confirm(`¿Abrir la puerta "${lector?.nombre || ip}"?\n\nEs una puerta real: se va a destrabar ahora.`)) return;
  boton.disabled = true;
  try {
    await api("/api/abrir", { method: "POST", body: JSON.stringify({ lector: ip }) });
    avisar(`Puerta "${lector?.nombre || ip}" abierta`, "ok");
  } catch (e) { avisar(`No se pudo abrir: ${e.message}`, "mal"); }
  finally { boton.disabled = false; }
});

// ---------------------------------------------------------------- eventos en vivo
function conectarStream() {
  if (estado.fuente) estado.fuente.close();
  const fuente = new EventSource("/api/stream");
  estado.fuente = fuente;
  fuente.onopen = () => {
    $("#conexion").className = "conexion viva";
    $("#conexion").innerHTML = '<span class="latido"></span> en vivo';
  };
  fuente.onerror = () => {
    $("#conexion").className = "conexion caida";
    $("#conexion").innerHTML = '<span class="latido"></span> reconectando…';
  };
  fuente.onmessage = (msg) => {
    let paquete;
    try { paquete = JSON.parse(msg.data); } catch { return; }
    if (paquete.tipo === "evento")       entroMarca(paquete.datos);
    else if (paquete.tipo === "estado")  { estado.lectores = paquete.datos; pintarPuertas(); pintarTablaPuertas(); }
    else if (paquete.tipo === "resumen") pintarMetricas(paquete.datos);
    else if (paquete.tipo === "apertura") avisar(`Apertura remota: ${paquete.datos.lector}`);
    else if (paquete.tipo === "sincronizado" && paquete.datos.aplicadas)
      avisar(`${paquete.datos.aplicadas} cambio(s) aplicados a los lectores`, "ok");
  };
}

function entroMarca(marca) {
  estado.marcas.unshift(marca);
  if (estado.marcas.length > TOPE_FEED) estado.marcas.length = TOPE_FEED;
  pintarFeed();
}

function pintarFeed() {
  const soloNo = $("#solo-rechazos").checked;
  const lista = soloNo ? estado.marcas.filter((m) => !m.concedido) : estado.marcas;
  $("#contador-feed").textContent = lista.length;
  $("#feed").innerHTML = lista.length
    ? lista.map(filaMarca).join("")
    : '<p class="vacio">Esperando movimiento en las puertas…</p>';
}

function filaMarca(m) {
  const hora = (m.momento || "").split(" ")[1] || "";
  const quien = m.nombre || (m.persona_id || m.id ? `ID ${m.persona_id || m.id}` : "Desconocido");
  return `<div class="marca-item ${m.concedido ? "si" : "no"}">
    <div class="avatar">${escapar(iniciales(m.nombre))}</div>
    <div class="marca-datos">
      <b>${escapar(quien)}</b>
      <span>${escapar(m.lector_nom || m.lector || "")} · ${escapar(m.metodo || "")}</span>
    </div>
    <div class="marca-hora">${escapar(hora)}
      <em>${m.concedido ? "" : escapar(m.motivo || "rechazado")}</em></div>
  </div>`;
}
$("#solo-rechazos").addEventListener("change", pintarFeed);

// ---------------------------------------------------------------- personas
async function cargarPersonas() {
  const params = new URLSearchParams();
  if ($("#buscar").value) params.set("q", $("#buscar").value);
  if ($("#filtro-lector").value) params.set("lector", $("#filtro-lector").value);
  if ($("#filtro-activos").checked) params.set("activos", "1");
  estado.personas = await api(`/api/personas?${params}`);
  $("#contador-personas").textContent = `${estado.personas.length} personas`;
  pintarPersonas();
}

function pintarPersonas() {
  if (!estado.personas.length) {
    $("#tabla-personas").innerHTML =
      '<tbody><tr><td><p class="vacio">No hay personas cargadas. ' +
      'Andá a Ajustes → "Importar padrón de los lectores" para traer las que ya están en los equipos.</p></td></tr></tbody>';
    return;
  }
  $("#tabla-personas").innerHTML = `
    <thead><tr><th>Nombre</th><th>ID</th><th>Documento</th><th>Sector</th>
      <th>Puertas</th><th>Sincronización</th></tr></thead>
    <tbody>${estado.personas.map((p) => `
      <tr class="clic ${p.activo ? "" : "baja"}" data-persona="${escapar(p.id)}">
        <td><b>${escapar(p.nombre)}</b>${p.activo ? "" : ' <span class="etiqueta">baja</span>'}</td>
        <td class="num">${escapar(p.id)}</td>
        <td class="num">${escapar(p.documento || "—")}</td>
        <td>${escapar(p.sector || "—")}</td>
        <td><span class="pastilla">${p.puertas}</span></td>
        <td>${p.sin_sincronizar
          ? `<span class="etiqueta pendiente">${p.sin_sincronizar} pendiente(s)</span>`
          : '<span class="etiqueta ok">al día</span>'}</td>
      </tr>`).join("")}</tbody>`;
}

$("#tabla-personas").addEventListener("click", (ev) => {
  const fila = ev.target.closest("[data-persona]");
  if (fila) abrirFicha(fila.dataset.persona);
});
let temporizador;
$("#buscar").addEventListener("input", () => {
  clearTimeout(temporizador);
  temporizador = setTimeout(cargarPersonas, 250);
});
$("#filtro-lector").addEventListener("change", cargarPersonas);
$("#filtro-activos").addEventListener("change", cargarPersonas);

// ---------------------------------------------------------------- ficha
function pintarSelectores() {
  const opciones = estado.lectores.map((l) =>
    `<option value="${escapar(l.ip)}">${escapar(l.nombre)}</option>`).join("");
  $("#filtro-lector").innerHTML = `<option value="">Todas las puertas</option>${opciones}`;
  $("#filtro-lector-ev").innerHTML = `<option value="">Todas las puertas</option>${opciones}`;
  $("#p-lectores").innerHTML = estado.lectores.map((l) => `
    <label><input type="checkbox" value="${escapar(l.ip)}">
      ${escapar(l.nombre)} <span>${escapar(l.sector || l.ip)}</span></label>`).join("");
  $("#perfil-lectores").innerHTML = estado.lectores.map((l) => `
    <label class="chip"><input type="checkbox" value="${escapar(l.ip)}">${escapar(l.nombre)}</label>`).join("");
  $("#p-perfil").innerHTML = '<option value="">— elegir puertas a mano —</option>' +
    estado.perfiles.map((p) => `<option value="${escapar(p.nombre)}">${escapar(p.nombre)}</option>`).join("");
}

$("#p-perfil").addEventListener("change", () => {
  const perfil = estado.perfiles.find((p) => p.nombre === $("#p-perfil").value);
  if (!perfil) return;
  $$("#p-lectores input").forEach((c) => { c.checked = perfil.lectores.includes(c.value); });
});

async function abrirFicha(id) {
  const persona = await api(`/api/personas/${encodeURIComponent(id)}`);
  estado.editando = persona;
  estado.fotoNueva = null;
  $("#cajon-titulo").textContent = persona.nombre;
  $("#p-id").value = persona.id;
  $("#p-id").disabled = true;
  $("#p-nombre").value = persona.nombre || "";
  $("#p-documento").value = persona.documento || "";
  $("#p-sector").value = persona.sector || "";
  $("#p-desde").value = (persona.desde || "").split(" ")[0];
  $("#p-hasta").value = (persona.hasta || "").split(" ")[0];
  $("#p-notas").value = persona.notas || "";
  $("#p-perfil").value = persona.perfil || "";
  $("#p-activo").checked = !!persona.activo;
  const conAcceso = persona.accesos.filter((a) => a.permitido).map((a) => a.lector);
  $$("#p-lectores input").forEach((c) => { c.checked = conAcceso.includes(c.value); });
  $("#foto-vista").innerHTML = persona.tiene_foto
    ? `<img src="/api/personas/${encodeURIComponent(id)}/foto?t=${Date.now()}" alt="">`
    : "<span>Sin foto</span>";
  $("#btn-baja").classList.toggle("oculto", !persona.activo);
  $("#error-persona").textContent = "";
  $("#cajon").classList.remove("oculto");
}

$("#btn-nueva").addEventListener("click", () => {
  estado.editando = null;
  estado.fotoNueva = null;
  $("#cajon-titulo").textContent = "Nueva persona";
  $("#form-persona").reset();
  $("#p-id").disabled = false;
  $("#p-activo").checked = true;
  $("#foto-vista").innerHTML = "<span>Sin foto</span>";
  $("#btn-baja").classList.add("oculto");
  $("#error-persona").textContent = "";
  $("#cajon").classList.remove("oculto");
});

const cerrarCajon = () => $("#cajon").classList.add("oculto");
$("#cajon-cerrar").addEventListener("click", cerrarCajon);
$("#btn-cancelar").addEventListener("click", cerrarCajon);
$(".cajon-fondo").addEventListener("click", cerrarCajon);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") cerrarCajon(); });

$("#foto-archivo").addEventListener("change", (ev) => {
  const archivo = ev.target.files[0];
  if (!archivo) return;
  const lector = new FileReader();
  lector.onload = () => {
    estado.fotoNueva = lector.result;
    $("#foto-vista").innerHTML = `<img src="${lector.result}" alt="">`;
  };
  lector.readAsDataURL(archivo);
});

$("#form-persona").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#error-persona").textContent = "";
  const cuerpo = {
    id: $("#p-id").value.trim(),
    nombre: $("#p-nombre").value.trim(),
    documento: $("#p-documento").value.trim(),
    sector: $("#p-sector").value.trim(),
    perfil: $("#p-perfil").value,
    desde: $("#p-desde").value ? `${$("#p-desde").value} 00:00:00` : "",
    hasta: $("#p-hasta").value ? `${$("#p-hasta").value} 23:59:59` : "",
    notas: $("#p-notas").value.trim(),
    activo: $("#p-activo").checked,
    lectores: $$("#p-lectores input:checked").map((c) => c.value),
  };
  if (estado.fotoNueva) cuerpo.foto = estado.fotoNueva;
  try {
    await api("/api/personas", { method: "POST", body: JSON.stringify(cuerpo) });
    cerrarCajon();
    avisar(`${cuerpo.nombre} guardado — se está aplicando a ${cuerpo.lectores.length} puerta(s)`, "ok");
    cargarPersonas();
  } catch (e) { $("#error-persona").textContent = e.message; }
});

$("#btn-baja").addEventListener("click", async () => {
  const persona = estado.editando;
  if (!persona) return;
  if (!confirm(`¿Dar de baja a ${persona.nombre}?\n\nSe lo saca de todas las puertas.`)) return;
  await api(`/api/personas/${encodeURIComponent(persona.id)}/baja`, { method: "POST" });
  cerrarCajon();
  avisar(`${persona.nombre} dado de baja`, "ok");
  cargarPersonas();
});

// ---------------------------------------------------------------- duplicados
$("#btn-duplicados").addEventListener("click", async () => {
  const grupos = await api("/api/duplicados");
  if (!grupos.length) { avisar("No hay nombres repetidos", "ok"); $("#aviso-duplicados").innerHTML = ""; return; }
  $("#aviso-duplicados").innerHTML = `<div class="alerta-duplicados">
    <h4>${grupos.length} persona(s) cargadas con más de un ID</h4>
    <p style="margin:0;color:var(--tenue)">Pasa cuando se vuelve a cargar a alguien en un equipo
      en vez de darle permiso al ID que ya tenía. Al darle de baja a uno, el otro sigue entrando.</p>
    <ul>${grupos.map((g) => `<li><b>${escapar(g[0].nombre)}</b> — ${
      g.map((p) => `ID ${escapar(p.id)} (${p.puertas} puerta${p.puertas === 1 ? "" : "s"})`).join(" · ")
    }</li>`).join("")}</ul></div>`;
});

// ---------------------------------------------------------------- historial
async function cargarHistorial() {
  const params = new URLSearchParams({ limite: "300" });
  if ($("#buscar-evento").value) params.set("q", $("#buscar-evento").value);
  if ($("#filtro-lector-ev").value) params.set("lector", $("#filtro-lector-ev").value);
  if ($("#filtro-rechazos-hist").checked) params.set("rechazos", "1");
  const eventos = await api(`/api/eventos?${params}`);
  $("#tabla-historial").innerHTML = eventos.length ? `
    <thead><tr><th>Cuándo</th><th>Persona</th><th>ID</th><th>Puerta</th>
      <th>Método</th><th>Resultado</th></tr></thead>
    <tbody>${eventos.map((e) => `<tr>
      <td class="num">${escapar(e.momento)}</td>
      <td>${escapar(e.nombre || "—")}</td>
      <td class="num">${escapar(e.persona_id || "—")}</td>
      <td>${escapar(e.lector_nom || e.lector)}</td>
      <td>${escapar(e.metodo || "—")}</td>
      <td>${e.concedido ? '<span class="etiqueta ok">acceso</span>'
                        : `<span class="etiqueta error">${escapar(e.motivo || "rechazado")}</span>`}</td>
    </tr>`).join("")}</tbody>` :
    '<tbody><tr><td><p class="vacio">No hay marcas guardadas todavía.</p></td></tr></tbody>';
}
$("#buscar-evento").addEventListener("input", () => {
  clearTimeout(temporizador); temporizador = setTimeout(cargarHistorial, 250);
});
$("#filtro-lector-ev").addEventListener("change", cargarHistorial);
$("#filtro-rechazos-hist").addEventListener("change", cargarHistorial);

$("#btn-importar-historial").addEventListener("click", async (ev) => {
  ev.target.disabled = true;
  ev.target.textContent = "Trayendo…";
  try {
    const r = await api("/api/importar/historial", { method: "POST", body: "{}" });
    const nuevas = r.resultados.reduce((a, x) => a + (x.nuevas || 0), 0);
    avisar(`${nuevas} marca(s) nuevas importadas`, "ok");
    cargarHistorial();
  } catch (e) { avisar(e.message, "mal"); }
  finally { ev.target.disabled = false; ev.target.textContent = "Traer del lector"; }
});

// ---------------------------------------------------------------- perfiles
function pintarPerfiles() {
  $("#lista-perfiles").innerHTML = estado.perfiles.length
    ? estado.perfiles.map((p) => `<div class="perfil">
        <b>${escapar(p.nombre)}</b>
        <span>${p.lectores.length} puerta(s)</span>
        <span class="crecer"></span>
        <button class="boton chico" data-borrar-perfil="${escapar(p.nombre)}">Borrar</button>
      </div>`).join("")
    : '<p class="ayuda" style="margin:0">Todavía no hay perfiles.</p>';
}

$("#lista-perfiles").addEventListener("click", async (ev) => {
  const boton = ev.target.closest("[data-borrar-perfil]");
  if (!boton) return;
  const datos = await api(`/api/perfiles/${encodeURIComponent(boton.dataset.borrarPerfil)}`,
                          { method: "DELETE" });
  estado.perfiles = datos.perfiles;
  pintarPerfiles(); pintarSelectores();
});

$("#btn-guardar-perfil").addEventListener("click", async () => {
  const nombre = $("#perfil-nombre").value.trim();
  if (!nombre) return avisar("Poné un nombre para el perfil", "mal");
  const lectores = $$("#perfil-lectores input:checked").map((c) => c.value);
  const datos = await api("/api/perfiles", { method: "POST",
    body: JSON.stringify({ nombre, lectores }) });
  estado.perfiles = datos.perfiles;
  $("#perfil-nombre").value = "";
  $$("#perfil-lectores input").forEach((c) => { c.checked = false; });
  pintarPerfiles(); pintarSelectores();
  avisar(`Perfil "${nombre}" guardado`, "ok");
});

// ---------------------------------------------------------------- ajustes
async function tarea(boton, texto, fn) {
  boton.disabled = true;
  const original = boton.textContent;
  boton.textContent = texto;
  $("#salida-ajustes").textContent = "";
  try {
    const r = await fn();
    $("#salida-ajustes").textContent = JSON.stringify(r, null, 2);
    avisar("Listo", "ok");
    await refrescarEstado();
    await cargarPersonas();
  } catch (e) {
    $("#salida-ajustes").textContent = e.message;
    avisar(e.message, "mal");
  } finally { boton.disabled = false; boton.textContent = original; }
}

$("#btn-importar-personas").addEventListener("click", (ev) =>
  tarea(ev.target, "Leyendo los 7 lectores…", () =>
    api("/api/importar/personas", { method: "POST", body: "{}" })));

$("#btn-importar-todo").addEventListener("click", (ev) => {
  if (!confirm("Relee el historial completo de los 7 lectores. Tarda ~1 minuto. ¿Seguir?")) return;
  tarea(ev.target, "Importando…", () =>
    api("/api/importar/historial", { method: "POST", body: JSON.stringify({ completo: true }) }));
});

$("#btn-sincronizar").addEventListener("click", (ev) =>
  tarea(ev.target, "Sincronizando…", () => api("/api/sincronizar", { method: "POST", body: "{}" })));



/* ---------------------------------------------------------------- camaras */
estado.camaras = [];
let relojMosaico = null;
let visorCanal = null;

async function cargarCamaras() {
  if (!estado.camaras.length) {
    const datos = await api("/api/camaras");
    estado.camaras = datos.canales || [];
    estado.gateway = datos.gateway || { vivo: false };
    $("#sub-nvr").textContent = datos.nvr
      ? (datos.nvr.en_linea
          ? `${datos.nvr.nombre} · ${datos.nvr.modelo || ""} · ${estado.camaras.length} cámaras`
          : `${datos.nvr.nombre} sin conexión — ${datos.nvr.error || ""}`)
      : "No hay NVR configurado (sección \"nvr\" de config.json)";
    const pisos = [...new Set(estado.camaras.map((c) => c.piso))];
    $("#filtro-piso").innerHTML = '<option value="">Todos los pisos</option>' +
      pisos.map((p) => `<option value="${escapar(p)}">${escapar(p)}</option>`).join("");
  }
  pintarMosaico();
  arrancarMosaico();
}

function camarasVisibles() {
  const piso = $("#filtro-piso").value;
  return piso ? estado.camaras.filter((c) => c.piso === piso) : estado.camaras;
}

function pintarMosaico() {
  const lista = camarasVisibles();
  if (!lista.length) {
    $("#mosaico").innerHTML = '<p class="vacio">No hay cámaras para mostrar.</p>';
    return;
  }
  let html = "";
  let pisoActual = null;
  const agrupar = !$("#filtro-piso").value;
  for (const c of lista) {
    if (agrupar && c.piso !== pisoActual) {
      pisoActual = c.piso;
      html += `<h4 class="camara-piso">${escapar(pisoActual)}</h4>`;
    }
    html += `<div class="camara" data-canal="${c.canal}" title="${escapar(c.nombre)}">
      <img alt="${escapar(c.nombre)}" loading="lazy">
      <div class="sin-senal oculto">sin señal</div>
      <div class="rotulo"><b>${escapar(c.nombre)}</b><span class="canal">CH${c.canal}</span></div>
    </div>`;
  }
  $("#mosaico").innerHTML = html;
}

// El NVR entrega un snapshot por segundo, asi que las miniaturas se piden de a
// UNA y en fila; pedirlas todas juntas lo satura y empieza a devolver 500.
// Una vuelta completa de 32 camaras lleva ~35s.
//
// `vueltaActual` es un contador de generacion, no un booleano: cada vez que se
// entra a la vista arranca una vuelta nueva y las viejas se tienen que morir
// solas. Con un flag compartido no alcanzaba — la vuelta nueva lo reseteaba y
// las anteriores seguian corriendo, se apilaban y ahi si tumbaban al NVR.
let vueltaActual = 0;

async function refrescarMiniaturas() {
  const miVuelta = ++vueltaActual;
  for (const img of $$("#mosaico .camara img")) {
    if (miVuelta !== vueltaActual) return;               // arranco otra vuelta
    if (!$("#vista-camaras").classList.contains("activa")) return;
    const tarjeta = img.closest(".camara");
    await new Promise((listo) => {
      let cerrado = false;
      const fin = () => { if (!cerrado) { cerrado = true; listo(); } };
      img.onload = () => { tarjeta.querySelector(".sin-senal")?.classList.add("oculto"); fin(); };
      img.onerror = () => {
        tarjeta.querySelector(".sin-senal")?.classList.remove("oculto");
        fin();
      };
      img.src = `/api/camaras/${tarjeta.dataset.canal}/foto?t=${Date.now()}`;
      setTimeout(fin, 8000);        // una camara colgada no frena a las demas
    });
  }
}

function arrancarMosaico() {
  pararMosaico();
  refrescarMiniaturas();
  if (!$("#mosaico-vivo").checked) return;
  // 90s: la vuelta entera tarda ~35s, asi que nunca se pisan dos.
  relojMosaico = setInterval(refrescarMiniaturas, 90000);
}

function pararMosaico() {
  vueltaActual++;                   // mata la vuelta que este corriendo
  if (relojMosaico) { clearInterval(relojMosaico); relojMosaico = null; }
}

$("#mosaico-vivo").addEventListener("change", arrancarMosaico);
$("#filtro-piso").addEventListener("change", () => { pintarMosaico(); arrancarMosaico(); });

// Abrir una cámara en grande, con video en vivo (MJPEG)
$("#mosaico").addEventListener("click", (ev) => {
  const tarjeta = ev.target.closest("[data-canal]");
  if (!tarjeta) return;
  abrirVisor(Number(tarjeta.dataset.canal));
});

let calidadVisor = "hd";   // "hd" = 1080p por el gateway, "sub" = MJPEG liviano

function abrirVisor(canal) {
  const camara = estado.camaras.find((c) => c.canal === canal);
  if (!camara) return;
  visorCanal = canal;
  $("#visor-nombre").textContent = `${camara.nombre} · CH${canal}`;
  $("#visor").classList.remove("oculto");
  mostrarCalidad();
  $("#visor").scrollIntoView({ behavior: "smooth", block: "start" });
}

function mostrarCalidad() {
  if (!visorCanal) return;
  const video = $("#visor-video");
  const img = $("#visor-img");
  // Cortar SIEMPRE la fuente anterior: si no, el stream que se deja de ver
  // sigue abierto contra el NVR y se acumulan sesiones.
  video.pause(); video.removeAttribute("src"); video.load();
  img.src = "";

  $$("#selector-calidad .boton").forEach((b) =>
    b.classList.toggle("activo", b.dataset.calidad === calidadVisor));

  if (calidadVisor === "hd" && estado.gateway?.vivo) {
    img.hidden = true; video.hidden = false;
    $("#visor-estado").textContent = "conectando…";
    $("#visor-nota").textContent =
      "Stream principal 1080p. Si la PC no decodifica H.265, el gateway lo convierte solo.";
    video.src = `/api/camaras/${visorCanal}/hd`;
    video.onplaying = () => { $("#visor-estado").textContent = "en vivo · 1080p"; };
    video.onerror = () => { $("#visor-estado").textContent = "sin señal"; };
  } else {
    video.hidden = true; img.hidden = false;
    $("#visor-estado").textContent = "conectando…";
    $("#visor-nota").textContent = calidadVisor === "hd"
      ? "El gateway de video no está corriendo: se muestra la calidad liviana."
      : "Sub-stream 704x576. Consume mucho menos que el HD.";
    img.onload = () => { $("#visor-estado").textContent = "en vivo · 704x576"; };
    img.onerror = () => { $("#visor-estado").textContent = "sin señal"; };
    img.src = `/api/camaras/${visorCanal}/vivo`;
  }
}

$("#selector-calidad").addEventListener("click", (ev) => {
  const boton = ev.target.closest("[data-calidad]");
  if (!boton) return;
  calidadVisor = boton.dataset.calidad;
  mostrarCalidad();
});

function cerrarVisor() {
  const video = $("#visor-video");
  video.pause(); video.removeAttribute("src"); video.load();
  $("#visor-img").src = "";
  $("#visor").classList.add("oculto");
  visorCanal = null;
}
$("#visor-cerrar").addEventListener("click", cerrarVisor);


arrancar();
