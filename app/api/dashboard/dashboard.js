"use strict";

const REFRESH_INTERVAL_MS = 30_000;
const SIDEBAR_STORAGE_KEY = "auditoria-sidebar-collapsed";
const MOBILE_NAVIGATION = window.matchMedia("(max-width: 760px)");
const INCIDENT_PAGE_SIZE = 50;
const INCIDENT_ID_PATTERN = /^INC-[0-9A-F]{16}$/;
const MODULES = {
  "/dashboard": { key: "overview", title: "Dashboard" },
  "/dashboard/events": { key: "events", title: "Eventos" },
  "/dashboard/detections": { key: "detections", title: "Detecciones" },
  "/dashboard/incidents": { key: "incidents", title: "Incidentes" },
  "/dashboard/responses": { key: "responses", title: "Respuestas" },
  "/dashboard/notifications": { key: "notifications", title: "Notificaciones" },
  "/dashboard/servers": { key: "servers", title: "Mis servidores" },
  "/dashboard/users": { key: "users", title: "Usuarios" },
};

const normalizedPath = window.location.pathname.replace(/\/+$/, "") || "/dashboard";
const currentModule = MODULES[normalizedPath] ?? MODULES["/dashboard"];
let refreshInProgress = false;
let refreshTimerId = null;
let refreshController = null;
let refreshGeneration = 0;
let authContext = null;
let knownAgents = [];
let selectedAgentId = null;

const elements = {
  appShell: document.querySelector("#app-shell"),
  apiIndicator: document.querySelector("#api-indicator"),
  apiStatus: document.querySelector("#api-status"),
  agentSelector: document.querySelector("#agent-selector"),
  automaticBlocking: document.querySelector("#automatic-blocking"),
  connectServerButton: document.querySelector("#connect-server-button"),
  copyRegistrationCommand: document.querySelector("#copy-registration-command"),
  createUserForm: document.querySelector("#create-user-form"),
  currentUser: document.querySelector("#current-user"),
  defenseApiStatus: document.querySelector("#status-api"),
  statusPresence: document.querySelector("#status-presence"),
  statusLastSeen: document.querySelector("#status-last-seen"),
  defenseHostname: document.querySelector("#status-hostname"),
  detectionsBody: document.querySelector("#detections-body"),
  detectionsCount: document.querySelector("#detections-count"),
  detectionsFilters: document.querySelector("#detections-filters"),
  eventsBody: document.querySelector("#events-body"),
  eventsCount: document.querySelector("#events-count"),
  eventsFilters: document.querySelector("#events-filters"),
  globalAlert: document.querySelector("#global-alert"),
  incidentActions: document.querySelector("#incident-actions"),
  incidentActionsAlert: document.querySelector("#incident-actions-alert"),
  incidentActionsHint: document.querySelector("#incident-actions-hint"),
  incidentActionsSection: document.querySelector("#incident-actions-section"),
  incidentActionsTitle: document.querySelector("#incident-actions-title"),
  incidentBack: document.querySelector("#incident-back"),
  incidentBadges: document.querySelector("#incident-badges"),
  incidentKicker: document.querySelector("#incident-kicker"),
  incidentsActive: document.querySelector("#incidents-active"),
  incidentsCritical: document.querySelector("#incidents-critical"),
  incidentsHigh: document.querySelector("#incidents-high"),
  fleetBar: document.querySelector("#fleet-bar"),
  fleetUnknownWrap: document.querySelector("#fleet-unknown-wrap"),
  overviewIncidentsBody: document.querySelector("#overview-incidents-body"),
  overviewServers: document.querySelector("#overview-servers"),
  pageTitle: document.querySelector("#page-title"),
  incidentDetailSection: document.querySelector("#incident-detail-section"),
  incidentDetailTitle: document.querySelector("#incident-detail-title"),
  incidentEvidence: document.querySelector("#incident-evidence"),
  incidentEvidenceCount: document.querySelector("#incident-evidence-count"),
  incidentHeader: document.querySelector("#incident-header"),
  incidentResponse: document.querySelector("#incident-response"),
  incidentTimeline: document.querySelector("#incident-timeline"),
  incidentTimelineCount: document.querySelector("#incident-timeline-count"),
  incidentsBody: document.querySelector("#incidents-body"),
  incidentsCount: document.querySelector("#incidents-count"),
  incidentsFilters: document.querySelector("#incidents-filters"),
  incidentsListSection: document.querySelector("#incidents-list-section"),
  incidentsNext: document.querySelector("#incidents-next"),
  incidentsPage: document.querySelector("#incidents-page"),
  incidentsPrevious: document.querySelector("#incidents-previous"),
  hostname: document.querySelector("#hostname"),
  fleetTotal: document.querySelector("#fleet-total"),
  fleetOnline: document.querySelector("#fleet-online"),
  fleetOffline: document.querySelector("#fleet-offline"),
  fleetUnknown: document.querySelector("#fleet-unknown"),
  lastUpdated: document.querySelector("#last-updated"),
  logoutButton: document.querySelector("#logout-button"),
  mobileMenuToggle: document.querySelector("#mobile-menu-toggle"),
  overviewDetectionsBody: document.querySelector("#overview-detections-body"),
  overviewEventsBody: document.querySelector("#overview-events-body"),
  notificationsBody: document.querySelector("#notifications-body"),
  notificationsCount: document.querySelector("#notifications-count"),
  notificationsFailed: document.querySelector("#notifications-failed"),
  notificationsFilters: document.querySelector("#notifications-filters"),
  notificationsPending: document.querySelector("#notifications-pending"),
  notificationsSent: document.querySelector("#notifications-sent"),
  notificationsTotal: document.querySelector("#notifications-total"),
  refreshButton: document.querySelector("#refresh-button"),
  registrationCommand: document.querySelector("#registration-command"),
  registrationExpiresAt: document.querySelector("#registration-expires-at"),
  registrationPanel: document.querySelector("#registration-panel"),
  responseMode: document.querySelector("#response-mode"),
  responsesBody: document.querySelector("#responses-body"),
  responsesCount: document.querySelector("#responses-count"),
  responsesFilters: document.querySelector("#responses-filters"),
  serverSelectorWrap: document.querySelector(".server-selector-wrap"),
  sidebar: document.querySelector("#sidebar"),
  sidebarBackdrop: document.querySelector("#sidebar-backdrop"),
  sidebarCollapse: document.querySelector("#sidebar-collapse"),
  serversAlert: document.querySelector("#servers-alert"),
  serversBody: document.querySelector("#servers-body"),
  serversCount: document.querySelector("#servers-count"),
  serversTitle: document.querySelector("#servers-title"),
  usersAlert: document.querySelector("#users-alert"),
  usersBody: document.querySelector("#users-body"),
  usersCount: document.querySelector("#users-count"),
};

function readSidebarPreference() {
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true";
  } catch (_error) {
    return false;
  }
}

function storeSidebarPreference(collapsed) {
  try {
    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed));
  } catch (_error) {
    // The layout remains usable when storage is unavailable.
  }
}

function setSidebarCollapsed(collapsed, persist = false) {
  elements.appShell.classList.toggle("is-sidebar-collapsed", collapsed);
  elements.sidebar.classList.toggle("is-collapsed", collapsed);
  elements.sidebarCollapse.setAttribute("aria-expanded", String(!collapsed));
  elements.sidebarCollapse.setAttribute(
    "aria-label",
    collapsed ? "Expandir menú" : "Contraer menú",
  );
  if (persist) storeSidebarPreference(collapsed);
}

function setDrawerOpen(open, restoreFocus = false) {
  if (!MOBILE_NAVIGATION.matches) open = false;
  elements.sidebar.classList.toggle("is-drawer-open", open);
  elements.sidebarBackdrop.hidden = !open;
  elements.mobileMenuToggle.setAttribute("aria-expanded", String(open));
  elements.mobileMenuToggle.setAttribute(
    "aria-label",
    open ? "Cerrar menú" : "Abrir menú",
  );
  document.body.classList.toggle("is-drawer-open", open);
  if (open) {
    elements.sidebar.removeAttribute("inert");
    elements.sidebar.removeAttribute("aria-hidden");
    document.querySelector(".nav-item.is-active:not([hidden])")?.focus();
    document.querySelector("#contenido").setAttribute("inert", "");
  } else {
    document.querySelector("#contenido").removeAttribute("inert");
    if (MOBILE_NAVIGATION.matches) {
      elements.sidebar.setAttribute("inert", "");
      elements.sidebar.setAttribute("aria-hidden", "true");
    } else {
      elements.sidebar.removeAttribute("inert");
      elements.sidebar.removeAttribute("aria-hidden");
    }
    if (restoreFocus && MOBILE_NAVIGATION.matches) {
      elements.mobileMenuToggle.focus();
    }
  }
}

// En móvil, usuario, rol y hora de actualización viven en el drawer para
// mantener el encabezado compacto. Se mueven los mismos nodos (sin duplicar ids).
function placeSecondaryHeader() {
  const account = document.querySelector(".account");
  const meta = document.querySelector(".refresh-meta");
  const drawerSlot = document.querySelector("#sidebar-account");
  const actions = document.querySelector(".topbar-actions");
  if (!account || !meta || !drawerSlot || !actions) return;
  if (MOBILE_NAVIGATION.matches) {
    drawerSlot.append(meta, account);
  } else {
    const refresh = document.querySelector("#refresh-button");
    refresh.before(meta);
    actions.append(account);
  }
}

function configureNavigation() {
  placeSecondaryHeader();
  MOBILE_NAVIGATION.addEventListener("change", placeSecondaryHeader);
  setSidebarCollapsed(readSidebarPreference());
  setDrawerOpen(false);
  elements.sidebarCollapse.addEventListener("click", () => {
    const collapsed = !elements.sidebar.classList.contains("is-collapsed");
    setSidebarCollapsed(collapsed, true);
  });
  elements.mobileMenuToggle.addEventListener("click", () => {
    setDrawerOpen(!elements.sidebar.classList.contains("is-drawer-open"));
  });
  elements.sidebarBackdrop.addEventListener("click", () => {
    setDrawerOpen(false, true);
  });
  elements.sidebar.querySelectorAll(".nav-item").forEach((link) => {
    link.addEventListener("click", () => setDrawerOpen(false));
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && elements.sidebar.classList.contains("is-drawer-open")) {
      setDrawerOpen(false, true);
    }
  });
  MOBILE_NAVIGATION.addEventListener("change", () => setDrawerOpen(false));
}

function configurePasswordToggles() {
  document.querySelectorAll("[data-password-toggle]").forEach((toggle) => {
    const input = document.querySelector(`#${toggle.getAttribute("aria-controls")}`);
    toggle.addEventListener("click", () => {
      const visible = input.type === "password";
      setPasswordVisibility(toggle, input, visible);
    });
  });
}

function setPasswordVisibility(toggle, input, visible) {
  input.type = visible ? "text" : "password";
  toggle.setAttribute("aria-pressed", String(visible));
  toggle.setAttribute(
    "aria-label",
    visible ? "Ocultar contraseña" : "Mostrar contraseña",
  );
  toggle.querySelector(".password-icon-show").hidden = visible;
  toggle.querySelector(".password-icon-hide").hidden = !visible;
}

function makeElement(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined && value !== null) element.textContent = String(value);
  return element;
}

function displayValue(value, fallback = "—") {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value ? "Sí" : "No";
  return String(value);
}

function formatTimestamp(value) {
  if (value === undefined || value === null || value === "") return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return displayValue(value);
  return new Intl.DateTimeFormat("es-GT", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(date);
}

function formatRelativeTimestamp(value) {
  if (!value) return "Nunca";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Desconocido";

  const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `hace ${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `hace ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `hace ${hours} h`;
  const days = Math.floor(hours / 24);
  return `hace ${days} d`;
}

function serverCell(event) {
  const wrapper = makeElement("div", "server-cell");
  wrapper.append(
    makeElement("span", "server-hostname", displayValue(event.hostname)),
    makeElement("span", "server-agent-id", shortAgentId(event.agent_id)),
  );
  return wrapper;
}

const SVG_NS = "http://www.w3.org/2000/svg";

function svgIcon(paths) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  paths.forEach((definition) => {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", definition);
    svg.append(path);
  });
  return svg;
}

const SEVERITY_LABELS = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
const SEVERITY_TITLES = {
  critical: "Severidad crítica",
  high: "Severidad alta",
  medium: "Severidad media",
  low: "Severidad baja",
};

function severityBadge(severity) {
  const normalized = Object.hasOwn(SEVERITY_LABELS, severity) ? severity : "low";
  const badge = makeElement("span", `severity-badge ${normalized}`, SEVERITY_LABELS[normalized]);
  badge.title = SEVERITY_TITLES[normalized];
  return badge;
}

const STATUS_TITLES = {
  OPEN: "Requiere atención: aprobación pendiente, ejecución fallida o acción no autorizada",
  OBSERVED: "Registrado sin contención (solo auditoría, simulación o IP protegida)",
  CONTAINED: "Contención aplicada: el bloqueo temporal fue ejecutado",
  CLOSED: "Sin actividad durante la ventana de agrupación",
  PENDING_APPROVAL: "Pendiente de aprobación",
  APPROVED: "Aprobada: esperando que el agente la revalide y ejecute",
  REJECTED: "Rechazada: no se modificó el firewall",
  EXECUTED: "Ejecutada por el agente",
  SKIPPED: "Omitida por el agente tras revalidar",
  FAILED: "La ejecución falló",
  EXPIRED: "Venció antes de ser aprobada",
  DRY_RUN: "Simulada: no se modificó el firewall",
  ONLINE: "El agente reportó actividad recientemente",
  OFFLINE: "El agente dejó de reportar",
  UNKNOWN: "Sin información de presencia",
};
const STATUS_DISPLAY = { PENDING_APPROVAL: "PENDING" };

function statusBadge(code, className) {
  const normalized = String(code ?? "").toUpperCase();
  const key = (className ?? normalized).toLowerCase().replace(/[^a-z_]/g, "");
  const badge = makeElement(
    "span",
    `status-badge is-${key || "unknown"}`,
    STATUS_DISPLAY[normalized] ?? (normalized || "—"),
  );
  if (!className && STATUS_TITLES[normalized]) badge.title = STATUS_TITLES[normalized];
  return badge;
}

function presenceBadge(presence) {
  const normalized = ["online", "offline", "unknown"].includes(presence) ? presence : "unknown";
  return statusBadge(normalized.toUpperCase());
}

const TYPE_LABELS = {
  SSH_USER_ENUMERATION_ATTEMPT: "Enumeración de usuarios SSH",
  SSH_BRUTE_FORCE_ATTEMPT: "Fuerza bruta SSH",
  SSH_REPEATED_PREAUTH_ACTIVITY: "Actividad preauth SSH repetida",
};
const ACTION_LABELS = {
  NO_ACTION: "Sin acción",
  RECOMMEND_BLOCK_IP: "Recomendación: bloquear IP",
  RECOMMEND_BLOCK_IP_PORT: "Recomendación: bloquear IP y puerto",
  TEMPORARY_BLOCK_IP: "Bloqueo temporal de IP",
  TEMPORARY_BLOCK_IP_PORT: "Bloqueo temporal de IP y puerto",
};

const ACRONYMS = new Set(["ssh", "ip", "tcp", "udp", "id", "dns", "tls", "http", "https", "sudo", "pam"]);

function humanizeCode(code) {
  const words = String(code).toLowerCase().split("_").filter(Boolean);
  return words
    .map((word, index) => {
      if (ACRONYMS.has(word)) return word.toUpperCase();
      return index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
    })
    .join(" ");
}

function typeLabel(code) {
  if (!code) return "—";
  return TYPE_LABELS[code] ?? humanizeCode(code);
}

function actionLabel(code) {
  if (!code) return "—";
  return ACTION_LABELS[code] ?? humanizeCode(code);
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function labeledCell(label, className = "", value = undefined) {
  const cell = makeElement("td", className, value);
  cell.dataset.label = label;
  return cell;
}

function typeCell(label, code, className = "") {
  const cell = labeledCell(label, className);
  cell.append(
    makeElement("span", "cell-primary", typeLabel(code)),
    makeElement("span", "cell-secondary monospace", displayValue(code)),
  );
  return cell;
}

function timeCell(label, value, relative = false) {
  const cell = labeledCell(label, "timestamp");
  if (!value) {
    cell.textContent = "—";
    return cell;
  }
  const time = document.createElement("time");
  time.dateTime = value;
  time.textContent = relative ? formatRelativeTimestamp(value) : formatTimestamp(value);
  if (relative) {
    cell.append(time, makeElement("span", "cell-secondary", formatTimestamp(value)));
  } else {
    cell.append(time);
  }
  return cell;
}

function badgeCell(label, badge) {
  const cell = labeledCell(label);
  cell.append(badge);
  return cell;
}

function evidenceObject(event) {
  if (
    event.evidence !== null &&
    typeof event.evidence === "object" &&
    !Array.isArray(event.evidence)
  ) {
    return event.evidence;
  }
  return {};
}

function activateModule() {
  const serverTitle = authContext?.role === "superadmin" ? "Servidores" : "Mis servidores";
  const pageTitle = currentModule.key === "servers" ? serverTitle : currentModule.title;
  document.title = `${pageTitle} | Nexora`;
  elements.serversTitle.textContent = serverTitle;
  elements.pageTitle.textContent = pageTitle;
  elements.serverSelectorWrap.hidden = ["notifications", "servers", "users"].includes(
    currentModule.key,
  );
  document.querySelectorAll("[data-view]").forEach((view) => {
    view.hidden = view.dataset.view !== currentModule.key;
  });
  document.querySelectorAll(".nav-item[data-module]").forEach((link) => {
    if (link.dataset.module === "users") {
      link.hidden = authContext?.role !== "superadmin";
    }
    if (link.dataset.module === "servers") {
      link.querySelector(".nav-label").textContent = serverTitle;
      link.setAttribute("aria-label", serverTitle);
      link.title = serverTitle;
    }
    const active = link.dataset.module === currentModule.key;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

async function loadAuthContext() {
  const response = await fetch("/auth/me", {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    window.location.assign("/login");
    throw new Error("Authentication required");
  }

  authContext = await response.json();
  const scope = authContext.role === "superadmin" ? "Todos los servidores" : "Servidores asignados";
  elements.currentUser.textContent = `${authContext.username} · ${authContext.role} · ${scope}`;

  const params = new URLSearchParams(window.location.search);
  selectedAgentId = params.get("agent_id") || null;
}

function shortAgentId(agentId) {
  const value = displayValue(agentId, "");
  if (!value) return "sin-id";
  return value.length > 14 ? `${value.slice(0, 12)}…` : value;
}

function presenceLabel(presence) {
  const labels = {
    online: "En línea",
    offline: "Sin conexión",
    unknown: "Desconocido",
  };
  return labels[presence] ?? "Desconocido";
}

function presenceClass(presence) {
  if (presence === "online") return "agent-online";
  if (presence === "offline") return "agent-offline";
  return "agent-unknown";
}

function selectedAgent() {
  if (!selectedAgentId) return null;
  return knownAgents.find((agent) => agent.agent_id === selectedAgentId) ?? null;
}

function agentDisplayName(agent) {
  if (!agent) return "Todos los servidores";
  return `${displayValue(agent.hostname)} · ${shortAgentId(agent.agent_id)}`;
}

function renderAgentSelector() {
  const firstOption = makeElement("option", "", "Todos los servidores");
  firstOption.value = "";
  elements.agentSelector.replaceChildren(firstOption);

  knownAgents.forEach((agent) => {
    const option = makeElement(
      "option",
      "",
      `${displayValue(agent.hostname)} · ${shortAgentId(agent.agent_id)} · ${presenceLabel(agent.presence)}`,
    );
    option.value = agent.agent_id;
    option.selected = agent.agent_id === selectedAgentId;
    elements.agentSelector.append(option);
  });

  elements.agentSelector.value = selectedAgentId ?? "";
  syncAgentNavigationLinks();
  const selected = selectedAgent();
  elements.hostname.textContent = selected ? agentDisplayName(selected) : "Todos los servidores";
}

function updateAgentQueryInLocation() {
  const params = new URLSearchParams(window.location.search);
  if (selectedAgentId) params.set("agent_id", selectedAgentId);
  else params.delete("agent_id");

  const query = params.toString();
  window.history.replaceState(null, "", query ? `${normalizedPath}?${query}` : normalizedPath);
}

function syncAgentNavigationLinks() {
  document.querySelectorAll("a[href^='/dashboard']").forEach((link) => {
    if (link.dataset.keepQuery === "true") return;
    const url = new URL(link.getAttribute("href"), window.location.origin);
    const targetPath = url.pathname.replace(/\/+$/, "") || "/dashboard";
    const supportsAgent = [
      "/dashboard",
      "/dashboard/events",
      "/dashboard/detections",
      "/dashboard/incidents",
      "/dashboard/responses",
    ].includes(targetPath);

    if (supportsAgent && selectedAgentId) url.searchParams.set("agent_id", selectedAgentId);
    else url.searchParams.delete("agent_id");

    link.setAttribute("href", `${url.pathname}${url.search}`);
  });
}

function filterParams(form, limit) {
  const params = new URLSearchParams();
  new FormData(form).forEach((value, key) => {
    const normalized = String(value).trim();
    if (normalized) params.set(key, normalized);
  });
  if (selectedAgentId && currentModule.key !== "notifications") {
    params.set("agent_id", selectedAgentId);
  }
  if (limit) params.set("limit", String(limit));
  return params;
}

function endpointWithFilters(path, form, limit) {
  const query = filterParams(form, limit).toString();
  return query ? `${path}?${query}` : path;
}

function populateFiltersFromLocation() {
  const form = elements[`${currentModule.key}Filters`];
  if (!form) return;
  const params = new URLSearchParams(window.location.search);
  form.querySelectorAll("[name]").forEach((control) => {
    control.value = params.get(control.name) ?? "";
  });
}

function setApiState(state, message) {
  elements.apiIndicator.className = `status-dot is-${state}`;
  elements.apiStatus.textContent = message;
  elements.defenseApiStatus.textContent = message;
}

function renderPill(container, text, style = "neutral") {
  container.replaceChildren(makeElement("span", `value-pill is-${style}`, text));
}

function setKpi(element, value) {
  element.textContent = value === null || value === undefined ? "—" : String(value);
  element.classList.remove("loading-value");
}

function renderFleetSummary(agents) {
  const counts = { online: 0, offline: 0, unknown: 0 };
  agents.forEach((agent) => {
    const presence = ["online", "offline", "unknown"].includes(agent.presence)
      ? agent.presence
      : "unknown";
    counts[presence] += 1;
  });

  setKpi(elements.fleetTotal, agents.length);
  setKpi(elements.fleetOnline, counts.online);
  setKpi(elements.fleetOffline, counts.offline);
  elements.fleetUnknown.textContent = String(counts.unknown);
  elements.fleetUnknownWrap.hidden = counts.unknown === 0;

  const segments = elements.fleetBar.querySelectorAll(".fleet-segment");
  ["online", "offline", "unknown"].forEach((key, index) => {
    const share = agents.length === 0 ? 0 : (counts[key] / agents.length) * 100;
    segments[index].style.width = `${share}%`;
  });
  elements.fleetBar.setAttribute(
    "aria-label",
    agents.length === 0
      ? "No hay servidores registrados"
      : `${counts.online} en línea, ${counts.offline} sin conexión y ${counts.unknown} desconocidos de ${agents.length} servidores`,
  );
}

function renderFleetError() {
  [elements.fleetTotal, elements.fleetOnline, elements.fleetOffline].forEach((element) => {
    setKpi(element, null);
  });
  elements.fleetBar.querySelectorAll(".fleet-segment").forEach((segment) => {
    segment.style.width = "0%";
  });
  elements.fleetBar.setAttribute("aria-label", "Estado de la flota no disponible");
}

function updateCurrentUserScope() {
  const count = knownAgents.length;
  const scope = authContext.role === "superadmin"
    ? `${count} ${count === 1 ? "servidor" : "servidores"}`
    : `${count} ${count === 1 ? "servidor asignado" : "servidores asignados"}`;
  elements.currentUser.textContent = `${authContext.username} · ${authContext.role} · ${scope}`;
}

function showAgentOnlyStatus(show) {
  document.querySelectorAll("[data-agent-only]").forEach((item) => {
    item.hidden = !show;
  });
}

// El central no siempre conoce el modo de respuesta ni los bloqueos del
// agente; esos datos se ocultan en lugar de repetir «No disponible».
function syncOperationalStrip(status) {
  const unavailable = (value) => value === null || value === undefined;
  const items = {
    "response-mode": !unavailable(status?.response_mode),
    "automatic-blocking": !unavailable(status?.automatic_blocking_enabled),
    "metric-blocks": !unavailable(status?.live_response_blocks),
  };
  Object.entries(items).forEach(([id, available]) => {
    document.querySelector(`#${id}`).closest("div").hidden = !available;
  });
  const anyDetail = Object.values(items).some(Boolean) || Boolean(selectedAgent());
  document.querySelector(".status-panel").hidden = !anyDetail;
}

function renderStatus(status) {
  const selected = selectedAgent();
  const hostname = selected
    ? displayValue(status.hostname, selected.hostname)
    : "Todos los servidores";

  elements.hostname.textContent = selected ? agentDisplayName(selected) : "Todos los servidores";
  elements.defenseHostname.textContent = hostname;
  showAgentOnlyStatus(Boolean(selected));

  const blocksMetric = document.querySelector("#metric-blocks");
  if (status.live_response_blocks === null || status.live_response_blocks === undefined) {
    blocksMetric.textContent = "No disp.";
  } else {
    blocksMetric.textContent = displayValue(status.live_response_blocks, "0");
  }
  blocksMetric.classList.remove("loading-value");

  if (selected) {
    const presence = status.presence ?? selected.presence;
    elements.statusPresence.replaceChildren(presenceBadge(presence));
    elements.statusLastSeen.textContent = formatRelativeTimestamp(
      status.last_seen_at ?? selected.last_seen_at,
    );
    elements.statusLastSeen.title = formatTimestamp(status.last_seen_at ?? selected.last_seen_at);
  }

  syncOperationalStrip(status);

  const modeLabels = {
    audit_only: "Solo auditoría",
    assisted: "Asistido",
    automatic: "Automático",
  };
  if (status.response_mode === null || status.response_mode === undefined) {
    renderPill(elements.responseMode, "No disponible centralmente");
  } else {
    renderPill(
      elements.responseMode,
      modeLabels[status.response_mode] ?? displayValue(status.response_mode),
      status.response_mode === "automatic" ? "warning" : "neutral",
    );
  }

  if (
    status.automatic_blocking_enabled === null ||
    status.automatic_blocking_enabled === undefined
  ) {
    renderPill(elements.automaticBlocking, "No disponible centralmente");
  } else {
    renderPill(
      elements.automaticBlocking,
      status.automatic_blocking_enabled ? "Habilitado" : "Deshabilitado",
      status.automatic_blocking_enabled ? "warning" : "neutral",
    );
  }
}

function renderStatusError() {
  const blocksMetric = document.querySelector("#metric-blocks");
  blocksMetric.textContent = "—";
  blocksMetric.classList.remove("loading-value");
  elements.hostname.textContent = selectedAgent() ? agentDisplayName(selectedAgent()) : "Todos los servidores";
  elements.defenseHostname.textContent = "—";
  showAgentOnlyStatus(Boolean(selectedAgent()));
  renderPill(elements.statusPresence, "No disponible");
  elements.statusLastSeen.textContent = "—";
  syncOperationalStrip(null);
}

// Conteos exactos de incidentes activos mediante el contrato existente de
// /incidents (cada consulta pide una sola fila y usa el total devuelto).
const ACTIVE_INCIDENT_STATUSES = ["OPEN", "OBSERVED", "CONTAINED"];

async function fetchIncidentSummary(signal) {
  const count = async (status, severity) => {
    const params = new URLSearchParams({ status, limit: "1" });
    if (severity) params.set("severity", severity);
    if (selectedAgentId) params.set("agent_id", selectedAgentId);
    const page = await fetchJson(`/incidents?${params.toString()}`, signal);
    return Number.isInteger(page?.total) ? page.total : 0;
  };
  const totals = await Promise.all(
    ACTIVE_INCIDENT_STATUSES.flatMap((status) => [
      count(status),
      count(status, "critical"),
      count(status, "high"),
    ]),
  );
  const sum = (offset) => totals.filter((_, index) => index % 3 === offset)
    .reduce((accumulator, value) => accumulator + value, 0);
  return { active: sum(0), critical: sum(1), high: sum(2) };
}

function renderIncidentSummary(summary) {
  setKpi(elements.incidentsActive, summary?.active);
  setKpi(elements.incidentsCritical, summary?.critical);
  setKpi(elements.incidentsHigh, summary?.high);
}

function renderOverviewServers(agents) {
  if (agents.length === 0) {
    elements.overviewServers.replaceChildren(
      makeElement("li", "state-cell", "No hay servidores conectados."),
    );
    return;
  }
  const limit = 6;
  const rows = agents.slice(0, limit).map((agent) => {
    const row = makeElement("li", "server-row");
    const lastSeen = makeElement("time", "timestamp", formatRelativeTimestamp(agent.last_seen_at));
    if (agent.last_seen_at) {
      lastSeen.dateTime = agent.last_seen_at;
      lastSeen.title = formatTimestamp(agent.last_seen_at);
    }
    row.append(presenceBadge(agent.presence), serverCell(agent), lastSeen);
    return row;
  });
  if (agents.length > limit) {
    const more = makeElement("li", "state-cell");
    const link = makeElement("a", "view-all", `Ver los ${agents.length} servidores`);
    link.href = "/dashboard/servers";
    link.dataset.keepQuery = "true";
    more.append(link);
    rows.push(more);
  }
  elements.overviewServers.replaceChildren(...rows);
}

function stateRow(columns, message, error = false) {
  const cell = makeElement("td", error ? "state-cell is-error" : "state-cell", message);
  cell.colSpan = columns;
  const row = document.createElement("tr");
  row.append(cell);
  return row;
}

function serverLabelCell(label, entity) {
  const cell = labeledCell(label);
  cell.append(serverCell(entity));
  return cell;
}

function renderEvents(events, body, compact = false) {
  const columnCount = compact ? 3 : 6;
  if (events.length === 0) {
    body.replaceChildren(stateRow(columnCount, "No hay eventos registrados."));
    return;
  }

  const rows = events.map((event) => {
    const row = document.createElement("tr");
    if (compact) {
      const summary = labeledCell("Evento");
      summary.append(
        makeElement("span", "cell-primary event-type", displayValue(event.event_type)),
        makeElement(
          "span",
          "cell-secondary",
          [event.hostname, event.description].filter(Boolean).join(" · ") || "—",
        ),
      );
      row.append(
        timeCell("Fecha/hora", event.timestamp),
        badgeCell("Severidad", severityBadge(event.severity)),
        summary,
      );
      return row;
    }
    row.append(
      serverLabelCell("Servidor", event),
      timeCell("Fecha/hora", event.timestamp),
      badgeCell("Severidad", severityBadge(event.severity)),
      labeledCell("Categoría", "", displayValue(event.category)),
      labeledCell("Tipo", "event-type", displayValue(event.event_type)),
      labeledCell("Descripción", "is-wrap", displayValue(event.description)),
    );
    return row;
  });
  body.replaceChildren(...rows);
}

function renderDetections(detections, body, compact = false) {
  const columnCount = compact ? 4 : 6;
  if (detections.length === 0) {
    body.replaceChildren(stateRow(columnCount, "No hay detecciones registradas."));
    return;
  }

  const rows = detections.map((detection) => {
    const evidence = evidenceObject(detection);
    const row = document.createElement("tr");
    if (compact) {
      const type = typeCell("Tipo", detection.event_type);
      type.append(makeElement("span", "cell-secondary", displayValue(detection.hostname)));
      row.append(
        timeCell("Fecha/hora", detection.timestamp),
        badgeCell("Severidad", severityBadge(detection.severity)),
        type,
        labeledCell("IP origen", "monospace", displayValue(evidence.source_ip)),
      );
      return row;
    }
    row.append(
      serverLabelCell("Servidor", detection),
      badgeCell("Severidad", severityBadge(detection.severity)),
      typeCell("Tipo", detection.event_type),
      labeledCell("IP origen", "monospace", displayValue(evidence.source_ip)),
      timeCell("Fecha/hora", detection.timestamp),
      labeledCell("Descripción", "is-wrap", displayValue(detection.description)),
    );
    return row;
  });
  body.replaceChildren(...rows);
}

const EXECUTION_STATUSES = ["EXECUTED", "SKIPPED", "FAILED", "DRY_RUN"];

function renderResponses(responses) {
  if (responses.length === 0) {
    elements.responsesBody.replaceChildren(stateRow(8, "No hay respuestas registradas."));
    return;
  }

  const rows = responses.map((response) => {
    const evidence = evidenceObject(response);
    const row = document.createElement("tr");
    const status = String(evidence.status ?? "").toUpperCase();
    const statusCell = EXECUTION_STATUSES.includes(status)
      ? badgeCell("Estado", statusBadge(status))
      : labeledCell("Estado", "", displayValue(evidence.status));
    const action = labeledCell("Acción");
    action.append(
      makeElement("span", "cell-primary", actionLabel(evidence.action)),
      makeElement("span", "cell-secondary monospace", displayValue(evidence.action)),
    );
    row.append(
      serverLabelCell("Servidor", response),
      timeCell("Fecha/hora", response.timestamp),
      labeledCell("Tipo", "event-type", displayValue(response.event_type)),
      labeledCell("IP objetivo", "monospace", displayValue(evidence.target_ip)),
      action,
      statusCell,
      labeledCell("Ejecutado", "", displayValue(evidence.executed)),
      labeledCell("Motivo", "is-wrap", displayValue(evidence.reason, response.description)),
    );
    return row;
  });
  elements.responsesBody.replaceChildren(...rows);
}

// --- Incidentes -----------------------------------------------------------

const TIMELINE_KINDS = {
  event: { label: "EVENTO", icon: ["M2.5 4h11M2.5 8h11M2.5 12h7"] },
  detection: { label: "DETECCIÓN", icon: ["M8 2.2 14 13H2Z", "M8 6.6v3M8 11.4h.01"] },
  decision: { label: "DECISIÓN", icon: ["M8 1.8 14.2 8 8 14.2 1.8 8Z"] },
  execution: { label: "EJECUCIÓN", icon: ["M9 1.8 4 9h4l-1 5.2L12 7H8Z"] },
  evidence: {
    label: "EVIDENCIA",
    icon: ["M4 1.8h5l3 3v9.4H4Z", "M9 1.8v3h3", "M6 8.2h4M6 10.8h4"],
  },
  approval: { label: "APROBACIÓN", icon: ["M3 8.5 6.5 12 13 4.5"] },
  rejection: { label: "RECHAZO", icon: ["M4 4l8 8M12 4l-8 8"] },
};

function selectedIncidentId() {
  const value = new URLSearchParams(window.location.search).get("incident");
  return value && INCIDENT_ID_PATTERN.test(value) ? value : null;
}

function incidentOffset() {
  const value = Number.parseInt(
    new URLSearchParams(window.location.search).get("offset") ?? "0",
    10,
  );
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function localDateBoundary(value, endOfDay) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T${endOfDay ? "23:59:59.999" : "00:00:00"}`);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function incidentsEndpoint() {
  const params = new URLSearchParams();
  new FormData(elements.incidentsFilters).forEach((value, key) => {
    const normalized = String(value).trim();
    if (!normalized) return;
    if (key === "since" || key === "until") {
      const boundary = localDateBoundary(normalized, key === "until");
      if (boundary) params.set(key, boundary);
      return;
    }
    params.set(key, normalized);
  });
  if (selectedAgentId) params.set("agent_id", selectedAgentId);
  params.set("limit", String(INCIDENT_PAGE_SIZE));
  params.set("offset", String(incidentOffset()));
  return `/incidents?${params.toString()}`;
}

function incidentDetailEndpoint(incidentId, suffix = "") {
  const params = new URLSearchParams(window.location.search);
  const agentId = params.get("agent_id");
  const query = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : "";
  return `/incidents/${encodeURIComponent(incidentId)}${suffix}${query}`;
}

function incidentHref(incident) {
  const params = new URLSearchParams({
    incident: incident.incident_id,
    agent_id: incident.agent_id,
  });
  return `/dashboard/incidents?${params.toString()}`;
}

function incidentResponseText(incident) {
  if (!incident.last_action) return null;
  const status = incident.last_execution_status ? ` · ${incident.last_execution_status}` : "";
  return `${actionLabel(incident.last_action)}${status}`;
}

function incidentRow(incident, compact = false) {
  const row = document.createElement("tr");
  const type = typeCell("Tipo", incident.incident_type);
  const statusCell = badgeCell("Estado", statusBadge(incident.status));
  const response = incidentResponseText(incident);
  if (response && !compact) statusCell.append(makeElement("span", "cell-secondary", response));

  if (compact) {
    const primary = type.querySelector(".cell-primary");
    const link = makeElement("a", "incident-link cell-primary", primary.textContent);
    link.href = incidentHref(incident);
    link.dataset.keepQuery = "true";
    primary.replaceWith(link);
    row.append(
      badgeCell("Severidad", severityBadge(incident.severity)),
      type,
      serverLabelCell("Servidor", incident),
      labeledCell("IP origen", "monospace", displayValue(incident.source_ip)),
      statusCell,
      timeCell("Última actividad", incident.last_activity_at, true),
    );
    return row;
  }

  const idCell = labeledCell("");
  const link = makeElement("a", "incident-link monospace", incident.incident_id);
  link.href = incidentHref(incident);
  link.dataset.keepQuery = "true";
  idCell.append(link);
  row.append(
    idCell,
    badgeCell("Severidad", severityBadge(incident.severity)),
    type,
    serverLabelCell("Servidor", incident),
    labeledCell("IP origen", "monospace", displayValue(incident.source_ip)),
    statusCell,
    timeCell("Última actividad", incident.last_activity_at, true),
  );
  return row;
}

function renderIncidents(page) {
  const incidents = Array.isArray(page?.items) ? page.items : [];
  const total = Number.isInteger(page?.total) ? page.total : incidents.length;
  const offset = Number.isInteger(page?.offset) ? page.offset : 0;
  elements.incidentsCount.textContent = `${total} ${total === 1 ? "incidente" : "incidentes"}`;
  elements.incidentsPage.textContent = total === 0
    ? "—"
    : `${offset + 1}–${offset + incidents.length} de ${total}`;
  elements.incidentsPrevious.disabled = offset <= 0;
  elements.incidentsNext.disabled = offset + incidents.length >= total;

  if (incidents.length === 0) {
    elements.incidentsBody.replaceChildren(stateRow(7, "No hay incidentes con estos filtros."));
    return;
  }
  elements.incidentsBody.replaceChildren(...incidents.map((incident) => incidentRow(incident)));
}

function renderOverviewIncidents(page) {
  const incidents = Array.isArray(page?.items) ? page.items : [];
  if (incidents.length === 0) {
    elements.overviewIncidentsBody.replaceChildren(
      stateRow(6, "Sin incidentes registrados. Las detecciones relevantes aparecerán aquí."),
    );
    return;
  }
  elements.overviewIncidentsBody.replaceChildren(
    ...incidents.map((incident) => incidentRow(incident, true)),
  );
}

function appendDetail(list, label, value, className = "") {
  const wrapper = document.createElement("div");
  const term = makeElement("dt", "", label);
  const description = makeElement("dd", className);
  if (value instanceof Node) description.append(value);
  else description.textContent = displayValue(value);
  wrapper.append(term, description);
  list.append(wrapper);
}

function stackedValue(primary, secondary, primaryClass = "") {
  const wrapper = document.createDocumentFragment();
  wrapper.append(makeElement("span", primaryClass, displayValue(primary)));
  if (secondary) wrapper.append(makeElement("span", "cell-secondary", secondary));
  return wrapper;
}

function durationLabel(seconds) {
  if (!Number.isInteger(seconds)) return null;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

function expiryLabel(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const minutes = Math.round((date.getTime() - Date.now()) / 60_000);
  if (minutes <= 0) return `${formatTimestamp(value)} (vencida)`;
  if (minutes < 60) return `${formatTimestamp(value)} (en ${minutes} min)`;
  return `${formatTimestamp(value)} (en ${Math.round(minutes / 60)} h)`;
}

function timelineKindOf(entry) {
  const rejected = entry.kind === "approval" && (
    entry.event_type === "RESPONSE_APPROVAL_DENIED" || entry.evidence?.status === "REJECTED"
  );
  return rejected ? "rejection" : entry.kind;
}

function timelineTitle(entry, kind) {
  const evidence = entry.evidence && typeof entry.evidence === "object" ? entry.evidence : {};
  if (!entry.available) return "Evento pendiente de sincronizar";
  if (kind === "detection") return typeLabel(entry.event_type);
  if (kind === "decision") return actionLabel(evidence.action);
  if (kind === "execution") return actionLabel(evidence.action ?? entry.event_type);
  if (kind === "evidence") return "Evidencia forense capturada";
  if (kind === "approval" || kind === "rejection") {
    return displayValue(entry.description, humanizeCode(entry.event_type ?? kind));
  }
  return entry.event_type ? humanizeCode(entry.event_type) : displayValue(entry.description);
}

function timelineSummary(entry, kind) {
  const evidence = entry.evidence && typeof entry.evidence === "object" ? entry.evidence : {};
  if (!entry.available) return "Aún no se sincroniza con el servidor central.";
  if (kind === "event") {
    return [evidence.user && `usuario ${evidence.user}`, evidence.ip, entry.description]
      .filter(Boolean)
      .join(" · ");
  }
  if (kind === "detection") {
    const attempts = Number.isInteger(evidence.attempt_count)
      ? `${evidence.attempt_count} intentos`
      : null;
    return [attempts, evidence.source_ip && `origen ${evidence.source_ip}`]
      .filter(Boolean)
      .join(" · ");
  }
  if (kind === "evidence") {
    const size = Number.isInteger(evidence.total_bytes) ? formatBytes(evidence.total_bytes) : null;
    const CAPTURE_STATES = { complete: "completa", partial: "parcial", failed: "fallida" };
    const state = CAPTURE_STATES[evidence.status] ?? evidence.status;
    return [state && `captura ${state}`, size].filter(Boolean).join(" · ");
  }
  if (kind === "decision") {
    const service = evidence.protocol && evidence.port ? `${evidence.protocol}/${evidence.port}` : null;
    const duration = durationLabel(evidence.duration_seconds ?? evidence.selected_duration_seconds);
    return [evidence.target_ip, service, duration, evidence.mode && `modo ${evidence.mode}`]
      .filter(Boolean)
      .join(" · ");
  }
  if (kind === "approval" || kind === "rejection") {
    return evidence.reason ? `Motivo: ${evidence.reason}` : "";
  }
  if (kind === "execution") {
    const approved = evidence.approved_by ? `aprobada por ${evidence.approved_by}` : null;
    return [evidence.target_ip, approved, evidence.reason].filter(Boolean).join(" · ");
  }
  return displayValue(entry.description, "");
}

function technicalValue(value) {
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  return text.length > 500 ? `${text.slice(0, 500)}…` : text;
}

function technicalDetails(entry) {
  const details = makeElement("details", "tech-details");
  details.append(makeElement("summary", "", "Detalles técnicos"));
  const list = makeElement("dl", "tech-list");
  const rows = [
    ["Entrada", entry.event_id],
    ["Tipo", entry.event_type],
    ["Categoría", entry.category],
    ["Severidad", entry.severity],
    ["Fuente", entry.source],
    ...Object.entries(entry.evidence && typeof entry.evidence === "object" ? entry.evidence : {}),
  ];
  rows.forEach(([key, value]) => {
    if (value === null || value === undefined || value === "") return;
    const wrapper = document.createElement("div");
    wrapper.append(makeElement("dt", "", key), makeElement("dd", "", technicalValue(value)));
    list.append(wrapper);
  });
  details.append(list);
  return details;
}

// Eventos consecutivos del mismo tipo (p. ej. decenas de intentos SSH) se
// muestran como un solo hito expandible para que la cronología siga legible.
function groupTimeline(timeline) {
  const groups = [];
  timeline.forEach((entry) => {
    const previous = groups[groups.length - 1];
    const sameKind = previous
      && entry.kind === "event"
      && entry.available
      && previous[0].kind === "event"
      && previous[0].available
      && previous[0].event_type === entry.event_type;
    if (sameKind) previous.push(entry);
    else groups.push([entry]);
  });
  return groups;
}

function groupSummary(group) {
  const unique = (key) => [...new Set(group.map((entry) => entry.evidence?.[key]).filter(Boolean))];
  const users = unique("user");
  const addresses = unique("ip");
  const shown = users.slice(0, 3).join(", ");
  return [
    users.length > 0 && `${users.length} ${users.length === 1 ? "usuario" : "usuarios"} (${shown}${users.length > 3 ? "…" : ""})`,
    addresses.length > 0 && `IP ${addresses.slice(0, 2).join(", ")}${addresses.length > 2 ? "…" : ""}`,
  ].filter(Boolean).join(" · ");
}

function groupDetails(group, timeFormat) {
  const details = makeElement("details", "tech-details");
  details.append(makeElement("summary", "", `Ver los ${group.length} eventos`));
  const list = makeElement("dl", "tech-list");
  group.forEach((entry) => {
    const wrapper = document.createElement("div");
    const date = new Date(entry.timestamp);
    wrapper.append(
      makeElement("dt", "", Number.isNaN(date.getTime()) ? "—" : timeFormat.format(date)),
      makeElement("dd", "", timelineSummary(entry, "event") || displayValue(entry.event_id)),
    );
    list.append(wrapper);
  });
  details.append(list);
  return details;
}

function renderIncidentTimeline(timeline) {
  elements.incidentTimelineCount.textContent =
    `${timeline.length} ${timeline.length === 1 ? "entrada" : "entradas"}`;
  if (timeline.length === 0) {
    elements.incidentTimeline.replaceChildren(makeElement("li", "state-cell", "Sin entradas."));
    return;
  }
  const dayFormat = new Intl.DateTimeFormat("es-GT", { dateStyle: "long" });
  const timeFormat = new Intl.DateTimeFormat("es-GT", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const items = [];
  let currentDay = null;

  groupTimeline(timeline).forEach((group) => {
    const entry = group[0];
    const date = new Date(entry.timestamp);
    const valid = !Number.isNaN(date.getTime());
    const day = valid ? dayFormat.format(date) : null;
    if (day && day !== currentDay) {
      currentDay = day;
      items.push(makeElement("li", "timeline-day", day));
    }

    const kind = timelineKindOf(entry);
    const definition = TIMELINE_KINDS[kind] ?? { label: String(kind).toUpperCase(), icon: [] };
    const item = makeElement("li", `timeline-item kind-${kind}`);
    const marker = makeElement("span", "timeline-marker");
    marker.append(svgIcon(definition.icon));

    const body = makeElement("div", "timeline-body");
    const meta = makeElement("div", "timeline-meta");
    const last = group[group.length - 1];
    const lastDate = new Date(last.timestamp);
    const range = group.length > 1 && !Number.isNaN(lastDate.getTime())
      ? `${valid ? timeFormat.format(date) : "—"} – ${timeFormat.format(lastDate)}`
      : valid ? timeFormat.format(date) : "—";
    const time = makeElement("time", "timeline-time", range);
    time.dateTime = entry.timestamp;
    meta.append(makeElement("span", "timeline-kind", definition.label), time);
    const executionStatus = kind === "execution" ? entry.evidence?.status : null;
    if (executionStatus) meta.append(statusBadge(executionStatus));
    if (group.length > 1) {
      body.append(
        meta,
        makeElement("p", "timeline-title", `${timelineTitle(entry, kind)} · ${group.length} eventos`),
        makeElement("p", "timeline-summary", groupSummary(group)),
        groupDetails(group, timeFormat),
      );
    } else {
      body.append(meta, makeElement("p", "timeline-title", timelineTitle(entry, kind)));
      const summary = timelineSummary(entry, kind);
      if (summary) body.append(makeElement("p", "timeline-summary", summary));
      if (entry.available) body.append(technicalDetails(entry));
    }

    item.append(marker, body);
    items.push(item);
  });
  elements.incidentTimeline.replaceChildren(...items);
}

function renderIncidentResponse(detail) {
  const list = elements.incidentResponse;
  list.replaceChildren();
  const decision = detail.decision?.evidence ?? null;
  const execution = detail.execution?.evidence ?? null;
  if (!decision && !execution) {
    list.append(makeElement("div", "state-cell", "Sin decisión registrada."));
    return;
  }
  if (decision) {
    appendDetail(list, "Acción", stackedValue(actionLabel(decision.action), decision.action));
    appendDetail(list, "Modo", decision.mode, "monospace");
    appendDetail(list, "Objetivo", decision.target_ip, "monospace");
    if (decision.protocol && decision.port) {
      appendDetail(list, "Servicio", `${decision.protocol}/${decision.port}`, "monospace");
    }
    appendDetail(
      list,
      "Duración",
      durationLabel(decision.duration_seconds ?? decision.selected_duration_seconds),
    );
    if (decision.recurrence_level !== null && decision.recurrence_level !== undefined) {
      appendDetail(
        list,
        "Reincidencia",
        `Nivel ${decision.recurrence_level} · ${decision.previous_incidents ?? 0} previas`,
      );
    }
    appendDetail(list, "Motivo", decision.reason);
  }
  if (execution) {
    appendDetail(list, "Ejecución", execution.status ? statusBadge(execution.status) : null);
    appendDetail(list, "Ejecutado", execution.executed);
    appendDetail(list, "Resultado", execution.reason);
  }
}

function captureStatusClass(status) {
  const value = String(status ?? "").toLowerCase();
  if (["ok", "complete", "completed", "captured"].includes(value)) return "ok";
  if (["error", "failed"].includes(value)) return "failed";
  if (["skipped", "unavailable"].includes(value)) return "skipped";
  return "unknown";
}

function renderIncidentEvidence(evidence) {
  elements.incidentEvidenceCount.textContent =
    `${evidence.length} ${evidence.length === 1 ? "captura" : "capturas"}`;
  if (evidence.length === 0) {
    elements.incidentEvidence.replaceChildren(
      makeElement("li", "state-cell", "No hay evidencia capturada para este incidente."),
    );
    return;
  }
  const items = evidence.map((capture) => {
    const item = makeElement("li", "evidence-item");
    const head = makeElement("div", "evidence-head");
    const title = makeElement("span", "evidence-title", `Captura forense ampliada ${shortAgentId(capture.capture_id)}`);
    title.title = capture.capture_id;
    head.append(title, statusBadge(displayValue(capture.status, "desconocido"), captureStatusClass(capture.status)));
    if (capture.truncated) head.append(makeElement("span", "cell-secondary", "truncada por límite de tamaño"));

    const meta = makeElement("div", "evidence-meta");
    const when = makeElement("span", "");
    when.append("Capturada ", makeElement("strong", "", formatTimestamp(capture.captured_at)));
    const size = makeElement("span", "");
    size.append("Tamaño ", makeElement("strong", "", formatBytes(capture.total_bytes)));
    const files = capture.artifacts ?? [];
    const count = makeElement("span", "");
    count.append("Archivos ", makeElement("strong", "", String(files.length)));
    meta.append(when, size, count);

    const artifacts = makeElement("ul", "artifact-list");
    files.forEach((artifact) => {
      const row = makeElement("li", "artifact-row");
      const name = makeElement("span", "artifact-name", artifact.file ?? artifact.name);
      name.title = artifact.sha256 ? `${artifact.name} · sha256 ${artifact.sha256}` : artifact.name;
      if (artifact.name === "quick_snapshot") {
        name.append(makeElement("small", "", "Instantánea rápida tomada al detectar, antes de la contención"));
      }
      row.append(
        name,
        statusBadge(displayValue(artifact.status, "desconocido"), captureStatusClass(artifact.status)),
        makeElement("span", "artifact-size", artifact.bytes ? formatBytes(artifact.bytes) : "—"),
      );
      artifacts.append(row);
    });
    item.append(head, meta);
    if (files.length > 0) item.append(artifacts);
    return item;
  });
  elements.incidentEvidence.replaceChildren(...items);
}

const pendingRejectReasons = new Map();

function showIncidentActionsAlert(message, error = true) {
  elements.incidentActionsAlert.textContent = message;
  elements.incidentActionsAlert.classList.toggle("is-success", !error);
  elements.incidentActionsAlert.hidden = false;
}

function confirmApproval(action) {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "confirm-dialog";
    dialog.setAttribute("aria-labelledby", "confirm-approval-title");
    const form = makeElement("div", "confirm-body");
    form.append(makeElement("h2", "", "Confirmar aprobación"));
    form.firstChild.id = "confirm-approval-title";
    form.append(makeElement("p", "confirm-lead", "Se aprobará la siguiente respuesta:"));
    const fields = makeElement("dl", "confirm-fields");
    appendDetail(fields, "Acción", actionLabel(action.action));
    appendDetail(fields, "IP", action.target_ip, "monospace");
    const target = [action.protocol ? action.protocol.toUpperCase() : null, action.port]
      .filter((part) => part !== null && part !== undefined)
      .join(" / ");
    appendDetail(fields, "Protocolo / puerto", target || "No aplica");
    appendDetail(fields, "Duración", durationLabel(action.duration_seconds) ?? "No aplica");
    form.append(fields);
    form.append(
      makeElement(
        "p",
        "confirm-note",
        "El agente volverá a validar las protecciones antes de ejecutar la respuesta.",
      ),
    );
    const cancel = makeElement("button", "secondary-action", "Cancelar");
    cancel.type = "button";
    const confirm = makeElement("button", "primary-action", "Confirmar aprobación");
    confirm.type = "button";
    const row = makeElement("div", "action-buttons");
    row.append(cancel, confirm);
    form.append(row);
    dialog.append(form);

    let result = false;
    cancel.addEventListener("click", () => dialog.close());
    confirm.addEventListener("click", () => {
      result = true;
      dialog.close();
    });
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(result);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}

async function decideIncidentAction(incident, action, verb, buttons, reasonInput) {
  buttons.forEach((button) => { button.disabled = true; });
  elements.incidentActionsAlert.hidden = true;
  const params = new URLSearchParams({ agent_id: incident.agent_id });
  const path = `/incidents/${encodeURIComponent(incident.incident_id)}/actions/${encodeURIComponent(action.action_id)}/${verb}?${params.toString()}`;
  const reason = reasonInput ? reasonInput.value.trim() : "";
  try {
    await authenticatedPost(path, verb === "reject" && reason ? { reason } : {});
    pendingRejectReasons.delete(action.action_id);
    showIncidentActionsAlert(
      verb === "approve"
        ? "Acción aprobada. El agente la validará y ejecutará en su próximo ciclo."
        : "Acción rechazada. No se modificará el firewall.",
      false,
    );
    await refreshAndReschedule();
  } catch (error) {
    showIncidentActionsAlert(error.message);
    buttons.forEach((button) => { button.disabled = false; });
  }
}

function renderActionBlock(detail, action) {
  const pending = action.status === "PENDING_APPROVAL";
  const block = makeElement("div", "action-block");

  const head = makeElement("div", "action-head");
  const name = makeElement("div", "action-name", actionLabel(action.action));
  name.append(makeElement("small", "", action.action));
  head.append(name, statusBadge(action.status));

  const fields = makeElement("dl", "action-fields");
  appendDetail(fields, "IP objetivo", action.target_ip, "monospace");
  appendDetail(fields, "Protocolo", action.protocol ? action.protocol.toUpperCase() : "No aplica");
  appendDetail(fields, "Puerto", action.port ?? "No aplica");
  appendDetail(fields, "Duración", durationLabel(action.duration_seconds));
  if (pending) {
    appendDetail(fields, "Vence", expiryLabel(action.expires_at) ?? formatTimestamp(action.expires_at));
    const proposalReason = detail.decision?.evidence?.reason;
    if (proposalReason) {
      const wide = document.createElement("div");
      wide.className = "is-wide";
      wide.append(makeElement("dt", "", "Motivo"), makeElement("dd", "", proposalReason));
      fields.append(wide);
    }
  } else {
    if (action.decided_by) {
      appendDetail(
        fields,
        action.status === "REJECTED" ? "Rechazada por" : "Aprobada por",
        `${action.decided_by} · ${formatTimestamp(action.decided_at)}`,
      );
    } else {
      appendDetail(fields, "Vencimiento", formatTimestamp(action.expires_at));
    }
    const outcome = [action.decision_reason && `Motivo: ${action.decision_reason}`, action.result_reason]
      .filter(Boolean)
      .join(" · ");
    if (outcome) {
      const wide = document.createElement("div");
      wide.className = "is-wide";
      wide.append(makeElement("dt", "", "Detalle"), makeElement("dd", "", outcome));
      fields.append(wide);
    }
  }
  block.append(head, fields);

  if (pending && authContext?.role === "superadmin") {
    const controls = makeElement("div", "action-controls");
    const reasonId = `reject-reason-${action.action_id}`;
    const label = makeElement("label", "", "Motivo del rechazo (opcional)");
    label.htmlFor = reasonId;
    const reasonInput = document.createElement("input");
    reasonInput.id = reasonId;
    reasonInput.type = "text";
    reasonInput.maxLength = 500;
    reasonInput.autocomplete = "off";
    reasonInput.value = pendingRejectReasons.get(action.action_id) ?? "";
    reasonInput.addEventListener("input", () => {
      pendingRejectReasons.set(action.action_id, reasonInput.value);
    });
    label.append(reasonInput);

    const reject = makeElement("button", "secondary-action", "Rechazar");
    reject.type = "button";
    const approve = makeElement("button", "primary-action", "Aprobar respuesta");
    approve.type = "button";
    const buttons = [reject, approve];
    approve.addEventListener("click", async () => {
      approve.disabled = true;
      const confirmed = await confirmApproval(action);
      approve.disabled = false;
      if (!confirmed) return;
      decideIncidentAction(detail.incident, action, "approve", buttons, null);
    });
    reject.addEventListener("click", () => {
      decideIncidentAction(detail.incident, action, "reject", buttons, reasonInput);
    });
    const row = makeElement("div", "action-buttons");
    row.append(reject, approve);
    controls.append(label, row);
    block.append(controls);
  } else if (pending) {
    block.append(
      makeElement("p", "action-footnote", "Solo un superadmin puede aprobar o rechazar esta acción."),
    );
  } else if (action.status === "APPROVED") {
    block.append(
      makeElement("p", "action-footnote", "Aprobada. El agente la revalidará y la ejecutará en su próximo ciclo."),
    );
  }
  return block;
}

function renderIncidentActions(detail) {
  const actions = Array.isArray(detail.actions) ? detail.actions : [];
  const section = elements.incidentActionsSection;
  section.hidden = actions.length === 0;
  if (actions.length === 0) {
    elements.incidentActions.replaceChildren();
    return;
  }
  const hasPending = actions.some((action) => action.status === "PENDING_APPROVAL");
  section.classList.toggle("is-resolved", !hasPending);
  elements.incidentActionsTitle.textContent = hasPending ? "Respuesta propuesta" : "Respuesta asistida";
  elements.incidentActionsHint.textContent = hasPending
    ? "El agente aplicará la acción solo si usted la aprueba y la revalida antes de ejecutarla."
    : "Resultado de las acciones propuestas para este incidente.";
  const ordered = [...actions].sort((first, second) => {
    const pendingFirst = Number(second.status === "PENDING_APPROVAL") - Number(first.status === "PENDING_APPROVAL");
    return pendingFirst || String(second.requested_at).localeCompare(String(first.requested_at));
  });
  elements.incidentActions.replaceChildren(...ordered.map((action) => renderActionBlock(detail, action)));
}

function lastResponseSummary(detail) {
  const incident = detail.incident;
  const actions = Array.isArray(detail.actions) ? detail.actions : [];
  const pending = actions.find((action) => action.status === "PENDING_APPROVAL");
  if (pending) {
    return {
      action: pending.action,
      status: "PENDING_APPROVAL",
      reason: "Esperando la decisión de un superadmin.",
    };
  }
  const execution = detail.execution?.evidence ?? null;
  if (execution) {
    return {
      action: execution.action ?? detail.decision?.evidence?.action ?? incident.last_action,
      status: execution.status,
      reason: execution.reason,
    };
  }
  const latest = [...actions].sort((first, second) =>
    String(second.requested_at).localeCompare(String(first.requested_at)),
  )[0];
  if (latest) {
    return {
      action: latest.action,
      status: latest.result_status ?? latest.status,
      reason: latest.result_reason ?? latest.decision_reason,
    };
  }
  if (incident.last_action) {
    return { action: incident.last_action, status: incident.last_execution_status, reason: null };
  }
  return null;
}

function renderIncidentDetail(detail) {
  const incident = detail.incident;
  elements.incidentDetailTitle.textContent = incident.incident_id;
  document.title = `${incident.incident_id} | Nexora`;

  elements.incidentKicker.replaceChildren(
    `${typeLabel(incident.incident_type)} · `,
    makeElement("span", "monospace", incident.incident_type),
  );
  elements.incidentBadges.replaceChildren(
    severityBadge(incident.severity),
    statusBadge(incident.status),
  );

  const header = elements.incidentHeader;
  header.replaceChildren();
  appendDetail(header, "Servidor", stackedValue(incident.hostname, shortAgentId(incident.agent_id), "monospace"));
  appendDetail(
    header,
    "IP origen",
    stackedValue(
      incident.source_ip,
      `${incident.detection_count} ${incident.detection_count === 1 ? "detección" : "detecciones"}`,
      "monospace",
    ),
  );
  const lastActivity = incident.closed_at
    ? `Cerrado: ${formatTimestamp(incident.closed_at)}`
    : `Última actividad: ${formatTimestamp(incident.last_activity_at)}`;
  appendDetail(header, "Fecha", stackedValue(formatTimestamp(incident.opened_at), lastActivity));
  appendDetail(
    header,
    "Reincidencia",
    incident.recurrence_level ? `Nivel ${incident.recurrence_level}` : null,
  );
  const response = lastResponseSummary(detail);
  appendDetail(
    header,
    "Última acción",
    response ? stackedValue(actionLabel(response.action), response.action) : null,
  );
  const result = document.createDocumentFragment();
  if (response?.status) result.append(statusBadge(response.status));
  if (response?.reason) result.append(makeElement("span", "cell-secondary", response.reason));
  appendDetail(header, "Resultado", result.childNodes.length > 0 ? result : null);

  renderIncidentActions(detail);
  renderIncidentResponse(detail);
  renderIncidentEvidence(Array.isArray(detail.evidence) ? detail.evidence : []);
}

function renderIncidentDetailError(message) {
  elements.incidentDetailTitle.textContent = "Incidente";
  elements.incidentKicker.textContent = "";
  elements.incidentBadges.replaceChildren();
  elements.incidentHeader.replaceChildren(makeElement("div", "state-cell is-error", message));
  elements.incidentActionsSection.hidden = true;
  elements.incidentTimeline.replaceChildren();
  elements.incidentResponse.replaceChildren();
  elements.incidentEvidence.replaceChildren();
}

function configureIncidentView() {
  if (currentModule.key !== "incidents") return;
  const detailMode = selectedIncidentId() !== null;
  elements.incidentsListSection.hidden = detailMode;
  elements.incidentDetailSection.hidden = !detailMode;
  const backParams = new URLSearchParams();
  if (selectedAgentId) backParams.set("agent_id", selectedAgentId);
  elements.incidentBack.href = backParams.toString()
    ? `/dashboard/incidents?${backParams.toString()}`
    : "/dashboard/incidents";

  const movePage = (direction) => {
    const params = new URLSearchParams(window.location.search);
    const next = Math.max(0, incidentOffset() + direction * INCIDENT_PAGE_SIZE);
    if (next > 0) params.set("offset", String(next));
    else params.delete("offset");
    const query = params.toString();
    window.history.replaceState(null, "", query ? `${normalizedPath}?${query}` : normalizedPath);
    refreshAndReschedule();
  };
  elements.incidentsPrevious.addEventListener("click", () => movePage(-1));
  elements.incidentsNext.addEventListener("click", () => movePage(1));
}

const NOTIFICATION_STATUS = {
  sent: ["ENVIADA", "ok"],
  failed: ["FALLIDA", "failed"],
  pending: ["PENDIENTE", "observed"],
};

function renderNotifications(notifications) {
  if (notifications.length === 0) {
    elements.notificationsBody.replaceChildren(stateRow(7, "No hay notificaciones registradas."));
    return;
  }
  const rows = notifications.map((notification) => {
    const row = document.createElement("tr");
    const [statusText, statusClass] = NOTIFICATION_STATUS[notification.status]
      ?? [displayValue(notification.status), "unknown"];
    const statusBadgeElement = makeElement("span", `status-badge is-${statusClass}`, statusText);
    row.append(
      timeCell("Fecha", notification.created_at),
      labeledCell("Servidor", "monospace", displayValue(notification.hostname)),
      badgeCell("Severidad", severityBadge(notification.severity)),
      labeledCell("Evento", "monospace", displayValue(notification.event_id)),
      labeledCell("Destinatario", "", displayValue(notification.recipient)),
      labeledCell("Proveedor", "", displayValue(notification.provider)),
      badgeCell("Estado", statusBadgeElement),
    );
    return row;
  });
  elements.notificationsBody.replaceChildren(...rows);
}

function renderNotificationSummary(summary) {
  elements.notificationsTotal.textContent = String(summary.total);
  elements.notificationsSent.textContent = String(summary.sent);
  elements.notificationsFailed.textContent = String(summary.failed);
  elements.notificationsPending.textContent = String(summary.pending);
}

function renderServersSummary(agents) {
  const counts = { online: 0, offline: 0, unknown: 0 };
  agents.forEach((agent) => {
    counts[["online", "offline"].includes(agent.presence) ? agent.presence : "unknown"] += 1;
  });
  document.querySelector("#servers-total").textContent = String(agents.length);
  document.querySelector("#servers-online").textContent = String(counts.online);
  document.querySelector("#servers-offline").textContent = String(counts.offline);
  document.querySelector("#servers-unknown").textContent = String(counts.unknown);
  document.querySelector("#servers-unknown-wrap").hidden = counts.unknown === 0;
}

function renderAgents(agents) {
  renderServersSummary(agents);
  elements.serversCount.textContent = `${agents.length} ${agents.length === 1 ? "servidor" : "servidores"}`;
  if (agents.length === 0) {
    elements.serversBody.replaceChildren(
      stateRow(5, "No tiene servidores conectados. Use Conectar servidor para comenzar."),
    );
    return;
  }

  const rows = agents.map((agent) => {
    const row = document.createElement("tr");
    const presence = ["online", "offline", "unknown"].includes(agent.presence)
      ? agent.presence
      : "unknown";

    const hostCell = labeledCell("Servidor");
    hostCell.append(makeElement("span", "server-hostname", displayValue(agent.hostname)));
    const actions = makeElement("div", "server-actions");
    const incidentsLink = makeElement("a", "", "Ver incidentes");
    incidentsLink.href = `/dashboard/incidents?${new URLSearchParams({ agent_id: agent.agent_id }).toString()}`;
    incidentsLink.dataset.keepQuery = "true";
    actions.append(incidentsLink);
    hostCell.append(actions);

    const agentCell = labeledCell("Agent ID", "monospace", shortAgentId(agent.agent_id));
    agentCell.title = displayValue(agent.agent_id, "");

    row.dataset.agentId = agent.agent_id;
    row.append(
      hostCell,
      badgeCell("Estado", presenceBadge(presence)),
      timeCell("Último contacto", agent.last_seen_at, true),
      agentCell,
      timeCell("Registrado", agent.registered_at),
    );
    return row;
  });
  elements.serversBody.replaceChildren(...rows);
}

function showUsersAlert(message, error = true) {
  elements.usersAlert.textContent = message;
  elements.usersAlert.classList.toggle("is-success", !error);
  elements.usersAlert.hidden = false;
}

async function authenticatedPost(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": authContext.csrf_token,
    },
    body: JSON.stringify(body),
  });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Authentication required");
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail ?? `HTTP ${response.status}`);
  }
  if (response.status === 204) return null;
  return response.json();
}

function renderUsers(users) {
  elements.usersCount.textContent = `${users.length} usuarios`;
  if (users.length === 0) {
    elements.usersBody.replaceChildren(stateRow(6, "No hay usuarios registrados."));
    return;
  }
  const rows = users.map((user) => {
    const row = document.createElement("tr");
    const roleSelect = document.createElement("select");
    roleSelect.className = "table-select";
    ["viewer", "superadmin"].forEach((role) => {
      const option = makeElement("option", "", role);
      option.value = role;
      option.selected = user.role === role;
      roleSelect.append(option);
    });
    roleSelect.setAttribute("aria-label", `Rol de ${user.username}`);
    roleSelect.addEventListener("change", async () => {
      try {
        await authenticatedPost(`/admin/users/${user.id}/role`, {
          role: roleSelect.value,
        });
        await refreshAndReschedule();
      } catch (error) {
        roleSelect.value = user.role;
        showUsersAlert(error.message);
      }
    });
    const roleCell = labeledCell("Rol");
    roleCell.append(roleSelect);

    const actionButton = makeElement(
      "button",
      "table-action",
      user.active ? "Desactivar" : "Activar",
    );
    actionButton.type = "button";
    actionButton.setAttribute(
      "aria-label",
      `${user.active ? "Desactivar" : "Activar"} a ${user.username}`,
    );
    actionButton.addEventListener("click", async () => {
      try {
        await authenticatedPost(`/admin/users/${user.id}/status`, {
          active: !user.active,
        });
        await refreshAndReschedule();
      } catch (error) {
        showUsersAlert(error.message);
      }
    });
    const actionCell = labeledCell("Acciones");
    actionCell.append(actionButton);
    row.append(
      labeledCell("Usuario", "monospace", user.username),
      roleCell,
      labeledCell(
        "Servidores",
        "",
        user.role === "superadmin" ? "Todos" : String(user.server_count ?? 0),
      ),
      labeledCell("Estado", user.active ? "user-active" : "user-inactive", user.active ? "Activo" : "Inactivo"),
      timeCell("Creado", user.created_at),
      actionCell,
    );
    return row;
  });
  elements.usersBody.replaceChildren(...rows);
}

async function fetchJson(path, signal) {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal,
  });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Authentication required");
  }
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function appendAgentParam(path) {
  if (!selectedAgentId) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}agent_id=${encodeURIComponent(selectedAgentId)}`;
}

function moduleRequests(signal) {
  const requests = [
    ["health", fetchJson("/health", signal)],
    ["status", fetchJson(appendAgentParam("/status"), signal)],
  ];

  if (currentModule.key === "overview") {
    requests.push(["events", fetchJson(appendAgentParam("/events?limit=5"), signal)]);
    requests.push(["detections", fetchJson(appendAgentParam("/detections?limit=4"), signal)]);
    requests.push([
      "overviewIncidents",
      fetchJson(appendAgentParam("/incidents?limit=8"), signal),
    ]);
    requests.push(["incidentSummary", fetchIncidentSummary(signal)]);
  } else if (currentModule.key === "events") {
    requests.push([
      "events",
      fetchJson(endpointWithFilters("/events", elements.eventsFilters, 100), signal),
    ]);
  } else if (currentModule.key === "detections") {
    requests.push([
      "detections",
      fetchJson(endpointWithFilters("/detections", elements.detectionsFilters, 100), signal),
    ]);
  } else if (currentModule.key === "incidents") {
    const incidentId = selectedIncidentId();
    if (incidentId) {
      requests.push(["incidentDetail", fetchJson(incidentDetailEndpoint(incidentId), signal)]);
      requests.push([
        "incidentTimeline",
        fetchJson(incidentDetailEndpoint(incidentId, "/timeline"), signal),
      ]);
    } else {
      requests.push(["incidents", fetchJson(incidentsEndpoint(), signal)]);
    }
  } else if (currentModule.key === "responses") {
    requests.push([
      "responses",
      fetchJson(endpointWithFilters("/responses", elements.responsesFilters, 100), signal),
    ]);
  } else if (currentModule.key === "users") {
    requests.push(["users", fetchJson("/admin/users", signal)]);
  } else if (currentModule.key === "notifications") {
    requests.push([
      "notifications",
      fetchJson(endpointWithFilters("/notifications", elements.notificationsFilters, 100), signal),
    ]);
    requests.push(["notificationSummary", fetchJson("/notifications/summary", signal)]);
  }
  return requests;
}

function renderModuleResult(key, result) {
  const validList = result.status === "fulfilled" && Array.isArray(result.value);
  if (key === "events") {
    const body = currentModule.key === "overview"
      ? elements.overviewEventsBody
      : elements.eventsBody;
    const compact = currentModule.key === "overview";
    if (validList) {
      renderEvents(result.value, body, compact);
      if (!compact) elements.eventsCount.textContent = `${result.value.length} resultados`;
    } else {
      body.replaceChildren(stateRow(compact ? 3 : 6, "No fue posible cargar los eventos.", true));
    }
  }
  if (key === "detections") {
    const body = currentModule.key === "overview"
      ? elements.overviewDetectionsBody
      : elements.detectionsBody;
    const compact = currentModule.key === "overview";
    if (validList) {
      renderDetections(result.value, body, compact);
      if (!compact) elements.detectionsCount.textContent = `${result.value.length} resultados`;
    } else {
      body.replaceChildren(
        stateRow(compact ? 4 : 6, "No fue posible cargar las detecciones.", true),
      );
    }
  }
  if (key === "overviewIncidents") {
    if (result.status === "fulfilled" && Array.isArray(result.value?.items)) {
      renderOverviewIncidents(result.value);
    } else {
      elements.overviewIncidentsBody.replaceChildren(
        stateRow(6, "No fue posible cargar los incidentes.", true),
      );
    }
  }
  if (key === "incidentSummary") {
    renderIncidentSummary(result.status === "fulfilled" ? result.value : null);
  }
  if (key === "incidents") {
    if (result.status === "fulfilled" && Array.isArray(result.value?.items)) {
      renderIncidents(result.value);
    } else {
      elements.incidentsBody.replaceChildren(
        stateRow(7, "No fue posible cargar los incidentes.", true),
      );
    }
  }
  if (key === "incidentDetail") {
    if (result.status === "fulfilled" && result.value?.incident) {
      renderIncidentDetail(result.value);
    } else {
      renderIncidentDetailError(
        result.reason?.status === 404
          ? "El incidente no existe o no pertenece a sus servidores."
          : "No fue posible cargar el incidente.",
      );
    }
  }
  if (key === "incidentTimeline") {
    if (validList) renderIncidentTimeline(result.value);
    else elements.incidentTimeline.replaceChildren(
      makeElement("li", "state-cell is-error", "No fue posible cargar la timeline."),
    );
  }
  if (key === "responses") {
    if (validList) {
      renderResponses(result.value);
      elements.responsesCount.textContent = `${result.value.length} resultados`;
    } else {
      elements.responsesBody.replaceChildren(
        stateRow(8, "No fue posible cargar las respuestas.", true),
      );
    }
  }
  if (key === "users") {
    if (validList) renderUsers(result.value);
    else {
      elements.usersBody.replaceChildren(
        stateRow(6, "No fue posible cargar los usuarios.", true),
      );
    }
  }
  if (key === "agents") {
    if (validList) renderAgents(result.value);
    else {
      elements.serversBody.replaceChildren(
        stateRow(5, "No fue posible cargar los servidores.", true),
      );
    }
  }
  if (key === "notifications") {
    if (validList) {
      renderNotifications(result.value);
      elements.notificationsCount.textContent = `${result.value.length} resultados`;
    } else {
      elements.notificationsBody.replaceChildren(stateRow(7, "No fue posible cargar las notificaciones.", true));
    }
  }
  if (key === "notificationSummary" && result.status === "fulfilled") {
    renderNotificationSummary(result.value);
  }
}

async function refreshDashboard() {
  const generation = ++refreshGeneration;
  refreshController?.abort();
  const controller = new AbortController();
  refreshController = controller;
  refreshInProgress = true;
  elements.refreshButton.disabled = true;
  elements.refreshButton.setAttribute("aria-busy", "true");
  elements.globalAlert.hidden = true;
  setApiState("loading", "Actualizando");

  try {
    const agentsResult = await Promise.resolve(
      fetchJson("/agents", controller.signal),
    ).then(
      (value) => ({ status: "fulfilled", value }),
      (reason) => ({ status: "rejected", reason }),
    );

    if (generation !== refreshGeneration) return;

    if (agentsResult.status === "fulfilled" && Array.isArray(agentsResult.value)) {
      knownAgents = agentsResult.value;
      if (
        selectedAgentId &&
        !knownAgents.some((agent) => agent.agent_id === selectedAgentId)
      ) {
        selectedAgentId = null;
        updateAgentQueryInLocation();
      }
      renderAgentSelector();
      renderFleetSummary(knownAgents);
      updateCurrentUserScope();
      if (currentModule.key === "servers") renderAgents(knownAgents);
      if (currentModule.key === "overview") renderOverviewServers(knownAgents);
    } else {
      renderFleetError();
      if (currentModule.key === "overview") {
        elements.overviewServers.replaceChildren(
          makeElement("li", "state-cell is-error", "No fue posible cargar los servidores."),
        );
      }
      if (currentModule.key === "servers") {
        elements.serversBody.replaceChildren(
          stateRow(5, "No fue posible cargar los servidores.", true),
        );
      }
    }

    const requests = moduleRequests(controller.signal);
    const settled = await Promise.allSettled(requests.map(([, request]) => request));
    if (generation !== refreshGeneration) return;

    const results = Object.fromEntries(
      requests.map(([key], index) => [key, settled[index]]),
    );

    if (results.health?.status === "fulfilled") setApiState("online", "API operativa");

    if (results.status?.status === "fulfilled") {
      renderStatus(results.status.value);
    } else if (results.status?.reason?.status === 404 && selectedAgentId) {
      selectedAgentId = null;
      updateAgentQueryInLocation();
      renderAgentSelector();
      elements.globalAlert.textContent = "El servidor seleccionado ya no está disponible. Se cambió a Todos los servidores.";
      elements.globalAlert.hidden = false;
      await refreshDashboard();
      return;
    } else {
      renderStatusError();
    }

    Object.entries(results).forEach(([key, result]) => {
      if (!["health", "status"].includes(key)) renderModuleResult(key, result);
    });

    const initialSuccesses = agentsResult.status === "fulfilled" ? 1 : 0;
    const successes = initialSuccesses +
      settled.filter((result) => result.status === "fulfilled").length;
    const totalRequests = 1 + settled.length;

    if (successes < totalRequests && elements.globalAlert.hidden) {
      elements.globalAlert.textContent = successes === 0
        ? "No fue posible conectar con la API."
        : "Algunos datos no pudieron actualizarse. La información visible puede estar incompleta.";
      elements.globalAlert.hidden = false;
    }

    if (successes > 0) {
      elements.lastUpdated.textContent = new Intl.DateTimeFormat("es-GT", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23",
      }).format(new Date());
    }
  } catch (error) {
    if (error.name !== "AbortError" && generation === refreshGeneration) {
      elements.globalAlert.textContent = "No fue posible actualizar el dashboard.";
      elements.globalAlert.hidden = false;
      setApiState("offline", "API no disponible");
    }
  } finally {
    if (generation === refreshGeneration) {
      refreshInProgress = false;
      elements.refreshButton.disabled = false;
      elements.refreshButton.removeAttribute("aria-busy");
      if (refreshController === controller) refreshController = null;
    }
  }
}

function stopAutoRefresh() {
  if (refreshTimerId !== null) {
    window.clearTimeout(refreshTimerId);
    refreshTimerId = null;
  }
}

function scheduleAutoRefresh() {
  stopAutoRefresh();
  if (document.hidden) return;
  refreshTimerId = window.setTimeout(async () => {
    refreshTimerId = null;
    await refreshDashboard();
    scheduleAutoRefresh();
  }, REFRESH_INTERVAL_MS);
}

async function refreshAndReschedule() {
  stopAutoRefresh();
  await refreshDashboard();
  scheduleAutoRefresh();
}

function configureFilters() {
  const form = elements[`${currentModule.key}Filters`];
  if (!form) return;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const params = filterParams(form);
    const nextLocation = params.toString()
      ? `${normalizedPath}?${params.toString()}`
      : normalizedPath;
    window.history.replaceState(null, "", nextLocation);
    refreshAndReschedule();
  });
  form.querySelector("[data-reset-filters]").addEventListener("click", () => {
    form.reset();
    const params = new URLSearchParams();
    if (selectedAgentId && currentModule.key !== "notifications") {
      params.set("agent_id", selectedAgentId);
    }
    const query = params.toString();
    window.history.replaceState(null, "", query ? `${normalizedPath}?${query}` : normalizedPath);
    refreshAndReschedule();
  });
}

function configureAgentSelector() {
  elements.agentSelector.addEventListener("change", () => {
    selectedAgentId = elements.agentSelector.value || null;
    updateAgentQueryInLocation();
    refreshAndReschedule();
  });
}

function configureAccountActions() {
  elements.logoutButton.addEventListener("click", async () => {
    try {
      await authenticatedPost("/auth/logout", {});
    } finally {
      window.location.assign("/login");
    }
  });
  elements.createUserForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.usersAlert.hidden = true;
    const data = new FormData(elements.createUserForm);
    try {
      await authenticatedPost("/admin/users", {
        username: data.get("username"),
        password: data.get("password"),
        role: data.get("role"),
      });
      elements.createUserForm.reset();
      const passwordInput = document.querySelector("#create-user-password");
      const passwordToggle = elements.createUserForm.querySelector(
        "[data-password-toggle]",
      );
      setPasswordVisibility(passwordToggle, passwordInput, false);
      showUsersAlert("Usuario creado.", false);
      await refreshAndReschedule();
    } catch (error) {
      showUsersAlert(error.message);
    }
  });
}

function showServersAlert(message, error = true) {
  elements.serversAlert.textContent = message;
  elements.serversAlert.classList.toggle("is-success", !error);
  elements.serversAlert.hidden = false;
}

function configureServerActions() {
  elements.connectServerButton.addEventListener("click", async () => {
    elements.serversAlert.hidden = true;
    elements.connectServerButton.disabled = true;
    try {
      const registration = await authenticatedPost("/agents/registration-token", {});
      elements.registrationCommand.textContent = registration.command;
      elements.registrationExpiresAt.textContent = formatTimestamp(registration.expires_at);
      elements.registrationPanel.hidden = false;
      elements.copyRegistrationCommand.focus();
    } catch (error) {
      showServersAlert(error.message);
    } finally {
      elements.connectServerButton.disabled = false;
    }
  });
  elements.copyRegistrationCommand.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(elements.registrationCommand.textContent);
      showServersAlert("Comando copiado.", false);
    } catch (_error) {
      showServersAlert("No fue posible copiar el comando. Selecciónelo manualmente.");
    }
  });
}

async function initializeDashboard() {
  configureNavigation();
  configurePasswordToggles();
  await loadAuthContext();
  activateModule();
  populateFiltersFromLocation();
  configureFilters();
  configureIncidentView();
  configureAgentSelector();
  configureAccountActions();
  configureServerActions();
  elements.refreshButton.addEventListener("click", refreshAndReschedule);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopAutoRefresh();
    else refreshAndReschedule();
  });
  await refreshDashboard();
  scheduleAutoRefresh();
}

initializeDashboard();
