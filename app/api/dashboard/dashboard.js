"use strict";

const REFRESH_INTERVAL_MS = 30_000;
const SIDEBAR_STORAGE_KEY = "auditoria-sidebar-collapsed";
const MOBILE_NAVIGATION = window.matchMedia("(max-width: 760px)");
const MODULES = {
  "/dashboard": { key: "overview", title: "Overview" },
  "/dashboard/events": { key: "events", title: "Eventos" },
  "/dashboard/detections": { key: "detections", title: "Detecciones" },
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

function configureNavigation() {
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
    dateStyle: "short",
    timeStyle: "medium",
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

function severityBadge(severity) {
  const normalized = ["critical", "high", "medium", "low"].includes(severity)
    ? severity
    : "low";
  const labels = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja" };
  return makeElement("span", `severity-badge ${normalized}`, labels[normalized]);
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
  document.title = `${pageTitle} | Auditoria System`;
  elements.serversTitle.textContent = serverTitle;
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
    const url = new URL(link.getAttribute("href"), window.location.origin);
    const targetPath = url.pathname.replace(/\/+$/, "") || "/dashboard";
    const supportsAgent = ["/dashboard", "/dashboard/events", "/dashboard/detections", "/dashboard/responses"]
      .includes(targetPath);

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

function setMetric(name, value) {
  const metric = document.querySelector(`#metric-${name}`);
  metric.textContent = displayValue(value, "0");
  metric.classList.remove("loading-value");
}

function renderPill(container, text, style = "neutral") {
  container.replaceChildren(makeElement("span", `value-pill is-${style}`, text));
}

function renderFleetSummary(agents) {
  const counts = { online: 0, offline: 0, unknown: 0 };
  agents.forEach((agent) => {
    const presence = ["online", "offline", "unknown"].includes(agent.presence)
      ? agent.presence
      : "unknown";
    counts[presence] += 1;
  });

  elements.fleetTotal.textContent = String(agents.length);
  elements.fleetOnline.textContent = String(counts.online);
  elements.fleetOffline.textContent = String(counts.offline);
  elements.fleetUnknown.textContent = String(counts.unknown);
  [elements.fleetTotal, elements.fleetOnline, elements.fleetOffline, elements.fleetUnknown]
    .forEach((element) => element.classList.remove("loading-value"));
}

function renderFleetError() {
  [elements.fleetTotal, elements.fleetOnline, elements.fleetOffline, elements.fleetUnknown]
    .forEach((element) => {
      element.textContent = "—";
      element.classList.remove("loading-value");
    });
}

function updateCurrentUserScope() {
  const count = knownAgents.length;
  const scope = authContext.role === "superadmin"
    ? `${count} ${count === 1 ? "servidor" : "servidores"}`
    : `${count} ${count === 1 ? "servidor asignado" : "servidores asignados"}`;
  elements.currentUser.textContent = `${authContext.username} · ${authContext.role} · ${scope}`;
}

function renderStatus(status) {
  const selected = selectedAgent();
  const hostname = selected
    ? displayValue(status.hostname, selected.hostname)
    : "Todos los servidores";

  elements.hostname.textContent = selected ? agentDisplayName(selected) : "Todos los servidores";
  elements.defenseHostname.textContent = hostname;
  setMetric("total", status.total_events);
  setMetric("critical", status.by_severity?.critical ?? 0);
  setMetric("high", status.by_severity?.high ?? 0);
  setMetric("medium", status.by_severity?.medium ?? 0);

  const blocksMetric = document.querySelector("#metric-blocks");
  if (status.live_response_blocks === null || status.live_response_blocks === undefined) {
    blocksMetric.textContent = "No disp.";
  } else {
    blocksMetric.textContent = displayValue(status.live_response_blocks, "0");
  }
  blocksMetric.classList.remove("loading-value");

  if (selected) {
    renderPill(
      elements.statusPresence,
      presenceLabel(status.presence ?? selected.presence),
      `presence-${status.presence ?? selected.presence ?? "unknown"}`,
    );
    elements.statusLastSeen.textContent = formatRelativeTimestamp(
      status.last_seen_at ?? selected.last_seen_at,
    );
    elements.statusLastSeen.title = formatTimestamp(status.last_seen_at ?? selected.last_seen_at);
  } else {
    renderPill(elements.statusPresence, "Resumen de flota");
    elements.statusLastSeen.textContent = "Consulta por servidor";
    elements.statusLastSeen.removeAttribute("title");
  }

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
  ["total", "critical", "high", "medium", "blocks"].forEach((name) => {
    const metric = document.querySelector(`#metric-${name}`);
    metric.textContent = "—";
    metric.classList.remove("loading-value");
  });
  elements.hostname.textContent = selectedAgent() ? agentDisplayName(selectedAgent()) : "Todos los servidores";
  elements.defenseHostname.textContent = "—";
  renderPill(elements.statusPresence, "No disponible");
  elements.statusLastSeen.textContent = "—";
  renderPill(elements.responseMode, "No disponible");
  renderPill(elements.automaticBlocking, "No disponible");
}

function stateRow(columns, message, error = false) {
  const cell = makeElement("td", error ? "state-cell is-error" : "state-cell", message);
  cell.colSpan = columns;
  const row = document.createElement("tr");
  row.append(cell);
  return row;
}

function renderEvents(events, body, compact = false) {
  const columnCount = compact ? 5 : 6;
  if (events.length === 0) {
    body.replaceChildren(stateRow(columnCount, "No hay eventos registrados."));
    return;
  }

  const rows = events.map((event) => {
    const row = document.createElement("tr");
    const server = document.createElement("td");
    server.append(serverCell(event));
    const severity = document.createElement("td");
    severity.append(severityBadge(event.severity));
    const cells = [
      server,
      makeElement("td", "timestamp", formatTimestamp(event.timestamp)),
      severity,
    ];
    if (!compact) cells.push(makeElement("td", "", displayValue(event.category)));
    cells.push(
      makeElement("td", "event-type", displayValue(event.event_type)),
      makeElement("td", "", displayValue(event.description)),
    );
    row.append(...cells);
    return row;
  });
  body.replaceChildren(...rows);
}

function renderDetections(detections, body) {
  if (detections.length === 0) {
    body.replaceChildren(stateRow(6, "No hay detecciones registradas."));
    return;
  }

  const rows = detections.map((detection) => {
    const evidence = evidenceObject(detection);
    const row = document.createElement("tr");
    const server = document.createElement("td");
    server.append(serverCell(detection));
    const severity = document.createElement("td");
    severity.append(severityBadge(detection.severity));
    row.append(
      server,
      severity,
      makeElement("td", "event-type", displayValue(detection.event_type)),
      makeElement("td", "monospace", displayValue(evidence.source_ip)),
      makeElement("td", "timestamp", formatTimestamp(detection.timestamp)),
      makeElement("td", "", displayValue(detection.description)),
    );
    return row;
  });
  body.replaceChildren(...rows);
}

function renderResponses(responses) {
  if (responses.length === 0) {
    elements.responsesBody.replaceChildren(stateRow(8, "No hay respuestas registradas."));
    return;
  }

  const rows = responses.map((response) => {
    const evidence = evidenceObject(response);
    const row = document.createElement("tr");
    const server = document.createElement("td");
    server.append(serverCell(response));
    row.append(
      server,
      makeElement("td", "timestamp", formatTimestamp(response.timestamp)),
      makeElement("td", "event-type", displayValue(response.event_type)),
      makeElement("td", "monospace", displayValue(evidence.target_ip)),
      makeElement("td", "monospace", displayValue(evidence.action)),
      makeElement("td", "", displayValue(evidence.status)),
      makeElement("td", "", displayValue(evidence.executed)),
      makeElement("td", "", displayValue(evidence.reason, response.description)),
    );
    return row;
  });
  elements.responsesBody.replaceChildren(...rows);
}

function renderNotifications(notifications) {
  if (notifications.length === 0) {
    elements.notificationsBody.replaceChildren(stateRow(7, "No hay notificaciones registradas."));
    return;
  }
  const rows = notifications.map((notification) => {
    const row = document.createElement("tr");
    row.append(
      makeElement("td", "timestamp", formatTimestamp(notification.created_at)),
      makeElement("td", "monospace", notification.hostname),
      makeElement("td", `severity-${notification.severity}`, notification.severity),
      makeElement("td", "monospace", notification.event_id),
      makeElement("td", "", notification.recipient),
      makeElement("td", "", notification.provider),
      makeElement("td", `status-${notification.status}`, notification.status),
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

function renderAgents(agents) {
  elements.serversCount.textContent = `${agents.length} ${agents.length === 1 ? "servidor" : "servidores"}`;
  if (agents.length === 0) {
    elements.serversBody.replaceChildren(
      stateRow(5, "No tienes servidores conectados. Usa Conectar servidor para comenzar."),
    );
    return;
  }

  const rows = agents.map((agent) => {
    const row = document.createElement("tr");
    const presence = ["online", "offline", "unknown"].includes(agent.presence)
      ? agent.presence
      : "unknown";
    const lastSeenCell = makeElement(
      "td",
      "timestamp",
      formatRelativeTimestamp(agent.last_seen_at),
    );
    if (agent.last_seen_at) lastSeenCell.title = formatTimestamp(agent.last_seen_at);

    row.dataset.agentId = agent.agent_id;
    row.append(
      makeElement("td", "monospace", displayValue(agent.hostname)),
      makeElement("td", presenceClass(presence), presenceLabel(presence)),
      lastSeenCell,
      makeElement("td", "monospace", shortAgentId(agent.agent_id)),
      makeElement("td", "timestamp", formatTimestamp(agent.registered_at)),
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
    const roleCell = document.createElement("td");
    roleCell.append(roleSelect);

    const actionButton = makeElement(
      "button",
      "table-action",
      user.active ? "Desactivar" : "Activar",
    );
    actionButton.type = "button";
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
    const actionCell = document.createElement("td");
    actionCell.append(actionButton);
    row.append(
      makeElement("td", "monospace", user.username),
      roleCell,
      makeElement(
        "td",
        "",
        user.role === "superadmin" ? "Todos" : String(user.server_count ?? 0),
      ),
      makeElement("td", user.active ? "user-active" : "user-inactive", user.active ? "Activo" : "Inactivo"),
      makeElement("td", "timestamp", formatTimestamp(user.created_at)),
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
      body.replaceChildren(stateRow(compact ? 5 : 6, "No fue posible cargar los eventos.", true));
    }
  }
  if (key === "detections") {
    const body = currentModule.key === "overview"
      ? elements.overviewDetectionsBody
      : elements.detectionsBody;
    if (validList) {
      renderDetections(result.value, body);
      if (currentModule.key !== "overview") {
        elements.detectionsCount.textContent = `${result.value.length} resultados`;
      }
    } else {
      body.replaceChildren(stateRow(6, "No fue posible cargar las detecciones.", true));
    }
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
    } else {
      renderFleetError();
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
        timeStyle: "medium",
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
      showServersAlert("No fue posible copiar el comando. Selecciónalo manualmente.");
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
