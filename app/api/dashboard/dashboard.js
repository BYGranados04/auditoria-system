"use strict";

const REFRESH_INTERVAL_MS = 30_000;
const MODULES = {
  "/dashboard": { key: "overview", title: "Overview" },
  "/dashboard/events": { key: "events", title: "Eventos" },
  "/dashboard/detections": { key: "detections", title: "Detecciones" },
  "/dashboard/responses": { key: "responses", title: "Respuestas" },
  "/dashboard/users": { key: "users", title: "Usuarios" },
};

const normalizedPath = window.location.pathname.replace(/\/+$/, "") || "/dashboard";
const currentModule = MODULES[normalizedPath] ?? MODULES["/dashboard"];
let refreshInProgress = false;
let refreshTimerId = null;
let authContext = null;

const elements = {
  apiIndicator: document.querySelector("#api-indicator"),
  apiStatus: document.querySelector("#api-status"),
  automaticBlocking: document.querySelector("#automatic-blocking"),
  createUserForm: document.querySelector("#create-user-form"),
  currentUser: document.querySelector("#current-user"),
  defenseApiStatus: document.querySelector("#status-api"),
  defenseHostname: document.querySelector("#status-hostname"),
  detectionsBody: document.querySelector("#detections-body"),
  detectionsCount: document.querySelector("#detections-count"),
  detectionsFilters: document.querySelector("#detections-filters"),
  eventsBody: document.querySelector("#events-body"),
  eventsCount: document.querySelector("#events-count"),
  eventsFilters: document.querySelector("#events-filters"),
  globalAlert: document.querySelector("#global-alert"),
  hostname: document.querySelector("#hostname"),
  lastUpdated: document.querySelector("#last-updated"),
  logoutButton: document.querySelector("#logout-button"),
  overviewDetectionsBody: document.querySelector("#overview-detections-body"),
  overviewEventsBody: document.querySelector("#overview-events-body"),
  refreshButton: document.querySelector("#refresh-button"),
  responseMode: document.querySelector("#response-mode"),
  responsesBody: document.querySelector("#responses-body"),
  responsesCount: document.querySelector("#responses-count"),
  responsesFilters: document.querySelector("#responses-filters"),
  usersAlert: document.querySelector("#users-alert"),
  usersBody: document.querySelector("#users-body"),
  usersCount: document.querySelector("#users-count"),
};

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
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return displayValue(value);
  return new Intl.DateTimeFormat("es-GT", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(date);
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
  document.title = `${currentModule.title} | Auditoria System`;
  document.querySelectorAll("[data-view]").forEach((view) => {
    view.hidden = view.dataset.view !== currentModule.key;
  });
  document.querySelectorAll(".nav-item[data-module]").forEach((link) => {
    if (link.dataset.module === "users") {
      link.hidden = authContext?.role !== "superadmin";
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
  elements.currentUser.textContent = `${authContext.username} · ${authContext.role}`;
}

function populateFiltersFromLocation() {
  const form = elements[`${currentModule.key}Filters`];
  if (!form) return;
  const params = new URLSearchParams(window.location.search);
  form.querySelectorAll("[name]").forEach((control) => {
    control.value = params.get(control.name) ?? "";
  });
}

function filterParams(form, limit) {
  const params = new URLSearchParams();
  new FormData(form).forEach((value, key) => {
    const normalized = String(value).trim();
    if (normalized) params.set(key, normalized);
  });
  if (limit) params.set("limit", String(limit));
  return params;
}

function endpointWithFilters(path, form, limit) {
  const query = filterParams(form, limit).toString();
  return query ? `${path}?${query}` : path;
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

function renderStatus(status) {
  const hostname = displayValue(status.hostname);
  elements.hostname.textContent = hostname;
  elements.defenseHostname.textContent = hostname;
  setMetric("total", status.total_events);
  setMetric("critical", status.by_severity?.critical ?? 0);
  setMetric("high", status.by_severity?.high ?? 0);
  setMetric("medium", status.by_severity?.medium ?? 0);
  setMetric("blocks", status.live_response_blocks);

  const modeLabels = {
    audit_only: "Solo auditoría",
    assisted: "Asistido",
    automatic: "Automático",
  };
  renderPill(
    elements.responseMode,
    modeLabels[status.response_mode] ?? displayValue(status.response_mode),
    status.response_mode === "automatic" ? "warning" : "neutral",
  );
  renderPill(
    elements.automaticBlocking,
    status.automatic_blocking_enabled ? "Habilitado" : "Deshabilitado",
    status.automatic_blocking_enabled ? "warning" : "neutral",
  );
}

function renderStatusError() {
  ["total", "critical", "high", "medium", "blocks"].forEach((name) => {
    const metric = document.querySelector(`#metric-${name}`);
    metric.textContent = "—";
    metric.classList.remove("loading-value");
  });
  elements.hostname.textContent = "—";
  elements.defenseHostname.textContent = "—";
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
  if (events.length === 0) {
    body.replaceChildren(stateRow(compact ? 4 : 5, "No hay eventos registrados."));
    return;
  }
  const rows = events.map((event) => {
    const row = document.createElement("tr");
    const severity = document.createElement("td");
    severity.append(severityBadge(event.severity));
    const cells = [
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
    body.replaceChildren(stateRow(5, "No hay detecciones registradas."));
    return;
  }
  const rows = detections.map((detection) => {
    const evidence = evidenceObject(detection);
    const row = document.createElement("tr");
    const severity = document.createElement("td");
    severity.append(severityBadge(detection.severity));
    row.append(
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
    elements.responsesBody.replaceChildren(stateRow(7, "No hay respuestas registradas."));
    return;
  }
  const rows = responses.map((response) => {
    const evidence = evidenceObject(response);
    const row = document.createElement("tr");
    row.append(
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
    elements.usersBody.replaceChildren(stateRow(5, "No hay usuarios registrados."));
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
      makeElement("td", user.active ? "user-active" : "user-inactive", user.active ? "Activo" : "Inactivo"),
      makeElement("td", "timestamp", formatTimestamp(user.created_at)),
      actionCell,
    );
    return row;
  });
  elements.usersBody.replaceChildren(...rows);
}

async function fetchJson(path) {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Authentication required");
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function moduleRequests() {
  const requests = [
    ["health", fetchJson("/health")],
    ["status", fetchJson("/status")],
  ];
  if (currentModule.key === "overview") {
    requests.push(["events", fetchJson("/events?limit=5")]);
    requests.push(["detections", fetchJson("/detections?limit=4")]);
  } else if (currentModule.key === "events") {
    requests.push([
      "events",
      fetchJson(endpointWithFilters("/events", elements.eventsFilters, 100)),
    ]);
  } else if (currentModule.key === "detections") {
    requests.push([
      "detections",
      fetchJson(endpointWithFilters("/detections", elements.detectionsFilters, 100)),
    ]);
  } else if (currentModule.key === "responses") {
    requests.push([
      "responses",
      fetchJson(endpointWithFilters("/responses", elements.responsesFilters, 100)),
    ]);
  } else {
    requests.push(["users", fetchJson("/admin/users")]);
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
      body.replaceChildren(stateRow(compact ? 4 : 5, "No fue posible cargar los eventos.", true));
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
      body.replaceChildren(stateRow(5, "No fue posible cargar las detecciones.", true));
    }
  }
  if (key === "responses") {
    if (validList) {
      renderResponses(result.value);
      elements.responsesCount.textContent = `${result.value.length} resultados`;
    } else {
      elements.responsesBody.replaceChildren(
        stateRow(7, "No fue posible cargar las respuestas.", true),
      );
    }
  }
  if (key === "users") {
    if (validList) renderUsers(result.value);
    else {
      elements.usersBody.replaceChildren(
        stateRow(5, "No fue posible cargar los usuarios.", true),
      );
    }
  }
}

async function refreshDashboard() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  elements.refreshButton.disabled = true;
  elements.refreshButton.setAttribute("aria-busy", "true");
  elements.globalAlert.hidden = true;
  setApiState("loading", "Actualizando");

  try {
    const requests = moduleRequests();
    const settled = await Promise.allSettled(requests.map(([, request]) => request));
    const results = Object.fromEntries(
      requests.map(([key], index) => [key, settled[index]]),
    );

    if (results.health.status === "fulfilled") setApiState("online", "API operativa");
    else setApiState("offline", "API no disponible");

    if (results.status.status === "fulfilled") renderStatus(results.status.value);
    else renderStatusError();

    Object.entries(results).forEach(([key, result]) => {
      if (!["health", "status"].includes(key)) renderModuleResult(key, result);
    });

    const successes = settled.filter((result) => result.status === "fulfilled").length;
    if (successes < settled.length) {
      elements.globalAlert.textContent = successes === 0
        ? "No fue posible conectar con la API local."
        : "Algunos datos no pudieron actualizarse. La información visible puede estar incompleta.";
      elements.globalAlert.hidden = false;
    }
    if (successes > 0) {
      elements.lastUpdated.textContent = new Intl.DateTimeFormat("es-GT", {
        timeStyle: "medium",
      }).format(new Date());
    }
  } finally {
    refreshInProgress = false;
    elements.refreshButton.disabled = false;
    elements.refreshButton.removeAttribute("aria-busy");
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
    const query = filterParams(form).toString();
    const nextLocation = query ? `${normalizedPath}?${query}` : normalizedPath;
    window.history.replaceState(null, "", nextLocation);
    refreshAndReschedule();
  });
  form.querySelector("[data-reset-filters]").addEventListener("click", () => {
    form.reset();
    window.history.replaceState(null, "", normalizedPath);
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
      showUsersAlert("Usuario creado.", false);
      await refreshAndReschedule();
    } catch (error) {
      showUsersAlert(error.message);
    }
  });
}

async function initializeDashboard() {
  await loadAuthContext();
  activateModule();
  populateFiltersFromLocation();
  configureFilters();
  configureAccountActions();
  elements.refreshButton.addEventListener("click", refreshAndReschedule);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopAutoRefresh();
    else refreshAndReschedule();
  });
  await refreshDashboard();
  scheduleAutoRefresh();
}

initializeDashboard();
