"use strict";

const REFRESH_INTERVAL_MS = 30_000;
const RECENT_LIMIT = 8;
let refreshInProgress = false;
let refreshTimerId = null;

const elements = {
  apiIndicator: document.querySelector("#api-indicator"),
  apiStatus: document.querySelector("#api-status"),
  automaticBlocking: document.querySelector("#automatic-blocking"),
  defenseApiStatus: document.querySelector("#status-api"),
  defenseHostname: document.querySelector("#status-hostname"),
  detectionsCount: document.querySelector("#detections-count"),
  detectionsBody: document.querySelector("#detections-body"),
  eventsBody: document.querySelector("#events-body"),
  eventsCount: document.querySelector("#events-count"),
  globalAlert: document.querySelector("#global-alert"),
  hostname: document.querySelector("#hostname"),
  lastUpdated: document.querySelector("#last-updated"),
  refreshButton: document.querySelector("#refresh-button"),
  responseMode: document.querySelector("#response-mode"),
  responsesCount: document.querySelector("#responses-count"),
  responsesBody: document.querySelector("#responses-body"),
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
  const pill = makeElement("span", `value-pill is-${style}`, text);
  container.replaceChildren(pill);
}

function renderStatus(status) {
  elements.hostname.textContent = displayValue(status.hostname);
  elements.defenseHostname.textContent = displayValue(status.hostname);
  setMetric("total", status.total_events);
  setMetric("critical", status.by_severity?.critical ?? 0);
  setMetric("high", status.by_severity?.high ?? 0);
  setMetric("medium", status.by_severity?.medium ?? 0);
  setMetric("low", status.by_severity?.low ?? 0);
  setMetric("blocks", status.live_response_blocks);

  const modeLabels = {
    audit_only: "Solo auditoría",
    assisted: "Asistido",
    automatic: "Automático",
  };
  const modeStyle = status.response_mode === "automatic" ? "warning" : "neutral";
  renderPill(
    elements.responseMode,
    modeLabels[status.response_mode] ?? displayValue(status.response_mode),
    modeStyle,
  );
  renderPill(
    elements.automaticBlocking,
    status.automatic_blocking_enabled ? "Habilitado" : "Deshabilitado",
    status.automatic_blocking_enabled ? "warning" : "neutral",
  );
}

function renderStatusError() {
  ["total", "critical", "high", "medium", "low", "blocks"].forEach((name) => {
    const metric = document.querySelector(`#metric-${name}`);
    metric.textContent = "—";
    metric.classList.remove("loading-value");
  });
  renderPill(elements.responseMode, "No disponible", "neutral");
  renderPill(elements.automaticBlocking, "No disponible", "neutral");
  elements.hostname.textContent = "—";
  elements.defenseHostname.textContent = "—";
}

function renderEvents(events) {
  elements.eventsCount.textContent = `${events.length} recientes`;
  if (events.length === 0) {
    const cell = makeElement("td", "state-cell", "No hay eventos registrados.");
    cell.colSpan = 5;
    const row = document.createElement("tr");
    row.append(cell);
    elements.eventsBody.replaceChildren(row);
    return;
  }

  const rows = events.map((event) => {
    const row = document.createElement("tr");
    const timestamp = makeElement("td", "timestamp", formatTimestamp(event.timestamp));
    timestamp.dataset.label = "Timestamp";
    const severity = document.createElement("td");
    severity.dataset.label = "Severidad";
    severity.append(severityBadge(event.severity));
    const category = makeElement("td", "", displayValue(event.category));
    category.dataset.label = "Categoría";
    const eventType = makeElement("td", "event-type", displayValue(event.event_type));
    eventType.dataset.label = "Tipo";
    const description = makeElement("td", "", displayValue(event.description));
    description.dataset.label = "Descripción";
    row.append(timestamp, severity, category, eventType, description);
    return row;
  });
  elements.eventsBody.replaceChildren(...rows);
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

function renderDetections(detections) {
  elements.detectionsCount.textContent = `${detections.length} recientes`;
  if (detections.length === 0) {
    const cell = makeElement("td", "state-cell", "No hay detecciones registradas.");
    cell.colSpan = 5;
    const row = document.createElement("tr");
    row.append(cell);
    elements.detectionsBody.replaceChildren(row);
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
  elements.detectionsBody.replaceChildren(...rows);
}

function renderResponses(responses) {
  elements.responsesCount.textContent = `${responses.length} recientes`;
  if (responses.length === 0) {
    const cell = makeElement("td", "state-cell", "No hay respuestas registradas.");
    cell.colSpan = 7;
    const row = document.createElement("tr");
    row.append(cell);
    elements.responsesBody.replaceChildren(row);
    return;
  }

  const rows = responses.map((response) => {
    const evidence = evidenceObject(response);
    const row = document.createElement("tr");
    row.append(
      makeElement("td", "timestamp", formatTimestamp(response.timestamp)),
      makeElement("td", "event-type", displayValue(response.event_type)),
      makeElement("td", "monospace", displayValue(evidence.action)),
      makeElement("td", "", displayValue(evidence.status)),
      makeElement("td", "monospace", displayValue(evidence.target_ip)),
      makeElement("td", "", displayValue(evidence.executed)),
      makeElement("td", "", displayValue(evidence.reason, response.description)),
    );
    return row;
  });
  elements.responsesBody.replaceChildren(...rows);
}

function renderSectionError(container, columns, message) {
  if (columns) {
    const cell = makeElement("td", "state-cell is-error", message);
    cell.colSpan = columns;
    const row = document.createElement("tr");
    row.append(cell);
    container.replaceChildren(row);
    return;
  }
  container.replaceChildren(makeElement("div", "list-state is-error", message));
}

async function fetchJson(path) {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function refreshDashboard() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  elements.refreshButton.disabled = true;
  elements.refreshButton.setAttribute("aria-busy", "true");
  elements.globalAlert.hidden = true;
  setApiState("loading", "Actualizando");

  try {
    const requests = await Promise.allSettled([
      fetchJson("/health"),
      fetchJson("/status"),
      fetchJson(`/events?limit=${RECENT_LIMIT}`),
      fetchJson(`/detections?limit=${RECENT_LIMIT}`),
      fetchJson(`/responses?limit=${RECENT_LIMIT}`),
    ]);
    const [health, status, events, detections, responses] = requests;

    if (health.status === "fulfilled") setApiState("online", "API operativa");
    else setApiState("offline", "API no disponible");

    if (status.status === "fulfilled") renderStatus(status.value);
    else renderStatusError();
    if (events.status === "fulfilled" && Array.isArray(events.value)) {
      renderEvents(events.value);
    } else {
      renderSectionError(elements.eventsBody, 5, "No fue posible cargar los eventos.");
    }
    if (detections.status === "fulfilled" && Array.isArray(detections.value)) {
      renderDetections(detections.value);
    } else {
      renderSectionError(
        elements.detectionsBody,
        5,
        "No fue posible cargar las detecciones.",
      );
    }
    if (responses.status === "fulfilled" && Array.isArray(responses.value)) {
      renderResponses(responses.value);
    } else {
      renderSectionError(
        elements.responsesBody,
        7,
        "No fue posible cargar las respuestas.",
      );
    }

    const successes = requests.filter(
      (result) => result.status === "fulfilled",
    ).length;
    if (successes < requests.length) {
      elements.globalAlert.textContent =
        successes === 0
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

elements.refreshButton.addEventListener("click", async () => {
  stopAutoRefresh();
  await refreshDashboard();
  scheduleAutoRefresh();
});

document.addEventListener("visibilitychange", async () => {
  if (document.hidden) {
    stopAutoRefresh();
    return;
  }
  await refreshDashboard();
  scheduleAutoRefresh();
});

refreshDashboard().finally(scheduleAutoRefresh);
