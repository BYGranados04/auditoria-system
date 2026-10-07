# Motor defensivo: incidentes, evidencia forense, bloqueo IP+puerto y reincidencia

Este documento describe las capacidades agregadas sobre la rama de
estabilización de v1.0. Todas son compatibles hacia atrás: una instalación
existente sin las variables nuevas conserva exactamente el comportamiento
anterior (incluido `TEMPORARY_BLOCK_IP` con su duración histórica).

## 1. Conceptos

| Concepto | Qué es | Dónde vive | Ejemplo |
|---|---|---|---|
| **Event** | Hecho observado y normalizado (`SecurityEvent`). | `auditoria.db` → outbox → `central.db` | `SSH_INVALID_USER` |
| **Detection** | Evento de categoría `detection` producido por la correlación a partir de varios eventos. | Igual que Event | `SSH_USER_ENUMERATION_ATTEMPT` |
| **Incident** | Agrupación de eventos, detecciones, evidencia y respuestas de un mismo origen en un servidor. Guarda **referencias**, no copias. | Agente: tabla `incidents`; central: `incidents` + `incident_links` | `INC-3F9A12C07B44E1D2` |
| **Response Decision** | Resultado del `ResponsePolicyEngine` para una detección (`RESPONSE_DECISION`). Indica acción, objetivo, duración, reincidencia y motivo. | Evento `response` | `TEMPORARY_BLOCK_IP_PORT 192.168.1.50 tcp/22 600 s` |
| **Response Execution** | Resultado del `ResponseExecutor` sobre la decisión (`RESPONSE_EXECUTION`): `SKIPPED`, `DRY_RUN`, `EXECUTED` o `FAILED`. | Evento `response` + `response_blocks` | `EXECUTED` |

Flujo para las detecciones SSH (`SSH_USER_ENUMERATION_ATTEMPT`,
`SSH_BRUTE_FORCE_ATTEMPT`, `SSH_REPEATED_PREAUTH_ACTIVITY`):

```text
journald → SSH_* (event) → correlación → detection
        → incidente (crear/actualizar)            INCIDENT_OPENED / INCIDENT_UPDATED
        → evidencia mínima rápida (psutil, sin subprocesos, solo HIGH/CRITICAL)
        → reincidencia (SQLite)
        → ResponsePolicyEngine (Response Decision) RESPONSE_DECISION
        → [assisted] solicitud de aprobación       RESPONSE_APPROVAL_REQUESTED
        → ResponseExecutor + Protection Validation RESPONSE_EXECUTION
        → incidente actualizado con vínculos        INCIDENT_UPDATED
        → (fin del lote) captura forense ampliada   FORENSIC_EVIDENCE_CAPTURED
        → (ciclo siguiente) aprobaciones humanas    RESPONSE_EXECUTION / RESPONSE_REJECTION_APPLIED
```

Separación de capas: el motor decide qué haría la política (por ejemplo
`TEMPORARY_BLOCK_IP_PORT`); la validación de protecciones (Tailscale, trusted
admin, sesiones SSH activas, IPs locales, gateways) ocurre en el ejecutor, que
registra `SKIPPED` con `protection_rejected=true` y el motivo. Así queda
demostrado qué quiso hacer el motor y por qué no se ejecutó. Las únicas guardas
que permanecen en el motor son las históricas de v1.0 (loopback, unspecified,
multicast, link-local y trusted admin IPs → `NO_ACTION`).

Los umbrales de los detectores no cambiaron. El agente sigue siendo el único
componente con operaciones privilegiadas; la API central solo lee/escribe
`central.db` y nunca accede a `auditoria.db` ni al sistema de archivos del
agente.

## 2. Incidentes

- **Agrupación**: por `(hostname, source_ip)` mientras exista actividad dentro
  de `AUDITORIA_INCIDENT_GROUPING_SECONDS` (por defecto 3600 s). Varias
  detecciones del mismo origen (por ejemplo, enumeración y luego fuerza bruta)
  quedan en el mismo incidente; `incident_type` conserva la primera detección y
  `severity` toma la mayor.
- **Estados**:
  - `OPEN`: requiere atención (aprobación pendiente en `assisted`, ejecución
    fallida o acción no autorizada en `automatic`).
  - `OBSERVED`: registrado sin contención (`audit_only`, dry-run o IP protegida).
  - `CONTAINED`: el bloqueo temporal fue aplicado.
  - `CLOSED`: sin actividad durante la ventana de agrupación. El agente cierra
    incidentes inactivos en cada ciclo y antes de abrir uno nuevo.
- **Timeline**: los eventos `INCIDENT_*` llevan una lista `links` con
  `{event_id, kind, occurred_at}` (`kind`: `event`, `detection`, `decision`,
  `approval`, `execution`, `evidence`). El central la proyecta en `incident_links` y arma la
  timeline con un JOIN contra `events`; si un evento aún no se sincronizó,
  aparece con `available=false`.
- Los eventos de autenticación que originaron la detección se reconstruyen desde
  la ventana `first_seen`/`last_seen` declarada por la detección (máximo 50).
- Desactivable con `AUDITORIA_INCIDENTS_ENABLED=false` (las respuestas siguen
  funcionando igual).

Ejemplo de timeline (`GET /incidents/{id}/timeline`):

```text
10:30:01 event      SSH_INVALID_USER
10:30:05 event      SSH_INVALID_USER
10:30:10 event      SSH_INVALID_USER
10:30:14 event      SSH_INVALID_USER
10:30:18 event      SSH_INVALID_USER
10:30:18 detection  SSH_USER_ENUMERATION_ATTEMPT
10:30:18 decision   RESPONSE_DECISION (TEMPORARY_BLOCK_IP_PORT)
10:30:18 execution  RESPONSE_EXECUTION (EXECUTED)
10:30:20 evidence   FORENSIC_EVIDENCE_CAPTURED
```

En `assisted` la timeline incluye además `RESPONSE_APPROVAL_REQUESTED`,
`RESPONSE_APPROVAL_GRANTED`/`RESPONSE_APPROVAL_DENIED` (decisión humana,
registrada por el central con usuario y fecha) y la ejecución o el rechazo
aplicados por el agente.

## 3. Captura forense (`COLLECT_FORENSIC_EVIDENCE`)

La captura se divide en dos fases para no retrasar la contención:

1. **Evidencia mínima rápida** (antes de decidir): conexiones hacia la IP de
   origen y sesiones activas, leídas en proceso con `psutil` (sin subprocesos,
   máximo 50 entradas por lista). Se guarda en la cola persistente.
2. **Captura ampliada** (después de contener): se encola en la tabla
   `forensic_capture_queue` de `auditoria.db` y se procesa al final del ciclo del
   agente, en el mismo hilo (sin threads ni procesos nuevos, sin competir con el
   ejecutor ni con SQLite). Máximo 3 capturas por ciclo; lo pendiente sobrevive
   reinicios. Cada captura se reintenta hasta 3 veces y luego se informa
   `FORENSIC_EVIDENCE_FAILED`. La evidencia mínima se escribe como
   `quick_snapshot.json` dentro de la captura ampliada.

Así, ninguna contención espera por comandos forensos: todas las detecciones del
lote se deciden y ejecutan antes de la primera captura ampliada.

Se ejecuta para detecciones `high`/`critical` cuando
`AUDITORIA_EVIDENCE_ENABLED=true` (desactivada por defecto). Es de solo lectura
y se realiza en **todos** los modos, incluido `audit_only`.

Contenido (`/var/lib/auditoria-system/evidence/<detection_event_id>/`):

| Archivo | Origen |
|---|---|
| `metadata.json` | timestamp UTC, hostname, agent_id, detection_id, tipo, severidad, source_ip, incident_id, estado y sha256/tamaño de cada artefacto |
| `network_connections.txt` | `ss -tunap` |
| `listening_sockets.txt` | `ss -tulpn` |
| `logged_in_users.txt` | `who -u` |
| `ssh_journal.txt` | `journalctl` de `ssh.service`/`sshd.service`, últimos 15 min, máx. 300 líneas (solo detecciones SSH) |
| `ssh_services.txt` | `systemctl show ssh.service sshd.service` (estado, PID) |
| `nftables_auditoria.txt` | `nft list table inet auditoria_response` |
| `relevant_processes.txt` | procesos `sshd*` y procesos con sockets hacia la IP de origen (cmdline truncada y sanitizada) |

Garantías:

- lista cerrada de comandos; ningún argumento proviene de eventos o usuarios;
- `subprocess.run` con lista de argumentos, sin `shell=True`, con timeout,
  `stdin` cerrado y entorno mínimo (`PATH` seguro, `LC_ALL=C`): las variables
  del agente (por ejemplo, la API key de notificaciones) no se heredan;
- directorio base y de captura `0700`, archivos `0600` creados con
  `O_EXCL|O_NOFOLLOW`; escritura en `.tmp-<uuid>` y renombrado atómico; se
  rechaza un directorio base que sea enlace simbólico;
- nunca se leen `agent.env`, `agent-identity.json`, claves ni el entorno;
- sanitización de secretos evidentes (`password=`, `token:`, `Bearer …`,
  `--password …`, bloques `PRIVATE KEY`);
- límite por captura (`AUDITORIA_EVIDENCE_MAX_BYTES`) y por artefacto (128 KiB);
  los artefactos que no caben se marcan `truncated`/`skipped`;
- errores parciales (`unavailable`, `error`) no abortan la captura; el estado
  global es `complete`, `partial` o `failed`;
- retención: al terminar cada captura se eliminan capturas con más de
  `AUDITORIA_EVIDENCE_RETENTION_DAYS` días y, si el total supera
  `AUDITORIA_EVIDENCE_MAX_TOTAL_BYTES`, las más antiguas. Solo se tocan entradas
  cuyo nombre es un UUID.

Al central viaja únicamente el evento `FORENSIC_EVIDENCE_CAPTURED` con
metadatos (nombres de artefacto, tamaños, sha256, estado). El contenido queda en
el agente; para revisarlo se accede al servidor con privilegios de root.

## 4. `TEMPORARY_BLOCK_IP_PORT`

Bloquea temporalmente solo el tráfico `IP → protocolo/puerto` (por ejemplo
`192.168.1.50 → tcp/22`), sin afectar el resto del tráfico de esa IP.

Estructuras nftables (en la tabla existente `inet auditoria_response`):

```nft
set blocked_ipv4_port { type ipv4_addr . inet_proto . inet_service; flags timeout; }
set blocked_ipv6_port { type ipv6_addr . inet_proto . inet_service; flags timeout; }
chain input_port {
    type filter hook input priority filter - 10; policy accept;
    iifname "lo" return
    iifname "tailscale0" return
    ip saddr . meta l4proto . th dport @blocked_ipv4_port counter drop
    ip6 saddr . meta l4proto . th dport @blocked_ipv6_port counter drop
}
```

- Se eligió la concatenación `addr . inet_proto . inet_service` porque permite
  un único set con timeout por familia y una sola regla, sin generar reglas por
  bloqueo.
- Idempotencia: `prepare_port_blocking()` primero ejecuta el `prepare()`
  histórico (que no cambia) y luego un script con `add table/set/chain` (no
  fallan si existen) + `flush chain input_port` + reinserción de reglas, todo en
  una transacción `nft -f` validada antes con `--check`. Reaplicarlo no duplica
  reglas ni toca `blocked_ipv4`, `blocked_ipv6` ni la cadena `input`.
- Elemento: `add element inet auditoria_response blocked_ipv4_port
  { 192.168.1.50 . tcp . 22 timeout 120s }`. El kernel lo expira solo; la base
  lo marca `EXPIRED` lógicamente y la recuperación tras reinicio lo restaura con
  el tiempo restante.
- Todas las protecciones aplican igual que en `TEMPORARY_BLOCK_IP` (el planner
  reutiliza `plan_temporary_block`): loopback, unspecified, multicast,
  link-local, Tailscale `100.64.0.0/10` y `fd7a:115c:a1e0::/48`, trusted admin
  IPs, sesiones SSH establecidas (también en `AUDITORIA_SSH_PORT` si no es 22),
  IPs locales y gateways. Todas se validan en la capa de ejecución: la decisión
  conserva la acción propuesta y la ejecución queda `SKIPPED` con
  `protection_rejected=true`. Las direcciones protegidas no generan ofensas de
  reincidencia.
- Idempotencia de ejecución: si ya existe un bloqueo vigente equivalente
  (mismo host, IP, acción, protocolo y puerto), la ejecución devuelve `SKIPPED`
  con el motivo en lugar de `FAILED`; el incidente sigue `CONTAINED` y no se
  cuenta una ofensa adicional. Aplica también a `TEMPORARY_BLOCK_IP`.
- `response_blocks` registra `action`, `protocol` y `port`. La unicidad de
  bloqueos vivos es por `(hostname, target_ip, action, protocol, port)`; para
  `TEMPORARY_BLOCK_IP` sigue siendo una por IP.

La decisión y la ejecución registran `action`, `target_ip`, `protocol`, `port`,
`duration_seconds`, `executed`, `status` y `reason`.

## 5. Reincidencia

- **Ofensa**: detección candidata a bloqueo cuya decisión no fue `NO_ACTION` y
  que no fue rechazada por protección. Se guarda en `response_offenses`
  (`auditoria.db`), por lo que sobrevive reinicios.
- **Nivel**: `1 + ofensas previas del mismo origen en el mismo servidor dentro
  de la ventana deslizante` (`AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS`, por
  defecto 86400 s), acotado al número de niveles.
- **Duración**: `AUDITORIA_RESPONSE_ESCALATION_SECONDS` (por defecto
  `120,600,3600`). Cada nivel está entre 60 y 86400 s y la lista es no
  decreciente (máximo 10 niveles): nunca hay bloqueo infinito.
- **Regreso a nivel 1**: cuando no hay ofensas del origen dentro de la ventana.
- **Direcciones protegidas**: no generan decisión de bloqueo y no se registran
  como ofensa.
- Con `AUDITORIA_RESPONSE_ESCALATION_ENABLED=false` (defecto) la duración es la
  histórica `AUDITORIA_TEMPORARY_BLOCK_SECONDS`; el nivel se informa igualmente.

La decisión registra `recurrence_level`, `previous_incidents`,
`selected_duration_seconds` y el motivo (`reason`) incluye el detalle cuando el
escalamiento está activo.

## 6. Modos de respuesta

| Modo | Incidente | Evidencia | Decisión | Firewall |
|---|---|---|---|---|
| `audit_only` | sí (`OBSERVED`) | sí, si está habilitada | `RECOMMEND_BLOCK_IP[_PORT]` | nunca (ejecutor en dry-run) |
| `assisted` | sí (`OPEN` → `CONTAINED`/`OBSERVED`) | sí | `RECOMMEND_…` con `approval_required=true` y `proposed_action`; queda `PENDING_APPROVAL` | solo tras aprobación de un superadmin, revalidada por el agente (ver sección 6.1) |
| `automatic` | sí (`CONTAINED`/`OPEN`) | sí | `TEMPORARY_BLOCK_IP[_PORT]` solo si su `AUDITORIA_ALLOW_*` está en `true` | sí, tras validar protecciones dinámicas |

### 6.1 Flujo de aprobación (`assisted`)

1. El agente crea la acción en `response_approvals` (`PENDING_APPROVAL`, vence a
   los `AUDITORIA_APPROVAL_TTL_SECONDS`) y emite `RESPONSE_APPROVAL_REQUESTED`.
   El central la proyecta en `response_actions`.
2. Un **superadmin** aprueba o rechaza desde el detalle del incidente:
   `POST /incidents/{id}/actions/{action_id}/approve` o `/reject`
   (`{"reason": "..."}` opcional, máximo 500 caracteres, sin caracteres de
   control). Requiere sesión, token CSRF y mismo origen; un viewer recibe `403`.
   La transición `PENDING_APPROVAL → APPROVED/REJECTED` es atómica
   (`BEGIN IMMEDIATE`); un segundo intento o una acción vencida devuelve `409`.
   Se registra usuario, id de usuario, fecha y motivo.
3. El agente consulta `GET /agent/response-actions` (credencial del agente) en
   su ciclo principal, solo si tiene acciones pendientes. El central solo envía
   `action_id` + decisión: el agente ejecuta únicamente la acción que él mismo
   propuso y almacenó.
4. Al aprobar, el agente: transiciona atómicamente `PENDING_APPROVAL →
   EXECUTING` (impide doble ejecución y rechaza acciones vencidas), comprueba
   que el modo siga siendo `assisted` y que el bloqueo esté autorizado
   (`AUDITORIA_ALLOW_TEMPORARY_IP[_PORT]_BLOCK`), y ejecuta con el mismo
   `ResponseExecutor`, que vuelve a resolver las protecciones dinámicas,
   Tailscale/trusted y bloqueos vigentes. Registra `RESPONSE_EXECUTION` con
   `approval_id`, `approved_by`, `approved_at` y actualiza el incidente.
5. Al rechazar: `REJECTED` local, `RESPONSE_REJECTION_APPLIED` con
   `rejected_by`, fecha y motivo; nunca toca el firewall; el incidente pasa a
   `OBSERVED`.
6. Vencimiento: el agente marca `EXPIRED` las acciones no decididas a tiempo y
   emite `RESPONSE_APPROVAL_EXPIRED`. Una ejecución interrumpida por un reinicio
   (`EXECUTING`) queda `FAILED` al arrancar.

Los resultados informados por el agente solo actualizan acciones que un humano
ya aprobó o rechazó; un agente no puede aprobar por sí mismo.

## 7. Configuración nueva (`/etc/auditoria-system/agent.env`)

| Variable | Defecto | Rango / valores |
|---|---|---|
| `AUDITORIA_RESPONSE_BLOCK_SCOPE` | `ip` | `ip`, `ip_port` |
| `AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK` | `false` | booleano |
| `AUDITORIA_SSH_PORT` | `22` | 1–65535 |
| `AUDITORIA_RESPONSE_ESCALATION_ENABLED` | `false` | booleano |
| `AUDITORIA_RESPONSE_ESCALATION_SECONDS` | `120,600,3600` | 1–10 niveles, 60–86400 s, no decreciente |
| `AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS` | `86400` | 300–2592000 |
| `AUDITORIA_INCIDENTS_ENABLED` | `true` | booleano |
| `AUDITORIA_INCIDENT_GROUPING_SECONDS` | `3600` | 60–86400 |
| `AUDITORIA_EVIDENCE_ENABLED` | `false` | booleano |
| `AUDITORIA_EVIDENCE_RETENTION_DAYS` | `7` | 1–365 |
| `AUDITORIA_EVIDENCE_MAX_BYTES` | `262144` | 16384–4194304 (por captura) |
| `AUDITORIA_EVIDENCE_MAX_TOTAL_BYTES` | `52428800` | 1 MiB–1 GiB |
| `AUDITORIA_EVIDENCE_COMMAND_TIMEOUT_SECONDS` | `5` | 1–30 |
| `AUDITORIA_APPROVAL_TTL_SECONDS` | `3600` | 300–86400 |

Valores inválidos vuelven al valor por defecto seguro (mismo patrón que el resto
de variables de respuesta).

Ejemplo de laboratorio (bloqueo automático de SSH por IP+puerto con
escalamiento):

```dotenv
AUDITORIA_RESPONSE_MODE=automatic
AUDITORIA_TRUSTED_ADMIN_IPS=<ip-de-administración>
AUDITORIA_RESPONSE_BLOCK_SCOPE=ip_port
AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK=true
AUDITORIA_RESPONSE_ESCALATION_ENABLED=true
AUDITORIA_RESPONSE_ESCALATION_SECONDS=120,600,3600
AUDITORIA_EVIDENCE_ENABLED=true
```

## 8. API

Todas requieren sesión y respetan el scope por `agent_id` (un viewer obtiene
`404` para incidentes de servidores ajenos).

| Método y ruta | Descripción |
|---|---|
| `GET /incidents` | Lista paginada (`limit` 1–200, `offset`) con filtros `agent_id`, `severity`, `status`, `incident_type`, `source_ip`, `since`, `until` (con zona horaria; filtran por `opened_at`). Respuesta `{items, total, limit, offset}`. |
| `GET /incidents/{incident_id}` | Cabecera, acciones propuestas (`actions`), detecciones, última decisión, última ejecución y metadatos de evidencia. |
| `POST /incidents/{incident_id}/actions/{action_id}/approve` | Solo superadmin + CSRF. Aprueba una acción `PENDING_APPROVAL`. |
| `POST /incidents/{incident_id}/actions/{action_id}/reject` | Solo superadmin + CSRF. Rechaza con motivo opcional. |
| `GET /agent/response-actions` | Solo credencial de agente. Decisiones aún no aplicadas por ese agente. |
| `GET /incidents/{incident_id}/timeline` | Timeline cronológica. |
| `GET /incidents/{incident_id}/evidence` | Metadatos de evidencia del incidente. |
| `GET /incidents/{incident_id}/evidence/{capture_id}` | Metadatos de una captura que pertenezca al incidente. |

`incident_id` se valida con `^INC-[0-9A-F]{16}$` y `capture_id` como UUID. La API
no expone archivos: los nombres de artefacto que no coinciden con
`^[a-z0-9_]+\.(txt|json)$` se devuelven como `null`. `agent_id` es opcional en
el detalle; si un mismo `incident_id` existiera en dos servidores visibles se
responde `409` pidiendo `agent_id`.

## 9. Esquemas

- `auditoria.db` (versión final **5**):
  - v3 → **v4** (aditiva): columnas `action`, `protocol`, `port` en
    `response_blocks` (los bloqueos existentes quedan como
    `TEMPORARY_BLOCK_IP`), índice único de bloqueos vivos ampliado, tablas
    `incidents` y `response_offenses`.
  - v4 → **v5** (aditiva): tablas `response_approvals` y
    `forensic_capture_queue`.
- `central.db` (versión final **3**):
  - v1 → **v2** (aditiva): tablas `incidents` e `incident_links`.
  - v2 → **v3** (aditiva): tabla `response_actions`.

Cada paso se aplica según `PRAGMA user_version`: una base v3 ejecuta v4 y v5,
una base v4 solo v5; una central v1 ejecuta v2 y v3, una v2 solo v3. Versiones
mayores a las soportadas se rechazan.

Las migraciones se aplican automáticamente al iniciar. Un rollback a una versión
anterior requiere restaurar también las bases desde el backup previo al upgrade
(como ya hace `scripts/rollback.sh --backup`), porque el código anterior
rechaza esquemas más nuevos.
