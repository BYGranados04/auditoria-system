# Referencia técnica de Nexora v1.0.0

Datos de consulta rápida. Las explicaciones están en los documentos enlazados.
Los identificadores `auditoria-*` se mantienen por compatibilidad con v1.0.

## Rutas

| Ruta | Rol | Contenido |
|---|---|---|
| `/opt/auditoria-system/` | todos | Código de la release y entorno virtual `.venv/` |
| `/opt/auditoria-system.rollback.<UTC>` | todos | Código anterior que deja `actualizar.sh` |
| `/opt/auditoria-system.fallido.<UTC>` | todos | Código que deja `rollback.sh` tras un fallo |
| `/etc/auditoria-system/agent.env` | todos | Configuración (`0640` root) |
| `/etc/auditoria-system/agent-identity.json` | todos | Identidad y credencial del agente (`0600` root) |
| `/var/lib/auditoria-system/auditoria.db` | todos | Base local del agente |
| `/var/lib/auditoria-system/notifications.db` | todos | Notificaciones |
| `/var/lib/auditoria-system/agent_state.json` | todos | Estado de baseline del agente |
| `/var/lib/auditoria-system/evidence/` | todos | Evidencia forense local |
| `/var/lib/auditoria-system-auth/auth.db` | central | Usuarios, sesiones, agentes y credenciales |
| `/var/lib/auditoria-system-central/central.db` | central | Eventos centralizados, incidentes y acciones |
| `/var/log/auditoria-system/events.jsonl` | todos | Log JSON de eventos |
| `/var/backups/auditoria-system/` | todos | Destino por defecto de `backup.sh` |
| `/etc/systemd/system/auditoria-agent.service` | todos | Unit del agente |
| `/etc/systemd/system/auditoria-api.service` | central | Unit de la API |

## Servicios

| Unit | Usuario | Proceso | Rol |
|---|---|---|---|
| `auditoria-agent.service` | `root` | `/opt/auditoria-system/.venv/bin/python -m app.agent` | central y agent |
| `auditoria-api.service` | `auditoria-api` | `uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log` | central |

Ambos usan `EnvironmentFile=-/etc/auditoria-system/agent.env`,
`Restart=on-failure` y `RestartSec=5s`. Endurecimiento en
[seguridad.md](seguridad.md#2-mínimo-privilegio).

## Bases SQLite

| Base | Versión de esquema | Tablas |
|---|---|---|
| `auditoria.db` | 5 (`PRAGMA user_version`) | `events`, `event_outbox`, `response_blocks`, `response_offenses`, `response_approvals`, `incidents`, `forensic_capture_queue` |
| `central.db` | 3, modo WAL | `events`, `incidents`, `incident_links`, `response_actions` |
| `auth.db` | 3 | `users`, `sessions`, `agents`, `agent_registration_tokens`, `agent_credentials`, `user_host_access` |
| `notifications.db` | sin versión numérica | `notifications` |

- Todas rechazan abrir un esquema más nuevo que el soportado.
- `user_host_access` es una tabla heredada; no se encontró uso funcional en
  v1.0.0 (no confirmado que no tenga uso futuro).
- El formato de los metadatos de evidencia es `schema_version` 1.

Comprobación de integridad (solo lectura):

```bash
sudo /opt/auditoria-system/.venv/bin/python -c 'import sqlite3,sys; c=sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True); print(c.execute("PRAGMA integrity_check").fetchone()[0], c.execute("PRAGMA user_version").fetchone()[0])' /var/lib/auditoria-system/auditoria.db
```

## Comandos de health

```bash
# Health de la API (público, solo desde el central)
curl --fail --silent --show-error http://127.0.0.1:8000/health
# {"status":"ok","service":"auditoria-system-api"}

# Servicios
systemctl is-active auditoria-agent.service
systemctl is-active auditoria-api.service
```

Los scripts usan el mismo `curl --fail` contra `/health`, con hasta 15 intentos
de 3 s separados por 1 s.

## Scripts

| Script | Sintaxis | Documento |
|---|---|---|
| `scripts/preparar-instalacion.sh` | `sudo /opt/auditoria-system/scripts/preparar-instalacion.sh` | [instalacion.md](instalacion.md) |
| `scripts/instalar-servicio.sh` | `sudo ./scripts/instalar-servicio.sh --role central\|agent` | [instalacion.md](instalacion.md) |
| `scripts/actualizar.sh` | `sudo ./scripts/actualizar.sh --role central\|agent --source /ruta/release [--destino-backup /ruta]` | [actualizacion.md](actualizacion.md) |
| `scripts/backup.sh` | `sudo ./scripts/backup.sh --role central\|agent [--destino /ruta]` | [backup-restore-rollback.md](backup-restore-rollback.md) |
| `scripts/restaurar-backup.sh` | `sudo ./scripts/restaurar-backup.sh --role central\|agent --backup /ruta/backup [--no-start]` | [backup-restore-rollback.md](backup-restore-rollback.md) |
| `scripts/rollback.sh` | `sudo ./scripts/rollback.sh --role central\|agent --backup /ruta/backup --codigo-anterior /opt/auditoria-system.rollback.<UTC>` | [backup-restore-rollback.md](backup-restore-rollback.md#4-rollback) |
| `scripts/lib/operaciones-comunes.sh` | biblioteca, no se ejecuta directamente | — |

## CLIs de Python

Se ejecutan desde `/opt/auditoria-system` con `.venv/bin/python`:

| Comando | Uso |
|---|---|
| `python -m app.agent` | Agente continuo (lo usa systemd). |
| `python -m app.agent register --server URL --token TOKEN` | Registro del agente; el comando completo lo genera el dashboard. |
| `python -m app.auth create-superadmin [--database RUTA]` | Crea el primer `superadmin` (pide usuario y contraseña de forma interactiva). |
| `python -m app.storage events [--severity] [--type] [--hostname] [--category] [--since] [--until] [--limit]` | Consulta de eventos locales. |
| `python -m app.storage stats` | Estadísticas de eventos. |
| `python -m app.storage retention --before FECHA [--apply]` | Retención; sin `--apply` solo simula. |
| `python -m app.audit` | Auditoría puntual del host en JSON. |

## Módulos de Python

| Módulo | Responsabilidad |
|---|---|
| `app/agent/continuous_agent.py` | Ciclo principal del agente |
| `app/agent/sync.py`, `heartbeat.py`, `approvals.py`, `registration.py` | Outbox, heartbeat, consulta de aprobaciones, identidad |
| `app/detection/ssh_collector.py`, `ssh_correlation.py` | Lectura de journald (`ssh.service`) y correlación |
| `app/response/engine.py`, `policy.py` | Decisión de respuesta |
| `app/response/executor.py`, `firewall.py`, `firewall_backend.py` | Ejecución, planificación y backend nftables |
| `app/response/protection.py` | Protecciones dinámicas y configuradas |
| `app/response/recurrence.py`, `recovery.py` | Reincidencia y recuperación al arrancar |
| `app/response/incidents.py`, `forensics.py` | Incidentes locales y evidencia |
| `app/storage/event_repository.py` | Persistencia y migraciones de `auditoria.db` |
| `app/api/main.py`, `incidents.py`, `dashboard/` | Aplicación FastAPI y dashboard |
| `app/agents/web.py`, `events.py` | Enrolamiento, heartbeat, agentes, ingesta y acciones |
| `app/central/repository.py`, `incidents.py` | `central.db` y proyección de incidentes |
| `app/auth/repository.py`, `web.py` | Usuarios, sesiones, roles y credenciales |
| `app/notifications/` | Política, almacenamiento y envío con Resend |
| `app/core/config.py`, `events.py` | Configuración del agente y modelo `SecurityEvent` |

## API HTTP

Todas las rutas las sirve la API en `127.0.0.1:8000`. «Sesión» significa cookie
de sesión válida; «CSRF» significa cabecera `X-CSRF-Token` y verificación de
origen.

### Autenticación y usuarios

| Método y ruta | Acceso |
|---|---|
| `POST /auth/login` | público, con verificación de origen |
| `GET /auth/me` | sesión |
| `POST /auth/logout` | sesión + CSRF |
| `GET /admin/users` | `superadmin` |
| `POST /admin/users` | `superadmin` + CSRF |
| `POST /admin/users/{user_id}/status` | `superadmin` + CSRF |
| `POST /admin/users/{user_id}/role` | `superadmin` + CSRF |

### Agentes

| Método y ruta | Acceso |
|---|---|
| `POST /agents/registration-token` | sesión + CSRF; 503 si falta `AUDITORIA_CENTRAL_URL` |
| `POST /agent/enroll` | público; token de registro en el cuerpo |
| `POST /agent/heartbeat` | credencial de agente (`Bearer`) |
| `POST /agent/events/batch` | credencial de agente |
| `GET /agent/response-actions` | credencial de agente |
| `GET /agents` | sesión |
| `GET /agents/{agent_id}` | sesión |

### Consulta e incidentes

| Método y ruta | Acceso |
|---|---|
| `GET /health` | público |
| `GET /status` | sesión |
| `GET /events`, `GET /detections`, `GET /responses` | sesión |
| `GET /incidents`, `GET /incidents/{incident_id}` | sesión |
| `GET /incidents/{incident_id}/timeline` | sesión |
| `GET /incidents/{incident_id}/evidence` | sesión |
| `GET /incidents/{incident_id}/evidence/{capture_id}` | sesión |
| `POST /incidents/{incident_id}/actions/{action_id}/approve` | `superadmin` + CSRF |
| `POST /incidents/{incident_id}/actions/{action_id}/reject` | `superadmin` + CSRF |
| `GET /notifications`, `GET /notifications/summary`, `GET /notifications/{notification_id}` | sesión |

Un `viewer` solo obtiene datos de los agentes de los que es propietario.

### Páginas del dashboard

`GET /login`, `/dashboard`, `/dashboard/events`, `/dashboard/detections`,
`/dashboard/responses`, `/dashboard/incidents`, `/dashboard/servers`,
`/dashboard/users`, `/dashboard/notifications` y los recursos
`/dashboard/assets/styles.css`, `/dashboard/assets/dashboard.js` y
`/dashboard/assets/login.js`.

## Tipos de evento

| Familia | Tipos |
|---|---|
| SSH | `SSH_AUTH_SUCCESS`, `SSH_AUTH_FAILURE`, `SSH_INVALID_USER`, `SSH_PREAUTH_CONNECTION_CLOSED`, `SSH_JOURNAL_RESYNC` |
| Detección | `SSH_BRUTE_FORCE_ATTEMPT`, `SSH_USER_ENUMERATION_ATTEMPT`, `SSH_REPEATED_PREAUTH_ACTIVITY` |
| Respuesta | `RESPONSE_DECISION`, `RESPONSE_EXECUTION`, `RESPONSE_RECOVERY`, `RESPONSE_RECOVERY_ERROR` |
| Aprobación | `RESPONSE_APPROVAL_REQUESTED`, `RESPONSE_APPROVAL_ERROR`, `RESPONSE_APPROVAL_EXPIRED`, `RESPONSE_REJECTION_APPLIED`; el timeline del central muestra además `RESPONSE_APPROVAL_GRANTED` y `RESPONSE_APPROVAL_DENIED`, que son entradas sintéticas derivadas de la decisión, no eventos almacenados |
| Incidente | `INCIDENT_OPENED`, `INCIDENT_UPDATED`, `INCIDENT_ERROR` |
| Evidencia | `FORENSIC_EVIDENCE_CAPTURED`, `FORENSIC_EVIDENCE_FAILED` |
| Host | `PORT_OPENED`, `PORT_CLOSED`, `USER_CREATED`, `USER_REMOVED`, `USER_MODIFIED`, `SERVICE_STARTED`, `SERVICE_STOPPED`, `CRITICAL_FILE_CHANGED`, `FIREWALL_DISABLED`, `FIREWALL_CHANGED`, `BASELINE_CREATED`, `BASELINE_MIGRATED`, `SYSTEM_REBOOT_DETECTED` |
| Agente | `AGENT_STARTED`, `AGENT_STOPPED`, `AGENT_ERROR` |

`CRITICAL_FILE_CHANGED` es una comparación básica con la baseline local, no un
sistema FIM avanzado.

## Estados

### `response_blocks`

| Estado | Significado |
|---|---|
| `PENDING` | Registrado; regla aún no confirmada. Si el agente se reinicia en este estado, pasa a `FAILED`. |
| `ACTIVE` | Regla aplicada en nftables y vigente. |
| `EXPIRED` | Venció su `expires_at`; marcado por la reconciliación del ciclo o al arrancar. |
| `FAILED` | No se pudo aplicar o restaurar. |
| `REMOVED` | Solo existe en la restricción del esquema y en el repositorio; ningún flujo del agente lo produce en v1.0.0. No debe esperarse en operación. |

### Resultado de ejecución (`RESPONSE_EXECUTION`)

`EXECUTED`, `SKIPPED`, `FAILED` y `DRY_RUN`. `DRY_RUN` solo lo devuelve el
ejecutor simulado ante una acción `TEMPORARY_*`. Con la lógica de v1.0.0 las
acciones `TEMPORARY_*` solo se deciden en `automatic` con el `ALLOW_*`
correspondiente, que usa el ejecutor real, y las `RECOMMEND_*` terminan en
`SKIPPED` antes de esa rama; por tanto no se espera ver `DRY_RUN` en operación
normal. En aprobaciones, el agente informa un `DRY_RUN` como `SKIPPED`.

### Aprobaciones

- Agente (`response_approvals`): `PENDING_APPROVAL`, `EXECUTING`, `EXECUTED`,
  `SKIPPED`, `FAILED`, `REJECTED`, `EXPIRED`.
- Central (`response_actions`): `PENDING_APPROVAL`, `APPROVED`, `REJECTED`,
  `EXECUTED`, `SKIPPED`, `FAILED`, `EXPIRED`.

### Incidentes

`OPEN`, `OBSERVED`, `CONTAINED` y `CLOSED`. Identificador `INC-` seguido de 16
caracteres hexadecimales en mayúscula. Detalle en
[incidentes-y-evidencia.md](incidentes-y-evidencia.md).

### Outbox y cola forense

- `event_outbox`: `pending`, `acknowledged`, `permanently_failed`.
- `forensic_capture_queue`: `PENDING`, `DONE`, `FAILED`.

## Roles y modos

| Concepto | Valores |
|---|---|
| Rol de despliegue | `central`, `agent` |
| Rol de usuario | `superadmin`, `viewer` |
| Modo de respuesta | `audit_only` (default), `assisted`, `automatic` |
| Alcance de bloqueo | `ip` (default), `ip_port` |
| Acciones | `NO_ACTION`, `RECOMMEND_BLOCK_IP`, `RECOMMEND_BLOCK_IP_PORT`, `TEMPORARY_BLOCK_IP`, `TEMPORARY_BLOCK_IP_PORT` |
| Escalamiento | 120 s → 600 s → 3600 s (ventana 86400 s), desactivado por defecto |
| Presencia de agente | `online`, `offline`, `unknown` |

## Documentos relacionados

- [arquitectura.md](arquitectura.md)
- [configuracion.md](configuracion.md)
- [operacion.md](operacion.md)
- [troubleshooting.md](troubleshooting.md)
