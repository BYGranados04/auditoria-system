# Configuración de Nexora v1.0.0

## 1. Archivo de configuración

Todos los servicios leen `/etc/auditoria-system/agent.env` mediante
`EnvironmentFile=-/etc/auditoria-system/agent.env`. El guion inicial hace que el
archivo sea opcional: si no existe, se aplican los valores por defecto.

- El instalador lo crea **una sola vez** a partir de `deploy/agent.env.example`
  (modo 0640, root). Las ejecuciones posteriores y `actualizar.sh` conservan el
  archivo existente.
- Después de modificarlo, reinicie los servicios afectados:

```bash
sudoedit /etc/auditoria-system/agent.env
sudo systemctl restart auditoria-agent.service
sudo systemctl restart auditoria-api.service   # solo central, si cambió una variable de la API
```

- No guarde credenciales del agente en este archivo. La identidad vive en
  `agent-identity.json` (ver [seguridad.md](seguridad.md)).

**Comportamiento ante valores inválidos.** La mayoría de las variables vuelven
en silencio a su valor por defecto. Hay tres excepciones que **impiden
arrancar**:

- `AUDITORIA_HEARTBEAT_INTERVAL` fuera de rango o no entero;
- `AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS` fuera de rango, no entero, o menor o
  igual que el intervalo de heartbeat;
- una entrada inválida en `AUDITORIA_TRUSTED_ADMIN_IPS`, incluido un rango CIDR.

## 2. Valores seguros de una instalación nueva

| Variable | Valor efectivo |
|---|---|
| `AUDITORIA_RESPONSE_MODE` | `audit_only` |
| `AUDITORIA_RESPONSE_BLOCK_SCOPE` | `ip` |
| `AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK` | `false` |
| `AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK` | `false` |
| `AUDITORIA_RESPONSE_ESCALATION_ENABLED` | `false` |
| `AUDITORIA_EVIDENCE_ENABLED` | `false` |

La plantilla no activa ninguna de estas variables, así que rigen los valores por
defecto del código. Con ellos, Nexora observa, detecta, agrupa incidentes y
recomienda, pero **no modifica el firewall**.

## 3. Qué habilita acciones activas

Un bloqueo de firewall requiere **dos** condiciones independientes:

1. **Un modo que ejecute:**
   - `automatic` ejecuta sin intervención humana;
   - `assisted` ejecuta solo después de la aprobación de un `superadmin`.
2. **El permiso del alcance correspondiente:**
   - alcance `ip`: `AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK=true`;
   - alcance `ip_port`: `AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK=true`.

| Modo | `ALLOW_*` del alcance | Resultado |
|---|---|---|
| `audit_only` | cualquiera | Solo recomendación (`RECOMMEND_*`). |
| `assisted` | `false` | Se registra la propuesta, pero al aprobarla termina en `SKIPPED` («La configuración del agente no autoriza este tipo de bloqueo»). |
| `assisted` | `true` | Se ejecuta tras la aprobación de un `superadmin`, revalidando las protecciones. |
| `automatic` | `false` | Recomendación: «el bloqueo temporal … no ha sido autorizado». |
| `automatic` | `true` | Bloqueo temporal inmediato, salvo protecciones. |

El permiso tiene que coincidir con el alcance. Por ejemplo, con
`AUDITORIA_RESPONSE_BLOCK_SCOPE=ip` y solo
`AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK=true`, no se ejecuta nada. El detalle
completo está en [respuesta-defensiva.md](respuesta-defensiva.md).

## 4. Referencia de variables

Columna «Plantilla»:

- **activa**: la variable tiene una línea activa en `deploy/agent.env.example`;
- **coment.**: aparece como línea comentada;
- **ausente**: no aparece.

### 4.1 Agente: rutas, ciclo, sincronización y heartbeat

| Variable | Propósito | Default | Valores válidos | Riesgo / observación | Plantilla |
|---|---|---|---|---|---|
| `AUDITORIA_INTERVAL` | Segundos entre ciclos del agente | `10` | entero > 0 | Valores altos retrasan la detección. | activa |
| `AUDITORIA_STATE_DIR` | Estado, `auditoria.db`, `notifications.db`, `evidence/` | `/var/lib/auditoria-system` | ruta | La unidad solo permite escribir en la ruta por defecto (`ProtectSystem=strict`). No la cambie. | activa |
| `AUDITORIA_LOG_DIR` | `events.jsonl` | `/var/log/auditoria-system` | ruta | Igual que la anterior. | activa |
| `AUDITORIA_AGENT_IDENTITY_FILE` | Identidad del agente | `/etc/auditoria-system/agent-identity.json` | ruta | Contiene la credencial; debe tener modo 0600. | activa |
| `AUDITORIA_SYNC_INTERVAL` | Ciclo del outbox | `10` | 1–3600 | – | activa |
| `AUDITORIA_SYNC_TIMEOUT_SECONDS` | Timeout HTTP de sincronización y aprobaciones | `5` | 1–60 | – | activa |
| `AUDITORIA_SYNC_BATCH_SIZE` | Eventos por lote | `50` | 1–100 | No debe superar `AUDITORIA_AGENT_EVENT_BATCH_MAX` del central. | activa |
| `AUDITORIA_SYNC_RETRY_BASE_SECONDS` | Base del backoff | `5` | 1–3600 | – | activa |
| `AUDITORIA_SYNC_RETRY_MAX_SECONDS` | Tope del backoff | `300` | 1–86400 | – | activa |
| `AUDITORIA_HEARTBEAT_INTERVAL` | Intervalo de heartbeat | `30` | 5–3600 | Un valor inválido **impide arrancar** el agente y la API. | activa |
| `AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS` | Segundos sin heartbeat para considerar un agente sin conexión | `120` | 10–86400, mayor que el heartbeat | Un valor inválido **impide arrancar**. | activa |

### 4.2 Agente: respuesta defensiva

| Variable | Propósito | Default | Valores válidos | Riesgo / observación | Plantilla |
|---|---|---|---|---|---|
| `AUDITORIA_RESPONSE_MODE` | Modo de respuesta | `audit_only` | `audit_only`, `assisted`, `automatic` | `automatic` bloquea sin intervención humana. Un valor inválido equivale a `audit_only`. | ausente |
| `AUDITORIA_RESPONSE_BLOCK_SCOPE` | Alcance del bloqueo | `ip` | `ip`, `ip_port` | `ip_port` bloquea solo `tcp/AUDITORIA_SSH_PORT`. | coment. |
| `AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK` | Autoriza bloquear la IP completa | `false` | booleano | Habilita acciones activas. | ausente |
| `AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK` | Autoriza bloquear IP + puerto | `false` | booleano | Habilita acciones activas. | coment. |
| `AUDITORIA_TEMPORARY_BLOCK_SECONDS` | Duración del bloqueo sin escalamiento | `900` | 60–86400 | Los bloqueos siempre son temporales. | ausente |
| `AUDITORIA_TRUSTED_ADMIN_IPS` | IPs que nunca se bloquean | vacío | IPs separadas por coma; **no** se admiten rangos CIDR | Si se deja vacía, un administrador puede bloquearse a sí mismo. Una entrada inválida impide arrancar el agente. | ausente |
| `AUDITORIA_SSH_PORT` | Puerto del servicio SSH (alcance `ip_port` y protección de sesiones) | `22` | 1–65535 | Si no coincide con el puerto real, el bloqueo `ip_port` apunta a otro puerto. | coment. |
| `AUDITORIA_RESPONSE_ESCALATION_ENABLED` | Escalamiento por reincidencia | `false` | booleano | – | coment. |
| `AUDITORIA_RESPONSE_ESCALATION_SECONDS` | Duración por nivel | `120,600,3600` | 1–10 niveles, cada uno 60–86400, no decrecientes | Un valor inválido vuelve a la lista por defecto. Nunca produce bloqueos infinitos. | coment. |
| `AUDITORIA_RESPONSE_ESCALATION_WINDOW_SECONDS` | Ventana de reincidencia | `86400` | 300–2592000 | – | coment. |
| `AUDITORIA_APPROVAL_TTL_SECONDS` | Vigencia de una acción pendiente en `assisted` | `3600` | 300–86400 | Al vencer queda `EXPIRED`. | coment. |

### 4.3 Agente: incidentes y evidencia

| Variable | Propósito | Default | Valores válidos | Riesgo / observación | Plantilla |
|---|---|---|---|---|---|
| `AUDITORIA_INCIDENTS_ENABLED` | Agrupar detecciones en incidentes | `true` | booleano | – | coment. |
| `AUDITORIA_INCIDENT_GROUPING_SECONDS` | Ventana de agrupación y de cierre por inactividad | `3600` | 60–86400 | También determina cuándo se cierran los incidentes inactivos. | coment. |
| `AUDITORIA_EVIDENCE_ENABLED` | Evidencia forense local | `false` | booleano | Ejecuta comandos de solo lectura en el host. | coment. |
| `AUDITORIA_EVIDENCE_RETENTION_DAYS` | Días de retención | `7` | 1–365 | – | coment. |
| `AUDITORIA_EVIDENCE_MAX_BYTES` | Bytes por captura | `262144` | 16384–4194304 | – | coment. |
| `AUDITORIA_EVIDENCE_MAX_TOTAL_BYTES` | Total en disco | `52428800` | 1048576–1073741824 | Al superarlo se borran las capturas más antiguas. | coment. |
| `AUDITORIA_EVIDENCE_COMMAND_TIMEOUT_SECONDS` | Timeout por comando | `5` | 1–30 | – | coment. |

### 4.4 Central: API, autenticación e ingesta

| Variable | Propósito | Default | Valores válidos | Riesgo / observación | Plantilla |
|---|---|---|---|---|---|
| `AUDITORIA_CENTRAL_URL` | URL del central que se incluye en el comando de registro | vacío | `http`/`https` con host; sin query, fragmento ni credenciales | Si está vacía, generar un token responde 503. | activa (vacía) |
| `AUDITORIA_CENTRAL_DB` | Ruta de `central.db` | `/var/lib/auditoria-system-central/central.db` | ruta | – | activa |
| `AUDITORIA_AUTH_DB` | Ruta de `auth.db` | `/var/lib/auditoria-system-auth/auth.db` | ruta | La fija la unidad de la API. | ausente |
| `AUDITORIA_AUTH_SESSION_SECONDS` | Duración de la sesión web | `28800` | 300–86400 | – | activa |
| `AUDITORIA_AUTH_COOKIE_SECURE` | Atributo `Secure` de las cookies | `false` | booleano | Póngalo en `true` cuando el acceso sea por HTTPS. | activa |
| `AUDITORIA_AGENT_EVENT_BATCH_MAX` | Máximo de eventos por lote recibido | `100` | 1–1000 | – | ausente |
| `AUDITORIA_EVENT_MAX_FUTURE_SECONDS` | Tolerancia para timestamps en el futuro | `300` | 0–86400 | – | ausente |
| `AUDITORIA_EVENT_EVIDENCE_MAX_BYTES` | Tamaño máximo de `evidence` por evento | `65536` | 1024–1048576 | Un evento que lo supere se rechaza con 422. | ausente |

### 4.5 Notificaciones (las envía el agente)

| Variable | Propósito | Default | Valores válidos | Riesgo / observación | Plantilla |
|---|---|---|---|---|---|
| `AUDITORIA_NOTIFICATIONS_ENABLED` | Activa el envío | `false` | `true/1/yes/on`; cualquier otro valor equivale a `false` | – | activa |
| `AUDITORIA_NOTIFICATION_MIN_SEVERITY` | Severidad mínima de las detecciones que se notifican | `high` | `low`, `medium`, `high`, `critical` | – | activa |
| `AUDITORIA_NOTIFICATION_PROVIDER` | Proveedor | `resend` | `resend` | – | activa |
| `AUDITORIA_RESEND_API_KEY` | Clave del proveedor | vacío | texto | **Secreto.** No lo imprima en terminales compartidas. | activa (vacía) |
| `AUDITORIA_NOTIFICATION_FROM` | Remitente verificado | vacío | texto | – | activa (vacía) |
| `AUDITORIA_NOTIFICATION_TO` | Destinatario | vacío | un solo destinatario | Una lista separada por comas se envía como una sola cadena. | activa (vacía) |
| `AUDITORIA_RESEND_API_URL` | URL del proveedor | `https://api.resend.com/emails` | `http`/`https` con host | – | activa |
| `AUDITORIA_NOTIFICATION_TIMEOUT_SECONDS` | Timeout del envío | `5` | 1–60 | – | activa |

Las notificaciones solo se generan para eventos de categoría `detection`. Se
guardan en el `notifications.db` del nodo que las envía y no se sincronizan con
el central.

## 5. Ejemplo de laboratorio (no es un default)

Bloqueo automático de SSH por IP + puerto, con escalamiento y evidencia. Úselo
solo después de definir las IPs administrativas:

```dotenv
AUDITORIA_RESPONSE_MODE=automatic
AUDITORIA_TRUSTED_ADMIN_IPS=192.0.2.10
AUDITORIA_RESPONSE_BLOCK_SCOPE=ip_port
AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK=true
AUDITORIA_RESPONSE_ESCALATION_ENABLED=true
AUDITORIA_EVIDENCE_ENABLED=true
```

`192.0.2.10` es una dirección de documentación; reemplácela por la IP real de
administración.

Para volver al modo seguro, elimine esas líneas o restablezca los valores de la
sección 2 y reinicie el agente.
