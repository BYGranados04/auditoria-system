# Operación diaria de Nexora v1.0.0

Manual de operación para administradores. Los comandos usan las rutas por
defecto.

## 1. Servicios

```bash
systemctl status auditoria-agent.service
systemctl status auditoria-api.service          # solo central
systemctl --failed
```

Ambos servicios usan `Restart=on-failure`. Un servicio en estado `failed` de
forma persistente indica un error de configuración o de permisos (ver
[troubleshooting.md](troubleshooting.md)).

## 2. Health y estado

```bash
# Público, sin sesión
curl --fail --silent --show-error http://127.0.0.1:8000/health
# Respuesta esperada: {"status":"ok","service":"auditoria-system-api"}
```

`GET /status` requiere sesión y devuelve:

- presencia y `last_seen_at` del agente;
- total de eventos y conteo por severidad.

Los campos `response_mode`, `automatic_blocking_enabled` y
`live_response_blocks` siempre son `null` en v1.0.0. Para conocer el modo de
respuesta, consulte la configuración del agente.

## 3. Logs

```bash
sudo journalctl -u auditoria-agent.service -n 200 --no-pager
sudo journalctl -u auditoria-api.service -n 200 --no-pager
sudo tail -n 50 /var/log/auditoria-system/events.jsonl
```

El agente escribe cada evento como JSON en `events.jsonl` y en su salida
estándar, que llega a journald. La API se ejecuta con `--no-access-log`.

## 4. Eventos

Use el dashboard (**Eventos**, **Detecciones**, **Respuestas**) o, en el host
del agente, la CLI de consulta:

```bash
cd /opt/auditoria-system
sudo .venv/bin/python -m app.storage events --type SSH_BRUTE_FORCE_ATTEMPT --limit 20
sudo .venv/bin/python -m app.storage events --category response --since 2026-01-01T00:00:00+00:00
sudo .venv/bin/python -m app.storage stats
```

Las fechas requieren zona horaria. `app.storage` abre `auditoria.db` en lectura
y escritura, y la inicializa o migra si hace falta; ejecútela con el mismo
código instalado. `retention --before FECHA` es una simulación salvo que se
añada `--apply`.

## 5. Incidentes

En el dashboard, **Incidentes** muestra la lista. El detalle de cada incidente
incluye:

- las detecciones agrupadas;
- la última decisión y la última ejecución;
- las acciones pendientes o resueltas;
- los metadatos de evidencia;
- la timeline.

Estados de un incidente:

| Estado | Significado |
|---|---|
| `OPEN` | Requiere atención: acción pendiente de aprobación, ejecución fallida o recomendación en `automatic` sin permiso. |
| `OBSERVED` | Registrado sin contención (`audit_only`, IP protegida, rechazo, vencimiento u omisión). |
| `CONTAINED` | Hubo un bloqueo ejecutado correctamente. |
| `CLOSED` | Sin actividad durante `AUDITORIA_INCIDENT_GROUPING_SECONDS` (3600 s por defecto). |

Un incidente `CONTAINED` también se cierra por inactividad, aunque su bloqueo
siga vigente. El estado del bloqueo se consulta en nftables (sección 8).

## 6. Qué hacer ante una detección

1. Abra el incidente e identifique la IP de origen, el tipo de detección y la
   cantidad de intentos.
2. Compruebe si la IP es legítima (administración, monitoreo, VPN). Si lo es,
   agréguela a `AUDITORIA_TRUSTED_ADMIN_IPS` y reinicie el agente.
3. Revise la decisión:
   - en `audit_only` es una recomendación (`RECOMMEND_BLOCK_IP` o
     `RECOMMEND_BLOCK_IP_PORT`);
   - en `automatic` revise la ejecución;
   - en `assisted` hay una acción pendiente.
4. Si la evidencia está habilitada, revise sus metadatos. El contenido está solo
   en el agente, en `/var/lib/auditoria-system/evidence/` (ver
   [incidentes-y-evidencia.md](incidentes-y-evidencia.md)).
5. Documente la decisión según su procedimiento interno.

## 7. Modo `assisted`

1. El incidente queda en `OPEN` con una acción `PENDING_APPROVAL`, que vence
   según `AUDITORIA_APPROVAL_TTL_SECONDS` (3600 s por defecto).
2. Solo un `superadmin` puede aprobar o rechazar desde el detalle del
   incidente. El rechazo admite un motivo de hasta 500 caracteres.
3. El agente consulta las decisiones al final de cada ciclo, y solo si tiene
   acciones pendientes.
4. Al aprobar, el agente revalida la acción y la ejecuta:
   - comprueba que el modo siga siendo `assisted`;
   - comprueba que el `ALLOW_*` correspondiente esté activo;
   - aplica las protecciones dinámicas;
   - evita duplicar bloqueos.
5. Resultado: `EXECUTED` (incidente `CONTAINED`), `SKIPPED` o `FAILED`. Un
   rechazo o un vencimiento dejan el incidente en `OBSERVED` sin tocar el
   firewall.

Si una aprobación termina en `SKIPPED` con «La configuración del agente no
autoriza este tipo de bloqueo», falta el `ALLOW_*` del alcance (ver
[configuracion.md](configuracion.md#3-qué-habilita-acciones-activas)).

## 8. Reconocer una ejecución automática

Una ejecución automática deja estas señales:

- un evento `RESPONSE_DECISION` con acción `TEMPORARY_BLOCK_IP` o
  `TEMPORARY_BLOCK_IP_PORT`;
- un evento `RESPONSE_EXECUTION` con estado `EXECUTED`;
- el incidente en `CONTAINED`.

En el host del agente, el bloqueo vigente se ve así (solo lectura):

```bash
sudo nft list table inet auditoria_response
```

Los elementos de los sets muestran su tiempo restante (`expires`). Al vencer, el
kernel los retira y el agente marca el registro `EXPIRED` en el siguiente ciclo.

## 9. Estados principales

| Objeto | Estados |
|---|---|
| Resultado de ejecución | `EXECUTED`, `SKIPPED`, `FAILED` (`DRY_RUN` existe en el modelo; ver [referencia-tecnica.md](referencia-tecnica.md#resultado-de-ejecución-response_execution)) |
| Bloqueo (`response_blocks`) | `PENDING`, `ACTIVE`, `EXPIRED`, `FAILED` |
| Aprobación en el agente | `PENDING_APPROVAL`, `EXECUTING`, `EXECUTED`, `SKIPPED`, `FAILED`, `REJECTED`, `EXPIRED` |
| Acción en el central | `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `EXECUTED`, `SKIPPED`, `FAILED`, `EXPIRED` |
| Incidente | `OPEN`, `OBSERVED`, `CONTAINED`, `CLOSED` |
| Presencia del agente | `online`, `offline`, `unknown` |
| Notificación | `pending`, `sent`, `failed` |

La lista completa de tipos de evento está en
[referencia-tecnica.md](referencia-tecnica.md#tipos-de-evento).

## 10. Gestión de usuarios

En **Usuarios** (solo `superadmin`) se crean usuarios `viewer` o `superadmin` y
se cambian su rol y su estado. No es posible desactivarse a uno mismo ni dejar
el sistema sin un `superadmin` activo.

Un `viewer` solo ve los agentes que él mismo registró.

## 11. Notificaciones

Las notificaciones están desactivadas por defecto. Cuando se activan, el agente
genera un intento por cada detección (categoría `detection`) cuya severidad
alcanza `AUDITORIA_NOTIFICATION_MIN_SEVERITY` (`high` por defecto). Cada intento
queda en el `notifications.db` del nodo, con estado `pending`, `sent` o
`failed`, y no se repite para el mismo evento, canal y destinatario.

- Un fallo del proveedor o una configuración incompleta se registran como
  `failed` con un error resumido, sin la API key. No detienen el agente.
- No hay reintentos automáticos de correo.
- Las notificaciones son locales a cada nodo: el dashboard del central solo
  muestra las de su propio `notifications.db`, que abre en solo lectura. Si la
  base no existe, las listas aparecen vacías y la API no crea el archivo.

Variables en [configuracion.md](configuracion.md#45-notificaciones-las-envía-el-agente).

### Prueba en laboratorio

Hágala solo en un laboratorio y con un remitente ya verificado en el proveedor.

1. En el nodo que enviará el correo, edite `agent.env` sin imprimir los
   valores:

   ```bash
   sudoedit /etc/auditoria-system/agent.env
   # AUDITORIA_NOTIFICATIONS_ENABLED=true
   # AUDITORIA_RESEND_API_KEY=<secreto>
   # AUDITORIA_NOTIFICATION_FROM=<remitente verificado>
   # AUDITORIA_NOTIFICATION_TO=<destinatario de prueba>
   ```

2. Mantenga `audit_only` y reinicie el agente:

   ```bash
   sudo systemctl restart auditoria-agent.service
   ```

3. Desde un host de laboratorio autorizado, provoque una detección `high`
   controlada; por ejemplo, diez autenticaciones SSH fallidas desde el mismo
   origen en menos de 60 segundos.
4. Compruebe el correo recibido y la vista **Notificaciones** del dashboard (si
   la prueba se hace en el central). Si el estado es `failed`, revise el error
   resumido sin copiar la API key a comandos de diagnóstico.
5. Vuelva a `AUDITORIA_NOTIFICATIONS_ENABLED=false`, retire los valores de
   prueba y reinicie el agente.
