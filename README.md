# Nexora

Nexora 1.0.0 es una plataforma de auditoría de seguridad para Ubuntu.
Recopila eventos en cada servidor, conserva un outbox local, sincroniza eventos
autenticados a un nodo central y ofrece una API y un dashboard locales para
consulta. La identidad estable de un servidor es `agent_id`; `hostname` es solo
metadata y nunca concede acceso.

Los identificadores internos de v1.0 (paquete `auditoria-system`, servicios
`auditoria-*.service`, usuario `auditoria-api`, rutas y variables
`AUDITORIA_*`) conservan el nombre anterior por compatibilidad.

## Arquitectura

- **central**: API y dashboard en `127.0.0.1:8000`, autenticación, eventos
  centralizados y un agente local;
- **agent**: agente root, persistencia local, heartbeat y sincronización hacia el
  central;
- **ownership**: usuario → registration token de un solo uso → agent →
  `owner_user_id`;
- **notificaciones**: intentos y resultados locales al nodo que ejecuta el
  agente. El dashboard central solo lee `notifications.db` del nodo central.

La API no se expone en `0.0.0.0`. El acceso remoto requiere una capa de acceso
aprobada por el operador (por ejemplo, proxy o túnel) y una
`AUDITORIA_CENTRAL_URL` alcanzable por los agentes.

## Plataformas y requisitos

- Ubuntu 24.04 como plataforma objetivo;
- Python 3.12 y `python3.12-venv`;
- `acl`, `curl` y herramientas base de systemd;
- ejecución como root para bootstrap, instalación y recuperación;
- una copia verificada de la release en `/opt/auditoria-system`.

Los scripts no descargan código ni eligen ramas. Las dependencias se instalan
desde las versiones exactas de `requirements.txt`; no se usan Poetry, Docker,
Ansible ni otro sistema de despliegue.

## Instalación

Instale los prerrequisitos y coloque el contenido verificado de la release:

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv acl curl
sudo install -d -m 0755 /opt/auditoria-system
# Copie aquí el contenido ya verificado de auditoria-system 1.0.0.
```

Prepare el entorno e instale el rol correspondiente:

```bash
sudo bash /opt/auditoria-system/scripts/preparar-instalacion.sh
sudo bash /opt/auditoria-system/scripts/instalar-servicio.sh --role central
# o, en un nodo remoto:
sudo bash /opt/auditoria-system/scripts/instalar-servicio.sh --role agent
```

El bootstrap crea `/opt/auditoria-system/.venv` con Python 3.12, instala
`requirements.txt`, ejecuta `pip check` y valida imports. Es razonablemente
idempotente y conserva un entorno válido existente. El instalador conserva
`agent.env` y `agent-identity.json`; si aún no hay identidad, habilita el
servicio agente sin arrancarlo.

## Configuración y servicios

La plantilla está en `deploy/agent.env.example`. La instalación crea una sola
vez `/etc/auditoria-system/agent.env`; las ejecuciones posteriores no lo
sobrescriben. Configure como mínimo `AUDITORIA_CENTRAL_URL` con una URL real
HTTP/HTTPS sin query, fragment ni credenciales embebidas.

Servicios instalados:

- `auditoria-agent.service` en ambos roles;
- `auditoria-api.service` solo en central.

El agente corre como root por las fuentes del sistema que inspecciona. La API
corre como `auditoria-api`, sin login, enlazada solo a localhost y sin
capacidades Linux. Las units aplican `NoNewPrivileges`, filesystem protegido,
home y dispositivos privados/restringidos y rutas de escritura mínimas.

## Enrollment e identidad

En central, cree primero un superadmin de forma interactiva; la contraseña no
viaja como argumento:

```bash
sudo runuser -u auditoria-api -- \
  /opt/auditoria-system/.venv/bin/python -m app.auth create-superadmin
```

Acceda al dashboard, cree el usuario owner si corresponde y genere su
registration token. Ejecute en el servidor agente el comando mostrado, en una
sesión administrativa controlada. Su forma es:

```bash
sudo /opt/auditoria-system/.venv/bin/python -m app.agent register \
  --server https://central.example \
  --token REGISTRATION_TOKEN_DE_UN_SOLO_USO
sudo systemctl start auditoria-agent.service
```

Use la URL real de su entorno; el valor anterior es únicamente ilustrativo. El
token expira y solo puede consumirse una vez. La identidad se guarda en:

```text
/etc/auditoria-system/agent-identity.json
```

Contiene la credential del agente y debe permanecer `root:root`, modo `0600`.
No la copie a `agent.env`, tickets, logs, terminales compartidas ni repositorios.
El agente no puede elegir ni modificar su owner.

## Ubicaciones y permisos

| Recurso | Ruta | Protección esperada |
|---|---|---|
| Configuración | `/etc/auditoria-system/agent.env` | `0640`, sin secretos en Git |
| Identidad | `/etc/auditoria-system/agent-identity.json` | `0600`, root |
| Estado local | `/var/lib/auditoria-system/` | `0700`, agente |
| Eventos locales | `/var/lib/auditoria-system/auditoria.db` | API sin lectura |
| Evidencia forense | `/var/lib/auditoria-system/evidence/` | `0700`/`0600`, solo agente; la API no la lee |
| Notificaciones locales | `/var/lib/auditoria-system/notifications.db` | API central solo lectura por ACL |
| Autenticación | `/var/lib/auditoria-system-auth/auth.db` | usuario API |
| Eventos centrales | `/var/lib/auditoria-system-central/central.db` | usuario API |
| Logs | `/var/log/auditoria-system/` | `0700`, agente |

No relaje permisos para resolver errores. En central, el instalador comprueba
que `auditoria-api` pueda leer pero no escribir `notifications.db`, y que no
pueda leer `auditoria.db`.

## Dashboard y API

El dashboard vive en `/dashboard` y requiere sesión. Expone eventos,
detecciones, incidentes, respuestas, servidores, notificaciones y administración
de usuarios según rol. La API incluye `/health`, `/status`, `/events`,
`/detections`, `/incidents`, `/responses`, `/agents` y `/notifications`.

Incidentes, captura forense defensiva, `TEMPORARY_BLOCK_IP_PORT` y escalamiento
por reincidencia se describen en
[`docs/motor-defensivo-incidentes.md`](docs/motor-defensivo-incidentes.md).
Todas estas capacidades respetan `audit_only`/`assisted`/`automatic` y quedan
desactivadas o en modo conservador si sus variables no existen. En `assisted`,
un superadmin aprueba o rechaza cada acción propuesta desde el detalle del
incidente; el agente la revalida antes de ejecutarla.

Los viewers quedan limitados por `agent_id` a sus agentes; el superadmin puede
consultar todos. `hostname` nunca se usa como autorización. La API abre
`notifications.db` en modo SQLite read-only; si aún no existe, las listas y el
summary son vacíos y ningún GET crea archivos.

## Backup

```bash
sudo bash /opt/auditoria-system/scripts/backup.sh --role central
sudo bash /opt/auditoria-system/scripts/backup.sh --role agent
```

Puede indicar `--destino /ruta/absoluta`. El destino debe quedar fuera de
`/opt/auditoria-system`. El backup detiene temporalmente solo los servicios
activos del rol, usa la API de backup de SQLite, valida integridad y recupera
el estado previo de los servicios. Rechaza symlinks y estructuras inválidas.

Los backups contienen configuración, identidad y bases sin cifrar. Se crean
con permisos restrictivos, pero deben almacenarse fuera del árbol activo, en
un medio seguro y con acceso administrativo limitado.

## Restore

```bash
sudo bash /opt/auditoria-system/scripts/restaurar-backup.sh \
  --role central --backup /var/backups/auditoria-system/backup-central-TIMESTAMP
```

El restore valida rol, estructura e integridad antes de detener servicios.
Restaura propietarios, modos y ACL; después arranca solo los servicios del rol
y verifica `/health` para central. `--no-start` restaura y valida sin arrancar
servicios ni consultar health y está reservado para el rollback ordenado.

## Upgrade

Prepare la release objetivo en una ruta distinta de la instalación activa:

```bash
sudo bash /srv/releases/auditoria-system-1.0.0/scripts/actualizar.sh \
  --role central --source /srv/releases/auditoria-system-1.0.0
```

El upgrade no usa Git. Primero crea un backup fuera del árbol activo; conserva
el código anterior en `/opt/auditoria-system.rollback.TIMESTAMP`, instala la
release preparada, reconstruye el entorno y reaplica el instalador del rol. Si
falla, intenta rollback automático y no elimina el código fallido.

Para migrar desde 0.9.0, verifique primero que el nodo está sano, prepare la
release 1.0.0 fuera de `/opt`, ejecute `actualizar.sh` con el mismo rol y
conserve las dos rutas que imprime (backup y código anterior) hasta terminar el
QA posterior.

## Rollback y recuperación

```bash
sudo bash /srv/releases/auditoria-system-1.0.0/scripts/rollback.sh \
  --role central \
  --backup /var/backups/auditoria-system/backup-central-TIMESTAMP \
  --codigo-anterior /opt/auditoria-system.rollback.TIMESTAMP
```

El rollback detiene servicios, recupera el código anterior, prepara su entorno,
restaura datos sin arrancar, reaplica las units del rol y finalmente valida
servicios y health. Ante un fallo posterior a la detención intenta detener otra
vez todos los servicios del rol, conserva el código fallido y devuelve error.

## Notificaciones y Resend

Las notificaciones están desactivadas por defecto. Solo las detecciones de
seguridad que alcanzan `AUDITORIA_NOTIFICATION_MIN_SEVERITY` generan un intento;
el mínimo predeterminado es `high`. Eventos `system` y respuestas normales no
generan correo. Cada intento queda en `notifications.db` como `pending`, `sent`
o `failed`, con deduplicación por evento, canal y destinatario.

El envío usa HTTP con timeout. Una configuración incompleta o un fallo de
Resend se registra con un error resumido, sin API key, y no detiene el agente ni
el procesamiento de la detección. No hay reintentos complejos en v1.0.

### Prueba real de notificaciones con Resend

Realice esta prueba solo en un LAB y con un dominio ya verificado en Resend:

1. Edite `/etc/auditoria-system/agent.env` en el nodo que enviará el correo y
   configure, sin imprimir los valores:

   ```text
   AUDITORIA_NOTIFICATIONS_ENABLED=true
   AUDITORIA_NOTIFICATION_MIN_SEVERITY=high
   AUDITORIA_RESEND_API_KEY=<secreto>
   AUDITORIA_NOTIFICATION_FROM=<remitente verificado>
   AUDITORIA_NOTIFICATION_TO=<destinatario de prueba>
   AUDITORIA_RESEND_API_URL=https://api.resend.com/emails
   AUDITORIA_NOTIFICATION_TIMEOUT_SECONDS=5
   ```

2. Mantenga el modo de respuesta predeterminado `audit_only` y reinicie:

   ```bash
   sudo systemctl restart auditoria-agent.service
   sudo systemctl --quiet is-active auditoria-agent.service
   ```

3. Desde un host autorizado y aislado del LAB, genere una detección controlada
   `high`, por ejemplo diez autenticaciones SSH fallidas desde el mismo origen
   dentro de 60 segundos. No use infraestructura ajena ni un entorno productivo.
4. Compruebe el correo de prueba y, en el central, la vista Notificaciones del
   dashboard. Revise el servicio sin volcar el entorno ni la identidad:

   ```bash
   sudo journalctl -u auditoria-agent.service -n 100 --no-pager
   ```

5. Si el intento falla, compruebe el estado `failed` y su mensaje resumido; no
   copie la key a comandos de diagnóstico.
6. Vuelva a poner `AUDITORIA_NOTIFICATIONS_ENABLED=false`, retire los valores
   de prueba que ya no necesite y reinicie `auditoria-agent.service`.

La base y el envío pertenecen al nodo agente donde se produjo la detección. Las
notificaciones de agentes remotos no se sincronizan al dashboard central.

## Diagnóstico

```bash
systemctl status auditoria-agent.service
systemctl status auditoria-api.service
systemctl --failed
journalctl -u auditoria-agent.service -n 100 --no-pager
journalctl -u auditoria-api.service -n 100 --no-pager
curl --fail --silent --show-error http://127.0.0.1:8000/health
```

Ante red o central no disponible, heartbeat y sync fallan de forma contenida y
el outbox conserva eventos para reintento. Credenciales inválidas aplican la
espera máxima. Si una base está corrupta, detenga el rol y use un backup cuya
integridad haya sido validada; no borre sidecars SQLite con servicios activos.

## Prueba limpia v1.0

### Central limpio

- [ ] Ubuntu 24.04 actualizado, Python 3.12, `python3.12-venv`, `acl` y `curl`.
- [ ] Release 1.0.0 verificada y colocada en `/opt/auditoria-system`.
- [ ] `preparar-instalacion.sh` termina con `pip check` e imports correctos.
- [ ] `instalar-servicio.sh --role central` instala agente y API.
- [ ] `agent.env` contiene la `AUDITORIA_CENTRAL_URL` real antes de emitir tokens.
- [ ] Superadmin creado con el CLI interactivo, sin contraseña en argumentos.
- [ ] Central enrolado si se desea su agente local; identity `0600`.
- [ ] `auditoria-api` y `auditoria-agent` activos tras completar enrollment.
- [ ] `curl http://127.0.0.1:8000/health` devuelve HTTP 200.
- [ ] `auth.db`, `central.db`, `auditoria.db` y `notifications.db` pasan
      `PRAGMA integrity_check`.
- [ ] API lee y no escribe `notifications.db`; no lee `auditoria.db`.
- [ ] Dashboard permite login y muestra el agente por su `agent_id`.
- [ ] `systemctl --failed` no muestra unidades fallidas.

### Agent limpio

- [ ] Ubuntu 24.04 y prerrequisitos instalados; release 1.0.0 verificada.
- [ ] Bootstrap y `instalar-servicio.sh --role agent` completados.
- [ ] No existen `auditoria-api.service`, `auth.db` ni `central.db` creados por el rol.
- [ ] Registration token creado para el owner correcto y consumido una sola vez.
- [ ] Registro usa la URL central real; identity queda `0600` y no se imprime.
- [ ] `auditoria-agent.service` queda enabled y active.
- [ ] Heartbeat actualiza presencia en central.
- [ ] Un evento controlado se sincroniza y el outbox vuelve a acknowledged sin pending.
- [ ] Dos agentes con el mismo hostname conservan identidad y scope separados.
- [ ] `systemctl --failed` no muestra unidades fallidas.

## Checklist de QA Linux posterior al congelamiento

En **control-server / role agent** vuelva a comprobar servicios, permisos de
configuración e identidad, integridad de `auditoria.db`, heartbeat, outbox,
upgrade, rollback y `systemctl --failed`.

En **auditoria-server / role central** vuelva a comprobar API/health, auth,
integridad de las cuatro bases, ACL de notificaciones, denegación de lectura de
`auditoria.db`, agente local, dashboard, aislamiento multiagente,
backup/restore, upgrade/rollback y `systemctl --failed`.

Backup, restore, upgrade, rollback, integridad SQLite, ACL, health y
sincronización ya tuvieron ejecución real exitosa en LAB. Esta lista es la
regresión final sobre el código congelado, no una afirmación de que systemd se
prueba desde Windows o CI.

## Alcance de v1.0

v1.0 cierra monitoreo y correlación inicial de seguridad, respuesta conservadora,
agentes enrolados con ownership, heartbeat, centralización persistente,
dashboard/API con scope, notificación local opcional y operaciones reproducibles
de instalación, backup, restore, upgrade y rollback.

Quedan fuera de alcance: antivirus, EDR completo, FIM avanzado, vulnerability
scanner empresarial, SIEM empresarial, notificaciones fleet-wide,
infraestructura cloud obligatoria, respuesta automática agresiva y
orquestación masiva. El modo predeterminado sigue siendo seguro y conservador;
las capacidades futuras no son bloqueadores de v1.0.
