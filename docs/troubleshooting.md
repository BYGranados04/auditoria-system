# Solución de problemas de Nexora v1.0.0

Guía de diagnóstico para administradores. Los comandos de la tabla se detallan
en la [sección 2](#2-comandos-de-diagnóstico). Antes de cambiar nada, haga un
backup (ver [backup-restore-rollback.md](backup-restore-rollback.md)).

Principios:

- Diagnostique primero con comandos de solo lectura.
- No borre bases SQLite, sus archivos `-wal`/`-shm` ni `agent-identity.json`
  con los servicios en marcha.
- No vacíe la tabla `inet auditoria_response` a mano salvo para salir de un
  bloqueo propio (ver el caso «Me bloqueé a mí mismo»).

## 1. Tabla de síntomas

| Síntoma | Causa posible | Diagnóstico | Acción segura |
|---|---|---|---|
| `auditoria-agent.service` inactivo o `failed` | Valor inválido en `AUDITORIA_HEARTBEAT_INTERVAL`, `AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS` o `AUDITORIA_TRUSTED_ADMIN_IPS` (un CIDR también es inválido); `.venv` ausente; base con esquema más nuevo. | `systemctl status`, `journalctl -u auditoria-agent.service` (D1, D3). | Corrija `agent.env` y reinicie. Si es un esquema más nuevo, vea esa fila. |
| `auditoria-api.service` inactivo o `failed` (central) | Mismas variables de heartbeat inválidas; `auth.db` o `central.db` con esquema más nuevo; permisos de `/var/lib/auditoria-system-auth` o `-central`; puerto 8000 ocupado. | D1, D3; `ss -ltnp` (D2). | Corrija la causa; si son permisos, vuelva a ejecutar `instalar-servicio.sh --role central`. |
| `/health` no responde | API detenida; consulta desde otro host (la API solo escucha en `127.0.0.1` y solo admite tráfico de localhost). | D2 desde el propio central. | Consulte siempre desde el central. Para acceso remoto use la capa de acceso del operador. |
| El dashboard responde 403 «Origen no permitido» en acciones | La capa de acceso no conserva el `Host` o el esquema, y `Origin`/`Referer` no coinciden con la URL base que ve la API. | Herramientas de desarrollo del navegador: cabeceras `Origin` y respuesta. | Ajuste la capa de acceso para que conserve el host y el esquema. No desactive la verificación. |
| El central no recibe eventos de un agente | Agente sin registrar; `agent-identity.json` con permisos de grupo u otros, symlink o contenido inválido (la sincronización se omite en silencio); URL del central inalcanzable; credencial no válida. | D4 (identidad), D5 (outbox: `pending` crece y `last_error`). | Corrija permisos a `0600` root. Restablezca la conectividad. No borre la identidad para «reintentar». |
| Outbox con eventos `permanently_failed` | Eventos sin `agent_id` (generados antes de registrar el agente) o con un `agent_id` distinto de la identidad instalada. | D5. | Comportamiento esperado: esos eventos no se envían. Si el `agent_id` no coincide, revise si se restauró una identidad de otro host. |
| Agente «sin conexión» en el dashboard | Heartbeat no llega en `AUDITORIA_AGENT_OFFLINE_AFTER_SECONDS` (120 s por defecto). | D1 en el agente; D5. | Restablezca servicio o red. |
| Error de permisos en SQLite | Ejecutar CLIs sin `sudo`; ACL o propietarios alterados; restore parcial. | D6 (propietarios, modos y ACL). | Use `sudo` para `app.storage`. Reaplique permisos con `instalar-servicio.sh --role <rol>`. |
| La API no puede leer `notifications.db` o puede leer `auditoria.db` | ACL ausente o histórica. | D6. | `instalar-servicio.sh --role central` reaplica y verifica las ACL. |
| Una detección no genera bloqueo | Modo `audit_only` (default); `ALLOW_*` del alcance en `false`; IP protegida; detección no elegible (tipo distinto de las tres detecciones SSH de respuesta, o sin `source_ip` válida). | D7: eventos `RESPONSE_DECISION` y `RESPONSE_EXECUTION` (estado y motivo). | Revise [configuracion.md](configuracion.md#3-qué-habilita-acciones-activas). Si la IP está protegida, el resultado es correcto. |
| `RESPONSE_EXECUTION` en `EXECUTED` pero no se ve la regla | El elemento ya venció y el kernel lo retiró. | D8; compare `expires_at` en D7. | Ninguna. El registro pasa a `EXPIRED` en el siguiente ciclo. |
| `RESPONSE_EXECUTION` en `FAILED` | `nft` ausente o con error; fallo del comando `ip`; error al guardar. | D7 (motivo), D8. | Instale `nftables` si falta. No cree reglas manuales en la tabla de Nexora. |
| nftables no disponible | Paquete no instalado o `/usr/sbin/nft` ausente. | `command -v nft`, D8. | `sudo apt-get install nftables`. Mientras tanto, mantenga `audit_only`. |
| Una aprobación no se ejecuta | La acción venció (`AUDITORIA_APPROVAL_TTL_SECONDS`); el modo ya no es `assisted`; el `ALLOW_*` está en `false`; la IP pasó a estar protegida; ya existe un bloqueo equivalente; el agente no alcanza el central. | Estado de la acción en el detalle del incidente; D7 (`RESPONSE_EXECUTION`, `RESPONSE_APPROVAL_*`). | Corrija la configuración. Una acción vencida o rechazada no se reactiva: espere una nueva detección. |
| Me bloqueé a mí mismo | `AUDITORIA_TRUSTED_ADMIN_IPS` vacía y conexión desde una IP no protegida. | Acceso por consola, Tailscale u otra IP; D8. | Elimine solo el elemento afectado (D9) y configure `AUDITORIA_TRUSTED_ADMIN_IPS` antes de reiniciar el agente. |
| Tailscale desconectado | Problema de Tailscale (Nexora no lo gestiona). | `tailscale status` si está instalado; D5. | Restablezca Tailscale. Los eventos esperan en el outbox y se reenvían con backoff. |
| `restaurar-backup.sh` falla antes de detener servicios | Backup con symlinks, `metadata.env` de otro rol o formato, archivos faltantes, `integrity_check` distinto de `ok`. | Mensaje de error del script. | Use un backup válido del mismo rol. |
| `restaurar-backup.sh` falla después de detener servicios | Error de permisos, ACL o health. | Mensaje del script; D1, D6. | Los servicios quedan detenidos. Corrija y repita el restore. |
| `rollback.sh` falla | Código anterior incompleto (`app/`, `deploy/`, `requirements.txt`, `pyproject.toml`); entorno virtual no recreable; backup inválido. | Mensaje del script; D1. | Los servicios quedan detenidos y el código fallido se conserva en `/opt/auditoria-system.fallido.<UTC>`. Corrija y repita. |
| `actualizar.sh` termina con los servicios detenidos y sin rollback | Ya existía `/opt/auditoria-system.rollback.<UTC>`. | Mensaje del script. | Inicie los servicios manualmente y repita (ver [actualizacion.md](actualizacion.md#4-rollback-automático)). |
| «La base de datos usa un esquema más nuevo» / «auth.db usa un esquema más nuevo» / «central.db usa un esquema más nuevo» | Código anterior sobre datos ya migrados (por ejemplo, rollback sin restaurar datos). | D3. | No edite `PRAGMA user_version`. Restaure el backup que corresponde al código instalado con `rollback.sh` o `restaurar-backup.sh`. |
| No aparecen eventos SSH | La unidad SSH no se llama `ssh.service`; journald sin registros. | `journalctl -u ssh.service -n 20`. | En v1.0.0 el colector solo lee `ssh.service`; otra configuración no está soportada. |
| No se encuentran logs | Consulta de la unidad equivocada o journald rotado. | D3; `events.jsonl`. | Use los nombres exactos de unidad. |

## 2. Comandos de diagnóstico

### D1. Servicios

```bash
systemctl status auditoria-agent.service --no-pager
systemctl status auditoria-api.service --no-pager   # central
systemctl --failed
```

### D2. API y health (en el central)

```bash
curl --fail --silent --show-error http://127.0.0.1:8000/health
sudo ss -ltnp | grep ':8000'
```

### D3. Logs de systemd

```bash
sudo journalctl -u auditoria-agent.service -n 200 --no-pager
sudo journalctl -u auditoria-api.service -n 200 --no-pager
sudo journalctl -u auditoria-agent.service --since "1 hour ago" --no-pager
sudo tail -n 50 /var/log/auditoria-system/events.jsonl
```

### D4. Identidad del agente (sin mostrar su contenido)

```bash
sudo stat -c '%U:%G %a %F' /etc/auditoria-system/agent-identity.json
```

Debe mostrar `root:root 600 regular file`. No imprima el archivo: contiene la
credencial.

### D5. Estado del outbox (solo lectura)

```bash
sudo /opt/auditoria-system/.venv/bin/python - <<'PY'
import sqlite3
db = "file:/var/lib/auditoria-system/auditoria.db?mode=ro"
with sqlite3.connect(db, uri=True) as c:
    for row in c.execute("SELECT status, COUNT(*) FROM event_outbox GROUP BY status"):
        print(row)
    for row in c.execute(
        "SELECT last_error, COUNT(*) FROM event_outbox "
        "WHERE last_error IS NOT NULL GROUP BY last_error LIMIT 10"
    ):
        print(row)
PY
```

### D6. Permisos y ACL

```bash
sudo stat -c '%U:%G %a %n' /var/lib/auditoria-system/*.db
sudo getfacl -p /var/lib/auditoria-system /var/lib/auditoria-system/notifications.db
sudo stat -c '%U:%G %a %n' /var/lib/auditoria-system-auth /var/lib/auditoria-system-central   # central
```

### D7. Decisiones y ejecuciones

```bash
cd /opt/auditoria-system
sudo .venv/bin/python -m app.storage events --type RESPONSE_DECISION --limit 10
sudo .venv/bin/python -m app.storage events --type RESPONSE_EXECUTION --limit 10
```

`app.storage` inicializa o migra la base si hace falta; ejecútelo con el código
instalado.

### D8. Tabla nftables de Nexora (solo lectura)

```bash
command -v nft
sudo nft list table inet auditoria_response
```

### D9. Retirar un único elemento propio

Úselo solo para recuperar el acceso. Sustituya la IP de ejemplo:

```bash
sudo nft delete element inet auditoria_response blocked_ipv4 '{ 203.0.113.10 }'
```

Para un bloqueo por puerto, el elemento del set `blocked_ipv4_port` tiene la
forma `dirección . protocolo . puerto`; obténgalo de la salida de D8.

El registro en `auditoria.db` sigue `ACTIVE` hasta su `expires_at`. **Si el
agente se reinicia antes, la recuperación vuelve a aplicar el bloqueo** con su
tiempo restante. Para evitarlo, añada la IP a `AUDITORIA_TRUSTED_ADMIN_IPS`
antes de reiniciar: la recuperación aplica las protecciones vigentes y no
restaura bloqueos sobre IP protegidas (ver
[respuesta-defensiva.md](respuesta-defensiva.md#10-recuperación-tras-un-reinicio)).

## Documentos relacionados

- [operacion.md](operacion.md)
- [respuesta-defensiva.md](respuesta-defensiva.md)
- [referencia-tecnica.md](referencia-tecnica.md)
