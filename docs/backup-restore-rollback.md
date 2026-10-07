# Backup, restauración y rollback de Nexora v1.0.0

Este documento se basa exclusivamente en `scripts/backup.sh`,
`scripts/restaurar-backup.sh`, `scripts/rollback.sh` y
`scripts/lib/operaciones-comunes.sh`. Todos se ejecutan como root.

## 1. Diferencias

| Operación | Qué hace | Cuándo usarla |
|---|---|---|
| **Backup** | Copia consistente de la configuración, la identidad y las bases SQLite del rol. | Antes de cambios y de forma periódica. La actualización lo crea automáticamente. |
| **Restore** | Reemplaza los datos actuales por los de un backup del mismo rol. No cambia el código. | Corrupción o pérdida de datos con el mismo código instalado. |
| **Rollback** | Vuelve al código anterior **y** restaura los datos del backup correspondiente. | Una actualización falló o hay que revertirla. |

El rollback siempre restaura los datos porque las bases rechazan abrir un
esquema más nuevo que el que soporta el código.

## 2. Backup

```bash
sudo bash /opt/auditoria-system/scripts/backup.sh --role central
sudo bash /opt/auditoria-system/scripts/backup.sh --role agent --destino /ruta/absoluta/backups
```

Opciones:

- `--role central|agent`: obligatorio.
- `--destino`: opcional. Por defecto `/var/backups/auditoria-system`. Debe ser
  una ruta absoluta y estar fuera de `/opt/auditoria-system`.

Antes de empezar, el script comprueba root, Ubuntu, el entorno de Python
instalado y que existan los archivos obligatorios del rol.

### Contenido del backup

| Archivo | Rol | Método |
|---|---|---|
| `etc/auditoria-system/agent.env` | ambos | copia 0600 |
| `etc/auditoria-system/agent-identity.json` | ambos (**obligatorio**) | copia 0600 |
| `var/lib/auditoria-system/agent_state.json` | ambos, si existe | copia 0600 |
| `var/lib/auditoria-system/auditoria.db` | ambos | API de backup de SQLite + `integrity_check` |
| `var/lib/auditoria-system/notifications.db` | ambos, si existe | ídem |
| `var/lib/auditoria-system-auth/auth.db` | central | ídem |
| `var/lib/auditoria-system-central/central.db` | central | ídem |
| `metadata.env` | ambos | `FORMATO=1`, `ROLE`, `CREATED_AT`, `VERSION`, `ACTIVE_SERVICES` |

**No se incluyen:**

- el directorio `evidence/`;
- `/var/log/auditoria-system/`;
- el código de `/opt`.

### Flujo

1. Registra qué servicios del rol estaban activos y detiene solo esos.
2. Escribe en un directorio temporal `.backup-<rol>-<UTC>.incompleto.<pid>`
   (0700).
3. Copia los archivos y valida la integridad de cada base copiada.
4. Renombra el directorio a `backup-<rol>-<YYYYMMDDTHHMMSSZ>`.
5. Reinicia los servicios que estaban activos y comprueba que sigan activos.
6. Imprime `BACKUP_CREADO=<ruta>`.

Si algo falla, un `trap` reinicia los servicios que estaban activos y borra el
temporal incompleto.

> El backup contiene la configuración, la credencial del agente y las bases
> **sin cifrar**. Guárdelo fuera del árbol activo, con acceso administrativo
> restringido.

## 3. Restore

```bash
sudo bash /opt/auditoria-system/scripts/restaurar-backup.sh \
  --role central \
  --backup /var/backups/auditoria-system/backup-central-AAAAMMDDTHHMMSSZ
```

Opciones:

- `--role` y `--backup` (ruta absoluta): obligatorias.
- `--no-start`: restaura y valida sin arrancar servicios ni consultar health.
  Está pensada para el rollback.

### Validaciones antes de detener servicios

- El backup es un directorio, no es un symlink y no contiene symlinks.
- `metadata.env` tiene `FORMATO=1` y el `ROLE` pedido.
- Están los archivos obligatorios del rol.
- `PRAGMA integrity_check` da `ok` en cada base del backup.
- En el rol central: existen `setfacl`, `getfacl`, `runuser` y el usuario
  `auditoria-api`, y también `curl` salvo con `--no-start`.
- Las units del rol están instaladas.

### Flujo

1. Detiene los servicios del rol y borra los archivos auxiliares de SQLite
   (`-wal`, `-shm`, `-journal`).
2. Restaura propietarios y modos:
   - `agent.env`: 0640 root;
   - `agent-identity.json`: 0600 root;
   - `auditoria.db`: 0600 root;
   - `auth.db` y `central.db`: 0600 `auditoria-api`.
   `agent_state.json` y `notifications.db` se restauran si están en el backup;
   si no están, se eliminan.
3. En el rol central, reaplica las ACL: la API lee pero no escribe
   `notifications.db`, y no lee `auditoria.db`. Luego lo verifica.
4. Vuelve a comprobar la integridad de las bases restauradas.
5. Sin `--no-start`: arranca los servicios, comprueba que estén activos y, en el
   rol central, consulta `/health`.

> El restore no tiene reversión automática. Si falla después de detener los
> servicios, estos quedan detenidos. Resuelva la causa y repita el restore, o
> restaure otro backup válido.

## 4. Rollback

```bash
sudo bash /ruta/release/scripts/rollback.sh \
  --role central \
  --backup /var/backups/auditoria-system/backup-central-AAAAMMDDTHHMMSSZ \
  --codigo-anterior /opt/auditoria-system.rollback.AAAAMMDDTHHMMSSZ
```

`--role`, `--backup` y `--codigo-anterior` son obligatorios y deben ser rutas
absolutas. El código anterior debe contener `app/`, `deploy/`,
`requirements.txt` y `pyproject.toml`.

### Flujo

1. Copia los scripts actuales a `/tmp/auditoria-operaciones.XXXXXX`.
2. Detiene los servicios del rol.
3. Mueve `/opt/auditoria-system` a `/opt/auditoria-system.fallido.<UTC>` y el
   código anterior a `/opt/auditoria-system`.
4. Desde la copia temporal, ejecuta en orden: `preparar-instalacion.sh`,
   `restaurar-backup.sh --no-start` e `instalar-servicio.sh --role <rol>`.
5. Comprueba que los servicios estén activos y, en el rol central, `/health`.
6. Imprime «Rollback completado correctamente.» y la ruta del código fallido.

Si falla después de detener los servicios, vuelve a detener todos los servicios
del rol, conserva el código fallido y termina con error. **Nunca elimina el
código fallido**; bórrelo manualmente cuando ya no lo necesite.

## 5. Flujo por rol

| Paso | `central` | `agent` |
|---|---|---|
| Servicios que se detienen | agente y API | agente |
| Bases incluidas | `auditoria.db`, `notifications.db`, `auth.db`, `central.db` | `auditoria.db`, `notifications.db` |
| ACL | se reaplican y se verifican | no aplica |
| Health | `http://127.0.0.1:8000/health` (15 intentos) | no aplica |

## 6. Validación de SQLite

Todas las operaciones verifican la integridad con:

```text
PRAGMA integrity_check  →  ok
```

Lo hacen sobre cada copia, sobre el backup antes de restaurar y sobre las bases
ya restauradas. Las bases se copian con la API de backup de SQLite, abriendo el
origen en solo lectura, nunca copiando el archivo directamente.

## 7. Precauciones

- Pruebe periódicamente un restore en un entorno no productivo.
- Conserve juntos el backup y el código anterior que imprime `actualizar.sh`
  hasta terminar la validación posterior.
- No borre los archivos auxiliares de SQLite con los servicios en marcha.
- Copie la evidencia forense por separado si debe conservarse.
- `backup.sh` no rechaza symlinks en los archivos de origen. La comprobación de
  symlinks se hace al restaurar.
- Si el entorno virtual no existe, `backup.sh` falla tarde, cuando ya detuvo
  los servicios; su `trap` los vuelve a iniciar. Compruebe
  `/opt/auditoria-system/.venv` antes de programar backups.
