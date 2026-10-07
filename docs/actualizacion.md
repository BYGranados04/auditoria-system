# Actualización de Nexora

Procedimiento basado en `scripts/actualizar.sh`. La actualización no usa Git:
instala una release ya preparada.

## 1. Sintaxis

```bash
sudo bash /srv/releases/auditoria-system-X.Y.Z/scripts/actualizar.sh \
  --role central \
  --source /srv/releases/auditoria-system-X.Y.Z \
  [--destino-backup /var/backups/auditoria-system]
```

`/srv/releases/...` es un ejemplo; puede usar cualquier ruta absoluta que cumpla
estos requisitos:

- `--source` es un directorio (no un symlink) fuera de `/opt/auditoria-system`.
- Su estructura de release es válida.
- **El script se ejecuta desde la misma release indicada en `--source`.**
- `--destino-backup` también debe quedar fuera de `/opt/auditoria-system`.

## 2. Antes de actualizar

1. Confirme que el nodo está sano:

   ```bash
   systemctl is-active auditoria-agent.service
   systemctl is-active auditoria-api.service    # central
   systemctl --failed
   curl --fail http://127.0.0.1:8000/health      # central
   ```

2. Verifique la release (SHA-256 o tag firmado) y colóquela fuera de `/opt`.
3. Compruebe que hay espacio para el backup.
4. Lea las notas de la versión nueva.
5. Si el agente está en `automatic`, decida si mantiene ese modo durante la
   ventana de mantenimiento.

## 3. Qué hace

1. **Backup previo.** Ejecuta `backup.sh` y obtiene `BACKUP_CREADO=`.
2. **Parada.** Detiene los servicios activos del rol.
3. **Conserva el código anterior.** Mueve `/opt/auditoria-system` a
   `/opt/auditoria-system.rollback.<UTC>`.
4. **Instala el código nuevo.** Copia `app/`, `deploy/`, `scripts/`,
   `requirements.txt` y `pyproject.toml` (sin cachés ni `.venv`).
5. **Entorno.** Ejecuta `preparar-instalacion.sh`, que crea el `.venv` e instala
   las dependencias fijadas.
6. **Reinstalación del rol.** Ejecuta `instalar-servicio.sh --role <rol>`, que
   aplica las units y los permisos y conserva `agent.env` y la identidad.
7. **Validación.** Comprueba que los servicios estén activos y, en el rol
   central, `/health`.
8. **Resultado.** Imprime el backup previo, el código anterior y el comando
   exacto de rollback manual.

**Migraciones.** Las bases se migran al primer arranque del código nuevo:

- `auditoria.db` hasta la versión 5;
- `auth.db` hasta la versión 3;
- `central.db` hasta la versión 3, en la primera ingesta.

Las migraciones son incrementales e idempotentes.

## 4. Rollback automático

Si algo falla a partir del paso 3, el script:

- imprime «La actualización falló; iniciando rollback automático.»;
- ejecuta `rollback.sh` con el backup y el código anterior.

El código fallido se conserva en `/opt/auditoria-system.fallido.<UTC>`.

Excepción: si `/opt/auditoria-system.rollback.<UTC>` ya existe, el script
termina con error **con los servicios ya detenidos** y sin rollback, porque
todavía no armó el `trap`. Inicie los servicios manualmente y repita la
actualización.

## 5. Rollback manual

Use el comando que imprime la actualización (ver
[backup-restore-rollback.md](backup-restore-rollback.md#4-rollback)):

```bash
sudo bash <release>/scripts/rollback.sh --role <rol> \
  --backup <ruta BACKUP_CREADO> \
  --codigo-anterior /opt/auditoria-system.rollback.<UTC>
```

## 6. Después de actualizar

- Revise servicios, `/health`, `systemctl --failed` y los logs del agente.
- Compruebe la integridad de las bases (ver
  [instalacion.md](instalacion.md#8-validación-posterior-a-la-instalación)).
- Verifique el heartbeat y que el outbox no acumule eventos pendientes; el
  dashboard debe mostrar eventos recientes.
- Conserve el backup y el código anterior hasta cerrar el periodo de
  observación acordado.

La actualización desde 0.9.0 está descrita en
[release-v1.0.0.md](release-v1.0.0.md).
