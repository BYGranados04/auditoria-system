# Nexora 1.0.0

Estado: publicada (tag `v1.0.0` y GitHub Release). QA físico y validación final
G4 completados en Ubuntu Server 24.04.5 LTS.

> Marca visible: Nexora. Los identificadores internos de v1.0 se conservan por
> compatibilidad: paquete `auditoria-system`, servicios `auditoria-agent.service`
> y `auditoria-api.service`, usuario `auditoria-api`, rutas
> `/opt|/etc|/var/lib|/var/log/auditoria-system*` y variables `AUDITORIA_*`.

## Resumen

La versión 1.0.0 estabiliza la arquitectura central/agente, el ownership por
identidad enrolada, la centralización persistente y las operaciones de ciclo de
vida, e incorpora un motor defensivo conservador: incidentes, evidencia forense
local, bloqueos temporales con nftables y escalamiento por reincidencia. La API
permanece local y la configuración de red queda bajo control del operador.

## Motor defensivo

- Modos de respuesta `audit_only` (predeterminado), `assisted` y `automatic`.
- Incidentes defensivos: agrupan detecciones relacionadas y ofrecen un timeline
  consultable desde la API y el dashboard. Activos por defecto.
- Evidencia forense local: captura defensiva acotada en tamaño, tiempo y
  retención, legible solo por el agente; la API no la expone. Desactivada por
  defecto.
- Bloqueo temporal IP (`TEMPORARY_BLOCK_IP`) y bloqueo temporal IP+puerto
  (`TEMPORARY_BLOCK_IP_PORT`) con nftables en la tabla `inet auditoria_response`,
  con expiración por timeout. Ambos desactivados por defecto.
- Aprobación y rechazo asistidos: en `assisted`, solo un superadmin aprueba o
  rechaza cada acción desde el detalle del incidente; el agente revalida la
  acción antes de ejecutarla y esta vence si no se resuelve (TTL
  predeterminado: 3600 s).
- Escalamiento por reincidencia con niveles predeterminados: nivel 1 = 120 s,
  nivel 2 = 600 s y nivel 3 = 3600 s, dentro de una ventana deslizante de 24 h.
  El nivel se recalcula desde SQLite tras un reinicio. Desactivado por defecto.
- Protecciones que impiden el bloqueo: IPs administrativas de confianza
  (`AUDITORIA_TRUSTED_ADMIN_IPS`), direcciones e interfaz Tailscale
  (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, `tailscale0`), sesiones SSH activas,
  IP local y gateway.
- Recuperación tras reinicio o reboot: al arrancar, el agente restaura los
  bloqueos vigentes, marca los vencidos y cierra de forma segura las acciones
  interrumpidas.

Detalle y variables de configuración en
[`docs/motor-defensivo-incidentes.md`](motor-defensivo-incidentes.md).

## Plataforma y operación

- instalación separada mediante `--role central` y `--role agent`;
- bootstrap reproducible con Python 3.12 y `requirements.txt` fijado;
- enrollment con registration token de un uso, `agent_id` estable y credential
  almacenada solo como digest en central;
- heartbeat y presencia autenticados;
- outbox SQLite y sincronización idempotente de eventos por `agent_id` hacia el
  central, con reintento cuando el central no está disponible;
- API/dashboard central con aislamiento de viewers y acceso global de superadmin;
- notificaciones locales de detecciones high/critical mediante provider Resend,
  desactivadas por defecto y sin secretos en errores;
- API con acceso estrictamente read-only a `notifications.db`;
- backup, restore, upgrade y rollback con integridad SQLite y conservación del
  código fallido;
- units systemd endurecidas y permisos/ACL separados entre agente y API;
- CI en Ubuntu 24.04 y Python 3.12, con validación `bash -n` de los scripts.

## Migraciones de esquema

- `auditoria.db`: v3 → v4 → v5.
- `central.db`: v1 → v2 → v3.

Las migraciones se aplican automáticamente al inicializar cada base y son
idempotentes: un reinicio no vuelve a migrar. Una base con un esquema más nuevo
que el soportado se rechaza; por eso el rollback restaura también los datos del
backup. `actualizar.sh` crea ese backup antes de instalar.

## Corrección durante el QA

**QA-01 — `response_blocks` vencidos quedaban en `ACTIVE`.** Con el agente en
ejecución, nftables retiraba la regla al vencer su timeout, pero SQLite
mantenía el bloqueo como `ACTIVE` hasta reiniciar el agente. Ahora cada ciclo
del agente reconcilia en SQLite los bloqueos `ACTIVE`/`PENDING` vencidos a
`EXPIRED`, sin reiniciar el agente, sin invocar nftables y sin alterar la
recuperación de arranque. Encontrado, corregido y revalidado en el servidor
físico.

Durante la validación final G4, la reconciliación quedó como best-effort ante
`PermissionError`, `OSError` y errores SQLite (nunca interrumpe el ciclo del
agente), y las pruebas afectadas se aislaron de las rutas y el estado reales
del host.

Efecto operativo: el evento `RESPONSE_RECOVERY` de arranque solo contabiliza en
`expired_count` los bloqueos que vencieron con el agente detenido.

## Evidencia de validación

QA físico sobre Ubuntu Server 24.04.5 LTS, con resultado PASS en:

- actualización desde 0.9.0 y migraciones de esquema;
- respuesta `automatic` con bloqueo temporal IP y bloqueo temporal IP+puerto;
- `assisted`: rechazo, y aprobación con ejecución;
- evidencia forense local;
- reincidencia de nivel 2 (600 s);
- protección de IP administrativa y Tailscale;
- reboot y recuperación del estado defensivo;
- rollback y restore final;
- QA-01 tras la corrección.

En el LAB de Ubuntu se validaron además: instalación de los roles central y
agent, conservación de configuración e identidad, `PRAGMA integrity_check`, ACL
read-only de `notifications.db` y denegación de `auditoria.db` a la API,
`/health` HTTP 200, heartbeat, sincronización y outbox acknowledged sin pending,
y `systemctl --failed = 0`.

Suite automatizada:

- Ubuntu Server 24.04.5 LTS (G4), con dependencias runtime fijadas según
  `requirements.txt`: `pip check` PASS; pytest `595 passed, 1 skipped,
  2 warnings, 0 failed`; `ruff` PASS; `compileall` PASS; `bash -n` PASS.
- Windows: pytest `591 passed, 5 skipped, 1 warning`; `ruff` PASS;
  `compileall` PASS.

Los skips dependen de la plataforma: en Ubuntu, solo la prueba que requiere
nft con namespaces sin privilegios; en Windows, además `pwd`, symlinks y
permisos POSIX.

## Upgrade desde 0.9.0

1. Confirme servicios sanos, espacio disponible y `systemctl --failed` vacío.
2. Coloque la release 1.0.0 verificada fuera de `/opt/auditoria-system`.
3. Ejecute el `actualizar.sh` de la release con el rol actual y `--source`.
4. Conserve las rutas de backup y código anterior informadas por el script.
5. Valide servicios, health si central, integridad SQLite, heartbeat y outbox.
6. Mantenga el backup hasta completar el período operativo acordado.

Ejemplo:

```bash
sudo bash /srv/releases/auditoria-system-1.0.0/scripts/actualizar.sh \
  --role central --source /srv/releases/auditoria-system-1.0.0
```

Las capacidades defensivas nuevas quedan desactivadas o en modo conservador
mientras sus variables no se configuren; el modo predeterminado sigue siendo
`audit_only`.

## Rollback

Use el backup y el código anterior exactos informados durante el upgrade:

```bash
sudo bash /srv/releases/auditoria-system-1.0.0/scripts/rollback.sh \
  --role central \
  --backup /var/backups/auditoria-system/backup-central-TIMESTAMP \
  --codigo-anterior /opt/auditoria-system.rollback.TIMESTAMP
```

El rollback restaura datos sin arrancar primero, reaplica units de la versión
recuperada y después inicia y valida. No elimina automáticamente el código
fallido.

## Limitaciones conocidas

- la API escucha solo en `127.0.0.1`; la conectividad remota no se provisiona;
- notificaciones y `notifications.db` son locales a cada nodo, no fleet-wide;
  no hay reintentos complejos de correo;
- la respuesta defensiva se limita a bloqueos temporales; no hay bloqueos
  permanentes ni respuesta automática agresiva;
- no es un antivirus, EDR, SIEM ni scanner de vulnerabilidades; la vigilancia
  de archivos críticos no constituye un FIM avanzado;
- no incluye multitenancy, Nexora Cloud ni gestión de flota completa; el
  dashboard central consulta agentes enrolados, pero no orquesta acciones
  masivas.

## Checklist previa a publicar

- [x] Congelar el diff y revisar todos los archivos untracked intencionales.
- [x] Confirmar versión 1.0.0 en `pyproject.toml` y API.
- [x] Ejecutar Ruff, compileall, pytest completo (Windows) y `bash -n`.
- [x] QA físico en Ubuntu Server 24.04.5 LTS, incluido QA-01.
- [x] Búsqueda segura de secretos y artefactos.
- [x] Ejecutar pytest completo en Ubuntu 24.04.
- [x] Indexar los scripts operativos como ejecutables (`100755`).
- [ ] Ejecutar prueba Resend solo con secreto gestionado fuera de Git, si se
      decide incluirla como criterio de release.
- [x] Revisar notas y diff final.
- [x] Solo después, y con autorización explícita, crear commit, tag y release.
