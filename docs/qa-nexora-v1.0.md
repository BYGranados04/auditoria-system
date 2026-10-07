# Nexora v1.0 — Procedimiento de QA en `auditoria-clean-server`

Procedimiento exacto para validar la rama `estabilizacion/v1.0` en el servidor
limpio cuando vuelva a estar conectado. Este documento **solo describe** pruebas:
no cambia código, tests ni configuración del repositorio.

| Dato | Valor |
|---|---|
| Marca visible | Nexora |
| Identificadores internos v1.0 | `auditoria-*` (no se renombran en esta versión) |
| Sistema objetivo | Ubuntu Server 24.04.5 LTS, Python 3.12 |
| Instalación | `/opt/auditoria-system` |
| Configuración | `/etc/auditoria-system/agent.env` |
| Identidad del agente | `/etc/auditoria-system/agent-identity.json` |
| Bases | `/var/lib/auditoria-system/auditoria.db`, `/var/lib/auditoria-system-central/central.db`, `/var/lib/auditoria-system-auth/auth.db`, `/var/lib/auditoria-system/notifications.db` |
| Servicios | `auditoria-agent.service` (root), `auditoria-api.service` (usuario `auditoria-api`, `127.0.0.1:8000`) |
| Tabla nftables | `inet auditoria_response` |
| Evidencia forense (en el agente) | `/var/lib/auditoria-system/evidence/<detection_event_id>/` |
| Esquemas a validar | `auditoria.db` v3 → v4 → v5; `central.db` v1 → v2 → v3 |

## Resultado de la ejecución (resumen)

> Resumen registrado el 2026-10-07. La tabla final por prueba de este documento
> no se completó; la evidencia detallada permanece en `$QA` del servidor. Las
> pruebas que no figuran aquí no se declaran como PASS en este resumen.

| Dato | Valor |
|---|---|
| Plataforma ejecutada | Ubuntu Server 24.04.5 LTS (servidor físico) |
| Estado | QA físico completado; sin FAIL críticos abiertos |
| Validación final (G4) | PASS: Ubuntu Server 24.04.5 LTS, 595 passed, 1 skipped, 0 failed |

| Área | Resultado |
|---|---|
| Actualización y migraciones (`auditoria.db` v3→v5, `central.db` v1→v3) | PASS |
| Respuesta `automatic` | PASS |
| `TEMPORARY_BLOCK_IP` | PASS |
| `TEMPORARY_BLOCK_IP_PORT` | PASS |
| `assisted`: rechazo | PASS |
| `assisted`: aprobación y ejecución | PASS |
| Evidencia forense | PASS |
| Reincidencia nivel 2 (600 s) | PASS |
| Protección IP administrativa / Tailscale | PASS |
| Reboot y recuperación | PASS |
| Rollback | PASS |
| Restore final | PASS |
| QA-01 (ver abajo) | Corregido y revalidado: PASS |

**QA-01 — `response_blocks` vencidos quedaban en `ACTIVE`.**

- *Encontrado:* con el agente en ejecución y tras vencer un bloqueo IP+puerto
  `tcp/22` de 600 s, nftables ya no tenía la regla, pero SQLite mantenía
  `ACTIVE` hasta reiniciar el agente.
- *Corregido:* `run_once()` reconcilia en cada ciclo los bloqueos
  `ACTIVE`/`PENDING` vencidos a `EXPIRED` mediante `expire_response_blocks()`,
  sin invocar nftables ni modificar la recuperación de arranque. Prueba
  automatizada: `tests/test_agent_response_block_reconciliation.py`.
- *Revalidado:* PASS sin reiniciar el agente.

Suite automatizada: Ubuntu Server 24.04.5 LTS (G4) `595 passed, 1 skipped,
2 warnings, 0 failed`; Windows `591 passed, 5 skipped, 1 warning`.

---

## Reglas del QA

1. **No inventar ni mostrar secretos.** Nunca se imprime `agent-identity.json`,
   `agent.env` completo, claves, API keys ni contraseñas. Los comandos de este
   documento consultan solo claves no sensibles, permisos y nombres de campos.
   Si un comando llegara a mostrar un secreto, redacte la evidencia antes de
   guardarla (`<REDACTADO>`).
2. **Placeholders** (se sustituyen a mano; no se guardan valores reales en este
   archivo):

   | Placeholder | Significado |
   |---|---|
   | `<SERVIDOR>` | Host o IP del servidor bajo prueba |
   | `<IP_ADMIN>` | IP desde la que opera el ingeniero (debe estar en `AUDITORIA_TRUSTED_ADMIN_IPS`) |
   | `<IP_ATACANTE>` | IP de un host de laboratorio, **distinta** de `<IP_ADMIN>`, usada para simular ataques |
   | `<TOKEN_TEMPORAL>` | Token de registro de un solo uso generado desde el dashboard |
   | `<RELEASE_DIR>` | Directorio de la release a probar, **fuera** de `/opt/auditoria-system` |
   | `<COMMIT>` | Hash exacto de la rama bajo prueba |
   | `<URL_CENTRAL>` | Valor de `AUDITORIA_CENTRAL_URL` |
   | `<IP_TAILSCALE>` | IP `100.64.0.0/10` de un par Tailscale de laboratorio |
   | `<IP_LOCAL_SERVIDOR>` | IP no loopback de la propia interfaz del servidor |
   | `<USUARIO_ADMIN>` | Superadmin del dashboard (la contraseña se teclea, nunca se documenta) |

3. **No acortar tiempos ni relajar configuración solo para obtener PASS.** Si
   una prueba exige cambiar un valor (por ejemplo `AUDITORIA_APPROVAL_TTL_SECONDS`
   o las duraciones de escalamiento), el cambio, el motivo, el valor original y
   la hora de reversión se anotan en la columna *Observación* de la tabla final.
4. **Un FAIL no se corrige durante la prueba.** Se registra, se conserva la
   evidencia y se continúa solo si el fallo no invalida las fases siguientes.
5. **Fuera de alcance de la QA = no ejecutado.** Una prueba que no pudo
   ejecutarse (sin Tailscale, sin segundo host, sin reboot permitido) se marca
   `NO EJECUTADO` con la causa; **nunca** `PASS`.
6. **Seguridad operativa:** mantenga una segunda sesión SSH desde `<IP_ADMIN>`
   abierta durante toda la QA y una vía fuera de banda (consola del
   hipervisor/VM). Los ataques simulados salen desde las IPs del *plan de IPs de
   ataque* y **nunca** desde `<IP_ADMIN>`, con **una única excepción**: F11-T01,
   que valida precisamente la protección de la IP de administración y exige haber
   comprobado antes F00-T03.
7. Los bloqueos de las fases 8 a 12 son **temporales** (60 a 86400 s). Si queda
   una regla indeseada: `sudo nft list table inet auditoria_response` para
   identificarla y esperar su expiración; no se edita la tabla a mano salvo
   emergencia, y entonces se anota en la tabla final.

### Convención de evidencia

```bash
export QA="$HOME/qa-nexora-v1.0/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$QA"
export AUD_DB=/var/lib/auditoria-system/auditoria.db
export CEN_DB=/var/lib/auditoria-system-central/central.db
export AUTH_DB=/var/lib/auditoria-system-auth/auth.db
export NOT_DB=/var/lib/auditoria-system/notifications.db
```

Cada prueba guarda su salida con `| tee "$QA/<ID>.txt"`. Las capturas del
dashboard se nombran `<ID>-<descripcion>.png`. Los identificadores de prueba
(`F03-T02`, etc.) son los de la tabla final.

### Plan de IPs de ataque

La reincidencia es **por IP de origen y servidor** y sobrevive reinicios
(`response_offenses`). Si todas las fases atacaran desde la misma IP, el nivel de
escalamiento subiría solo (120 s → 600 s → 3600 s) y la QA se haría inmanejable.
Use una IP distinta por prueba; en un único host atacante se consiguen con
direcciones secundarias y `ssh -b`:

```bash
# en el host atacante (laboratorio), una vez por IP adicional:
sudo ip addr add <IP_ATACANTE_N>/<MASCARA> dev <INTERFAZ>
ssh -b <IP_ATACANTE_N> ...        # el servidor verá esa IP como origen
```

| Alias | Fase / prueba | Notas |
|---|---|---|
| `<IP_ATACANTE_1>` (= `<IP_ATACANTE>`) | F07 `audit_only`; F11-T02 (sesión SSH protegida) | |
| `<IP_ATACANTE_2>` | F08 assisted — rechazo | |
| `<IP_ATACANTE_3>` | F08 assisted — aprobación | |
| `<IP_ATACANTE_4>` | F09 automatic `TEMPORARY_BLOCK_IP` | |
| `<IP_ATACANTE_5>` | F10 `TEMPORARY_BLOCK_IP_PORT` | |
| `<IP_ATACANTE_6>` | F12 reincidencia | No usada antes: parte del nivel 1 |
| `<IP_ATACANTE_7>` | F13/F14 (outbox, reinicio) | |
| `<IP_TAILSCALE>` | F11-T03 | Par Tailscale real |

Si no se dispone de tantas IPs, **documente** cuáles se reutilizaron: el nivel y
la duración observados serán `1 + ofensas previas dentro de la ventana` y las
esperas crecen; no se edita `response_offenses` para "limpiar" el historial.

### Formato de cada prueba

Cada prueba lista: **Objetivo**, **Precondición**, **Comandos**, **Resultado
esperado**, **Evidencia** y **Resultado** (`[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`).
Una prueba es PASS solo si **todos** los puntos del resultado esperado se cumplen.

### Rol del servidor

Se asume el rol `central` (agente + API, que es lo que `auditoria-clean-server`
debe ejercitar). Con rol `agent` se omiten las pruebas de `auditoria-api`,
`central.db`, `auth.db` y dashboard.

---

## FASE 0 — Preparación

### F00-T01 — Código a probar identificado y reproducible

- **Objetivo:** que la QA se ejecute sobre un commit conocido.
- **Precondición:** la release está preparada en `<RELEASE_DIR>` (fuera de
  `/opt/auditoria-system`). El script de actualización **no** hace `git pull` ni
  descarga código. *Riesgo conocido:* si el trabajo vigente aún no está
  confirmado en la rama, la release no lo contiene; la decisión de confirmar
  corresponde al ingeniero y debe resolverse antes de iniciar la QA.
- **Comandos:**
  ```bash
  cd <RELEASE_DIR>
  git rev-parse HEAD && git status --short | head -20   # <COMMIT>; árbol limpio
  sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -n 1
  ls scripts scripts/lib deploy/systemd | tee "$QA/F00-T01.txt"
  ```
- **Resultado esperado:** `<COMMIT>` corresponde a `estabilizacion/v1.0`; árbol
  limpio; existen `backup.sh`, `restaurar-backup.sh`, `actualizar.sh`,
  `rollback.sh`, `preparar-instalacion.sh`, `instalar-servicio.sh`,
  `scripts/lib/operaciones-comunes.sh` y ambos `.service`.
- **Evidencia:** `F00-T01.txt` con hash, versión y listado.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F00-T02 — Herramientas del servidor

- **Objetivo:** confirmar que existen las utilidades que usan scripts y pruebas.
- **Precondición:** acceso `sudo`.
- **Comandos:**
  ```bash
  . /etc/os-release && echo "$PRETTY_NAME"
  python3 --version
  for c in sqlite3 nft curl getfacl setfacl runuser ss journalctl systemctl; do
    command -v "$c" >/dev/null && echo "OK   $c" || echo "FALTA $c"
  done | tee "$QA/F00-T02.txt"
  ```
- **Resultado esperado:** Ubuntu 24.04.x, Python 3.12.x y ningún `FALTA`. Si falta
  `sqlite3`, `acl` o `nftables`, instálelos (`sudo apt-get install -y sqlite3 acl
  nftables`) y anótelo: es una desviación de la instalación limpia.
- **Evidencia:** `F00-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F00-T03 — Acceso y condiciones de seguridad

- **Objetivo:** garantizar que ningún ataque simulado pueda dejar al ingeniero
  sin acceso.
- **Precondición:** sesión SSH abierta desde `<IP_ADMIN>`.
- **Comandos:**
  ```bash
  sudo grep -E '^AUDITORIA_(TRUSTED_ADMIN_IPS|RESPONSE_MODE|SSH_PORT)=' \
    /etc/auditoria-system/agent.env | tee "$QA/F00-T03.txt"
  ss -tn state established '( sport = :22 )' | tee -a "$QA/F00-T03.txt"
  ```
- **Resultado esperado:** `AUDITORIA_TRUSTED_ADMIN_IPS` incluye `<IP_ADMIN>`;
  la sesión de administración aparece establecida; `<IP_ATACANTE>` no está en la
  lista de confiables.
- **Evidencia:** `F00-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 1 — Estado previo

### F01-T01 — Servicios y plataforma antes de actualizar

- **Objetivo:** fotografiar el estado de partida.
- **Precondición:** instalación anterior funcionando en `/opt/auditoria-system`.
- **Comandos:**
  ```bash
  {
    systemctl is-active auditoria-agent.service auditoria-api.service
    systemctl is-enabled auditoria-agent.service auditoria-api.service
    systemctl --failed --no-legend
    sed -n 's/^version = "\([^"]*\)"/\1/p' /opt/auditoria-system/pyproject.toml | head -n 1
    sudo nft list table inet auditoria_response 2>&1 | head -40
  } | tee "$QA/F01-T01.txt"
  ```
- **Resultado esperado:** ambos servicios `active` y `enabled`; `--failed` vacío;
  versión previa anotada; la tabla puede no existir todavía (anótelo).
- **Evidencia:** `F01-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F01-T02 — Esquemas y volumen de datos previos (línea base de migración)

- **Objetivo:** registrar `user_version`, integridad y conteos **antes** de
  migrar, para demostrar después que no se perdieron datos.
- **Precondición:** F01-T01 realizado. Idealmente `auditoria.db` en v3 y
  `central.db` en v1; si ya están en v5/v3, la migración **no puede
  demostrarse** en este servidor (ver F04-T01).
- **Comandos:**
  ```bash
  for db in "$AUD_DB" "$CEN_DB" "$AUTH_DB" "$NOT_DB"; do
    echo "== $db"
    sudo sqlite3 -readonly "$db" "PRAGMA user_version; PRAGMA integrity_check;"
  done | tee "$QA/F01-T02-versiones.txt"

  sudo sqlite3 -readonly "$AUD_DB" \
    "SELECT 'events',COUNT(*) FROM events UNION ALL
     SELECT 'response_blocks',COUNT(*) FROM response_blocks UNION ALL
     SELECT 'event_outbox',COUNT(*) FROM event_outbox;" \
    | tee "$QA/F01-T02-conteos-local.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT 'events',COUNT(*) FROM events;" \
    | tee "$QA/F01-T02-conteos-central.txt"
  ```
- **Resultado esperado:** cada base devuelve `integrity_check = ok`; las versiones
  quedan registradas; los conteos quedan guardados.
- **Evidencia:** los tres archivos `F01-T02-*.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F01-T03 — Permisos previos (sin mostrar contenido)

- **Objetivo:** línea base de permisos para comparar tras la actualización.
- **Comandos:**
  ```bash
  sudo stat -c '%a %U:%G %n' /etc/auditoria-system \
    /etc/auditoria-system/agent.env /etc/auditoria-system/agent-identity.json \
    /var/lib/auditoria-system /var/lib/auditoria-system/*.db \
    /var/lib/auditoria-system-auth /var/lib/auditoria-system-central \
    | tee "$QA/F01-T03.txt"
  sudo getfacl -cp /var/lib/auditoria-system /var/lib/auditoria-system/notifications.db \
    2>&1 | tee -a "$QA/F01-T03.txt"
  ```
- **Resultado esperado:** `agent-identity.json` `600 root:root`; `auditoria.db`
  `600 root:root`; `agent.env` `640 root:root`; directorios de `auth` y `central`
  `700` propiedad de `auditoria-api`. El ACL del usuario `auditoria-api` sobre
  `/var/lib/auditoria-system` es solo `--x`, y sobre `notifications.db` solo
  `r--`; **no** hay ACL de `auditoria-api` sobre `auditoria.db`.
- **Evidencia:** `F01-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 2 — Backup

### F02-T01 — Backup consistente previo a la actualización

- **Objetivo:** crear un backup válido que sirva de punto de retorno.
- **Precondición:** F01 completada; espacio libre suficiente en
  `/var/backups`.
- **Comandos:**
  ```bash
  sudo bash <RELEASE_DIR>/scripts/backup.sh --role central \
    | tee "$QA/F02-T01.txt"
  export BACKUP_PREVIO="$(sed -n 's/^BACKUP_CREADO=//p' "$QA/F02-T01.txt" | tail -n 1)"
  echo "$BACKUP_PREVIO"
  sudo stat -c '%a %U:%G %n' "$BACKUP_PREVIO" "$BACKUP_PREVIO"/metadata.env
  sudo find "$BACKUP_PREVIO" -type f -printf '%m %p\n' | sort -k2 | tee -a "$QA/F02-T01.txt"
  sudo cat "$BACKUP_PREVIO/metadata.env"   # sin secretos: FORMATO, ROLE, CREATED_AT, VERSION, ACTIVE_SERVICES
  systemctl is-active auditoria-agent.service auditoria-api.service
  ```
- **Resultado esperado:** imprime `BACKUP_CREADO=/var/backups/auditoria-system/backup-central-<UTC>`;
  el directorio es `700` y los archivos `600`; el backup contiene `agent.env`,
  `agent-identity.json`, las cuatro bases (`auditoria.db`, `notifications.db` si
  existía, `auth.db`, `central.db`) y `metadata.env`; los servicios que estaban
  activos **vuelven a estar activos**.
- **Evidencia:** `F02-T01.txt` (la ruta del backup, sin su contenido).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F02-T02 — Integridad del backup y línea base de migración

- **Objetivo:** confirmar que el backup contiene el estado v3/v1 sin migrar y es
  legible.
- **Comandos:**
  ```bash
  for db in $(sudo find "$BACKUP_PREVIO/var/lib" -name '*.db' | sort); do
    echo "== $db"
    sudo sqlite3 -readonly "$db" "PRAGMA user_version; PRAGMA integrity_check;"
  done | tee "$QA/F02-T02.txt"
  ```
- **Resultado esperado:** todas las bases `ok`; `user_version` coincide con
  F01-T02.
- **Evidencia:** `F02-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 3 — Actualización QA

### F03-T01 — Actualización con `actualizar.sh`

- **Objetivo:** actualizar a `<COMMIT>` con el procedimiento oficial.
- **Precondición:** F02 PASS. El script debe ejecutarse **desde la misma
  release** indicada en `--source`.
- **Comandos:**
  ```bash
  sudo bash <RELEASE_DIR>/scripts/actualizar.sh --role central \
    --source <RELEASE_DIR> 2>&1 | tee "$QA/F03-T01.txt"
  grep -E '^(Backup previo|Código anterior):' "$QA/F03-T01.txt"
  ```
- **Resultado esperado:** termina con `Actualización completada correctamente.`
  y exit 0; imprime `Backup previo:` y `Código anterior: /opt/auditoria-system.rollback.<UTC>`;
  **no** se disparó `La actualización falló; iniciando rollback automático.`
- **Evidencia:** `F03-T01.txt`. Anote las rutas de backup y de código anterior
  (se usan en F16).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F03-T02 — Versión instalada y código anterior conservado

- **Comandos:**
  ```bash
  sed -n 's/^version = "\([^"]*\)"/\1/p' /opt/auditoria-system/pyproject.toml | head -n 1
  ls -d /opt/auditoria-system /opt/auditoria-system.rollback.* | tee "$QA/F03-T02.txt"
  sudo -u auditoria-api test -r /var/lib/auditoria-system/auditoria.db \
    && echo "FALLA: auditoria-api lee auditoria.db" || echo "OK: auditoria-api no lee auditoria.db"
  ```
- **Resultado esperado:** la versión es la de `<COMMIT>`; existe el directorio
  `rollback.<UTC>`; `auditoria-api` **no** puede leer `auditoria.db`.
- **Evidencia:** `F03-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 4 — Migraciones

> Las migraciones se aplican automáticamente al iniciar cada servicio. El agente
> migra `auditoria.db`; la API/central migra `central.db`.

### F04-T01 — `auditoria.db` v3 → v4 → v5

- **Objetivo:** demostrar la migración aditiva local con datos preservados.
- **Precondición:** F01-T02 registró `user_version = 3`. **Si ya era 5, esta
  prueba es `NO EJECUTADO`**: no puede demostrarse la migración sin una base v3
  (no se simula editando `user_version`).
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "PRAGMA user_version; PRAGMA integrity_check;" | tee "$QA/F04-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" \
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN
     ('incidents','response_offenses','response_approvals','forensic_capture_queue')
     ORDER BY name;" | tee -a "$QA/F04-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "PRAGMA table_info(response_blocks);" | cut -d'|' -f2 \
    | grep -E '^(action|protocol|port)$' | tee -a "$QA/F04-T01.txt"
  # datos preservados: comparar con la línea base y con el backup
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM events;" | tee -a "$QA/F04-T01.txt"
  cat "$QA/F01-T02-conteos-local.txt"
  sudo sqlite3 -readonly "$BACKUP_PREVIO/var/lib/auditoria-system/auditoria.db" \
    "SELECT COUNT(*) FROM events;"
  ```
- **Resultado esperado:** `user_version = 5`; `integrity_check = ok`; existen
  las 4 tablas nuevas (`incidents`, `response_offenses`, `response_approvals`,
  `forensic_capture_queue`); `response_blocks` tiene `action`, `protocol` y
  `port`; `COUNT(events)` ≥ el conteo previo (el agente puede haber añadido
  eventos nuevos, nunca menos); los bloqueos previos quedaron como
  `TEMPORARY_BLOCK_IP`:
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT action,COUNT(*) FROM response_blocks GROUP BY action;"
  ```
- **Evidencia:** `F04-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F04-T02 — `central.db` v1 → v2 → v3

- **Objetivo:** demostrar la migración central con datos preservados.
- **Precondición:** F01-T02 registró `user_version = 1`. Si ya era 3,
  `NO EJECUTADO`.
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$CEN_DB" "PRAGMA user_version; PRAGMA integrity_check;" | tee "$QA/F04-T02.txt"
  sudo sqlite3 -readonly "$CEN_DB" \
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN
     ('incidents','incident_links','response_actions') ORDER BY name;" | tee -a "$QA/F04-T02.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT COUNT(*) FROM events;" | tee -a "$QA/F04-T02.txt"
  cat "$QA/F01-T02-conteos-central.txt"
  ```
- **Resultado esperado:** `user_version = 3`; `integrity_check = ok`; existen
  `incidents`, `incident_links` y `response_actions`; `COUNT(events)` ≥ conteo previo.
- **Evidencia:** `F04-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F04-T03 — Otras bases íntegras y sin regresión de versión

- **Objetivo:** `auth.db` y `notifications.db` no deben dañarse con la
  actualización.
- **Comandos:**
  ```bash
  for db in "$AUTH_DB" "$NOT_DB"; do
    echo "== $db"; sudo sqlite3 -readonly "$db" "PRAGMA user_version; PRAGMA integrity_check;"
  done | tee "$QA/F04-T03.txt"
  ```
- **Resultado esperado:** `integrity_check = ok` en ambas; `auth.db` en la versión
  que soporta el código (esquema 3). Cualquier versión superior a la soportada
  sería un FAIL.
- **Evidencia:** `F04-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F04-T04 — Idempotencia: reiniciar no vuelve a migrar ni daña

- **Comandos:**
  ```bash
  sudo systemctl restart auditoria-agent.service auditoria-api.service
  sleep 10
  sudo sqlite3 -readonly "$AUD_DB" "PRAGMA user_version; PRAGMA integrity_check;"
  sudo sqlite3 -readonly "$CEN_DB" "PRAGMA user_version; PRAGMA integrity_check;" | tee "$QA/F04-T04.txt"
  ```
- **Resultado esperado:** versiones 5 y 3; ambas `ok`.
- **Evidencia:** `F04-T04.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 5 — Servicios base

### F05-T01 — Servicios activos, habilitados y sin fallos

- **Comandos:**
  ```bash
  {
    systemctl is-active auditoria-agent.service auditoria-api.service
    systemctl is-enabled auditoria-agent.service auditoria-api.service
    systemctl --failed --no-legend
    systemctl status auditoria-agent.service auditoria-api.service --no-pager -n 5
  } | tee "$QA/F05-T01.txt"
  ```
- **Resultado esperado:** `active` ×2, `enabled` ×2, `--failed` vacío; sin
  reinicios en bucle (`NRestarts` bajo):
  ```bash
  systemctl show auditoria-agent.service auditoria-api.service -p NRestarts
  ```
- **Evidencia:** `F05-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F05-T02 — Registros sin errores

- **Comandos:**
  ```bash
  sudo journalctl -u auditoria-agent.service -u auditoria-api.service \
    --since "-15 min" -p warning --no-pager | tee "$QA/F05-T02.txt"
  ```
- **Resultado esperado:** sin `Traceback`, sin errores de migración ni de
  permisos. Los warnings se justifican en *Observación*.
- **Evidencia:** `F05-T02.txt` (revisar que no incluya secretos).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F05-T03 — `/health` y vínculo de red

- **Comandos:**
  ```bash
  curl -sS --max-time 5 -i http://127.0.0.1:8000/health | tee "$QA/F05-T03.txt"
  ss -ltnp 'sport = :8000' | tee -a "$QA/F05-T03.txt"
  ```
- **Resultado esperado:** `HTTP/1.1 200` y cuerpo `{"status":"ok","service":"auditoria-system-api"}`
  (el identificador interno `auditoria-system-api` es correcto en v1.0); la API
  escucha **solo** en `127.0.0.1:8000`, nunca en `0.0.0.0`.
- **Evidencia:** `F05-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F05-T04 — Permisos tras la actualización

- **Comandos:** repetir F01-T03 y comparar:
  ```bash
  sudo stat -c '%a %U:%G %n' /etc/auditoria-system \
    /etc/auditoria-system/agent.env /etc/auditoria-system/agent-identity.json \
    /var/lib/auditoria-system /var/lib/auditoria-system/*.db \
    /var/lib/auditoria-system-auth /var/lib/auditoria-system-central \
    | tee "$QA/F05-T04.txt"
  sudo getfacl -cp /var/lib/auditoria-system /var/lib/auditoria-system/notifications.db \
    2>&1 | tee -a "$QA/F05-T04.txt"
  diff <(grep -E '^[0-9]{3,4} ' "$QA/F01-T03.txt" | sort) \
       <(grep -E '^[0-9]{3,4} ' "$QA/F05-T04.txt" | sort) && echo "SIN CAMBIOS"
  ```
- **Resultado esperado:** mismos permisos/propietarios que F01-T03; ACL de
  `auditoria-api` sin acceso a `auditoria.db`.
- **Evidencia:** `F05-T04.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F05-T05 — Identidad del agente y heartbeat (solo lectura)

- **Objetivo:** validar registro/identidad sin exponer la credencial.
- **Comandos:**
  ```bash
  sudo stat -c '%a %U:%G %n' /etc/auditoria-system/agent-identity.json
  # solo NOMBRES de campos, nunca valores:
  sudo python3 -c "import json;print(sorted(json.load(open('/etc/auditoria-system/agent-identity.json'))))" \
    | tee "$QA/F05-T05.txt"
  sudo journalctl -u auditoria-agent.service --since "-10 min" --no-pager | grep -ci heartbeat
  ```
- **Resultado esperado:** archivo `600 root:root`; el listado muestra campos de
  identidad (sin imprimir valores); en el dashboard (F06) el servidor aparece
  `ONLINE` con "Último contacto" de segundos a pocos minutos
  (`AUDITORIA_HEARTBEAT_INTERVAL`).
- **Evidencia:** `F05-T05.txt` (solo nombres de campos) + captura del dashboard.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F05-T06 — Registro de un agente nuevo con token de un solo uso

- **Objetivo:** validar el flujo `Conectar servidor` → comando → agente registrado.
- **Precondición:** un **segundo host** `<SERVIDOR_AGENTE>` de laboratorio con la
  release instalada con rol `agent`. **No** re-registre el propio servidor
  central: sobrescribiría su identidad. Sin segundo host: `NO EJECUTADO`.
- **Comandos:**
  1. En el dashboard (sesión de `<USUARIO_ADMIN>`), *Servidores → Conectar
     servidor*; copie el comando (contiene `<TOKEN_TEMPORAL>`; no lo guarde en
     la evidencia).
  2. En `<SERVIDOR_AGENTE>`:
     ```bash
     sudo /opt/auditoria-system/.venv/bin/python -m app.agent register \
       --server <URL_CENTRAL> --token <TOKEN_TEMPORAL>
     sudo systemctl restart auditoria-agent.service
     ```
  3. Reutilizar el **mismo** token una segunda vez.
- **Resultado esperado:** el primer registro termina correctamente; el servidor
  aparece en *Servidores* como `ONLINE`; el segundo uso del token es **rechazado**
  y el token vence a los pocos minutos que muestra el panel.
- **Evidencia:** captura de *Servidores* antes/después; mensaje de rechazo (sin token).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 6 — Dashboard

> La API escucha solo en `127.0.0.1:8000`. Acceda con un túnel desde su equipo:
> `ssh -L 8000:127.0.0.1:8000 <usuario>@<SERVIDOR>` y abra `http://127.0.0.1:8000/dashboard`.
> No exponga el puerto. Si no existe superadmin:
> `sudo runuser -u auditoria-api -- /opt/auditoria-system/.venv/bin/python -m app.auth create-superadmin`
> (usuario y contraseña se teclean en el prompt; no se documentan).

### F06-T01 — Login, marca y sesión

- **Objetivo:** login funcional con la marca Nexora y sesión segura.
- **Comandos:**
  ```bash
  curl -sS -i http://127.0.0.1:8000/login | sed -n '1,25p' | tee "$QA/F06-T01.txt"
  curl -sS http://127.0.0.1:8000/login | grep -o '<title>[^<]*</title>'
  ```
  En el navegador: iniciar sesión con `<USUARIO_ADMIN>`; cerrar sesión; intentar
  `/dashboard` sin sesión.
- **Resultado esperado:** `Content-Security-Policy` con `default-src 'self'` y
  sin `unsafe-inline`; `X-Content-Type-Options: nosniff`; título
  `Iniciar sesión | Nexora`; el logo y el descriptor «Monitoreo y seguridad de tu
  infraestructura» se ven; sin sesión, `/dashboard` no muestra datos; contraseña
  errónea muestra error sin revelar si el usuario existe.
- **Evidencia:** `F06-T01.txt`; captura del login.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F06-T02 — Navegación y vistas

- **Objetivo:** todas las vistas cargan y los datos coinciden con las bases.
- **Pasos:** recorrer *Resumen, Servidores, Incidentes, Detecciones, Eventos,
  Respuestas, Notificaciones, Usuarios* en 1440 px y 390 px; abrir la consola del
  navegador y la pestaña de red.
- **Resultado esperado:** sin errores en consola; sin respuestas 4xx/5xx
  inesperadas; sin scroll horizontal; KPIs del Resumen coherentes con:
  ```bash
  sudo sqlite3 -readonly "$CEN_DB" \
    "SELECT status,COUNT(*) FROM incidents GROUP BY status;" | tee "$QA/F06-T02.txt"
  ```
- **Evidencia:** capturas 1440/390 de Resumen, Incidentes y Servidores; `F06-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F06-T03 — Rol viewer sin privilegios de aprobación

- **Objetivo:** un viewer no puede aprobar ni rechazar.
- **Precondición:** un usuario `viewer` creado desde *Usuarios* (contraseña
  tecleada, no documentada) con acceso a `<SERVIDOR>`.
- **Resultado esperado:** el viewer ve los incidentes de su alcance, **no** ve
  botones de aprobar/rechazar y el detalle indica que solo un superadmin puede
  decidir; una petición directa de aprobación devuelve `403`.
- **Evidencia:** captura del detalle como viewer y como superadmin.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## Preparación común de las fases 7 a 14 (ejecutar una vez)

Las fases siguientes cambian el modo de respuesta en `agent.env` y reinician el
agente. **Antes** de empezar, guarde una copia **privada** de la configuración
(contiene secretos: nunca dentro de `$QA`) para revertirla en F17.

```bash
sudo install -m 0600 -o root -g root /etc/auditoria-system/agent.env \
  /root/agent.env.qa-original

# Helpers de la sesión (copiar y pegar en cada terminal de QA)
set_env() {   # uso: set_env CLAVE valor   (reemplaza o agrega una línea)
  sudo sed -i "/^#\\?${1}=/d" /etc/auditoria-system/agent.env
  printf '%s=%s\n' "$1" "$2" | sudo tee -a /etc/auditoria-system/agent.env >/dev/null
}
show_env() {  # solo claves NO sensibles de respuesta; nunca la API key
  sudo grep -E '^AUDITORIA_(RESPONSE_|ALLOW_|SSH_PORT|TRUSTED_ADMIN_IPS|EVIDENCE_|INCIDENT|APPROVAL_|TEMPORARY_BLOCK_SECONDS|INTERVAL)' \
    /etc/auditoria-system/agent.env
}
q_det()  { sudo sqlite3 -readonly "$AUD_DB" "SELECT timestamp,event_type,severity,json_extract(evidence_json,'\$.source_ip') FROM events WHERE category='detection' ORDER BY timestamp DESC LIMIT ${1:-5};"; }
q_resp() { sudo sqlite3 -readonly "$AUD_DB" "SELECT timestamp,event_type,json_extract(evidence_json,'\$.action'),json_extract(evidence_json,'\$.status'),json_extract(evidence_json,'\$.executed'),json_extract(evidence_json,'\$.protection_rejected'),json_extract(evidence_json,'\$.recurrence_level'),json_extract(evidence_json,'\$.selected_duration_seconds') FROM events WHERE category='response' ORDER BY timestamp DESC LIMIT ${1:-8};"; }
q_inc()  { sudo sqlite3 -readonly "$AUD_DB" "SELECT incident_id,status,severity,source_ip,last_action,last_execution_status FROM incidents ORDER BY opened_at DESC LIMIT ${1:-3};"; }
q_nft()  { sudo nft list table inet auditoria_response 2>&1; }
```

Configuración base de las fases 7 a 14 (cada fase indica lo que cambia):

```bash
set_env AUDITORIA_TRUSTED_ADMIN_IPS "<IP_ADMIN>"
set_env AUDITORIA_INCIDENTS_ENABLED true
set_env AUDITORIA_EVIDENCE_ENABLED true
set_env AUDITORIA_RESPONSE_ESCALATION_ENABLED true      # defaults: 120,600,3600 s; ventana 86400 s
show_env | tee "$QA/F07-config-base.txt"
```

**Cómo generar los ataques.** Ambas detecciones HIGH se disparan por SSH con
usuarios inexistentes (no requieren credenciales); no se guarda ninguna
contraseña:

- `SSH_USER_ENUMERATION_ATTEMPT` (HIGH): **5 usuarios distintos** inválidos en 60 s
  desde la misma IP.
- `SSH_BRUTE_FORCE_ATTEMPT` (HIGH): 10 fallos de contraseña en 60 s (alternativa;
  requiere un usuario válido de laboratorio y contraseña errónea).
- Una segunda detección de la misma clase desde la misma IP se **suprime
  durante 60 s**: espere más de 60 s antes de repetir un ataque.

```bash
# desde el host atacante (IP de origen = <IP_ATACANTE_N>):
atacar() {  # uso: atacar <IP_ATACANTE_N> <SERVIDOR>
  for u in qa-enum1 qa-enum2 qa-enum3 qa-enum4 qa-enum5 qa-enum6; do
    ssh -b "$1" -o BatchMode=yes -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=accept-new "$u@$2" true 2>/dev/null
  done
}
```

El agente procesa por ciclos (`AUDITORIA_INTERVAL`). Tras atacar, espere uno o dos
ciclos y consulte con `q_det`, `q_resp` y `q_inc`.

---

## FASE 7 — Incidentes y evidencia (modo `audit_only`)

Cubre además: eventos, correlación, detecciones, incidente, timeline, evidencia
forense y la prueba de seguridad **1 (audit_only: detección sí; firewall no)**.

### F07-T01 — Detección e incidente sin tocar el firewall

- **Objetivo:** en `audit_only` hay evento, correlación, detección HIGH,
  decisión recomendada e incidente `OBSERVED`, y **ninguna** regla de firewall.
- **Precondición:** configuración base aplicada; `set_env AUDITORIA_RESPONSE_MODE audit_only`;
  `sudo systemctl restart auditoria-agent.service`; `q_nft` anotado (la tabla
  puede no existir).
- **Comandos:**
  ```bash
  T0="$(date -u +%Y-%m-%dT%H:%M:%S)"; echo "$T0" > "$QA/F07-T0.txt"
  # en el atacante:  atacar <IP_ATACANTE_1> <SERVIDOR>
  sleep 90
  { q_det; echo ---; q_resp; echo ---; q_inc; echo ---; q_nft; } | tee "$QA/F07-T01.txt"
  sudo nft list ruleset | grep -c '<IP_ATACANTE_1>' | tee -a "$QA/F07-T01.txt"
  ```
- **Resultado esperado:** eventos `SSH_INVALID_USER` (≥5 usuarios distintos);
  una detección `SSH_USER_ENUMERATION_ATTEMPT` `high`; `RESPONSE_DECISION` con
  acción `RECOMMEND_BLOCK_IP`/`RECOMMEND_BLOCK_IP_PORT` (nunca `TEMPORARY_*`);
  `RESPONSE_EXECUTION` con `executed = 0` y estado `DRY_RUN` o `SKIPPED`;
  incidente `OBSERVED`; `grep -c` devuelve **0**; sin elementos para la IP en
  ningún set de `inet auditoria_response`.
- **Evidencia:** `F07-T01.txt`; captura del incidente en el dashboard.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F07-T02 — Outbox y sincronización de los eventos

- **Objetivo:** los eventos locales llegan al central y el outbox se vacía.
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM event_outbox GROUP BY status;" | tee "$QA/F07-T02.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT event_id FROM events WHERE timestamp >= '$(cat "$QA/F07-T0.txt")' ORDER BY 1;" > "$QA/F07-ids-local.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT event_id FROM events WHERE timestamp >= '$(cat "$QA/F07-T0.txt")' ORDER BY 1;" > "$QA/F07-ids-central.txt"
  diff "$QA/F07-ids-local.txt" "$QA/F07-ids-central.txt" && echo "LOCAL == CENTRAL" | tee -a "$QA/F07-T02.txt"
  ```
- **Resultado esperado:** `pending` = 0 (o ausente) y `acknowledged` > 0; **sin**
  `permanently_failed`; el `diff` no muestra diferencias.
- **Evidencia:** `F07-T02.txt` y los dos archivos de IDs.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F07-T03 — Incidente y timeline en el central y en el dashboard

- **Objetivo:** el incidente existe en `central.db` con vínculos y la timeline
  respeta el orden real del flujo.
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$CEN_DB" "SELECT incident_id,status,severity,source_ip FROM incidents ORDER BY opened_at DESC LIMIT 3;" | tee "$QA/F07-T03.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT l.kind,l.occurred_at FROM incident_links l JOIN (SELECT incident_id FROM incidents ORDER BY opened_at DESC LIMIT 1) i USING (incident_id) ORDER BY l.occurred_at;" | tee -a "$QA/F07-T03.txt"
  ```
  En el dashboard: *Incidentes → detalle del incidente*; revisar *Línea de tiempo*.
- **Resultado esperado:** vínculos `event`, `detection`, `decision`, `execution`,
  `evidence`; en el dashboard la línea de tiempo muestra EVENTO → DETECCIÓN →
  DECISIÓN → EJECUCIÓN → **EVIDENCIA al final** (la captura ampliada es posterior
  a la contención); los códigos técnicos (`SSH_USER_ENUMERATION_ATTEMPT`,
  `EXECUTED`/`SKIPPED`/`DRY_RUN`) no están traducidos; las fechas se ven en
  formato `dd/mm/aaaa`.
- **Evidencia:** `F07-T03.txt`; captura del detalle a 1440 px y 390 px.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F07-T04 — Evidencia forense: contenido, permisos y orden

- **Objetivo:** captura defensiva, de solo lectura, con permisos estrictos y
  posterior a la contención.
- **Comandos:**
  ```bash
  D="$(sudo ls -1dt /var/lib/auditoria-system/evidence/*/ | head -n 1)"; echo "$D" | tee "$QA/F07-T04.txt"
  sudo stat -c '%a %U:%G %n' /var/lib/auditoria-system/evidence "$D" | tee -a "$QA/F07-T04.txt"
  sudo find "$D" -type f -printf '%m %s %f\n' | sort -k3 | tee -a "$QA/F07-T04.txt"
  sudo python3 -c "import json,sys;m=json.load(open(sys.argv[1]+'metadata.json'));print(m['status'],m['truncated'],[a['name']+':'+a['status'] for a in m['artifacts']])" "$D" | tee -a "$QA/F07-T04.txt"
  # sin secretos evidentes:
  sudo grep -rIEi 'password=|token[:=]|Bearer |PRIVATE KEY' "$D" | wc -l | tee -a "$QA/F07-T04.txt"
  # orden: la captura debe ser posterior a la ejecución
  sudo sqlite3 -readonly "$AUD_DB" "SELECT event_type,timestamp FROM events WHERE event_type IN ('RESPONSE_EXECUTION','FORENSIC_EVIDENCE_CAPTURED') ORDER BY timestamp DESC LIMIT 4;" | tee -a "$QA/F07-T04.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM forensic_capture_queue GROUP BY status;" | tee -a "$QA/F07-T04.txt"
  ```
- **Resultado esperado:** directorio base y de captura `700`, archivos `600`;
  `metadata.json`, `network_connections.txt`, `listening_sockets.txt`,
  `logged_in_users.txt`, `ssh_journal.txt`, `ssh_services.txt`,
  `nftables_auditoria.txt`, `relevant_processes.txt` y `quick_snapshot.json`;
  estado `complete` o `partial` justificado (artefacto `unavailable` aislado);
  conteo de secretos = **0**; `FORENSIC_EVIDENCE_CAPTURED` tiene marca de tiempo
  **≥** la de `RESPONSE_EXECUTION`; la cola sin `PENDING` ni `FAILED`.
- **Evidencia:** `F07-T04.txt`. **No** copie el contenido de la evidencia al
  informe; solo metadatos.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F07-T05 — La API no expone archivos de evidencia

- **Objetivo:** el dashboard muestra solo metadatos.
- **Pasos:** en el detalle del incidente revisar el panel *Evidencia forense*;
  intentar descargar o abrir un archivo.
- **Resultado esperado:** muestra captura, fecha, archivos y tamaños; **sin**
  enlaces de descarga ni contenido; el aviso indica que la evidencia permanece
  en el servidor del agente.
- **Evidencia:** captura del panel de evidencia.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 8 — Assisted

Cubre la prueba de seguridad **2** (assisted: `PENDING_APPROVAL`; firewall
intacto; approve; el agente revalida; ejecución; reject; sin firewall).

### F08-T01 — Acción pendiente sin tocar el firewall

- **Precondición:**
  ```bash
  set_env AUDITORIA_RESPONSE_MODE assisted
  set_env AUDITORIA_RESPONSE_BLOCK_SCOPE ip_port
  set_env AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK true
  set_env AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK true
  sudo systemctl restart auditoria-agent.service; show_env | tee "$QA/F08-config.txt"
  ```
  (No modifique `AUDITORIA_APPROVAL_TTL_SECONDS` aquí; F08-T05 lo trata.)
- **Comandos:**
  ```bash
  # en el atacante:  atacar <IP_ATACANTE_2> <SERVIDOR>
  sleep 90
  { q_resp; echo ---; q_inc; echo ---; q_nft; } | tee "$QA/F08-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT action_id,status,action,target_ip,protocol,port,duration_seconds,expires_at FROM response_approvals ORDER BY requested_at DESC LIMIT 3;" | tee -a "$QA/F08-T01.txt"
  sudo nft list ruleset | grep -c '<IP_ATACANTE_2>' | tee -a "$QA/F08-T01.txt"
  ```
- **Resultado esperado:** `RESPONSE_DECISION` con acción `RECOMMEND_…` y
  `approval_required`; `RESPONSE_APPROVAL_REQUESTED`; fila `PENDING_APPROVAL` con
  `TEMPORARY_BLOCK_IP_PORT`, `tcp`, `22` y `expires_at` a +3600 s; incidente
  `OPEN`; **cero** reglas/elementos para la IP; en el dashboard aparece el panel
  *Respuesta propuesta* con acción, IP, protocolo, puerto, duración y motivo.
- **Evidencia:** `F08-T01.txt`; captura del panel en 1440 px y 390 px.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F08-T02 — Confirmación visual y cancelación sin petición

- **Objetivo:** aprobar exige confirmación; cancelar no genera ninguna petición.
- **Pasos:** con las herramientas de desarrollo abiertas (pestaña *Red*,
  filtro `approve`/`reject`): pulsar *Aprobar respuesta*; verificar el cuadro de
  confirmación; pulsar *Cancelar*; repetir con `Esc`.
- **Resultado esperado:** el cuadro muestra acción, IP, protocolo/puerto y
  duración y el texto «El agente volverá a validar las protecciones antes de
  ejecutar la respuesta.»; *Cancelar* y `Esc` cierran el cuadro **sin** ninguna
  petición `POST`; la acción sigue `PENDING_APPROVAL`:
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM response_approvals GROUP BY status;" | tee "$QA/F08-T02.txt"
  ```
- **Evidencia:** captura del cuadro; captura de la pestaña *Red* sin `POST`; `F08-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F08-T03 — Rechazo: sin firewall

- **Pasos:** en el detalle de la acción de F08-T01, motivo opcional
  (`QA rechazo`) y *Rechazar*. Espere un ciclo del agente.
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,decided_by,decision_reason FROM response_approvals ORDER BY requested_at DESC LIMIT 1;" | tee "$QA/F08-T03.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT event_type,timestamp FROM events WHERE event_type IN ('RESPONSE_REJECTION_APPLIED','RESPONSE_EXECUTION') ORDER BY timestamp DESC LIMIT 3;" | tee -a "$QA/F08-T03.txt"
  q_inc 1 | tee -a "$QA/F08-T03.txt"; sudo nft list ruleset | grep -c '<IP_ATACANTE_2>' | tee -a "$QA/F08-T03.txt"
  ```
- **Resultado esperado:** estado `REJECTED` con usuario y motivo; evento
  `RESPONSE_REJECTION_APPLIED`; **sin** `RESPONSE_EXECUTION` nuevo; incidente
  `OBSERVED`; **cero** reglas para la IP; el dashboard muestra la acción como
  `REJECTED` y la timeline incluye el rechazo (RECHAZO).
- **Evidencia:** `F08-T03.txt`; captura de la timeline.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F08-T04 — Aprobación: el agente revalida y ejecuta

- **Pasos:** `atacar <IP_ATACANTE_3> <SERVIDOR>`; esperar `PENDING_APPROVAL`;
  en el dashboard *Aprobar respuesta* → *Confirmar aprobación*. Espere un ciclo.
  Después intente aprobar la **misma** acción desde una segunda pestaña.
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,decided_by,execution_event_id FROM response_approvals ORDER BY requested_at DESC LIMIT 1;" | tee "$QA/F08-T04.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT json_extract(evidence_json,'\$.approval_id'),json_extract(evidence_json,'\$.approved_by'),json_extract(evidence_json,'\$.status'),json_extract(evidence_json,'\$.executed') FROM events WHERE event_type='RESPONSE_EXECUTION' ORDER BY timestamp DESC LIMIT 1;" | tee -a "$QA/F08-T04.txt"
  sudo nft list set inet auditoria_response blocked_ipv4_port 2>&1 | tee -a "$QA/F08-T04.txt"
  q_inc 1 | tee -a "$QA/F08-T04.txt"
  ```
- **Resultado esperado:** `response_approvals` pasa `PENDING_APPROVAL → EXECUTED`
  (nunca queda en `EXECUTING`); `RESPONSE_EXECUTION` con `approval_id`,
  `approved_by` y `executed = 1`; el set `blocked_ipv4_port` contiene
  `<IP_ATACANTE_3> . tcp . 22` con `expires`; incidente `CONTAINED`; el segundo
  intento de aprobar devuelve error `409` visible en el dashboard (sin segunda
  ejecución). *(Para IPv6 el set es `blocked_ipv6_port`.)*
- **Evidencia:** `F08-T04.txt`; captura del detalle `CONTAINED`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F08-T05 — Vencimiento de una acción no decidida

- **Objetivo:** una acción sin decisión no queda pendiente para siempre.
- **Precondición:** el TTL por defecto es 3600 s (rango válido 300–86400). Para no
  esperar una hora se **reduce temporalmente** a 300 s; **documente** el cambio
  y la hora de reversión en *Observación*:
  ```bash
  set_env AUDITORIA_APPROVAL_TTL_SECONDS 300; sudo systemctl restart auditoria-agent.service
  ```
- **Comandos:** `atacar <IP_ATACANTE_7> <SERVIDOR>`; **no** decidir; esperar > 300 s +
  un ciclo:
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status FROM response_approvals ORDER BY requested_at DESC LIMIT 1;" | tee "$QA/F08-T05.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM events WHERE event_type='RESPONSE_APPROVAL_EXPIRED';" | tee -a "$QA/F08-T05.txt"
  ```
  Revierta: `sudo sed -i '/^AUDITORIA_APPROVAL_TTL_SECONDS=/d' /etc/auditoria-system/agent.env; sudo systemctl restart auditoria-agent.service`.
- **Resultado esperado:** estado `EXPIRED`; evento `RESPONSE_APPROVAL_EXPIRED`;
  el dashboard ya no ofrece aprobar; sin reglas de firewall para la IP.
- **Evidencia:** `F08-T05.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 9 — Automatic

Cubre la prueba de seguridad **3** (automatic: detección HIGH; decisión;
protecciones; ejecución) con `TEMPORARY_BLOCK_IP`.

### F09-T01 — Bloqueo automático por IP

- **Precondición:**
  ```bash
  set_env AUDITORIA_RESPONSE_MODE automatic
  set_env AUDITORIA_RESPONSE_BLOCK_SCOPE ip
  set_env AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK true
  sudo systemctl restart auditoria-agent.service; show_env | tee "$QA/F09-config.txt"
  ```
- **Comandos:**
  ```bash
  # en el atacante:  atacar <IP_ATACANTE_4> <SERVIDOR>
  sleep 90
  { q_det 3; echo ---; q_resp 4; echo ---; q_inc 1; echo ---; q_nft; } | tee "$QA/F09-T01.txt"
  # en el atacante (debe agotar el tiempo, no conectar):
  #   nc -vz -w 4 <SERVIDOR> 22 ; ssh -b <IP_ATACANTE_4> -o ConnectTimeout=5 -o BatchMode=yes u@<SERVIDOR> true
  ```
- **Resultado esperado:** detección `high`; `RESPONSE_DECISION` con
  `TEMPORARY_BLOCK_IP`, duración de nivel 1 (120 s con escalamiento activo);
  `RESPONSE_EXECUTION` `EXECUTED` con `executed = 1` y `protection_rejected`
  falso; la IP aparece en `blocked_ipv4` con `expires`; incidente `CONTAINED`;
  desde el atacante la conexión **no** se establece (timeout); transcurrida la
  duración, el elemento desaparece y la conexión vuelve a ser posible.
- **Evidencia:** `F09-T01.txt`; salida del atacante antes y después de expirar.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F09-T02 — Idempotencia: sin duplicados mientras el bloqueo está vigente

- **Comandos:** durante la vigencia, repetir el ataque **a los >60 s** de la
  detección y consultar:
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM response_blocks WHERE target_ip='<IP_ATACANTE_4>' GROUP BY status;" | tee "$QA/F09-T02.txt"
  q_resp 4 | tee -a "$QA/F09-T02.txt"
  ```
- **Resultado esperado:** un único bloqueo vivo por (host, IP, acción);
  ejecución repetida `SKIPPED` con motivo de bloqueo vigente (no `FAILED`); el
  incidente sigue `CONTAINED`.
- **Evidencia:** `F09-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 10 — nftables IP + puerto

Cubre la prueba de seguridad **5** (atacante bloqueado únicamente hacia TCP/22;
otros servicios no se bloquean).

### F10-T01 — Estructuras nftables y bloqueo selectivo

- **Precondición:**
  ```bash
  set_env AUDITORIA_RESPONSE_MODE automatic
  set_env AUDITORIA_RESPONSE_BLOCK_SCOPE ip_port
  set_env AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK true
  sudo systemctl restart auditoria-agent.service
  # servicio de prueba en OTRO puerto (se cierra al terminar):
  sudo python3 -m http.server 8081 --bind <IP_LOCAL_SERVIDOR> >/dev/null 2>&1 &
  echo $! | tee "$QA/F10-http-pid.txt"
  ss -ltn 'sport = :8081'
  ```
  Si hay firewall de host (p. ej. `ufw`), permita 8081 solo desde el atacante
  durante la prueba y anótelo.
- **Comandos:**
  ```bash
  # en el atacante:
  #   curl -sS -m 5 -o /dev/null -w '%{http_code}\n' --interface <IP_ATACANTE_5> http://<IP_LOCAL_SERVIDOR>:8081/   -> 200 (antes)
  #   atacar <IP_ATACANTE_5> <SERVIDOR>
  sleep 90
  { q_resp 4; echo ---; q_inc 1; echo ---; q_nft; } | tee "$QA/F10-T01.txt"
  # en el atacante, con el bloqueo vigente:
  #   ssh -b <IP_ATACANTE_5> -o ConnectTimeout=5 -o BatchMode=yes u@<SERVIDOR> true      -> timeout
  #   curl -sS -m 5 -o /dev/null -w '%{http_code}\n' --interface <IP_ATACANTE_5> http://<IP_LOCAL_SERVIDOR>:8081/   -> 200 (sigue)
  #   ping -c2 -I <IP_ATACANTE_5> <SERVIDOR>                                             -> responde (si ICMP está permitido)
  ```
- **Resultado esperado:** `RESPONSE_DECISION` y `RESPONSE_EXECUTION` con
  `TEMPORARY_BLOCK_IP_PORT`, `protocol=tcp`, `port=22`, `EXECUTED`; la tabla
  contiene `set blocked_ipv4_port`, `set blocked_ipv6_port`, `chain input_port`
  con `iifname "lo" return`, `iifname "tailscale0" return` y reglas `counter drop`;
  el set tiene el elemento `<IP_ATACANTE_5> . tcp . 22` con `expires`; **SSH
  desde la IP queda bloqueado** y **8081 sigue accesible**; los contadores de la
  regla `drop` aumentan; los sets `blocked_ipv4`/`blocked_ipv6` y la cadena
  `input` históricos **no** se alteraron.
- **Evidencia:** `F10-T01.txt`; salidas del atacante (SSH timeout, HTTP 200).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F10-T02 — Expiración y limpieza

- **Comandos:** tras la duración, `q_nft | tee "$QA/F10-T02.txt"`;
  `sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM response_blocks GROUP BY status;"`;
  detener el servicio de prueba: `kill "$(cat "$QA/F10-http-pid.txt")"`.
- **Resultado esperado:** el elemento ya no está en el set (lo expira el kernel);
  el bloqueo figura `EXPIRED`; SSH desde la IP vuelve a conectar; el servicio de
  prueba en 8081 queda detenido; sin reglas huérfanas.
- **Evidencia:** `F10-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 11 — Protecciones

Todas con `AUDITORIA_RESPONSE_MODE=automatic`, `AUDITORIA_RESPONSE_BLOCK_SCOPE=ip_port`
y bloqueos permitidos (configuración de F10). Una IP protegida **no** genera
ofensa de reincidencia. **Riesgo:** si una protección fallara, la IP afectada
quedaría bloqueada hacia el puerto 22 hasta que expire el bloqueo (≤ 120 s en
nivel 1); mantenga la vía fuera de banda de la regla 6.

Criterio común de PASS para F11-T02 a F11-T05: la detección existe;
`RESPONSE_DECISION` conserva la acción propuesta (`TEMPORARY_BLOCK_IP_PORT`);
`RESPONSE_EXECUTION` queda `SKIPPED`, `executed = 0` y `protection_rejected = 1`
con el motivo; el incidente queda `OBSERVED`; **no** hay regla ni elemento para
esa IP; no se crea fila en `response_offenses`.

### F11-T01 — Trusted admin

- **Objetivo:** una IP de `AUDITORIA_TRUSTED_ADMIN_IPS` jamás se bloquea.
- **Precondición:** F00-T03 PASS; `<IP_ADMIN>` en la lista de confiables; vía
  fuera de banda disponible.
- **Comandos:** desde `<IP_ADMIN>` generar 6 usuarios inexistentes (como
  `atacar`, con `-b <IP_ADMIN>`); luego:
  ```bash
  { q_det 3; echo ---; q_resp 4; echo ---; q_nft; } | tee "$QA/F11-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM response_offenses WHERE source_ip='<IP_ADMIN>';" | tee -a "$QA/F11-T01.txt"
  sudo nft list ruleset | grep -c '<IP_ADMIN>' | tee -a "$QA/F11-T01.txt"
  ```
- **Resultado esperado:** la sesión de administración sigue funcionando; la
  decisión es `NO_ACTION` (guarda histórica de v1.0, no `SKIPPED`) o, si
  hubiera propuesta, ejecución `SKIPPED` con `protection_rejected = 1`; `0` ofensas;
  `0` reglas.
- **Evidencia:** `F11-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F11-T02 — Sesión SSH establecida

- **Objetivo:** no se bloquea una IP con una sesión SSH activa.
- **Comandos:** desde `<IP_ATACANTE_1>` abrir y **mantener** una sesión SSH
  válida de laboratorio (`ssh -b <IP_ATACANTE_1> <USUARIO_QA>@<SERVIDOR>`); en
  otra terminal desde la misma IP ejecutar `atacar <IP_ATACANTE_1> <SERVIDOR>`
  (esperar > 60 s si ya hubo detección de F07). Luego `q_resp 4`, `q_nft`.
- **Resultado esperado:** criterio común de F11; el motivo menciona la sesión
  SSH establecida; la sesión abierta no se corta.
- **Evidencia:** `F11-T02.txt` (`{ q_resp 4; q_nft; } | tee`).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F11-T03 — Tailscale (prueba de seguridad 4)

- **Objetivo:** decisión = bloquear; ejecución = `SKIPPED`; `protection_rejected = true`;
  sin regla nftables.
- **Precondición:** un par Tailscale `<IP_TAILSCALE>` (rango `100.64.0.0/10`)
  con acceso SSH a la IP Tailscale del servidor `<IP_TAILSCALE_SERVIDOR>`. Sin par
  disponible: `NO EJECUTADO`.
- **Comandos:** desde el par: 6 usuarios inexistentes contra
  `<IP_TAILSCALE_SERVIDOR>`; luego:
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT json_extract(evidence_json,'\$.action'),json_extract(evidence_json,'\$.target_ip') FROM events WHERE event_type='RESPONSE_DECISION' ORDER BY timestamp DESC LIMIT 1;" | tee "$QA/F11-T03.txt"
  q_resp 3 | tee -a "$QA/F11-T03.txt"
  sudo nft list ruleset | grep -c '<IP_TAILSCALE>' | tee -a "$QA/F11-T03.txt"
  ```
- **Resultado esperado:** la decisión propone `TEMPORARY_BLOCK_IP_PORT` hacia
  `<IP_TAILSCALE>`; la ejecución `SKIPPED` con `protection_rejected = 1`; `0`
  reglas para esa IP; el par Tailscale conserva el acceso.
- **Evidencia:** `F11-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F11-T04 — IP local del propio servidor

- **Comandos:** en el servidor: 6 usuarios inexistentes contra su propia IP:
  ```bash
  for u in qa-loc1 qa-loc2 qa-loc3 qa-loc4 qa-loc5 qa-loc6; do
    ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
        "$u@<IP_LOCAL_SERVIDOR>" true 2>/dev/null
  done
  sleep 90; { q_det 3; q_resp 4; q_nft; } | tee "$QA/F11-T04.txt"
  ```
- **Resultado esperado:** criterio común de F11 con `target_ip = <IP_LOCAL_SERVIDOR>`;
  el servidor no se bloquea a sí mismo.
- **Evidencia:** `F11-T04.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F11-T05 — Gateway

- **Objetivo:** la puerta de enlace nunca se bloquea.
- **Comandos:** `ip route show default | tee "$QA/F11-T05.txt"`. Generar el
  ataque con origen = IP del gateway **no es posible de forma legítima** sin
  suplantarlo; no se simula con `ip addr` ni spoofing en una red compartida.
- **Resultado esperado:** documentar el gateway detectado. La cobertura E2E es
  `NO EJECUTADO` salvo que exista un laboratorio aislado donde un host pueda
  actuar como gateway real; la protección queda cubierta por las pruebas
  automatizadas del repositorio (`tests/test_response_protection.py`, p. ej.
  `test_reads_ipv4_and_ipv6_gateways`). La decisión de aceptar esa cobertura la
  toma el ingeniero y se anota en *Observación*.
- **Evidencia:** `F11-T05.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 12 — Reincidencia

Cubre la prueba de seguridad **6** (nivel 1; esperar expiración; repetir; nivel
2; comprobar duración mayor). Se usa `<IP_ATACANTE_6>`, **no utilizada antes**.

### F12-T01 — Nivel 1

- **Precondición:**
  ```bash
  set_env AUDITORIA_RESPONSE_MODE automatic
  set_env AUDITORIA_RESPONSE_BLOCK_SCOPE ip_port
  set_env AUDITORIA_RESPONSE_ESCALATION_ENABLED true
  show_env | tee "$QA/F12-config.txt"      # escalamiento por defecto: 120,600,3600 s
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM response_offenses WHERE source_ip='<IP_ATACANTE_6>';"   # debe ser 0
  ```
- **Comandos:** `atacar <IP_ATACANTE_6> <SERVIDOR>`; `sleep 90`;
  ```bash
  q_resp 3 | tee "$QA/F12-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT recurrence_level,selected_duration_seconds,occurred_at FROM response_offenses WHERE source_ip='<IP_ATACANTE_6>';" | tee -a "$QA/F12-T01.txt"
  sudo nft list set inet auditoria_response blocked_ipv4_port | tee -a "$QA/F12-T01.txt"
  ```
- **Resultado esperado:** `recurrence_level = 1`, duración seleccionada **120 s**,
  `previous_incidents = 0`; elemento con `timeout 2m` aproximado.
- **Evidencia:** `F12-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F12-T02 — Nivel 2 tras la expiración

- **Comandos:** esperar a que el elemento desaparezca de `blocked_ipv4_port`
  (≥ 120 s) **y** a que pasen > 60 s desde la detección anterior; repetir
  `atacar <IP_ATACANTE_6> <SERVIDOR>`; `sleep 90`; repetir las consultas de
  F12-T01 guardando en `F12-T02.txt`.
- **Resultado esperado:** `recurrence_level = 2`, `previous_incidents = 1`,
  duración seleccionada **600 s** (> 120 s); el elemento nuevo expira a ~10 min;
  el motivo de la decisión describe el escalamiento; el incidente sigue
  `CONTAINED`.
- **Evidencia:** `F12-T02.txt`; captura de la decisión en el dashboard.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F12-T03 — Nivel 3 y regreso a nivel 1 (opcional, largo)

- **Objetivo:** nivel 3 = 3600 s; sin ofensas en la ventana (86400 s) vuelve a
  nivel 1. Esperar 10 min + > 60 s y repetir para el nivel 3; el regreso a nivel 1
  exige 24 h sin ofensas de la IP.
- **Resultado esperado:** nivel 3 con **3600 s** (sin bloqueo infinito, máximo
  86400 s); el regreso a nivel 1 solo se valida pasadas 24 h. No se reduce la
  ventana para obtener PASS; si no se espera: `NO EJECUTADO`.
- **Evidencia:** `F12-T03.txt` (salida de `q_resp` y `response_offenses`).
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 13 — Outbox y central temporalmente no disponible

### F13-T01 — El outbox acumula y vacía sin pérdida

- **Objetivo:** con la API caída el agente sigue funcionando, el outbox acumula
  y todo se sincroniza al volver.
- **Precondición:** `set_env AUDITORIA_RESPONSE_MODE audit_only` y reinicio del
  agente (para no bloquear durante esta prueba); outbox en `pending = 0`.
- **Comandos:**
  ```bash
  T1="$(date -u +%Y-%m-%dT%H:%M:%S)"; echo "$T1" > "$QA/F13-T1.txt"
  sudo systemctl stop auditoria-api.service
  # en el atacante: 3 usuarios inexistentes (no alcanzan el umbral de detección)
  for u in qa-out1 qa-out2 qa-out3; do ssh -b <IP_ATACANTE_7> -o BatchMode=yes -o ConnectTimeout=5 "$u@<SERVIDOR>" true 2>/dev/null; done
  sleep 60
  systemctl is-active auditoria-agent.service | tee "$QA/F13-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*),MAX(attempt_count),MAX(last_error IS NOT NULL) FROM event_outbox GROUP BY status;" | tee -a "$QA/F13-T01.txt"
  sudo systemctl start auditoria-api.service
  sleep 90
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM event_outbox GROUP BY status;" | tee -a "$QA/F13-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT event_id FROM events WHERE timestamp >= '$T1' ORDER BY 1;" > "$QA/F13-ids-local.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT event_id FROM events WHERE timestamp >= '$T1' ORDER BY 1;" > "$QA/F13-ids-central.txt"
  diff "$QA/F13-ids-local.txt" "$QA/F13-ids-central.txt" && echo "LOCAL == CENTRAL" | tee -a "$QA/F13-T01.txt"
  ```
- **Resultado esperado:** el agente permanece `active` con la API caída; durante
  la caída aparecen filas `pending` con `attempt_count` > 0 y `last_error`; al
  volver la API, `pending` baja a 0 sin `permanently_failed`; **ningún evento se
  pierde ni se duplica** (`diff` vacío); el servidor aparece `ONLINE` otra vez.
- **Evidencia:** `F13-T01.txt` y archivos de IDs.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F13-T02 — La respuesta local no depende del central

- **Objetivo:** con el central caído, el agente decide y ejecuta localmente; el
  incidente aparece después en el central.
- **Precondición:** `set_env AUDITORIA_RESPONSE_MODE automatic`,
  `AUDITORIA_RESPONSE_BLOCK_SCOPE ip_port`; reinicio del agente; IP no usada
  antes (agregue una `<IP_ATACANTE_8>` o documente la reutilización de `_7` con su
  nivel).
- **Comandos:** `sudo systemctl stop auditoria-api.service`; atacar; esperar 90 s;
  `{ q_resp 4; q_inc 1; q_nft; } | tee "$QA/F13-T02.txt"`; iniciar la API; esperar
  90 s; consultar el incidente en `central.db` y en el dashboard.
- **Resultado esperado:** durante la caída hay decisión, ejecución `EXECUTED` y
  elemento nftables; tras restablecer el central, el incidente, su timeline y
  la evidencia aparecen completos en el dashboard.
- **Evidencia:** `F13-T02.txt`; captura del incidente tras la sincronización.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 14 — Reinicio y recuperación

### F14-T01 — Reinicio de servicios con una aprobación pendiente

- **Precondición:** `set_env AUDITORIA_RESPONSE_MODE assisted`; reinicio del
  agente; una acción `PENDING_APPROVAL` (atacar desde una IP no usada).
- **Comandos:**
  ```bash
  sudo sqlite3 -readonly "$AUD_DB" "SELECT action_id,status FROM response_approvals WHERE status='PENDING_APPROVAL';" | tee "$QA/F14-T01.txt"
  sudo systemctl restart auditoria-agent
  sudo systemctl restart auditoria-api
  sleep 30
  systemctl is-active auditoria-agent.service auditoria-api.service | tee -a "$QA/F14-T01.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT action_id,status FROM response_approvals WHERE status IN ('PENDING_APPROVAL','EXECUTING');" | tee -a "$QA/F14-T01.txt"
  curl -sS -m 5 http://127.0.0.1:8000/health | tee -a "$QA/F14-T01.txt"
  ```
- **Resultado esperado:** servicios `active`; la acción pendiente **sigue**
  `PENDING_APPROVAL` (o `EXPIRED` si venció, nunca perdida); ninguna acción en
  `EXECUTING`; tras reiniciar, aprobar la acción desde el dashboard funciona.
- **Evidencia:** `F14-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F14-T02 — Reinicio con un bloqueo vigente

- **Precondición:** `set_env AUDITORIA_RESPONSE_MODE automatic`;
  `AUDITORIA_RESPONSE_BLOCK_SCOPE ip_port`; un bloqueo activo reciente de una
  IP **nueva** (nivel 1 = 120 s: reinicie **inmediatamente** después de verlo).
- **Comandos:**
  ```bash
  sudo nft list set inet auditoria_response blocked_ipv4_port | tee "$QA/F14-T02.txt"
  sudo systemctl restart auditoria-agent
  sleep 15
  sudo nft list set inet auditoria_response blocked_ipv4_port | tee -a "$QA/F14-T02.txt"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM response_blocks GROUP BY status;" | tee -a "$QA/F14-T02.txt"
  ```
- **Resultado esperado:** el bloqueo sigue presente con su tiempo restante
  (no se reinicia a 120 s ni se duplica); `response_blocks` coherente con el
  firewall.
- **Evidencia:** `F14-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F14-T03 — Cola forense tras una interrupción

- **Objetivo:** una captura ampliada pendiente sobrevive a una caída del agente.
- **Comandos:** atacar con una IP nueva y vigilar la cola; en cuanto aparezca una
  fila `PENDING`, terminar el agente de forma abrupta y reiniciarlo:
  ```bash
  while ! sudo sqlite3 -readonly "$AUD_DB" "SELECT 1 FROM forensic_capture_queue WHERE status='PENDING' LIMIT 1;" | grep -q 1; do sleep 0.5; done
  sudo systemctl kill -s SIGKILL auditoria-agent.service; sleep 8; sudo systemctl start auditoria-agent.service
  sleep 40
  sudo sqlite3 -readonly "$AUD_DB" "SELECT status,attempts,COUNT(*) FROM forensic_capture_queue GROUP BY status,attempts;" | tee "$QA/F14-T03.txt"
  sudo ls -1t /var/lib/auditoria-system/evidence | head -n 3 | tee -a "$QA/F14-T03.txt"
  ```
- **Resultado esperado:** la fila `PENDING` se completa (`DONE`) tras el reinicio
  y aparece su directorio de evidencia; sin `FAILED`. Si la ventana entre
  encolar y capturar es demasiado corta para interrumpirla: `NO EJECUTADO`
  (no se considera PASS ni se fuerza modificando la cola).
- **Evidencia:** `F14-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F14-T04 — Reinicio real del servidor (`reboot`)

- **Objetivo:** recuperación completa tras reiniciar el sistema operativo.
- **Precondición:** solo si es seguro: consola fuera de banda disponible, ventana
  de mantenimiento, sin otros usuarios en el servidor. Prepare antes: una acción
  `PENDING_APPROVAL` (F14-T01) y un bloqueo **largo** de una IP nueva. Para que
  el bloqueo sobreviva al reinicio, **documente** esta configuración temporal:
  `AUDITORIA_RESPONSE_ESCALATION_ENABLED=false` y
  `AUDITORIA_TEMPORARY_BLOCK_SECONDS=900` (valor por defecto del producto), con
  alcance `ip_port`.
- **Comandos:**
  ```bash
  { sudo nft list table inet auditoria_response; sudo sqlite3 -readonly "$AUD_DB" \
      "SELECT status,COUNT(*) FROM response_approvals GROUP BY status; SELECT status,COUNT(*) FROM response_blocks GROUP BY status; SELECT status,COUNT(*) FROM event_outbox GROUP BY status; SELECT status,COUNT(*) FROM forensic_capture_queue GROUP BY status;"; } \
    | tee "$QA/F14-T04-antes.txt"
  sudo systemctl reboot
  # tras reconectar (puede requerir la consola):
  uptime -s
  { systemctl is-active auditoria-agent.service auditoria-api.service
    systemctl --failed --no-legend
    curl -sS -m 5 http://127.0.0.1:8000/health
    sudo nft list table inet auditoria_response 2>&1
    sudo sqlite3 -readonly "$AUD_DB" "SELECT status,COUNT(*) FROM response_approvals GROUP BY status; SELECT status,COUNT(*) FROM response_blocks GROUP BY status; SELECT status,COUNT(*) FROM event_outbox GROUP BY status; SELECT status,COUNT(*) FROM forensic_capture_queue GROUP BY status; PRAGMA integrity_check;"
  } | tee "$QA/F14-T04-despues.txt"
  ```
- **Resultado esperado:** ambos servicios `active` y `enabled` sin intervención;
  `--failed` vacío; `/health` 200; la tabla `inet auditoria_response` se
  **recrea** y el bloqueo vigente se **restaura con el tiempo restante** (el
  kernel pierde las reglas al reiniciar; la recuperación del agente las
  reconstruye desde `auditoria.db`); un bloqueo ya vencido no reaparece; la
  acción pendiente conserva su estado (o `EXPIRED` si venció); outbox sin
  `pending` residual tras unos ciclos; cola forense sin `PENDING` residual;
  `integrity_check = ok`. Revierta la configuración temporal en F17.
- **Evidencia:** `F14-T04-antes.txt` y `F14-T04-despues.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 15 — Backup / restore

### F15-T01 — Backup con estado conocido

- **Comandos:**
  ```bash
  sudo bash /opt/auditoria-system/scripts/backup.sh --role central | tee "$QA/F15-T01.txt"
  export BACKUP_B1="$(sed -n 's/^BACKUP_CREADO=//p' "$QA/F15-T01.txt" | tail -n 1)"
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM events; SELECT COUNT(*) FROM incidents;" | tee "$QA/F15-T01-estado-B1.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT COUNT(*) FROM events; SELECT COUNT(*) FROM incidents;" | tee -a "$QA/F15-T01-estado-B1.txt"
  for db in $(sudo find "$BACKUP_B1/var/lib" -name '*.db'); do sudo sqlite3 -readonly "$db" "PRAGMA integrity_check;"; done | sort | uniq -c
  ```
- **Resultado esperado:** `BACKUP_CREADO=…` con permisos `700`/`600`; integridad
  `ok` en todas las bases; servicios activos al terminar; conteos guardados.
- **Evidencia:** `F15-T01.txt`, `F15-T01-estado-B1.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F15-T02 — Restore completo

- **Objetivo:** volver exactamente al estado de B1 tras haber cambiado datos.
- **Precondición:** después de B1, generar actividad (p. ej. 3 usuarios
  inexistentes y/o un usuario `viewer` nuevo) para que el estado difiera.
- **Comandos:**
  ```bash
  sudo bash /opt/auditoria-system/scripts/restaurar-backup.sh --role central \
    --backup "$BACKUP_B1" 2>&1 | tee "$QA/F15-T02.txt"
  sleep 15
  sudo sqlite3 -readonly "$AUD_DB" "SELECT COUNT(*) FROM events; SELECT COUNT(*) FROM incidents;" | tee -a "$QA/F15-T02.txt"
  sudo sqlite3 -readonly "$CEN_DB" "SELECT COUNT(*) FROM events; SELECT COUNT(*) FROM incidents;" | tee -a "$QA/F15-T02.txt"
  diff <(head -n 4 "$QA/F15-T01-estado-B1.txt") <(tail -n 4 "$QA/F15-T02.txt") && echo "ESTADO == B1"
  sudo stat -c '%a %U:%G %n' /etc/auditoria-system/agent-identity.json /var/lib/auditoria-system/*.db | tee -a "$QA/F15-T02.txt"
  sudo getfacl -cp /var/lib/auditoria-system/notifications.db 2>&1 | tee -a "$QA/F15-T02.txt"
  systemctl is-active auditoria-agent.service auditoria-api.service | tee -a "$QA/F15-T02.txt"
  curl -sS -m 5 http://127.0.0.1:8000/health | tee -a "$QA/F15-T02.txt"
  ```
- **Resultado esperado:** termina con `Backup restaurado y validado correctamente
  para role central.`; los conteos coinciden con B1 (el estado posterior a B1
  desaparece, incluido el usuario nuevo); permisos y ACL idénticos a F05-T04
  (`auditoria-api` sin acceso a `auditoria.db`); servicios activos; `/health` 200;
  el servidor vuelve a `ONLINE` con la misma identidad.
- **Evidencia:** `F15-T02.txt`; captura del dashboard tras el restore.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F15-T03 — Restore rechaza un backup inválido

- **Comandos:**
  ```bash
  sudo bash /opt/auditoria-system/scripts/restaurar-backup.sh --role central --backup /var/backups/auditoria-system/no-existe; echo "exit=$?" | tee "$QA/F15-T03.txt"
  systemctl is-active auditoria-agent.service auditoria-api.service | tee -a "$QA/F15-T03.txt"
  ```
- **Resultado esperado:** error claro, salida distinta de 0 y los servicios
  **siguen activos** (el script valida antes de detenerlos).
- **Evidencia:** `F15-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 16 — Update / rollback

### F16-T01 — Rollback manual a la versión anterior

- **Objetivo:** volver al código **y a los datos** previos a la actualización
  (esquemas v3/v1) con el procedimiento oficial.
- **Precondición:** `BACKUP_PREVIO` y el código anterior
  `/opt/auditoria-system.rollback.<UTC>` de F03-T01 siguen disponibles; los
  datos creados después de F02 se pierden **por diseño**. Cree un backup nuevo
  antes (F15-T01) si desea conservarlos.
- **Comandos:**
  ```bash
  sudo bash <RELEASE_DIR>/scripts/rollback.sh --role central \
    --backup "$BACKUP_PREVIO" \
    --codigo-anterior /opt/auditoria-system.rollback.<UTC> 2>&1 | tee "$QA/F16-T01.txt"
  sed -n 's/^version = "\([^"]*\)"/\1/p' /opt/auditoria-system/pyproject.toml | head -n 1
  ls -d /opt/auditoria-system.fallido.* | tee -a "$QA/F16-T01.txt"
  for db in "$AUD_DB" "$CEN_DB"; do sudo sqlite3 -readonly "$db" "PRAGMA user_version; PRAGMA integrity_check;"; done | tee -a "$QA/F16-T01.txt"
  systemctl is-active auditoria-agent.service auditoria-api.service | tee -a "$QA/F16-T01.txt"
  curl -sS -m 5 http://127.0.0.1:8000/health | tee -a "$QA/F16-T01.txt"
  ```
- **Resultado esperado:** `Rollback completado correctamente.`; versión anterior;
  existe `/opt/auditoria-system.fallido.<UTC>` (código fallido conservado);
  `user_version` de F01-T02 (v3/v1) con `integrity_check = ok`; servicios activos;
  `/health` 200.
- **Evidencia:** `F16-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F16-T02 — Actualizar de nuevo y repetir la migración

- **Objetivo:** demostrar que la actualización es repetible y que la migración
  v3→v5 y v1→v3 funciona también desde una base restaurada.
- **Comandos:** repetir F03-T01 y F04-T01/F04-T02 (guardar como `F16-T02-*.txt`).
- **Resultado esperado:** mismos resultados que F03/F04.
- **Evidencia:** `F16-T02-*.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F16-T03 — Una actualización fallida se revierte sola

- **Objetivo:** si la actualización falla después de reemplazar el código,
  `actualizar.sh` ejecuta el rollback automático.
- **Precondición:** hágalo **solo sobre una copia** de la release (no edite el
  repositorio ni `<RELEASE_DIR>`): `cp -a <RELEASE_DIR> <RELEASE_DIR>-rota`; rompa
  a propósito `requirements.txt` **de la copia** (un paquete inexistente). Backup
  reciente disponible (F15-T01).
- **Comandos:**
  ```bash
  sudo bash <RELEASE_DIR>-rota/scripts/actualizar.sh --role central \
    --source <RELEASE_DIR>-rota 2>&1 | tee "$QA/F16-T03.txt"; echo "exit=${PIPESTATUS[0]}" | tee -a "$QA/F16-T03.txt"
  systemctl is-active auditoria-agent.service auditoria-api.service | tee -a "$QA/F16-T03.txt"
  curl -sS -m 5 http://127.0.0.1:8000/health | tee -a "$QA/F16-T03.txt"
  sed -n 's/^version = "\([^"]*\)"/\1/p' /opt/auditoria-system/pyproject.toml | head -n 1
  ```
  Limpie la copia rota al terminar (`sudo rm -rf <RELEASE_DIR>-rota`).
- **Resultado esperado:** mensaje `La actualización falló; iniciando rollback
  automático.`; salida distinta de 0; al terminar, el código y los datos vuelven
  al estado previo, los servicios están `active` y `/health` responde 200.
- **Evidencia:** `F16-T03.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## FASE 17 — QA final

### F17-T01 — Restablecer la configuración y limpiar

- **Comandos:**
  ```bash
  sudo install -m 0640 -o root -g root /root/agent.env.qa-original /etc/auditoria-system/agent.env
  sudo systemctl restart auditoria-agent.service
  kill "$(cat "$QA/F10-http-pid.txt" 2>/dev/null)" 2>/dev/null; ss -ltn 'sport = :8081' | tee "$QA/F17-T01.txt"
  sudo nft list table inet auditoria_response 2>&1 | tee -a "$QA/F17-T01.txt"
  sudo shred -u /root/agent.env.qa-original   # copia privada con secretos
  ```
- **Resultado esperado:** `agent.env` restaurado a su contenido original; sin
  servicio de prueba escuchando en 8081; sin bloqueos residuales de la QA.
- **Evidencia:** `F17-T01.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F17-T02 — Estado final del sistema

- **Comandos:**
  ```bash
  {
    systemctl is-active auditoria-agent.service auditoria-api.service
    systemctl is-enabled auditoria-agent.service auditoria-api.service
    systemctl --failed --no-legend
    curl -sS -m 5 http://127.0.0.1:8000/health; echo
    for db in "$AUD_DB" "$CEN_DB" "$AUTH_DB" "$NOT_DB"; do echo "== $db"; sudo sqlite3 -readonly "$db" "PRAGMA user_version; PRAGMA integrity_check;"; done
    sudo stat -c '%a %U:%G %n' /etc/auditoria-system/agent-identity.json /etc/auditoria-system/agent.env /var/lib/auditoria-system/*.db
    sudo journalctl -u auditoria-agent.service -u auditoria-api.service --since "-30 min" -p err --no-pager
  } | tee "$QA/F17-T02.txt"
  ```
- **Resultado esperado:** servicios activos y habilitados; `--failed` vacío;
  `/health` 200; `auditoria.db` v5 y `central.db` v3, todas `ok`; permisos
  idénticos a F01-T03; sin errores en el registro.
- **Evidencia:** `F17-T02.txt`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

### F17-T03 — La evidencia del QA no contiene secretos

- **Comandos:**
  ```bash
  grep -rIlE 'RESEND_API_KEY=|BEGIN [A-Z ]*PRIVATE KEY|Bearer [A-Za-z0-9._-]{20,}' "$QA" | tee "$QA/F17-T03.txt"
  find "$QA" -type f ! -name 'SHA256SUMS' -exec sha256sum {} + > "$QA/SHA256SUMS"
  ```
- **Resultado esperado:** `grep` no lista ningún archivo; se genera `SHA256SUMS`
  para trazabilidad. Cualquier coincidencia se redacta **antes** de compartir.
- **Evidencia:** `F17-T03.txt`, `SHA256SUMS`.
- **Resultado:** `[ ] PASS  [ ] FAIL  [ ] NO EJECUTADO`

---

## Criterio final de release

### Clasificación de fallos

Un **FAIL crítico** es cualquiera de los siguientes (bloquea el release):

- `audit_only` o un rechazo modifica el firewall (F07-T01, F08-T03).
- Una acción `assisted` se ejecuta sin aprobación, se ejecuta dos veces o el
  agente no revalida (F08-T02, F08-T04).
- Una IP protegida (trusted admin, sesión SSH, IP local, Tailscale, gateway) es
  bloqueada (F11).
- `TEMPORARY_BLOCK_IP_PORT` bloquea otros puertos u otros orígenes (F10-T01) o
  un bloqueo no expira.
- Pérdida de datos, falla de `integrity_check`, versión de esquema incorrecta o
  error de migración (F04, F15, F16).
- Backup, restore o rollback fallan o dejan el sistema sin servicio (F02, F15,
  F16).
- Pérdida o duplicación de eventos con el central caído (F13).
- Servicio caído, en bucle de reinicios o que no se recupera tras reinicio/reboot
  (F05, F14).
- Un secreto aparece en un registro, evidencia, API o dashboard; permisos más
  abiertos que los especificados (F01-T03, F05-T04, F07-T04, F17-T03).
- Un viewer puede aprobar/rechazar (F06-T03) o la API escucha fuera de
  `127.0.0.1` (F05-T03).

Un FAIL **no crítico** (cosmético, texto, warning justificado) se registra y
requiere decisión del ingeniero, pero no bloquea por sí mismo.

Una prueba **NO EJECUTADO** no es PASS: si es crítica, el release queda
condicionado a ejecutarla o a una **excepción escrita del ingeniero** con su
justificación (por ejemplo, cobertura por pruebas automatizadas en F11-T05).

> **No se recomienda el release `v1.0.0` mientras exista un FAIL crítico o una
> prueba crítica sin ejecutar y sin excepción escrita.**

### Tabla final

Complete una fila por prueba (`PASS`, `FAIL` o `NO EJECUTADO`), enlazando el
archivo de evidencia (en `$QA`). La columna *Observación* documenta cualquier
configuración temporal, desviación o excepción.

| Prueba | PASS/FAIL | Evidencia | Observación |
|---|---|---|---|
| F00-T01 Código a probar identificado | | `F00-T01.txt` | |
| F00-T02 Herramientas del servidor | | `F00-T02.txt` | |
| F00-T03 Acceso y condiciones de seguridad | | `F00-T03.txt` | |
| F01-T01 Servicios y plataforma previos | | `F01-T01.txt` | |
| F01-T02 Esquemas y datos previos | | `F01-T02-*.txt` | |
| F01-T03 Permisos previos | | `F01-T03.txt` | |
| F02-T01 Backup previo | | `F02-T01.txt` | |
| F02-T02 Integridad del backup | | `F02-T02.txt` | |
| F03-T01 Actualización con `actualizar.sh` | | `F03-T01.txt` | |
| F03-T02 Versión y código anterior | | `F03-T02.txt` | |
| F04-T01 Migración `auditoria.db` v3→v4→v5 | | `F04-T01.txt` | |
| F04-T02 Migración `central.db` v1→v2→v3 | | `F04-T02.txt` | |
| F04-T03 Otras bases íntegras | | `F04-T03.txt` | |
| F04-T04 Idempotencia al reiniciar | | `F04-T04.txt` | |
| F05-T01 Servicios activos/habilitados | | `F05-T01.txt` | |
| F05-T02 Registros sin errores | | `F05-T02.txt` | |
| F05-T03 `/health` y vínculo de red | | `F05-T03.txt` | |
| F05-T04 Permisos tras actualizar | | `F05-T04.txt` | |
| F05-T05 Identidad y heartbeat | | `F05-T05.txt` | |
| F05-T06 Registro con token de un solo uso | | capturas | |
| F06-T01 Login, marca y sesión | | `F06-T01.txt` | |
| F06-T02 Navegación y vistas | | `F06-T02.txt` | |
| F06-T03 Viewer sin privilegios | | capturas | |
| F07-T01 audit_only: detección sin firewall | | `F07-T01.txt` | |
| F07-T02 Outbox y sincronización | | `F07-T02.txt` | |
| F07-T03 Incidente y timeline | | `F07-T03.txt` | |
| F07-T04 Evidencia forense | | `F07-T04.txt` | |
| F07-T05 La API no expone archivos | | captura | |
| F08-T01 assisted: pendiente sin firewall | | `F08-T01.txt` | |
| F08-T02 Confirmación y cancelación | | `F08-T02.txt` | |
| F08-T03 Rechazo sin firewall | | `F08-T03.txt` | |
| F08-T04 Aprobación, revalidación y ejecución | | `F08-T04.txt` | |
| F08-T05 Vencimiento de acción | | `F08-T05.txt` | |
| F09-T01 automatic `TEMPORARY_BLOCK_IP` | | `F09-T01.txt` | |
| F09-T02 Idempotencia del bloqueo | | `F09-T02.txt` | |
| F10-T01 `TEMPORARY_BLOCK_IP_PORT` selectivo | | `F10-T01.txt` | |
| F10-T02 Expiración y limpieza | | `F10-T02.txt` | |
| F11-T01 Protección trusted admin | | `F11-T01.txt` | |
| F11-T02 Protección sesión SSH | | `F11-T02.txt` | |
| F11-T03 Protección Tailscale | | `F11-T03.txt` | |
| F11-T04 Protección IP local | | `F11-T04.txt` | |
| F11-T05 Protección gateway | | `F11-T05.txt` | |
| F12-T01 Reincidencia nivel 1 | | `F12-T01.txt` | |
| F12-T02 Reincidencia nivel 2 | | `F12-T02.txt` | |
| F12-T03 Nivel 3 / regreso a nivel 1 | | `F12-T03.txt` | |
| F13-T01 Outbox con central caído | | `F13-T01.txt` | |
| F13-T02 Respuesta local sin central | | `F13-T02.txt` | |
| F14-T01 Reinicio con aprobación pendiente | | `F14-T01.txt` | |
| F14-T02 Reinicio con bloqueo vigente | | `F14-T02.txt` | |
| F14-T03 Cola forense tras interrupción | | `F14-T03.txt` | |
| F14-T04 Reboot real | | `F14-T04-*.txt` | |
| F15-T01 Backup con estado conocido | | `F15-T01*.txt` | |
| F15-T02 Restore completo | | `F15-T02.txt` | |
| F15-T03 Restore rechaza backup inválido | | `F15-T03.txt` | |
| F16-T01 Rollback manual | | `F16-T01.txt` | |
| F16-T02 Re-actualización y migración | | `F16-T02-*.txt` | |
| F16-T03 Rollback automático | | `F16-T03.txt` | |
| F17-T01 Configuración restablecida | | `F17-T01.txt` | |
| F17-T02 Estado final | | `F17-T02.txt` | |
| F17-T03 Evidencia sin secretos | | `F17-T03.txt` | |

### Dictamen

| Campo | Valor |
|---|---|
| Fecha y hora (UTC) | |
| Responsable | |
| `<COMMIT>` probado | |
| FAIL críticos | |
| Pruebas críticas sin ejecutar (con excepción escrita) | |
| Dictamen | `[ ] APTO para v1.0.0`   `[ ] NO APTO` |

### Cobertura de funciones solicitadas

| Función | Pruebas |
|---|---|
| Agente / API / dashboard | F05, F06 |
| Registro / identidad | F05-T05, F05-T06 |
| Outbox / eventos | F07-T02, F13 |
| Correlación / detecciones | F07-T01 |
| Incidentes / timeline | F07-T03, F06-T02 |
| Evidencia forense | F07-T04, F07-T05, F14-T03 |
| Respuesta `audit_only` | F07-T01 |
| Respuesta `assisted`, approve, reject | F08 |
| Respuesta `automatic` | F09, F10 |
| `TEMPORARY_BLOCK_IP` / `TEMPORARY_BLOCK_IP_PORT` | F09, F10 |
| Protecciones (trusted admin, sesión SSH, IP local, gateway, Tailscale) | F11 |
| Reincidencia / escalamiento | F12 |
| Recuperación tras reinicio | F14 |
| Backup / restore | F02, F15 |
| Update / rollback | F03, F16 |
| Migraciones | F04, F16-T02 |
