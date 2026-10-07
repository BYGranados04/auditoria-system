# Seguridad de Nexora v1.0.0

Este documento describe los controles de seguridad que **existen en el código y
en los archivos de despliegue** de la versión 1.0.0, y sus límites. Nexora no
cuenta con certificaciones ni auditorías externas, y este documento no ofrece
garantías: describe el diseño verificado en el repositorio.

## 1. Modelo de confianza

| Componente | Confía en | No confía en |
|---|---|---|
| Agente (root) | Su configuración en `/etc/auditoria-system/`, su base `auditoria.db`, journald del host. | Contenido de los logs SSH (se valida y normaliza), respuestas del central (se validan antes de ejecutar). |
| API central (`auditoria-api`) | `auth.db`, `central.db`, la credencial presentada por cada agente. | Navegador (sesión + CSRF + verificación de origen), agentes (cada uno solo actúa sobre sus propios datos). |
| Operador `superadmin` | Puede aprobar o rechazar acciones y gestionar usuarios. | — |
| Operador `viewer` | Solo lectura sobre los agentes de los que es propietario. | — |

Supuestos del modelo:

- Quien tiene root en un host controla por completo su agente, su base y su
  evidencia. Nexora no protege contra un administrador del propio host.
- El central es el punto de autoridad para aprobaciones en modo `assisted`.
  El agente consulta las acciones aprobadas y vuelve a validar protecciones y
  vigencia antes de ejecutar (ver
  [respuesta-defensiva.md](respuesta-defensiva.md)).
- La capa de acceso remoto a la API (proxy o túnel) la aporta y protege el
  operador; Nexora no la instala.

## 2. Mínimo privilegio

### Agente (`auditoria-agent.service`)

Se ejecuta como `root` porque necesita leer journald y aplicar reglas nftables.
La unidad limita el resto:

- `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `UMask=0077`;
- `ProtectSystem=strict` con escritura solo en `/var/lib/auditoria-system` y
  `/var/log/auditoria-system`;
- `ProtectHome`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`,
  `ProtectHostname`;
- `RestrictNamespaces`, `RestrictSUIDSGID`, `RestrictRealtime`,
  `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`.

La unidad del agente no define `CapabilityBoundingSet`: conserva las
capacidades de root que no restringen las opciones anteriores.

### API (`auditoria-api.service`, solo central)

- Usuario y grupo de sistema `auditoria-api`, sin home (`/nonexistent`) y con
  shell `/usr/sbin/nologin`.
- `CapabilityBoundingSet=` y `AmbientCapabilities=` vacíos.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
- `IPAddressDeny=any` e `IPAddressAllow=localhost`: el servicio solo intercambia
  tráfico con localhost.
- Escucha en `127.0.0.1:8000` con un worker y sin access log.
- Mismas protecciones de sistema de archivos que el agente
  (`ProtectSystem=strict`, etc.), con `StateDirectory` para
  `auditoria-system-auth` y `auditoria-system-central` en modo `0700`.

## 3. Permisos de archivos

| Ruta | Propietario | Modo | Notas |
|---|---|---|---|
| `/etc/auditoria-system/` | root | `0750` | |
| `/etc/auditoria-system/agent.env` | root | `0640` | Lo lee systemd al arrancar los servicios. Puede contener secretos. |
| `/etc/auditoria-system/agent-identity.json` | root | `0600` | Credencial del agente. No se sobrescribe si ya existe. |
| `/var/lib/auditoria-system/` | root | `0700` | En el central, ACL `u:auditoria-api:--x` (solo travesía). |
| `/var/lib/auditoria-system/notifications.db` | root | no fijado por los scripts | En el central, ACL `u:auditoria-api:r--`. El directorio `0700` limita el acceso. |
| `/var/lib/auditoria-system/auditoria.db` | root | `0600` si la crea el agente (`UMask=0077`) | La API **no** debe poder leerla; la instalación retira una ACL histórica si existe. |
| `/var/lib/auditoria-system/evidence/` | root | `0700` | Archivos `0600`. |
| `/var/lib/auditoria-system-auth/` | auditoria-api | `0700` | `auth.db`. |
| `/var/lib/auditoria-system-central/` | auditoria-api | `0700` | `central.db`. |
| `/var/log/auditoria-system/` | root | `0700` | `events.jsonl`. |
| Copias de bases en backups | root | `0600` | |

`instalar-servicio.sh --role central` comprueba con `runuser` que la API puede
leer pero no escribir `notifications.db` y que no puede leer `auditoria.db`; si
no se cumple, la instalación falla. Validación manual en
[instalacion.md](instalacion.md#8-validación-posterior-a-la-instalación).

## 4. Secretos

| Secreto | Dónde vive | Cómo se protege |
|---|---|---|
| Contraseñas de usuarios | `auth.db` | Hash scrypt (`n=2^15`, `r=8`, `p=3`). Mínimo 8 caracteres. |
| Tokens de sesión y CSRF | Cookies `auditoria_session` / `auditoria_csrf` | En base solo se guarda su digest SHA-256. Cookies `SameSite=Strict`. |
| Token de registro (`reg_…`) | `auth.db` (digest) | Un solo uso, válido 15 minutos. |
| Credencial de agente (`agc_…`) | `agent-identity.json` (agente) y digest en `auth.db` | Archivo `0600`; se envía como `Authorization: Bearer`. |
| Clave de Resend | `agent.env` (`AUDITORIA_RESEND_API_KEY`) | Archivo `0640` root. |

Recomendaciones:

- No copie `agent.env` ni `agent-identity.json` fuera del host salvo en backups
  protegidos (los backups los incluyen; ver
  [backup-restore-rollback.md](backup-restore-rollback.md)).
- Active `AUDITORIA_AUTH_COOKIE_SECURE=true` cuando el acceso al dashboard sea
  por HTTPS. El default es `false`.
- No pegue tokens ni credenciales en tickets, chats o capturas.

## 5. Identidad del agente

1. Un usuario autenticado genera un token de registro de un solo uso.
2. El agente lo canjea en `POST /agent/enroll` y recibe `agent_id` (`agt_…`) y
   una credencial (`agc_…`), que guarda en `agent-identity.json`.
3. Cada llamada posterior del agente (heartbeat, lote de eventos, consulta de
   acciones aprobadas) usa esa credencial.
4. El agente queda asociado al usuario que generó el token (`owner_user_id`),
   lo que determina la visibilidad para los `viewer`.

El central asocia los eventos al `agent_id` de la credencial, no al contenido
enviado por el agente. La tabla `agent_credentials` tiene una columna
`revoked_at` que se respeta al autenticar, pero v1.0.0 no ofrece ruta HTTP ni
CLI para revocar o rotar credenciales.

## 6. Autenticación y autorización web

- Roles existentes: `superadmin` y `viewer`. No hay otros roles.
- Las operaciones que cambian estado requieren sesión, token CSRF
  (`X-CSRF-Token` igual a la cookie) y verificación de `Origin`/`Referer` frente
  a la URL base de la petición.
- Aprobar o rechazar acciones y administrar usuarios requiere `superadmin`.
- Un `viewer` solo ve datos de los agentes de los que es propietario.
- No se encontró en el código limitación de intentos de inicio de sesión ni
  bloqueo de cuentas. Si el dashboard es accesible desde una red no confiable,
  aplique esa protección en la capa de acceso.

## 7. Red y Tailscale

- La API no se expone fuera de localhost. El acceso remoto requiere una capa de
  acceso del operador, y los agentes necesitan una `AUDITORIA_CENTRAL_URL`
  alcanzable.
- Nexora no instala, configura ni supervisa Tailscale. Su relación con
  Tailscale se limita a:
  - no bloquear direcciones de `100.64.0.0/10` ni `fd7a:115c:a1e0::/48`;
  - no descartar tráfico que entra por la interfaz `tailscale0`.
- Si el central se alcanza por Tailscale y el túnel cae, los agentes acumulan
  eventos en su outbox y reintentan (ver [troubleshooting.md](troubleshooting.md)).

## 8. Protección administrativa y respuesta activa

- Instalación nueva: modo `audit_only`, sin acciones activas, sin
  escalamiento y sin evidencia (ver
  [configuracion.md](configuracion.md#2-valores-seguros-de-una-instalación-nueva)).
- Antes de habilitar `assisted` o `automatic`, configure
  `AUDITORIA_TRUSTED_ADMIN_IPS` con las IP desde las que administra. Es la
  única protección determinista configurable.
- Las protecciones dinámicas (sesión SSH, IP local, gateway) se calculan al
  ejecutar y son *fail-open* si `psutil` no puede leer el sistema. Detalle en
  [respuesta-defensiva.md](respuesta-defensiva.md#5-protecciones).
- Una IP inválida en `AUDITORIA_TRUSTED_ADMIN_IPS` (incluido un CIDR) impide
  arrancar el agente: falla de forma visible, no silenciosa.

## 9. nftables

- Nexora solo gestiona la tabla `inet auditoria_response`. No modifica UFW ni
  otras tablas.
- Cada bloqueo es temporal (60–86400 s) y lo retira el kernel al vencer.
- `nft` se invoca sin shell, con timeout, y cada cambio se valida con `--check`.
- Revisión de solo lectura:

```bash
sudo nft list table inet auditoria_response
```

## 10. Evidencia

- Se captura solo si `AUDITORIA_EVIDENCE_ENABLED=true` y solo para detecciones
  de severidad alta o crítica.
- Se guarda localmente con permisos `0700`/`0600`, con redacción de patrones de
  secretos; la redacción es heurística y no garantiza eliminar todo dato
  sensible.
- Al central solo llegan metadatos. Los archivos no forman parte de
  `backup.sh`.

Detalle en [incidentes-y-evidencia.md](incidentes-y-evidencia.md).

## 11. Limitaciones conocidas

- La detección cubre solo SSH (`ssh.service` en journald). No hay escaneo de
  vulnerabilidades, FIM avanzado, multitenancy ni gestión completa de flota.
- Las protecciones dinámicas son *fail-open* si `psutil` falla.
- `GET /status` devuelve `null` en `response_mode`,
  `automatic_blocking_enabled` y `live_response_blocks`.
- Sin limitación de intentos de login en la aplicación.
- Sin ruta ni CLI para revocar o rotar credenciales de agente.
- La evidencia forense no se incluye en los backups.
- Las cookies no llevan `Secure` salvo que se active
  `AUDITORIA_AUTH_COOKIE_SECURE`.
- La redacción de secretos en evidencia es por patrones.

## Documentos relacionados

- [arquitectura.md](arquitectura.md)
- [configuracion.md](configuracion.md)
- [referencia-tecnica.md](referencia-tecnica.md)
