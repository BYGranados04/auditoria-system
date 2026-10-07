# Nexora

Nexora es una plataforma de auditoría y respuesta defensiva para servidores
Ubuntu. Un agente observa cada host, detecta y correlaciona actividad SSH,
agrupa las detecciones en incidentes y puede aplicar bloqueos temporales con
nftables. Un nodo central recibe los eventos de los agentes y ofrece una API y
un dashboard con autenticación.

**Estado:** v1.0.0, publicada. Notas de la versión en
[docs/release-v1.0.0.md](docs/release-v1.0.0.md).

Los identificadores internos (`auditoria-system`, `auditoria-*.service`,
usuario `auditoria-api`, rutas y variables `AUDITORIA_*`) conservan el nombre
anterior por compatibilidad con v1.0.

## Capacidades

- Monitoreo continuo del host: puertos, usuarios, servicios, archivos
  críticos, estado del firewall y reinicios.
- Detección y correlación de actividad SSH: fuerza bruta, enumeración de
  usuarios y actividad repetida en preautenticación.
- Incidentes defensivos con timeline.
- Modos de respuesta `audit_only`, `assisted` (aprobación o rechazo por un
  `superadmin`) y `automatic`.
- Bloqueo temporal por IP o por IP + puerto con nftables, con escalamiento por
  reincidencia (120 s, 600 s y 3600 s).
- Protección de IPs administrativas, Tailscale, sesiones SSH activas, IPs
  locales y gateway.
- Evidencia forense local, recuperación tras reinicio y reconciliación de
  bloqueos vencidos en cada ciclo.
- Sincronización autenticada de eventos con el central, con outbox y
  reintentos.
- API y dashboard con roles `superadmin` y `viewer`.
- Notificaciones por correo opcionales (Resend), locales a cada nodo.
- Migraciones SQLite, instalación por rol, actualización, backup, restore y
  rollback mediante scripts.

## Límites

- La detección y la respuesta cubren solo SSH. Los bloqueos son temporales; no
  hay bloqueos permanentes.
- La API escucha solo en `127.0.0.1:8000`. El acceso remoto requiere una capa
  de acceso que aporta el operador (proxy o túnel).
- No es antivirus, EDR, SIEM ni escáner de vulnerabilidades. La vigilancia de
  archivos críticos no es un FIM avanzado.
- No incluye multitenancy, Nexora Cloud ni gestión completa de flota. El
  roadmap describe capacidades futuras, no implementadas.

## Arquitectura

| Rol | Servicios | Datos |
|---|---|---|
| `central` | `auditoria-agent.service` (root) y `auditoria-api.service` (`auditoria-api`) | `auditoria.db`, `notifications.db`, `auth.db`, `central.db` |
| `agent` | `auditoria-agent.service` (root) | `auditoria.db`, `notifications.db` |

El agente se registra en el central con un token de un solo uso y recibe una
identidad (`agent_id`) y una credencial propias. Detalle en
[docs/arquitectura.md](docs/arquitectura.md).

## Requisitos

- Ubuntu Server 24.04 LTS (validado en 24.04.5).
- Python 3.12 exacto, con `python3.12-venv`.
- `acl`, `curl` y systemd; `nftables` para ejecutar bloqueos.
- Acceso root para instalar y mantener.

## Instalación rápida

1. Instale los prerrequisitos y copie la release verificada en
   `/opt/auditoria-system`.
2. Prepare el entorno:
   `sudo bash /opt/auditoria-system/scripts/preparar-instalacion.sh`.
3. Instale el rol:
   `sudo bash /opt/auditoria-system/scripts/instalar-servicio.sh --role central`
   (o `--role agent`).
4. En el central, configure `AUDITORIA_CENTRAL_URL`, cree el `superadmin` y
   registre los agentes desde el dashboard.
5. Valide los servicios y, en el central,
   `curl --fail http://127.0.0.1:8000/health`. El check de los scripts se
   considera correcto cuando `curl --fail` termina sin error, es decir, con una
   respuesta HTTP menor que 400; el endpoint responde
   `{"status":"ok","service":"auditoria-system-api"}`.

Guía completa en [docs/instalacion.md](docs/instalacion.md).

### Mantenimiento: puntos clave

- `scripts/actualizar.sh` se ejecuta **desde la release nueva** que se va a
  instalar, y `--source` debe apuntar a esa misma release, fuera de
  `/opt/auditoria-system`. Si no coinciden, el script termina con error. Ver
  [docs/actualizacion.md](docs/actualizacion.md).
- Validación de enlaces simbólicos: `restaurar-backup.sh` (y `rollback.sh`, que
  lo usa) rechaza un backup que sea un enlace simbólico o que contenga alguno.
  Los scripts que instalan código rechazan una release, un `--source` o un
  código anterior que sea un enlace simbólico. `backup.sh` **no** valida enlaces
  simbólicos en los archivos de origen. Ver
  [docs/backup-restore-rollback.md](docs/backup-restore-rollback.md).

## Defaults de seguridad

Una instalación nueva no ejecuta acciones activas:

```dotenv
AUDITORIA_RESPONSE_MODE=audit_only
AUDITORIA_RESPONSE_BLOCK_SCOPE=ip
AUDITORIA_ALLOW_TEMPORARY_IP_BLOCK=false
AUDITORIA_ALLOW_TEMPORARY_IP_PORT_BLOCK=false
AUDITORIA_RESPONSE_ESCALATION_ENABLED=false
AUDITORIA_EVIDENCE_ENABLED=false
```

Antes de habilitar `assisted` o `automatic`, configure
`AUDITORIA_TRUSTED_ADMIN_IPS`. Ver [docs/configuracion.md](docs/configuracion.md)
y [docs/seguridad.md](docs/seguridad.md).

## Documentación

Índice completo: [docs/README.md](docs/README.md).
