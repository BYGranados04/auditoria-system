# Instalación de Nexora v1.0.0

Instalación limpia de los roles `central` y `agent` usando únicamente los
scripts incluidos en la release.

## 1. Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Ubuntu Server 24.04 LTS (validado en 24.04.5 LTS). Los scripts solo comprueban `ID=ubuntu`; otras versiones no están validadas. |
| Python | 3.12 exacto. `preparar-instalacion.sh` lo exige tanto en el sistema como en el entorno virtual. |
| Paquetes | `python3.12`, `python3.12-venv`, `acl`, `curl` y systemd. |
| Firewall | `nftables` (`/usr/sbin/nft`) para ejecutar bloqueos. No hace falta si la respuesta queda en `audit_only`. |
| SSH | El colector lee la unidad `ssh.service` de journald (nombre por defecto en Ubuntu). |
| Privilegios | root para bootstrap, instalación, backup, restore, actualización y rollback. |
| Red | Los agentes deben alcanzar la URL del central configurada en `AUDITORIA_CENTRAL_URL`. |

```bash
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv acl curl
```

Los scripts no descargan código ni eligen ramas: trabajan sobre una copia ya
verificada de la release.

## 2. Colocar la release

```bash
sudo install -d -m 0755 /opt/auditoria-system
# Copie en /opt/auditoria-system el contenido verificado de la release 1.0.0
# (app/, deploy/, scripts/, requirements.txt, pyproject.toml).
```

Antes de copiar, verifique la integridad de la release; por ejemplo, el SHA-256
del paquete o la firma del tag `v1.0.0`, según su procedimiento interno.

## 3. Preparar el entorno de Python

```bash
sudo bash /opt/auditoria-system/scripts/preparar-instalacion.sh
```

El script hace lo siguiente:

- Valida que el sistema sea Ubuntu, que haya Python 3.12 y que la estructura de
  la release sea correcta (sin symlinks).
- Crea `/opt/auditoria-system/.venv` en un directorio temporal y lo mueve al
  terminar. Si ya existe un `.venv` válido, lo conserva.
- Instala las versiones exactas con
  `pip install --no-deps --requirement requirements.txt` y ejecuta `pip check`.
- Valida los imports de la aplicación y `python -m app.agent --help`.

## 4. Instalar el rol

```bash
# Nodo central
sudo bash /opt/auditoria-system/scripts/instalar-servicio.sh --role central

# Nodo agente
sudo bash /opt/auditoria-system/scripts/instalar-servicio.sh --role agent
```

Lo que hace el instalador:

| Acción | Rol |
|---|---|
| Crea `/etc/auditoria-system` (0750), `/var/lib/auditoria-system` (0700) y `/var/log/auditoria-system` (0700). | ambos |
| Crea `/etc/auditoria-system/agent.env` desde `deploy/agent.env.example` con modo 0640, **solo si no existe**. | ambos |
| Instala `auditoria-agent.service`. | ambos |
| Crea el usuario y grupo de sistema `auditoria-api`, sin login y sin home. | central |
| Crea `/var/lib/auditoria-system-auth` y `/var/lib/auditoria-system-central` (0700, `auditoria-api`). | central |
| Inicializa `notifications.db` y aplica ACL para que la API la lea sin poder escribirla. Retira cualquier ACL de la API sobre `auditoria.db`. | central |
| Instala y arranca `auditoria-api.service`. | central |
| Si existe `agent-identity.json`, habilita y arranca el agente; si no, lo habilita sin arrancarlo. | ambos |

Si alguna de las comprobaciones de permisos falla, el instalador termina con
error y no informa éxito.

## 5. Configuración mínima

Edite `/etc/auditoria-system/agent.env` (ver
[configuracion.md](configuracion.md)). En el central, defina la URL con la que
los agentes alcanzarán la API antes de generar tokens:

```bash
sudoedit /etc/auditoria-system/agent.env
# AUDITORIA_CENTRAL_URL=https://central.example
```

La URL debe usar `http` o `https` y no puede contener query, fragmento ni
credenciales. La valida el agente al registrarse.

## 6. Crear el superadmin (central)

El comando es interactivo; la contraseña nunca viaja como argumento:

```bash
sudo runuser -u auditoria-api -- \
  /opt/auditoria-system/.venv/bin/python -m app.auth create-superadmin
```

## 7. Registrar un agente

1. En el dashboard, abra **Servidores → Conectar servidor**. Se genera un token
   de registro de un solo uso, válido 15 minutos, y el comando que hay que
   ejecutar. El agente quedará asociado al usuario que generó el token.
2. En el servidor agente, ejecute el comando mostrado. Tiene esta forma:

```bash
sudo /opt/auditoria-system/.venv/bin/python -m app.agent register \
  --server https://central.example \
  --token REGISTRATION_TOKEN_DE_UN_SOLO_USO
sudo systemctl start auditoria-agent.service
```

El registro crea `/etc/auditoria-system/agent-identity.json` con modo 0600, que
contiene la credencial del agente. Falla si ya existe una identidad. No copie su
contenido a tickets, logs ni repositorios.

El central también puede registrar su propio agente local con el mismo
procedimiento.

## 8. Validación posterior a la instalación

```bash
# Servicios
systemctl is-active auditoria-agent.service
systemctl is-active auditoria-api.service      # solo central
systemctl --failed

# Health (solo central; responde {"status":"ok","service":"auditoria-system-api"})
curl --fail --silent --show-error http://127.0.0.1:8000/health

# Permisos esperados
sudo stat -c '%a %U:%G %n' /etc/auditoria-system/agent.env \
  /etc/auditoria-system/agent-identity.json /var/lib/auditoria-system

# Central: la API lee pero no escribe notifications.db y no lee auditoria.db
sudo getfacl -p /var/lib/auditoria-system/notifications.db
sudo runuser -u auditoria-api -- test -r /var/lib/auditoria-system/notifications.db && echo "lectura OK"
sudo runuser -u auditoria-api -- test -r /var/lib/auditoria-system/auditoria.db || echo "auditoria.db protegida"
```

Integridad de las bases, en lectura (ejemplo para `auditoria.db`):

```bash
sudo /opt/auditoria-system/.venv/bin/python -c \
  'import sqlite3; c=sqlite3.connect("file:/var/lib/auditoria-system/auditoria.db?mode=ro", uri=True); print(c.execute("PRAGMA integrity_check").fetchone())'
```

Finalmente, inicie sesión en el dashboard y compruebe que el agente aparece en
**Servidores** con presencia «en línea» después de su primer heartbeat
(30 segundos por defecto).

## 9. Lista de comprobación

Central:

- [ ] `preparar-instalacion.sh` termina con `pip check` e imports correctos.
- [ ] `AUDITORIA_CENTRAL_URL` configurada antes de generar tokens.
- [ ] `superadmin` creado con la CLI interactiva.
- [ ] `auditoria-api.service` y `auditoria-agent.service` activos.
- [ ] `/health` responde y las cuatro bases pasan `PRAGMA integrity_check`.
- [ ] La API lee pero no escribe `notifications.db` y no lee `auditoria.db`.
- [ ] El dashboard permite iniciar sesión y muestra el agente por su
      `agent_id`.

Agente:

- [ ] No existen `auditoria-api.service`, `auth.db` ni `central.db`.
- [ ] Token de registro generado por el usuario propietario correcto y usado
      una sola vez.
- [ ] `agent-identity.json` con `0600` root; no se imprime.
- [ ] `auditoria-agent.service` habilitado y activo.
- [ ] El heartbeat actualiza la presencia en el central.
- [ ] Un evento controlado llega al central y el outbox queda sin pendientes
      (comando D5 de [troubleshooting.md](troubleshooting.md#d5-estado-del-outbox-solo-lectura)).

En ambos roles: `systemctl --failed` vacío.

## Siguientes pasos

- [configuracion.md](configuracion.md): variables y valores seguros.
- [operacion.md](operacion.md): operación diaria.
- [seguridad.md](seguridad.md): modelo de permisos y confianza.
