#!/usr/bin/env bash

RAIZ_INSTALACION="/opt/auditoria-system"
DIRECTORIO_CONFIG="/etc/auditoria-system"
DIRECTORIO_ESTADO="/var/lib/auditoria-system"
DIRECTORIO_AUTH="/var/lib/auditoria-system-auth"
DIRECTORIO_CENTRAL="/var/lib/auditoria-system-central"
USUARIO_API="auditoria-api"

error() {
    echo "Error: $*" >&2
    return 1
}

requerir_root() {
    [[ "${EUID}" -eq 0 ]] || error "esta operación debe ejecutarse como root."
}

validar_ubuntu() {
    [[ -r /etc/os-release ]] || error "no se pudo identificar el sistema operativo."
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || error "la plataforma soportada es Ubuntu."
}

validar_rol() {
    [[ "$1" == "central" || "$1" == "agent" ]] || \
        error "el role debe ser central o agent."
}

requerir_comando() {
    command -v "$1" >/dev/null 2>&1 || error "falta el comando requerido: $1."
}

validar_entrypoints_rol() {
    local raiz="$1"
    local rol="$2"

    [[ -f "${raiz}/app/agent/__main__.py" && \
       ! -L "${raiz}/app/agent/__main__.py" ]] || {
        error "falta el entrypoint requerido: app/agent/__main__.py."
        return 1
    }

    if [[ "${rol}" == "central" ]]; then
        [[ -f "${raiz}/app/api/main.py" && \
           ! -L "${raiz}/app/api/main.py" ]] || {
            error "falta el entrypoint requerido: app/api/main.py."
            return 1
        }
    fi
}

validar_estructura_release() {
    local raiz="$1"
    local requerido

    [[ -d "${raiz}" && ! -L "${raiz}" ]] || {
        error "la release no es un directorio válido: ${raiz}."
        return 1
    }

    for requerido in \
        app app/agent app/api deploy deploy/systemd scripts scripts/lib; do
        [[ -d "${raiz}/${requerido}" && ! -L "${raiz}/${requerido}" ]] || {
            error "la release no contiene el directorio ${requerido}/."
            return 1
        }
    done

    for requerido in \
        deploy/systemd/auditoria-agent.service \
        deploy/systemd/auditoria-api.service \
        scripts/lib/operaciones-comunes.sh \
        scripts/preparar-instalacion.sh \
        scripts/instalar-servicio.sh \
        scripts/restaurar-backup.sh \
        scripts/rollback.sh \
        requirements.txt \
        pyproject.toml; do
        [[ -f "${raiz}/${requerido}" && ! -L "${raiz}/${requerido}" ]] || {
            error "la release no contiene el archivo ${requerido}."
            return 1
        }
    done

    validar_entrypoints_rol "${raiz}" central
}

validar_destino_fuera_instalacion() {
    local destino="$1"
    local destino_resuelto
    local instalacion_resuelta

    destino_resuelto="$(readlink -m -- "${destino}")" || \
        error "no se pudo resolver la ruta de destino."
    instalacion_resuelta="$(readlink -m -- "${RAIZ_INSTALACION}")" || \
        error "no se pudo resolver la ruta de instalación."
    [[ "${destino_resuelto}" != "${instalacion_resuelta}" && \
       "${destino_resuelto}" != "${instalacion_resuelta}"/* ]] || \
        error "el destino de backup debe estar fuera de ${RAIZ_INSTALACION}."
}

python_instalado() {
    local python="${RAIZ_INSTALACION}/.venv/bin/python"
    [[ -x "${python}" ]] || error "no existe el Python instalado en ${python}."
    printf '%s\n' "${python}"
}

servicios_del_rol() {
    if [[ "$1" == "central" ]]; then
        printf '%s\n' auditoria-agent.service auditoria-api.service
    else
        printf '%s\n' auditoria-agent.service
    fi
}

servicios_para_inicio() {
    if [[ "$1" == "central" ]]; then
        printf '%s\n' auditoria-api.service auditoria-agent.service
    else
        printf '%s\n' auditoria-agent.service
    fi
}

servicios_activos() {
    local servicio
    for servicio in "$@"; do
        if systemctl --quiet is-active "${servicio}"; then
            printf '%s\n' "${servicio}"
        fi
    done
}

detener_servicios() {
    local servicio
    for servicio in "$@"; do
        if systemctl --quiet is-active "${servicio}"; then
            systemctl stop "${servicio}"
        fi
    done
}

iniciar_servicios() {
    local servicio
    for servicio in "$@"; do
        systemctl start "${servicio}"
    done
}

comprobar_servicios_activos() {
    local servicio
    for servicio in "$@"; do
        systemctl --quiet is-active "${servicio}" || \
            error "${servicio} no está activo."
    done
}

comprobar_health() {
    local intento
    for intento in {1..15}; do
        if curl --fail --silent --max-time 3 \
            http://127.0.0.1:8000/health >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    curl --fail --silent --show-error --max-time 3 \
        http://127.0.0.1:8000/health >/dev/null || true
    error "la API no respondió correctamente en /health."
}

comprobar_integridad_sqlite() {
    local python="$1"
    local database="$2"
    "${python}" - "${database}" <<'PY'
import sqlite3
import sys

database = sys.argv[1]
with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
    result = connection.execute("PRAGMA integrity_check").fetchone()
if result != ("ok",):
    raise SystemExit(f"integrity_check falló para {database}")
PY
}

limpiar_sidecars_sqlite() {
    local database="$1"
    rm -f -- "${database}-wal" "${database}-shm" "${database}-journal"
}

respaldar_sqlite() {
    local python="$1"
    local origen="$2"
    local destino="$3"
    "${python}" - "${origen}" "${destino}" <<'PY'
import sqlite3
import sys

source_path, destination_path = sys.argv[1:]
with sqlite3.connect(f"file:{source_path}?mode=ro", uri=True) as source:
    with sqlite3.connect(destination_path) as destination:
        source.backup(destination)
        result = destination.execute("PRAGMA integrity_check").fetchone()
if result != ("ok",):
    raise SystemExit(f"integrity_check falló para {destination_path}")
PY
    chmod 0600 "${destino}"
}

valor_metadata() {
    local archivo="$1"
    local clave="$2"
    awk -F= -v clave="${clave}" '$1 == clave {print substr($0, index($0, "=") + 1)}' \
        "${archivo}"
}

validar_backup() {
    local rol="$1"
    local backup="$2"
    local metadata="${backup}/metadata.env"

    [[ -d "${backup}" && ! -L "${backup}" ]] || \
        error "la ruta de backup no es un directorio válido."
    if find "${backup}" -type l -print -quit | grep -q .; then
        error "el backup contiene enlaces simbólicos no permitidos."
    fi
    [[ -f "${metadata}" ]] || error "el backup no contiene metadata.env."
    [[ "$(valor_metadata "${metadata}" FORMATO)" == "1" ]] || \
        error "formato de backup no soportado."
    [[ "$(valor_metadata "${metadata}" ROLE)" == "${rol}" ]] || \
        error "el role del backup no coincide con el solicitado."
    [[ -f "${backup}/etc/auditoria-system/agent.env" ]] || \
        error "el backup no contiene agent.env."
    [[ -f "${backup}/etc/auditoria-system/agent-identity.json" ]] || \
        error "el backup no contiene agent-identity.json."
    [[ -f "${backup}/var/lib/auditoria-system/auditoria.db" ]] || \
        error "el backup no contiene auditoria.db."

    if [[ "${rol}" == "central" ]]; then
        [[ -f "${backup}/var/lib/auditoria-system-auth/auth.db" ]] || \
            error "el backup no contiene auth.db."
        [[ -f "${backup}/var/lib/auditoria-system-central/central.db" ]] || \
            error "el backup no contiene central.db."
    fi
}

copiar_codigo_release() {
    local origen="$1"
    local destino="$2"

    validar_estructura_release "${origen}"
    [[ ! -e "${destino}" ]] || error "el destino ya existe: ${destino}."

    install -d -m 0755 "${destino}"
    tar -C "${origen}" \
        --exclude='__pycache__' --exclude='*.pyc' --exclude='.venv' \
        -cf - app deploy scripts requirements.txt pyproject.toml | \
        tar -C "${destino}" -xf -
}
