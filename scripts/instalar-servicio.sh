#!/usr/bin/env bash

set -euo pipefail
umask 0077

ROL=""

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo ./scripts/instalar-servicio.sh --role central
  sudo ./scripts/instalar-servicio.sh --role agent
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            if [[ $# -lt 2 ]]; then
                echo "Error: --role requiere un valor." >&2
                mostrar_uso >&2
                exit 2
            fi
            ROL="$2"
            shift 2
            ;;
        -h|--help)
            mostrar_uso
            exit 0
            ;;
        *)
            echo "Error: argumento no reconocido: $1" >&2
            mostrar_uso >&2
            exit 2
            ;;
    esac
done

if [[ "${ROL}" != "central" && "${ROL}" != "agent" ]]; then
    echo "Error: debe indicar --role central o --role agent." >&2
    mostrar_uso >&2
    exit 2
fi

RAIZ_PROYECTO="/opt/auditoria-system"
DIRECTORIO_CONFIG="/etc/auditoria-system"
DIRECTORIO_ESTADO="/var/lib/auditoria-system"
DIRECTORIO_AUTH="/var/lib/auditoria-system-auth"
DIRECTORIO_CENTRAL="/var/lib/auditoria-system-central"
DIRECTORIO_LOG="/var/log/auditoria-system"
ARCHIVO_IDENTIDAD="${DIRECTORIO_CONFIG}/agent-identity.json"

SERVICIO_AGENTE_ORIGEN="${RAIZ_PROYECTO}/deploy/systemd/auditoria-agent.service"
SERVICIO_AGENTE_DESTINO="/etc/systemd/system/auditoria-agent.service"

CONFIG_ORIGEN="${RAIZ_PROYECTO}/deploy/agent.env.example"
CONFIG_DESTINO="${DIRECTORIO_CONFIG}/agent.env"

SERVICIO_API_ORIGEN="${RAIZ_PROYECTO}/deploy/systemd/auditoria-api.service"
SERVICIO_API_DESTINO="/etc/systemd/system/auditoria-api.service"

USUARIO_API="auditoria-api"
GRUPO_API="auditoria-api"
BASE_DATOS="${DIRECTORIO_ESTADO}/auditoria.db"
BASE_DATOS_NOTIFICACIONES="${DIRECTORIO_ESTADO}/notifications.db"
BASE_DATOS_AUTH="${DIRECTORIO_AUTH}/auth.db"
BASE_DATOS_CENTRAL="${DIRECTORIO_CENTRAL}/central.db"
LIB_OPERACIONES="${RAIZ_PROYECTO}/scripts/lib/operaciones-comunes.sh"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: este instalador debe ejecutarse como root." >&2
    exit 1
fi

if [[ ! -f "${LIB_OPERACIONES}" ]]; then
    echo "Error: no existe ${LIB_OPERACIONES}." >&2
    exit 1
fi

# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${LIB_OPERACIONES}"
validar_entrypoints_rol "${RAIZ_PROYECTO}" "${ROL}"

if [[ ! -x "${RAIZ_PROYECTO}/.venv/bin/python" ]]; then
    echo "Error: no existe el entorno virtual esperado." >&2
    exit 1
fi

if [[ ! -f "${SERVICIO_AGENTE_ORIGEN}" ]]; then
    echo "Error: no existe ${SERVICIO_AGENTE_ORIGEN}." >&2
    exit 1
fi

if [[ ! -f "${CONFIG_ORIGEN}" ]]; then
    echo "Error: no existe ${CONFIG_ORIGEN}." >&2
    exit 1
fi

if [[ "${ROL}" == "central" ]]; then
    if [[ ! -x "${RAIZ_PROYECTO}/.venv/bin/uvicorn" ]]; then
        echo "Error: uvicorn no está disponible en el entorno virtual." >&2
        exit 1
    fi

    if [[ ! -f "${SERVICIO_API_ORIGEN}" ]]; then
        echo "Error: no existe ${SERVICIO_API_ORIGEN}." >&2
        exit 1
    fi

    for comando in setfacl getfacl runuser; do
        if ! command -v "${comando}" >/dev/null 2>&1; then
            echo "Error: falta el comando requerido: ${comando}." >&2
            exit 1
        fi
    done
fi

install -d -m 0750 "${DIRECTORIO_CONFIG}"
install -d -m 0700 "${DIRECTORIO_ESTADO}"
install -d -m 0700 "${DIRECTORIO_LOG}"

if [[ ! -f "${CONFIG_DESTINO}" ]]; then
    install -m 0640 "${CONFIG_ORIGEN}" "${CONFIG_DESTINO}"
    echo "Configuración creada: ${CONFIG_DESTINO}"
else
    echo "Configuración existente conservada: ${CONFIG_DESTINO}"
fi

install -m 0644 "${SERVICIO_AGENTE_ORIGEN}" "${SERVICIO_AGENTE_DESTINO}"

if [[ "${ROL}" == "central" ]]; then
    install -m 0644 "${SERVICIO_API_ORIGEN}" "${SERVICIO_API_DESTINO}"
fi

if [[ "${ROL}" == "central" ]]; then
    if ! getent group "${GRUPO_API}" >/dev/null; then
        groupadd --system "${GRUPO_API}"
        echo "Grupo creado: ${GRUPO_API}"
    else
        echo "Grupo existente conservado: ${GRUPO_API}"
    fi

    if ! getent passwd "${USUARIO_API}" >/dev/null; then
        useradd \
            --system \
            --gid "${GRUPO_API}" \
            --no-create-home \
            --home-dir /nonexistent \
            --shell /usr/sbin/nologin \
            "${USUARIO_API}"

        echo "Usuario creado: ${USUARIO_API}"
    else
        echo "Usuario existente conservado: ${USUARIO_API}"
    fi

    install -d -o "${USUARIO_API}" -g "${GRUPO_API}" -m 0700 \
        "${DIRECTORIO_AUTH}" "${DIRECTORIO_CENTRAL}"

    for directorio in "${DIRECTORIO_AUTH}" "${DIRECTORIO_CENTRAL}"; do
        if ! runuser -u "${USUARIO_API}" -- test -w "${directorio}"; then
            echo "Error: ${USUARIO_API} no puede escribir en ${directorio}." >&2
            exit 1
        fi
    done

    (
        cd "${RAIZ_PROYECTO}"
        AUDITORIA_INSTALL_NOTIFICATIONS_DB="${BASE_DATOS_NOTIFICACIONES}" \
            "${RAIZ_PROYECTO}/.venv/bin/python" -c \
            'import os; from pathlib import Path; from app.notifications.repository import NotificationRepository; NotificationRepository(Path(os.environ["AUDITORIA_INSTALL_NOTIFICATIONS_DB"])).initialize()'
    )

    setfacl -m "u:${USUARIO_API}:--x" "${DIRECTORIO_ESTADO}"
    setfacl -m "u:${USUARIO_API}:r--" "${BASE_DATOS_NOTIFICACIONES}"

    if [[ -f "${BASE_DATOS}" ]] && \
        getfacl -cp "${BASE_DATOS}" | grep -q "^user:${USUARIO_API}:"; then
        setfacl -x "u:${USUARIO_API}" "${BASE_DATOS}"
        echo "ACL histórica retirada de ${BASE_DATOS}"
    fi

    if ! runuser -u "${USUARIO_API}" -- test -r \
        "${BASE_DATOS_NOTIFICACIONES}"; then
        echo "Error: ${USUARIO_API} no puede leer ${BASE_DATOS_NOTIFICACIONES}." >&2
        exit 1
    fi

    if runuser -u "${USUARIO_API}" -- test -w \
        "${BASE_DATOS_NOTIFICACIONES}"; then
        echo "Error: ${USUARIO_API} puede escribir ${BASE_DATOS_NOTIFICACIONES}." >&2
        exit 1
    fi

    if [[ -f "${BASE_DATOS}" ]] && \
        runuser -u "${USUARIO_API}" -- test -r "${BASE_DATOS}"; then
        echo "Error: ${USUARIO_API} todavía puede leer ${BASE_DATOS}." >&2
        exit 1
    fi
fi

systemctl daemon-reload

if [[ -f "${ARCHIVO_IDENTIDAD}" ]]; then
    systemctl enable --now auditoria-agent.service

    if ! systemctl --quiet is-active auditoria-agent.service; then
        echo "Error: auditoria-agent.service no está activo." >&2
        exit 1
    fi
else
    systemctl enable auditoria-agent.service
    echo "Agente instalado sin iniciar: falta ${ARCHIVO_IDENTIDAD}."
    echo "Registre el agente y luego inicie auditoria-agent.service."
fi

if [[ "${ROL}" == "central" ]]; then
    systemctl enable --now auditoria-api.service

    if ! systemctl --quiet is-active auditoria-api.service; then
        echo "Error: auditoria-api.service no está activo." >&2
        exit 1
    fi
fi

echo
echo "Nexora instalado correctamente (${ROL})."
echo "Configuración: ${CONFIG_DESTINO}"
echo "Estado:        ${DIRECTORIO_ESTADO}"
echo "Logs:          ${DIRECTORIO_LOG}"
echo "Agente:        auditoria-agent.service"

if [[ "${ROL}" == "central" ]]; then
    echo "Autenticación: ${BASE_DATOS_AUTH}"
    echo "Eventos centralizados: ${BASE_DATOS_CENTRAL}"
    echo "Notificaciones: ${BASE_DATOS_NOTIFICACIONES} (API: solo lectura)"
    echo "API local:     http://127.0.0.1:8000"
    echo "Usuario API:   ${USUARIO_API}"
    echo "Crear superadmin (sin contraseña por argumentos):"
    echo "  runuser -u ${USUARIO_API} -- ${RAIZ_PROYECTO}/.venv/bin/python -m app.auth create-superadmin"
fi
