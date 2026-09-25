#!/usr/bin/env bash

set -euo pipefail

RAIZ_PROYECTO="/opt/auditoria-system"
DIRECTORIO_CONFIG="/etc/auditoria-system"
DIRECTORIO_ESTADO="/var/lib/auditoria-system"
DIRECTORIO_LOG="/var/log/auditoria-system"

SERVICIO_ORIGEN="${RAIZ_PROYECTO}/deploy/systemd/auditoria-agent.service"
SERVICIO_DESTINO="/etc/systemd/system/auditoria-agent.service"

CONFIG_ORIGEN="${RAIZ_PROYECTO}/deploy/agent.env.example"
CONFIG_DESTINO="${DIRECTORIO_CONFIG}/agent.env"

SERVICIO_API_ORIGEN="${RAIZ_PROYECTO}/deploy/systemd/auditoria-api.service"
SERVICIO_API_DESTINO="/etc/systemd/system/auditoria-api.service"

USUARIO_API="auditoria-api"
GRUPO_API="auditoria-api"
BASE_DATOS="${DIRECTORIO_ESTADO}/auditoria.db"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: este instalador debe ejecutarse como root." >&2
    exit 1
fi

if [[ ! -x "${RAIZ_PROYECTO}/.venv/bin/python" ]]; then
    echo "Error: no existe el entorno virtual esperado." >&2
    exit 1
fi

if [[ ! -x "${RAIZ_PROYECTO}/.venv/bin/uvicorn" ]]; then
    echo "Error: uvicorn no está disponible en el entorno virtual." >&2
    exit 1
fi

for comando in setfacl getfacl runuser; do
    if ! command -v "${comando}" >/dev/null 2>&1; then
        echo "Error: falta el comando requerido: ${comando}." >&2
        exit 1
    fi
done

if [[ ! -f "${SERVICIO_ORIGEN}" ]]; then
    echo "Error: no existe ${SERVICIO_ORIGEN}." >&2
    exit 1
fi

if [[ ! -f "${SERVICIO_API_ORIGEN}" ]]; then
    echo "Error: no existe ${SERVICIO_API_ORIGEN}." >&2
    exit 1
fi

if [[ ! -f "${CONFIG_ORIGEN}" ]]; then
    echo "Error: no existe ${CONFIG_ORIGEN}." >&2
    exit 1
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

install -m 0644 "${SERVICIO_ORIGEN}" "${SERVICIO_DESTINO}"
install -m 0644 "${SERVICIO_API_ORIGEN}" "${SERVICIO_API_DESTINO}"

if ! getent group "${GRUPO_API}" >/dev/null; then
    groupadd --system "${GRUPO_API}"
    echo "Grupo creado: ${GRUPO_API}"
else
    echo "Grupo existente conservado: ${GRUPO_API}"
fi

if ! getent passwd "${USUARIO_API}" >/dev/null; then
    useradd         --system         --gid "${GRUPO_API}"         --no-create-home         --home-dir /nonexistent         --shell /usr/sbin/nologin         "${USUARIO_API}"

    echo "Usuario creado: ${USUARIO_API}"
else
    echo "Usuario existente conservado: ${USUARIO_API}"
fi

systemctl daemon-reload

systemctl enable --now auditoria-agent.service

for intento in {1..30}; do
    if [[ -f "${BASE_DATOS}" ]]; then
        break
    fi

    if [[ "${intento}" -eq 30 ]]; then
        echo "Error: ${BASE_DATOS} no apareció después de 30 segundos." >&2
        exit 1
    fi

    sleep 1
done

setfacl     -m "u:${USUARIO_API}:--x"     "${DIRECTORIO_ESTADO}"

setfacl     -m "u:${USUARIO_API}:r--"     "${BASE_DATOS}"

if ! runuser -u "${USUARIO_API}" -- test -r "${BASE_DATOS}"; then
    echo "Error: ${USUARIO_API} no puede leer ${BASE_DATOS}." >&2
    exit 1
fi

if runuser -u "${USUARIO_API}" -- test -w "${BASE_DATOS}"; then
    echo "Error: ${USUARIO_API} puede escribir ${BASE_DATOS}." >&2
    exit 1
fi

systemctl enable --now auditoria-api.service

if ! systemctl --quiet is-active auditoria-agent.service; then
    echo "Error: auditoria-agent.service no está activo." >&2
    exit 1
fi

if ! systemctl --quiet is-active auditoria-api.service; then
    echo "Error: auditoria-api.service no está activo." >&2
    exit 1
fi

echo
echo "Auditoria System instalado correctamente."
echo "Configuración: ${CONFIG_DESTINO}"
echo "Estado:        ${DIRECTORIO_ESTADO}"
echo "Logs:          ${DIRECTORIO_LOG}"
echo "Agente:        auditoria-agent.service"
echo "API local:     http://127.0.0.1:8000"
echo "Usuario API:   ${USUARIO_API}"
