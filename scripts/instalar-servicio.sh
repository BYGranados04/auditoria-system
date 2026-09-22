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

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: este instalador debe ejecutarse como root." >&2
    exit 1
fi

if [[ ! -x "${RAIZ_PROYECTO}/.venv/bin/python" ]]; then
    echo "Error: no existe el entorno virtual esperado." >&2
    exit 1
fi

if [[ ! -f "${SERVICIO_ORIGEN}" ]]; then
    echo "Error: no existe ${SERVICIO_ORIGEN}." >&2
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

systemctl daemon-reload
systemctl enable auditoria-agent.service

echo
echo "Auditoria System instalado correctamente."
echo "Configuración: ${CONFIG_DESTINO}"
echo "Estado:        ${DIRECTORIO_ESTADO}"
echo "Logs:          ${DIRECTORIO_LOG}"
