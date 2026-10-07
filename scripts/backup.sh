#!/usr/bin/env bash

set -euo pipefail
umask 0077

DIRECTORIO_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/operaciones-comunes.sh
. "${DIRECTORIO_SCRIPT}/lib/operaciones-comunes.sh"

ROL=""
DESTINO_BASE="/var/backups/auditoria-system"

mostrar_uso() {
    cat <<'EOF'
Uso:
  sudo ./scripts/backup.sh --role central [--destino /ruta]
  sudo ./scripts/backup.sh --role agent [--destino /ruta]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--role requiere un valor."; }
            ROL="$2"
            shift 2
            ;;
        --destino)
            [[ $# -ge 2 ]] || { mostrar_uso >&2; error "--destino requiere una ruta."; }
            DESTINO_BASE="$2"
            shift 2
            ;;
        -h|--help)
            mostrar_uso
            exit 0
            ;;
        *)
            mostrar_uso >&2
            error "argumento no reconocido: $1"
            ;;
    esac
done

validar_rol "${ROL}"
requerir_root
validar_ubuntu
requerir_comando systemctl
requerir_comando install
requerir_comando readlink
PYTHON="$(python_instalado)"

[[ "${DESTINO_BASE}" == /* ]] || error "--destino debe ser una ruta absoluta."
validar_destino_fuera_instalacion "${DESTINO_BASE}"
[[ -f "${DIRECTORIO_CONFIG}/agent.env" ]] || error "falta agent.env."
[[ -f "${DIRECTORIO_CONFIG}/agent-identity.json" ]] || \
    error "falta agent-identity.json; el backup operativo quedaría incompleto."
[[ -f "${DIRECTORIO_ESTADO}/auditoria.db" ]] || error "falta auditoria.db."
if [[ "${ROL}" == "central" ]]; then
    [[ -f "${DIRECTORIO_AUTH}/auth.db" ]] || error "falta auth.db."
    [[ -f "${DIRECTORIO_CENTRAL}/central.db" ]] || error "falta central.db."
fi

install -d -m 0700 "${DESTINO_BASE}"
MARCA_TIEMPO="$(date -u +%Y%m%dT%H%M%SZ)"
NOMBRE="backup-${ROL}-${MARCA_TIEMPO}"
DESTINO_FINAL="${DESTINO_BASE}/${NOMBRE}"
DESTINO_TEMPORAL="${DESTINO_BASE}/.${NOMBRE}.incompleto.$$"
[[ ! -e "${DESTINO_FINAL}" && ! -e "${DESTINO_TEMPORAL}" ]] || \
    error "ya existe un backup con el mismo identificador."
install -d -m 0700 "${DESTINO_TEMPORAL}"

mapfile -t SERVICIOS < <(servicios_del_rol "${ROL}")
mapfile -t ACTIVOS_ANTES < <(servicios_activos "${SERVICIOS[@]}")
BACKUP_COMPLETO=false

finalizar() {
    local estado=$?
    if [[ ${#ACTIVOS_ANTES[@]} -gt 0 ]]; then
        iniciar_servicios "${ACTIVOS_ANTES[@]}" || estado=1
    fi
    if [[ "${BACKUP_COMPLETO}" != true ]]; then
        case "${DESTINO_TEMPORAL}" in
            "${DESTINO_BASE}"/.*.incompleto.*)
                rm -rf -- "${DESTINO_TEMPORAL}"
                ;;
        esac
    fi
    exit "${estado}"
}
trap finalizar EXIT

detener_servicios "${SERVICIOS[@]}"

install -d -m 0700 \
    "${DESTINO_TEMPORAL}/etc/auditoria-system" \
    "${DESTINO_TEMPORAL}/var/lib/auditoria-system"
install -m 0600 "${DIRECTORIO_CONFIG}/agent.env" \
    "${DESTINO_TEMPORAL}/etc/auditoria-system/agent.env"
install -m 0600 "${DIRECTORIO_CONFIG}/agent-identity.json" \
    "${DESTINO_TEMPORAL}/etc/auditoria-system/agent-identity.json"
if [[ -f "${DIRECTORIO_ESTADO}/agent_state.json" ]]; then
    install -m 0600 "${DIRECTORIO_ESTADO}/agent_state.json" \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system/agent_state.json"
fi

respaldar_sqlite "${PYTHON}" "${DIRECTORIO_ESTADO}/auditoria.db" \
    "${DESTINO_TEMPORAL}/var/lib/auditoria-system/auditoria.db"
if [[ -f "${DIRECTORIO_ESTADO}/notifications.db" ]]; then
    respaldar_sqlite "${PYTHON}" "${DIRECTORIO_ESTADO}/notifications.db" \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system/notifications.db"
fi

if [[ "${ROL}" == "central" ]]; then
    install -d -m 0700 \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system-auth" \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system-central"
    respaldar_sqlite "${PYTHON}" "${DIRECTORIO_AUTH}/auth.db" \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system-auth/auth.db"
    respaldar_sqlite "${PYTHON}" "${DIRECTORIO_CENTRAL}/central.db" \
        "${DESTINO_TEMPORAL}/var/lib/auditoria-system-central/central.db"
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${RAIZ_INSTALACION}/pyproject.toml" | head -n 1)"
{
    echo "FORMATO=1"
    echo "ROLE=${ROL}"
    echo "CREATED_AT=${MARCA_TIEMPO}"
    echo "VERSION=${VERSION:-desconocida}"
    echo "ACTIVE_SERVICES=${ACTIVOS_ANTES[*]}"
} >"${DESTINO_TEMPORAL}/metadata.env"
chmod 0600 "${DESTINO_TEMPORAL}/metadata.env"

mv "${DESTINO_TEMPORAL}" "${DESTINO_FINAL}"
BACKUP_COMPLETO=true

if [[ ${#ACTIVOS_ANTES[@]} -gt 0 ]]; then
    iniciar_servicios "${ACTIVOS_ANTES[@]}"
    comprobar_servicios_activos "${ACTIVOS_ANTES[@]}"
    ACTIVOS_ANTES=()
fi

trap - EXIT
echo "Backup consistente creado con permisos restrictivos."
echo "BACKUP_CREADO=${DESTINO_FINAL}"
